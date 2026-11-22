"""Metadata-only readers for explicitly scoped branch inventories."""
from contextlib import closing
from fnmatch import fnmatchcase
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from subprocess import SubprocessError
from time import monotonic
from urllib.error import URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from setrya.casework.profiles import stamp
from setrya.core.errors import InputError
from setrya.core.inputs import require, unique_fields
from setrya.erasure.fs_canary import _git_env, _git_read

from setrya.core.branch_journal import MAX_BRANCHES, branch

MAX_FILES = 4096
MAX_RESPONSE = 2 * 1024 * 1024
NEON_API = "https://console.neon.tech/api/v2"


def _entries(root):
    before = root.lstat()
    require(stat.S_ISDIR(before.st_mode), "Branch scanner root must be a physical directory.")
    with os.scandir(root) as entries:
        for index, entry in enumerate(entries):
            require(index < MAX_FILES, "Branch scanner exceeded its directory budget.")
            yield entry.name, Path(entry.path)
    after = root.lstat()
    require((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
            "Branch scanner directory changed during enumeration.")


def _local_id(name, path):
    return "copy:" + sha256(os.fsencode(name) + b"\0" + os.fsencode(path)).hexdigest()[:32]


def _checks(name, root, aliases, observed, known):
    checks = []
    for item in sorted(set(aliases) | set(observed)):
        child = aliases.get(item) or _local_id(name, item)
        if item in observed:
            checks.append({"child": child, "state": observed[item],
                           **({"edge": branch(root, child, None)} if child not in known else {})})
        elif child in known:
            checks.append({"child": child, "state": "gone"})
        else:
            # An alias with no creation event cannot establish whether it once existed.
            checks.append({"child": child, "state": "unknown", "edge": branch(root, child, None)})
    return checks


def _sqlite_state(file):
    try:
        details = file.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_size < 100:
            return "unknown"
        # Offline backup files should have no recovery state beside them.
        if any(os.path.lexists(str(file) + extension) for extension in ("-wal", "-journal", "-shm")):
            return "unknown"
        with closing(sqlite3.connect(file.absolute().as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("SELECT name FROM main.sqlite_schema LIMIT 1").fetchone()
        current = file.lstat()
        if (details.st_ino, details.st_dev, details.st_mtime_ns, details.st_size) == (
                current.st_ino, current.st_dev, current.st_mtime_ns, current.st_size):
            return "live"
    except (OSError, sqlite3.Error):
        pass
    return "unknown"


def sqlite_backups(path, patterns):
    files = {}
    for name, candidate in _entries(path):
        if any(fnmatchcase(name, pattern) for pattern in patterns):
            files[name] = _sqlite_state(candidate)
    return files, False


def _git(path, *args):
    environment = {**_git_env(), "GIT_CEILING_DIRECTORIES": str(path.absolute().parent), "LC_ALL": "C"}
    return _git_read(["git", *args], path, environment, monotonic() + 8, MAX_RESPONSE)


def _git_remotes(path):
    rows = _git(path, "config", "--no-includes", "--null", "--list").split(b"\x00")
    keys = [entry.partition(b"\n")[0].lower() for entry in rows if entry]
    # Included configuration and per-worktree overrides can contribute remote
    # definitions beyond the common repository config read here.
    return any(key == b"include.path" or key.startswith(b"includeif.") or key == b"extensions.worktreeconfig"
               or key.startswith(b"remote.") and key.count(b".") >= 2 for key in keys)


def _git_repository(path, *, allow_bare=False):
    bare = _git(path, "rev-parse", "--is-bare-repository").strip() == b"true"
    require(not bare or allow_bare, "Git worktree scanner needs a non-bare checkout.")
    arg = "--absolute-git-dir" if bare else "--show-toplevel"
    checked = _git(path, "rev-parse", "--path-format=absolute", arg)
    require(Path(os.fsdecode(checked.rstrip(b"\n"))).resolve() == path.resolve(), "Unexpected Git checkout root.")


def git_clones(path, aliases):
    files, remote = {}, False
    for name, candidate in _entries(path):
        marker = candidate / ".git"
        if candidate.is_symlink() or marker.is_symlink():
            files[name] = "unknown"
        elif os.path.lexists(marker) or ((candidate / "HEAD").is_file() and (candidate / "objects").is_dir()):
            try:
                _git_repository(candidate, allow_bare=True)
                files[name] = "live"
            except (OSError, SubprocessError, InputError):
                files[name] = "unknown"
            else:
                try:
                    remote |= _git_remotes(candidate)
                except (OSError, SubprocessError, InputError):
                    remote = True
        elif name in aliases:
            # An expected clone path with an unreadable or replaced checkout is uncertain.
            files[name] = "unknown"
    return files, remote


def git_worktrees(path, aliases):
    require(not path.is_symlink() and path.is_dir(), "Git worktree scanner needs a physical checkout.")
    _git_repository(path)
    files = {}
    output = _git(path, "worktree", "list", "--porcelain", "-z")
    for start, *info in (row.split(b"\x00") for row in output.split(b"\x00\x00") if row):
        require(start.startswith(b"worktree "), "Git returned malformed worktree metadata.")
        worktree = Path(os.fsdecode(start[9:]))
        if worktree == path.resolve():
            continue
        name = str(worktree)
        require(worktree.is_absolute() and name not in files, "Unexpected Git worktree identity.")
        files[name] = ("live" if worktree.is_dir() and not worktree.is_symlink()
                       and not any(v.startswith(b"prunable") for v in info) else "unknown")
    for name in aliases:
        if name not in files and os.path.lexists(name):
            files[name] = "unknown"
    try:
        remote = _git_remotes(path)
    except (OSError, SubprocessError, InputError):
        remote = True
    return files, remote


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _neon_page(project, token, cursor):
    args = {"limit": 100, "include_deleted": "true"}
    if cursor:
        args["cursor"] = cursor
    request = Request(f"{NEON_API}/projects/{quote(project, safe='')}/branches?{urlencode(args)}",
                      headers={"Authorization": "Bearer " + token, "Accept": "application/json"}, method="GET")
    with build_opener(_NoRedirect()).open(request, timeout=8) as response:
        raw = response.read(MAX_RESPONSE + 1)
    require(len(raw) <= MAX_RESPONSE, "Neon metadata exceeds the branch scan budget.")
    return json.loads(raw, object_pairs_hook=unique_fields)


def _neon_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}", value),
            "Invalid Neon resource ID.")
    return value


def _stable_generation(item, erased):
    reset = item.get("last_reset_at")
    return stamp(reset) < erased if reset else not item.get("restore_status")


def neon_branches(project, source_id, token, root, known, erased, page=None):
    page = page or _neon_page
    require(isinstance(token, str) and 0 < len(token) <= 4096 and not any(ch.isspace() for ch in token),
            "Missing or invalid Neon API credential.")
    _neon_id(project)
    _neon_id(source_id)
    rows, cursors, cursor = {}, set(), None
    for _ in range(12):
        document = page(project, token, cursor)
        require(isinstance(document, dict) and isinstance(document.get("branches"), list),
                "Neon did not return branch inventory.")
        for item in document["branches"]:
            require(isinstance(item, dict), "Invalid Neon branch metadata.")
            key = _neon_id(item.get("id"))
            require(item.get("project_id", project) == project, "Neon returned a branch from a different project.")
            require(key not in rows and len(rows) < MAX_BRANCHES, "Repeated or excessive Neon branch metadata.")
            rows[key] = item
        metadata = document.get("pagination") or {}
        require(isinstance(metadata, dict), "Invalid Neon branch pagination metadata.")
        cursor = metadata.get("next")
        if cursor is None:
            break
        require(isinstance(cursor, str) and 0 < len(cursor) <= 2048 and cursor not in cursors,
                "Neon returned an invalid branch cursor.")
        cursors.add(cursor)
    else:
        raise InputError("Neon branch inventory exceeded its pagination budget.")
    require(source_id in rows and not rows[source_id].get("recovery"), "Neon source branch is missing from inventory.")
    source = rows[source_id]
    complete = source.get("current_state") in ("ready", "archived") and _stable_generation(source, erased)
    prefix = f"neon:{project}:"
    identifiers = {item: root if item == source_id else prefix + item for item in rows}
    children = {}
    for name, item in rows.items():
        if name == source_id:
            continue
        if item.get("parent_id") is None:
            # A promoted branch can lose its ancestry. An opaque, unbound
            # source is surfaced as unknown instead of assuming post-erasure.
            parent = prefix + "unbound-parent"
        else:
            raw_parent = _neon_id(item["parent_id"])
            parent = identifiers.get(raw_parent, prefix + raw_parent)
        child = identifiers[name]
        stable = (not item.get("recovery") and item.get("current_state") in ("ready", "archived")
                  and _stable_generation(item, erased))
        state = "live" if stable else "unknown"
        copy_time = item.get("parent_timestamp") or None
        if state != "live" or item.get("init_source") not in (None, "parent-data"):
            copy_time = None
        if copy_time is None and child in known:
            # Keep the journal's origin, but an unreadable branch can never
            # inherit a positive live-state observation from the journal.
            children[child] = {"child": child, "state": state if item.get("init_source") in (None, "parent-data") else "unknown"}
        else:
            children[child] = {"child": child, "state": state, "edge": branch(parent, child, copy_time)}
    for child in known:
        if child.startswith(prefix) and child not in children and child != root:
            # Metadata does not establish expiry of provider snapshots or backups.
            children[child] = {"child": child, "state": "unknown"}
    return [children[name] for name in sorted(children)], complete


def observe(spec, root, known, erased):
    kind = spec["kind"]
    metadata = {"id": spec["id"], "kind": kind, "complete": False, "remote": False, "checks": []}
    complete = True
    try:
        if kind == "neon":
            checks, complete = neon_branches(spec["project"], spec["source_branch"], os.getenv(spec["token_env"]),
                                              root, known, erased)
            remote = False
        else:
            path, aliases = spec["path"], spec["aliases"]
            if kind == "sqlite":
                files, remote = sqlite_backups(path, spec["patterns"])
            elif kind == "git-clones":
                files, remote = git_clones(path, aliases)
            else:
                files, remote = git_worktrees(path, aliases)
            checks = _checks(spec["id"], root, aliases, files, known)
        require(len(checks) <= MAX_BRANCHES, "Branch scanner exceeded its observation budget.")
    except (InputError, OSError, SubprocessError, URLError, ValueError):
        return metadata
    return {**metadata, "complete": complete, "remote": remote, "checks": checks}
