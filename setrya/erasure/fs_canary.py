"""Read exact synthetic markers in local file-backed agent memory."""

from base64 import b64decode, urlsafe_b64encode
from collections import defaultdict
from contextlib import closing, contextmanager
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import cache
from hashlib import sha1, sha256
import os
from pathlib import Path
import re
from selectors import DefaultSelector, EVENT_READ
import shutil
import sqlite3
import stat
import subprocess
from tempfile import TemporaryDirectory, TemporaryFile
from time import monotonic

from setrya.core.scan_scope import SKIPPED_EXTENSIONS
from setrya.drill import InputError
from .adapters import _require_sqlite_base_table
from .journal import identifier


_MAX_ENTRIES = 4096
_MAX_FILE = 1024 * 1024
_MAX_CONTENT = 16 * 1024 * 1024
_MAX_DB = 64 * 1024 * 1024
_MAX_DEPTH = 32
_MAX_COMMITS = 128
_TIMEOUT = 15
_OID = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")
_ENCODED_PATH = "path64:"



@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Tune local file and Git scan budgets without disabling their bounds."""

    max_entries: int = 32768
    max_file_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 128 * 1024 * 1024
    max_commits: int = 2048
    timeout_seconds: int = 30

    def __post_init__(self):
        limits = {"max_entries": 1_000_000, "max_file_bytes": 128 * 1024 * 1024,
                  "max_total_bytes": 2 * 1024 * 1024 * 1024, "max_commits": 100_000,
                  "timeout_seconds": 300}
        for name, high in limits.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= high:
                raise InputError(f"{name} must be between 1 and {high}")


class CanaryMatches(set):
    """Set-compatible locations and the scope of their completed scan."""

    def __init__(self, locations, coverage):
        super().__init__(locations)
        self.coverage = coverage

    def encode_keys(self):
        """Encode all locations for receipt evidence while retaining scope metadata."""
        return CanaryMatches((encode_scan_location(location) for location in self), self.coverage)


def _limits(limits):
    if limits is None:
        return ScanLimits()
    if not isinstance(limits, ScanLimits):
        raise InputError("expected ScanLimits")
    return limits



def _scope(scope, marker):
    from .canary import validate_probe

    validate_probe("root", marker)
    if not isinstance(scope, str) or len(scope) > 1024:
        raise InputError("expected a bounded relative canary scope")
    return () if scope == "." else _parts(scope, "canary scope")


def _parts(value, label):
    parts = tuple(value.split("/"))
    if len(parts) > _MAX_DEPTH or any(not part or part in (".", "..") or chr(92) in part
                                      or not part.isprintable()
                                      for part in parts):
        raise InputError(f"invalid {label}")
    return parts


def encode_scan_location(location: str) -> str:
    """Encode a scanner path or commit:path as a replayable fixture key."""
    if not isinstance(location, str) or len(location) > 1024:
        raise InputError("expected a bounded scanner location")
    _parts(location, "scanner location")
    if not location.startswith(_ENCODED_PATH):
        try:
            return identifier(location, "scanner location")
        except InputError:
            pass
    try:
        encoded = urlsafe_b64encode(location.encode()).rstrip(b"=").decode("ascii")
    except UnicodeError:
        raise InputError("scanner location requires UTF-8") from None
    return identifier(_ENCODED_PATH + encoded, "encoded scanner location")


def decode_scan_location(key: str) -> str:
    """Restore the exact path to read from a fixture key."""
    identifier(key, "scanner key")
    if not key.startswith(_ENCODED_PATH):
        _parts(key, "scanner location")
        return key
    encoded = key[len(_ENCODED_PATH):]
    try:
        location = b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True).decode()
    except ValueError:
        raise InputError("invalid encoded scanner location") from None
    if encode_scan_location(location) != key:
        raise InputError("invalid encoded scanner location")
    return location


def _over(count, limit, kind):
    if count > limit:
        raise InputError(f"{kind} exceeds the canary scan budget")


def _stable(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def _open_at(name, flags, parent=None):
    if not hasattr(os, "O_NOFOLLOW"):
        raise InputError("safe local scanning requires no-follow file reads")
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        yield fd
    finally:
        os.close(fd)


class FilesystemCanaryScanner:
    """Scan selected regular files under a real directory using relative paths."""

    def __init__(self, root, include=("**/*.md", "**/*.jsonl"), *, limits=None):
        self.root = Path(root).absolute()
        self.limits = _limits(limits)
        if not isinstance(include, (tuple, list)) or not 1 <= len(include) <= 16:
            raise InputError("declare one to sixteen file patterns")
        self.patterns = tuple(_parts(pattern, "file pattern") for pattern in include
                              if isinstance(pattern, str) and 0 < len(pattern) <= 256)
        if len(self.patterns) != len(include):
            raise InputError("invalid file pattern")

    def find(self, *, scope, marker):
        prefix = _scope(scope, marker)
        needle = marker.encode()
        entries = size = 0
        deadline = monotonic() + self.limits.timeout_seconds
        fingerprints = {}
        found = set()
        skipped = defaultdict(int)

        def selected(path):
            for pattern in self.patterns:
                @cache
                def match(file_index, pattern_index):
                    if pattern_index == len(pattern):
                        return file_index == len(path)
                    segment = pattern[pattern_index]
                    if segment == "**":
                        return match(file_index, pattern_index + 1) or (
                            file_index < len(path) and match(file_index + 1, pattern_index))
                    return (file_index < len(path) and fnmatchcase(path[file_index], segment)
                            and match(file_index + 1, pattern_index + 1))
                if match(0, 0):
                    return True
            return False

        def visit(directory, path, *, recheck=False):
            nonlocal entries, size
            _over(len(path), _MAX_DEPTH, "directory depth")
            before = _stable(os.fstat(directory))
            if recheck and fingerprints.get(path) != before:
                raise InputError("directory changed during canary scan")
            fingerprints[path] = before
            with os.scandir(directory) as children:
                for child in children:
                    entries += 1
                    _over(entries, self.limits.max_entries, "filesystem entries")
                    if monotonic() >= deadline:
                        raise InputError("file canary deadline expired")
                    if not path and child.name == ".git":
                        continue  # Read the Git boundary with GitHistoryCanaryScanner.
                    if len(path) < len(prefix) and child.name != prefix[len(path)]:
                        continue
                    child_path = (*path, child.name)
                    info = child.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        raise InputError("file canary refuses symbolic links in scope")
                    if stat.S_ISDIR(info.st_mode):
                        with _open_at(child.name, os.O_RDONLY | os.O_DIRECTORY, directory) as fd:
                            if _stable(info) != _stable(os.fstat(fd)):
                                raise InputError("directory changed during canary scan")
                            visit(fd, child_path, recheck=recheck)
                    elif len(child_path) >= len(prefix):
                        if not selected(child_path):
                            suffix = Path(child.name).suffix.lower()
                            if stat.S_ISREG(info.st_mode) and suffix in SKIPPED_EXTENSIONS:
                                if recheck and fingerprints.get(child_path) != _stable(info):
                                    raise InputError("excluded file changed during canary scan")
                                if not recheck:
                                    skipped[suffix] += 1
                                    fingerprints[child_path] = _stable(info)
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            raise InputError("file canary requires regular files")
                        if recheck:
                            if fingerprints.get(child_path) != _stable(info):
                                raise InputError("file changed during canary scan")
                            continue
                        fingerprints[child_path] = _stable(info)
                        _over(info.st_size, self.limits.max_file_bytes, "file size")
                        size += info.st_size
                        _over(size, self.limits.max_total_bytes, "filesystem content")
                        with _open_at(child.name, os.O_RDONLY, directory) as fd:
                            if _stable(info) != _stable(os.fstat(fd)):
                                raise InputError("file changed during canary scan")
                            with open(fd, "rb", closefd=False) as stream:
                                content = stream.read(info.st_size + 1)
                            if len(content) != info.st_size or _stable(info) != _stable(os.fstat(fd)):
                                raise InputError("file changed during canary scan")
                        if needle in content:
                            key = "/".join(child_path)
                            _parts(key, "file canary location")
                            found.add(key)
            if before != _stable(os.fstat(directory)):
                raise InputError("directory changed during canary scan")

        if not hasattr(os, "O_NOFOLLOW") or os.scandir not in os.supports_fd:
            raise InputError("file canary needs descriptor-relative reads with no-follow support")
        try:
            with _open_at(self.root, os.O_RDONLY | os.O_DIRECTORY) as fd:
                visit(fd, ())
                entries = 0
                visit(fd, (), recheck=True)
                if _stable(os.stat(self.root, follow_symlinks=False)) != _stable(os.fstat(fd)):
                    raise InputError("scan root changed during canary scan")
        except OSError as error:
            raise InputError(f"unable to inspect scoped files ({type(error).__name__})") from None
        return CanaryMatches(found, {"kind": "filesystem", "scope": scope,
                                     "patterns": ["/".join(pattern) for pattern in self.patterns],
                                     "skipped": dict(sorted(skipped.items()))})


def _git_env():
    return {**{name: value for name, value in os.environ.items() if not name.startswith("GIT_")},
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": ""}


def _git_read(command, cwd, env, deadline, limit, data=b""):
    with TemporaryFile() as source:
        source.write(data)
        source.seek(0)
        with subprocess.Popen(command, cwd=cwd, env=env, stdin=source, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            with DefaultSelector() as selector:
                selector.register(proc.stdout, EVENT_READ)
                selector.register(proc.stderr, EVENT_READ)
                payload = bytearray()
                try:
                    while selector.get_map():
                        readers = selector.select(max(0, deadline - monotonic()))
                        if not readers:
                            raise InputError("Git canary deadline expired")
                        for event, _ in readers:
                            block = os.read(event.fd, 65536)
                            if not block:
                                selector.unregister(event.fileobj)
                            elif event.fileobj == proc.stderr:
                                raise InputError("Git reported an incomplete local history read")
                            else:
                                payload.extend(block)
                                _over(len(payload), limit, "Git output")
                        if monotonic() >= deadline:
                            raise InputError("Git canary deadline expired")
                    if proc.wait(timeout=max(0, deadline - monotonic())) != 0:
                        raise InputError("Git could not read the complete local history")
                finally:
                    if proc.poll() is None:
                        proc.kill()
    return bytes(payload)


def _batch_content(payload, expected):
    start = 0
    for oid, expected_size in expected:
        end = payload.find(b"\n", start)
        fields = payload[start:end].split() if end != -1 else ()
        if len(fields) != 3 or tuple(fields[:2]) != (oid, b"blob") or not fields[2].isdigit():
            raise InputError("Git returned an incomplete blob")
        size = int(fields[2])
        if size != expected_size:
            raise InputError("Git blob size differs from its inventory")
        start, end = end + 1, end + 1 + size
        if payload[end:end + 1] != b"\n":
            raise InputError("Git returned an incomplete blob")
        content = payload[start:end]
        digest = sha1() if len(oid) == 40 else sha256()
        digest.update(b"blob " + fields[2] + b"\x00")
        digest.update(content)
        if digest.hexdigest().encode("ascii") != oid:
            raise InputError("Git blob bytes do not match the object ID")
        yield oid, content
        start = end + 1
    if start != len(payload):
        raise InputError("unexpected trailing Git output")


def _check_local_git_files(directory, deadline, limits):
    """Restrict Git's object, reference and reflog paths to this repository."""
    if (not (directory / "objects").is_dir() or any(os.path.lexists(directory / name) for name in (
            "objects/info/alternates", "objects/info/http-alternates", "shallow", "info/grafts", "commondir"))):
        raise InputError("Git canary needs complete local history without alternates")
    entries = 0

    def check(path, depth):
        nonlocal entries
        entries += 1
        _over(entries, limits.max_entries * 2, "Git metadata")
        _over(depth, _MAX_DEPTH, "Git metadata depth")
        if monotonic() >= deadline:
            raise InputError("Git canary deadline expired")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            with os.scandir(path) as children:
                for child in children:
                    check(Path(child.path), depth + 1)
        elif not stat.S_ISREG(mode) or path.name.endswith(".promisor"):
            raise InputError("Git canary refuses symbolic paths and promised objects")

    for name in ("HEAD", "config", "config.worktree", "packed-refs", "objects", "refs", "logs", "worktrees", "reftable"):
        path = directory / name
        if os.path.lexists(path):
            check(path, 0)


class GitHistoryCanaryScanner:
    """Scan all local Git blobs and report their known history locations."""

    def __init__(self, repo, *, limits=None, remote_owner="repository-maintainer"):
        self.repo = Path(repo).absolute()
        self.limits = _limits(limits)
        self.remote_owner = identifier(remote_owner, "remote review owner")

    def find(self, *, scope, marker):
        prefix = tuple(part.encode() for part in _scope(scope, marker))
        executable = shutil.which("git")
        if executable is None:
            raise InputError("Git history canary requires git")
        directory = self.repo / ".git"
        if not os.path.lexists(directory):
            directory = self.repo
        if directory.is_symlink() or self.repo.is_symlink() or not directory.is_dir():
            raise InputError("Git canary requires a standalone local repository")
        deadline = monotonic() + self.limits.timeout_seconds
        env = _git_env()

        def git(*args, limit=512 * 1024, data=b""):
            return _git_read([executable, "--no-replace-objects", f"--git-dir={directory}", *args],
                             self.repo, env, deadline, limit, data)

        def inventory():
            payload = git("cat-file", "--batch-all-objects", "--unordered",
                          "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                          limit=self.limits.max_entries * 100)
            rows = payload.splitlines()
            _over(len(rows), self.limits.max_entries, "local Git objects")
            result = {}
            for row in rows:
                oid, kind, size = row.split()
                if (not _OID.fullmatch(oid) or kind not in (b"blob", b"tree", b"commit", b"tag")
                        or not size.isdigit() or len(size) > 20 or oid in result):
                    raise InputError("invalid local Git object inventory")
                result[oid] = kind, int(size)
            return result

        def remote_configured():
            raw = git("config", "--no-includes", "--null", "--list", limit=1024 * 1024)
            keys = [entry.partition(b"\n")[0].lower() for entry in raw.split(b"\x00") if entry]
            if any(key == b"include.path" or key.startswith(b"includeif.") for key in keys):
                raise InputError("Git canary requires standalone configuration without includes")
            return any(key.startswith(b"remote.") and key.count(b".") >= 2 for key in keys)

        def commit_roots():
            raw = git("log", "--all", "--reflog", "--no-color", "--no-decorate", "--no-notes",
                      "--no-show-signature", "--format=%H %T", f"-{self.limits.max_commits + 1}",
                      limit=(self.limits.max_commits + 1) * 132)
            rows = raw.splitlines()
            _over(len(rows), self.limits.max_commits, "local Git commits")
            roots = defaultdict(list)
            for row in rows:
                commit, tree = row.split()
                if not _OID.fullmatch(commit) or not _OID.fullmatch(tree) or len(commit) != len(tree):
                    raise InputError("invalid Git commit or tree ID")
                roots[tree].append(commit)
            return roots

        try:
            _check_local_git_files(directory, deadline, self.limits)
            remotes = remote_configured()
            objects = inventory()
            roots = commit_roots()
            hits = _blob_matches(git, objects, marker.encode(), self.limits)
            found = _history_locations(git, objects, roots, hits, prefix, self.limits)
            _check_local_git_files(directory, deadline, self.limits)
            if objects != inventory() or roots != commit_roots() or remotes != remote_configured():
                raise InputError("Git objects, refs, reflogs or remote configuration changed during the scan")
        except InputError:
            raise
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            raise InputError(f"unable to inspect Git history ({type(error).__name__})") from None
        return CanaryMatches(found, {"kind": "git", "scope": scope, "objects": "all-local-blobs",
                                     "remote_configured": remotes, "remote_owner": self.remote_owner})


def _blob_matches(git, objects, needle, limits):
    blobs = sorted((oid, size) for oid, (kind, size) in objects.items() if kind == b"blob")
    _over(sum(size for _, size in blobs), limits.max_total_bytes, "Git blob content")
    matches = set()
    batch, pending = [], 0

    def read():
        payload = git("cat-file", "--batch", data=b"".join(oid + b"\n" for oid, _ in batch),
                      limit=pending + len(batch) * 100)
        for oid, content in _batch_content(payload, batch):
            if needle in content:
                matches.add(oid)
    for oid, size in blobs:
        _over(size, limits.max_file_bytes, "Git blob size")
        if batch and (pending + size > 8 * 1024 * 1024 or len(batch) >= 1024):
            read()
            batch, pending = [], 0
        batch.append((oid, size))
        pending += size
    if batch:
        read()
    return matches


def _history_locations(git, objects, roots, hits, prefix, limits):
    entries = 0
    wanted = set(hits)
    found = set()

    @cache
    def load_tree(oid):
        nonlocal entries
        if objects.get(oid, (None,))[0] != b"tree":
            raise InputError("Git history refers to a missing tree")
        raw = git("ls-tree", "-z", oid.decode("ascii"),
                  limit=min(128 * 1024 * 1024, limits.max_entries * 1200))
        if raw and not raw.endswith(b"\x00"):
            raise InputError("Git returned an incomplete tree")
        result = []
        for row in raw.split(b"\x00")[:-1]:
            header, name = row.split(b"\t", 1)
            _, kind, child = header.split()
            if not name or b"/" in name or kind not in (b"tree", b"blob", b"commit") or not _OID.fullmatch(child):
                raise InputError("invalid Git tree entry")
            if kind == b"blob":
                if objects.get(child, (None,))[0] != b"blob":
                    raise InputError("Git history refers to a missing blob")
                wanted.discard(child)
            result.append((kind, child, name))
        entries += len(result)
        _over(entries, limits.max_entries, "unique Git tree entries")
        return result

    @cache
    def relevant(oid, depth):
        _over(depth, _MAX_DEPTH, "Git tree depth")
        return tuple((kind, child, name) for kind, child, name in load_tree(oid)
                     if kind == b"commit" or kind == b"blob" and child in hits
                     or kind == b"tree" and relevant(child, depth + 1))

    def visit(root, path, commits):
        for kind, child, name in relevant(root, len(path)):
            full = (*path, name)
            in_scope = full[:len(prefix)] == prefix
            contains_scope = prefix[:len(full)] == full
            if kind == b"tree" and (in_scope or contains_scope):
                visit(child, full, commits)
            elif kind == b"commit" and (in_scope or contains_scope):
                raise InputError("declare submodule histories separately")
            elif kind == b"blob" and in_scope:
                location = b"/".join(full).decode("utf-8")
                _parts(location, "Git canary path")
                for commit in commits:
                    found.add(f"{commit.decode('ascii')}:{location}")
                    _over(len(found), 512, "Git matching locations")

    for root, commits in roots.items():
        visit(root, (), commits)
    # A blob without an addressable commit path has unknown scope. Retain
    # the positive observation even for a directory-scoped scan.
    found.update(f"blob:{oid.decode('ascii')}" for oid in wanted)
    _over(len(found), 512, "Git matching locations")
    return found


@contextmanager
def _snapshot(path):
    """Copy a quiescent main database and its WAL without creating source sidecars."""
    wal, rollback = Path(f"{path}-wal"), Path(f"{path}-journal")

    def signatures():
        if os.path.lexists(rollback):
            raise InputError("finish the AgentFS transaction before scanning")
        return [(src, _stable(src.lstat())) for src in (path, wal) if src == path or os.path.lexists(src)]

    initial = signatures()
    with TemporaryDirectory(prefix="setrya-agentfs-read-") as work:
        snap = Path(work) / path.name
        size = 0
        for source, fingerprint in initial:
            info = source.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise InputError("AgentFS canary requires regular database files")
            size += info.st_size
            _over(size, _MAX_DB, "AgentFS database snapshot")
            with _open_at(source, os.O_RDONLY) as fd:
                if _stable(os.fstat(fd)) != fingerprint:
                    raise InputError("AgentFS changed during the scan")
                with open(fd, "rb", closefd=False) as stream:
                    content = stream.read(info.st_size + 1)
                if len(content) != info.st_size:
                    raise InputError("AgentFS changed during the scan")
            (Path(work) / source.name).write_bytes(content)
        if signatures() != initial:
            raise InputError("AgentFS changed during the scan")
        yield snap


class AgentFSCanaryScanner:
    """Read a local, unencrypted AgentFS file snapshot using its published inode schema."""

    def __init__(self, sqlite_path):
        self.path = Path(sqlite_path).absolute()

    def find(self, *, scope, marker):
        prefix = _scope(scope, marker)
        try:
            with _snapshot(self.path) as path, closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
                db.execute("PRAGMA trusted_schema=OFF")
                db.execute("PRAGMA query_only=ON")
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_FILE + 4096)
                deadline = monotonic() + _TIMEOUT
                db.set_progress_handler(lambda: monotonic() >= deadline, 1000)
                db.execute("BEGIN")
                return self._scan(db, prefix, marker.encode())
        except (sqlite3.Error, OSError, UnicodeError) as error:
            raise InputError(f"unable to inspect AgentFS snapshot ({type(error).__name__})") from None

    def _scan(self, db, prefix, needle):
        for table in ("fs_config", "fs_inode", "fs_dentry", "fs_data"):
            _require_sqlite_base_table(db, '"' + table + '"')
        settings = db.execute("SELECT key,value FROM main.fs_config WHERE key IN "
                              "('chunk_size','schema_version') LIMIT 3").fetchall()
        config = dict(settings)
        if (len(settings) != 2 or config.get("schema_version") != "0.4"
                or not isinstance(config.get("chunk_size"), str)
                or not re.fullmatch(r"[1-9][0-9]{0,6}", config["chunk_size"])):
            raise InputError("expected an AgentFS 0.4 database with a known chunk size")
        if db.execute("SELECT name FROM main.sqlite_schema WHERE name IN ('fs_origin','fs_whiteout') LIMIT 1").fetchone():
            raise InputError("scan standalone AgentFS file snapshots; resolve overlay layers separately")
        chunk_size = int(config["chunk_size"])
        _over(chunk_size, _MAX_FILE, "AgentFS chunk size")
        inodes = db.execute("SELECT ino, mode, size FROM main.fs_inode LIMIT ?", (_MAX_ENTRIES + 1,)).fetchall()
        _over(len(inodes), _MAX_ENTRIES, "AgentFS inodes")
        if any(type(ino) is not int or type(mode) is not int or type(size) is not int or ino < 1 or size < 0
               for ino, mode, size in inodes):
            raise InputError("invalid AgentFS inode")
        files = {ino: (mode, size) for ino, mode, size in inodes}
        if len(files) != len(inodes) or 1 not in files or not stat.S_ISDIR(files[1][0]):
            raise InputError("expected an unambiguous AgentFS root inode")
        dentries = db.execute("SELECT parent_ino, CASE WHEN length(CAST(name AS BLOB)) <= 255 "
                              "THEN name END, ino FROM main.fs_dentry LIMIT ?", (_MAX_ENTRIES + 1,)).fetchall()
        _over(len(dentries), _MAX_ENTRIES, "AgentFS paths")
        children = defaultdict(dict)
        for parent, name, child in dentries:
            if (type(parent) is not int or type(child) is not int or child == 1
                    or parent not in files or child not in files or not stat.S_ISDIR(files[parent][0])
                    or not isinstance(name, str) or len(_parts(name, "AgentFS component")) != 1
                    or name in children[parent]):
                raise InputError("invalid AgentFS directory entry")
            children[parent][name] = child
        if db.execute("SELECT 1 FROM main.fs_data AS d LEFT JOIN main.fs_inode AS i ON d.ino = i.ino "
                      "WHERE i.ino IS NULL OR (i.mode & 61440) != 32768 LIMIT 1").fetchone():
            raise InputError("AgentFS data rows have no regular-file inode")
        visited = {1}
        directories = {1}
        scoped = defaultdict(set)

        def visit(parent, path):
            _over(len(path), _MAX_DEPTH, "AgentFS tree depth")
            for name, ino in children.get(parent, {}).items():
                full = (*path, name)
                mode, _ = files[ino]
                visited.add(ino)
                if stat.S_ISDIR(mode):
                    if ino in directories:
                        raise InputError("AgentFS directory has multiple paths or forms a cycle")
                    directories.add(ino)
                    visit(ino, full)
                elif full[:len(prefix)] == prefix:
                    if not stat.S_ISREG(mode):
                        raise InputError("AgentFS canary requires regular files and does not follow symbolic links")
                    scoped[ino].add("/".join(full))
        visit(1, ())
        if visited != files.keys():
            raise InputError("AgentFS inode has no visible path")
        total = 0
        found = set()
        for ino, paths in scoped.items():
            size = files[ino][1]
            _over(size, _MAX_FILE, "AgentFS file")
            total += size
            _over(total, _MAX_CONTENT, "AgentFS content")
            count = (size + chunk_size - 1) // chunk_size
            _over(count, _MAX_ENTRIES, "AgentFS chunk count")
            chunks = db.execute("SELECT chunk_index, CASE WHEN length(data)<=? THEN data END "
                                "FROM main.fs_data WHERE ino=? ORDER BY chunk_index LIMIT ?",
                                (chunk_size, ino, count + 1))
            content = bytearray()
            for expected, (index, data) in enumerate(chunks):
                if (type(index) is not int or index != expected or expected >= count
                        or not isinstance(data, bytes) or len(data) != min(chunk_size, size - len(content))):
                    raise InputError("AgentFS file has incomplete or unsupported chunks")
                content.extend(data)
            if len(content) != size:
                raise InputError("AgentFS file has incomplete or unsupported chunks")
            if needle in content:
                found.update(paths)
        return found
