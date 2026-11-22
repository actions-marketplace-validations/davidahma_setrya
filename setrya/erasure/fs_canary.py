"""Read exact synthetic markers in local file-backed agent memory."""

from base64 import b64decode, urlsafe_b64encode
from collections import defaultdict
from contextlib import closing, contextmanager
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


def _scope(scope, marker):
    from .canary import validate_probe

    validate_probe("root", marker)
    if not isinstance(scope, str) or len(scope) > 1024:
        raise InputError("expected a bounded relative canary scope")
    return () if scope == "." else _parts(scope, "canary scope")


def _parts(value, label):
    parts = tuple(value.split("/"))
    if len(parts) > _MAX_DEPTH or any(not part or part in (".", "..") or chr(92) in part
                                      or any(ord(char) < 32 or ord(char) == 127 for char in part)
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

    def __init__(self, root, include=("**/*.md", "**/*.jsonl")):
        self.root = Path(root).absolute()
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
        deadline = monotonic() + _TIMEOUT
        fingerprints = {}
        found = set()

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
                    _over(entries, _MAX_ENTRIES, "filesystem entries")
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
                    elif len(child_path) >= len(prefix) and selected(child_path):
                        if not stat.S_ISREG(info.st_mode):
                            raise InputError("file canary requires regular files")
                        if recheck:
                            if fingerprints.get(child_path) != _stable(info):
                                raise InputError("file changed during canary scan")
                            continue
                        fingerprints[child_path] = _stable(info)
                        _over(info.st_size, _MAX_FILE, "file size")
                        size += info.st_size
                        _over(size, _MAX_CONTENT, "filesystem content")
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
        return found


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
                              stderr=subprocess.DEVNULL) as proc:
            with DefaultSelector() as selector:
                selector.register(proc.stdout, EVENT_READ)
                payload = bytearray()
                try:
                    while True:
                        if not selector.select(max(0, deadline - monotonic())):
                            raise InputError("Git canary deadline expired")
                        block = os.read(proc.stdout.fileno(), 65536)
                        if not block:
                            break
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
    total = 0
    for oid in expected:
        end = payload.find(b"\n", start)
        fields = payload[start:end].split() if end != -1 else ()
        if len(fields) != 3 or tuple(fields[:2]) != (oid, b"blob") or not fields[2].isdigit():
            raise InputError("Git returned an incomplete blob")
        size = int(fields[2])
        _over(size, _MAX_FILE, "Git blob size")
        total += size
        _over(total, _MAX_CONTENT, "Git blob content")
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


def _check_local_git_files(directory, deadline):
    """Restrict Git's object, reference and reflog paths to this repository."""
    if (not (directory / "objects").is_dir() or any(os.path.lexists(directory / name) for name in (
            "objects/info/alternates", "objects/info/http-alternates", "shallow", "info/grafts", "commondir"))):
        raise InputError("Git canary needs complete local history without alternates")
    entries = 0

    def check(path, depth):
        nonlocal entries
        entries += 1
        _over(entries, _MAX_ENTRIES * 2, "Git metadata")
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

    for name in ("HEAD", "config", "packed-refs", "objects", "refs", "logs", "worktrees", "reftable"):
        path = directory / name
        if os.path.lexists(path):
            check(path, 0)


class GitHistoryCanaryScanner:
    """Scan every local commit reachable from refs, HEADs or reflogs in a complete repository."""

    def __init__(self, repo):
        self.repo = Path(repo).absolute()

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
        deadline = monotonic() + _TIMEOUT
        env = _git_env()

        def git(*args, limit=512 * 1024, data=b""):
            return _git_read([executable, "--no-replace-objects", f"--git-dir={directory}", *args],
                             self.repo, env, deadline, limit, data)

        def objects(*args):
            result = git("rev-list", "--all", "--reflog", *args, limit=_MAX_ENTRIES * 66).splitlines()
            _over(len(result), _MAX_ENTRIES, "reachable Git objects")
            if any(not _OID.fullmatch(oid) for oid in result):
                raise InputError("invalid reachable Git object ID")
            return set(result)

        try:
            _check_local_git_files(directory, deadline)
            all_objects = objects("--objects", "--no-object-names")
            commits = objects()
            _over(len(commits), _MAX_COMMITS, "reachable Git commits")
            paths = defaultdict(set)
            blobs = set()
            entries = path_bytes = 0
            for commit in sorted(commits):
                tree = git("ls-tree", "-r", "-z", "--full-tree", commit.decode("ascii"))
                if tree and not tree.endswith(b"\x00"):
                    raise InputError("Git returned an incomplete tree")
                for row in tree.split(b"\x00")[:-1]:
                    spec, filename = row.split(b"\t", 1)
                    _, kind, oid = spec.split()
                    components = tuple(filename.split(b"/"))
                    entries += 1
                    path_bytes += len(filename)
                    _over(entries, _MAX_ENTRIES, "Git tree entries")
                    _over(path_bytes, _MAX_CONTENT, "Git tree paths")
                    if kind == b"commit":  # A gitlink is a pointer to a separate repository.
                        if components[:len(prefix)] == prefix or prefix[:len(components)] == components:
                            raise InputError("declare submodule histories separately")
                        continue
                    if kind != b"blob" or not _OID.fullmatch(oid):
                        raise InputError("invalid Git tree entry")
                    blobs.add(oid)
                    if components[:len(prefix)] == prefix:
                        key = filename.decode("utf-8")
                        _parts(key, "Git canary path")
                        paths[oid].add(f"{commit.decode('ascii')}:{key}")

            # Raw refs can point at a blob or a tree instead of a commit. Account
            # for them rather than silently making a commit-only negative claim.
            extra = sorted(all_objects - blobs - commits)
            if extra:
                checks = git("cat-file", "--batch-check=%(objectname) %(objecttype)", data=b"\n".join(extra) + b"\n")
                rows = checks.splitlines()
                if len(rows) != len(extra):
                    raise InputError("Git did not check every reachable object")
                for oid, row in zip(extra, rows):
                    if row not in (oid + b" tree", oid + b" tag"):
                        raise InputError("reachable Git object has no commit:path location")

            found = set()
            if paths:
                ids = sorted(paths)
                payload = git("cat-file", "--batch", data=b"\n".join(ids) + b"\n",
                              limit=_MAX_CONTENT + len(ids) * 100)
                needle = marker.encode()
                for oid, content in _batch_content(payload, ids):
                    if needle in content:
                        found.update(paths[oid])
            if all_objects != objects("--objects", "--no-object-names") or commits != objects():
                raise InputError("Git refs or reflogs changed during the scan")
        except InputError:
            raise
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            raise InputError(f"unable to inspect Git history ({type(error).__name__})") from None
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
