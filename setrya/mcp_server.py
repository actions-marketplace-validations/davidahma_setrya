"""Local MCP tools for reviewing erasure evidence and running approved fixtures."""

import argparse
from contextlib import contextmanager, ExitStack
from hashlib import sha256
import os
from pathlib import Path
import re
from selectors import DefaultSelector, EVENT_READ
import signal
import stat
import subprocess
import sys
from tempfile import NamedTemporaryFile, TemporaryDirectory
from time import monotonic

from .drill import InputError


_LIMIT = 16 * 1024
_TIMEOUT = 120


def _local(root, value, *, existing=True):
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise InputError("Use a workspace-relative path.")
    path = root / candidate
    if any(entry.is_symlink() for entry in (path, *path.parents) if entry != root and root in entry.parents):
        raise InputError("MCP paths cannot traverse symbolic links.")
    resolved = path.resolve(strict=existing)
    if root not in resolved.parents:
        raise InputError("Choose a path inside the workspace.")
    return resolved


def _read_inside(root, path, limit):
    directories = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parts = path.relative_to(root).parts
    with ExitStack() as opened:
        descriptor = os.open(root, directories)
        opened.callback(os.close, descriptor)
        for part in parts[:-1]:
            descriptor = os.open(part, directories, dir_fd=descriptor)
            opened.callback(os.close, descriptor)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(fd, "rb") as stream:
            status = os.fstat(stream.fileno())
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise InputError("Evidence must be a regular, unlinked workspace file.")
            raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise InputError("The evidence exceeds the MCP bundle budget.")
    return raw


@contextmanager
def _bundle(root, name):
    from .casework.recheck import copy_source
    from .evidence import bundle_manifest

    source = _local(root, name)
    if source.is_file():
        if source.name != bundle_manifest(source.parent):
            raise InputError("Choose the v3 evidence directory or its receipt.")
        source = source.parent
    with TemporaryDirectory(prefix="setrya-mcp-") as temp:
        target = Path(temp) / "bundle"
        copy_source(source, target, [128 * 1024 * 1024], read=lambda path, limit: _read_inside(root, path, limit))
        yield target


def _child(args, root):
    # Drain output without saving unbounded fixture logs or writing to stdio.
    command = [sys.executable, "-I", "-m", "setrya", *args]
    deadline = monotonic() + _TIMEOUT
    raw = bytearray()
    with DefaultSelector() as selector, subprocess.Popen(
        command, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True,
    ) as task:
        selector.register(task.stdout, EVENT_READ)
        try:
            while monotonic() < deadline and selector.select(max(0, deadline - monotonic())):
                block = os.read(task.stdout.fileno(), 8192)
                if not block:
                    status = task.wait(timeout=max(0, deadline - monotonic()))
                    break
                if len(raw) <= _LIMIT:
                    raw.extend(block[:_LIMIT + 1 - len(raw)])
            else:
                raise subprocess.TimeoutExpired(command, _TIMEOUT)
        except BaseException as exc:
            try:
                os.killpg(task.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            task.wait()
            if isinstance(exc, subprocess.TimeoutExpired):
                raise InputError("The fixture exceeded the MCP tool time limit.") from None
            raise
    text = raw[:_LIMIT].decode(errors="replace").rstrip()
    if len(raw) > _LIMIT:
        text += "\nOutput truncated."
    return {"exit_code": status, "output": text}


def _approve_fixture(root, name):
    path = _local(root, name)
    if path.suffix not in (".py", ".yaml", ".yml"):
        raise InputError("Approve one trusted Python or YAML fixture.")
    return sha256(_read_inside(root, path, 1024 * 1024)).digest()


def command(argv):
    parser = argparse.ArgumentParser(prog="setrya mcp", description="Expose local Setrya tools over MCP stdio.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="workspace containing evidence")
    parser.add_argument("--allow-init", action="store_true", help="allow creating a new starter directory")
    parser.add_argument("--fixture", help="approve this one trusted, disposable fixture for doctor and run")
    args = parser.parse_args(argv)
    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.types import ToolAnnotations
        from typing_extensions import TypedDict
    except ImportError:
        raise InputError("Install the MCP extra with python -m pip install 'setrya[mcp]'.") from None

    class CommandResult(TypedDict):
        exit_code: int
        output: str

    from .casework.receipt_summary import receipt_summary as render
    from .receipts import exit_code, replay as evaluate, summary

    root = args.root.resolve(strict=True)
    if not root.is_dir():
        raise InputError("Provide a workspace directory.")
    approved = _approve_fixture(root, args.fixture) if args.fixture else None
    server = FastMCP("Setrya", instructions="Review local erasure receipts. Use only synthetic fixtures for test runs.")

    @contextmanager
    def fixture():
        if args.fixture is None:
            raise InputError("Start the server with --fixture to approve a trusted disposable fixture.")
        entry = _local(root, args.fixture)
        raw = _read_inside(root, entry, 1024 * 1024)
        if sha256(raw).digest() != approved:
            raise InputError("The approved fixture changed. Review it before restarting the server.")
        # Preserve the fixture's directory for sibling imports and YAML
        # references while running exactly the approved entry bytes.
        with NamedTemporaryFile(prefix=".setrya-approved-", suffix=entry.suffix, dir=entry.parent) as copy:
            copy.write(raw)
            copy.flush()
            yield copy.name, str(entry)

    def output(name):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
            raise InputError("A new output directory must be a single workspace folder name.")
        path = _local(root, name, existing=False)
        if os.path.lexists(path):
            raise InputError("Choose a fresh output directory.")
        return str(path)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    def replay(bundle: str) -> CommandResult:
        """Recompute the verdict from a saved evidence bundle."""
        with _bundle(root, bundle) as snapshot:
            receipt = evaluate(snapshot)
            return {"exit_code": exit_code(receipt), "output": summary(receipt)[:_LIMIT]}

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    def receipt_summary(bundle: str, audience: str = "reviewer") -> str:
        """Explain the recorded checks and open items for the chosen audience."""
        with _bundle(root, bundle) as snapshot:
            return render(snapshot, audience=audience)[:_LIMIT]

    @server.tool(annotations=ToolAnnotations(readOnlyHint=not args.allow_init, destructiveHint=False, openWorldHint=False))
    def init(folder: str = "setrya-case") -> CommandResult:
        """Generate a starter in a fresh directory, if the server enables initialization."""
        if not args.allow_init:
            raise InputError("Initialization is disabled. Start the server with --allow-init to enable it.")
        return _child(["init", "--output", output(folder)], root)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=approved is None, openWorldHint=approved is not None))
    def doctor() -> dict:
        """Report MCP permissions or check wiring in the approved disposable fixture."""
        if approved is None:
            return {"mode": "read-only", "checks": ["replay", "receipt_summary"],
                    "fixture": "Approve a trusted disposable fixture at server startup to run diagnostics."}
        with fixture() as (entry, original):
            result = _child(["doctor", "--starter", entry], root)
        result["output"] = result["output"].replace(entry, original)
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=approved is None, openWorldHint=approved is not None))
    def run(folder: str = "setrya-evidence", mode: str = "deletion") -> CommandResult:
        """Run the approved disposable fixture and record its observations."""
        if mode not in ("deletion", "late-write"):
            raise InputError("Choose deletion or late-write.")
        with fixture() as (entry, original):
            result = _child(["run", "--starter", entry, "--output", output(folder), "--mode", mode], root)
        result["output"] = result["output"].replace(entry, original)
        return result

    server.run(transport="stdio")
    return 0
