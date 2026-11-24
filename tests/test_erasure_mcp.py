"""Exercise the actual stdio protocol and its opt-in execution boundary."""

import asyncio
import shutil
import subprocess
from pathlib import Path
import sys
import unittest

try:
    import pytest
except ImportError:
    raise unittest.SkipTest("Install pytest to exercise the MCP protocol.") from None

from setrya.cli import main
from setrya.receipts import replay

mcp = pytest.importorskip("mcp")
from mcp.client.stdio import StdioServerParameters, stdio_client


def test_local_mcp_tools(tmp_path, monkeypatch):
    # Keep the repository importable for the server process when testing a checkout.
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).parents[1]))
    assert main(["demo", "--output", str(tmp_path / "example"), "--mode", "deletion"]) == 0
    assert main(["init", "--output", str(tmp_path / "fixture")]) == 0

    def git(*args):
        return subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True,
                              text=True).stdout.strip()

    git("init", "-q")
    git("add", "fixture/test_erasure.py")
    git("-c", "user.name=Setrya fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Fixture")
    commit = git("rev-parse", "HEAD")

    copied = tmp_path / "symlinked"
    shutil.copytree(tmp_path / "example" / "guarded", copied)
    private = tmp_path.parent / (tmp_path.name + "-outside.json")
    evidence = copied / "erasure-evidence.json"
    evidence.replace(private)
    evidence.symlink_to(private)

    async def check(extra, *, permitted):
        command = StdioServerParameters(command=sys.executable,
                                       args=["-m", "setrya", "mcp", "--root", str(tmp_path), *extra])
        async with stdio_client(command) as (incoming, outgoing):
            async with mcp.ClientSession(incoming, outgoing) as session:
                await session.initialize()
                tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                assert set(tools) == {"init", "doctor", "run", "replay", "receipt_summary"}
                assert tools["init"].annotations.readOnlyHint is not permitted
                assert tools["replay"].annotations.readOnlyHint
                assert tools["run"].annotations.readOnlyHint is not permitted
                assert not (await session.call_tool("replay", {"bundle": "example/guarded"})).isError
                result = await session.call_tool("receipt_summary", {"bundle": "example/guarded", "audience": "customer"})
                assert not result.isError
                assert "recorded checks met" in result.content[0].text
                assert (await session.call_tool("replay", {"bundle": "../guarded"})).isError
                assert (await session.call_tool("replay", {"bundle": "symlinked"})).isError
                assert (await session.call_tool("receipt_summary", {"bundle": "symlinked"})).isError
                created = await session.call_tool("init", {"folder": "new-case"})
                assert created.isError is not permitted
                checked = await session.call_tool("doctor", {})
                assert not checked.isError
                ran = await session.call_tool("run", {"folder": "new-evidence"})
                assert ran.isError is not permitted
                if permitted:
                    assert ran.structuredContent["exit_code"] == 0

    asyncio.run(check([], permitted=False))
    assert not (tmp_path / "new-case").exists()
    assert not (tmp_path / "new-evidence").exists()
    asyncio.run(check(["--allow-init", "--fixture", "fixture/test_erasure.py"], permitted=True))
    receipt = replay(tmp_path / "new-evidence", expected_app_commit=commit)
    assert receipt["provenance"]["test_files"][0]["path"] == "fixture/test_erasure.py"
