"""Native working-tree, reflog and SQLite AgentFS evidence for a synthetic subject."""
import asyncio
from contextlib import closing, redirect_stderr, redirect_stdout
import importlib.util
from io import StringIO
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from setrya.cli import main
from setrya.drill import InputError
from setrya.erasure.canary import AgentFSCanaryScanner, FilesystemCanaryScanner, GitHistoryCanaryScanner
from setrya.examples.memory_files import DERIVED_FILE, TARGET_FILE, _git_env
from setrya.receipts import replay


MARKER = "erasure-canary-417"


class WorkingTreeTests(unittest.TestCase):
    def test_scope_patterns_nested_and_root_paths(self):
        with TemporaryDirectory() as work:
            folder = Path(work)
            for path in ("top.md", "team/one/a.jsonl", "team/one/private.txt", "outside/b.md"):
                file = folder / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(MARKER)
            scanner = FilesystemCanaryScanner(folder)
            self.assertEqual(scanner.find(scope="team", marker=MARKER), {"team/one/a.jsonl"})
            self.assertEqual(scanner.find(scope=".", marker=MARKER), {"top.md", "team/one/a.jsonl", "outside/b.md"})
            with self.assertRaises(InputError):
                scanner.find(scope="team/../outside", marker=MARKER)

    def test_rechecks_earlier_files_before_claiming_absence(self):
        # Change the first file in place after its bytes and metadata were read.
        # The scope directory itself does not change, so a directory check alone misses it.
        from setrya.erasure import fs_canary

        with TemporaryDirectory() as work:
            path = Path(work, "memory.md")
            path.write_text("clean-session-note")
            original = fs_canary._stable
            checks = 0

            def change_after_read(info):
                nonlocal checks
                signature = original(info)
                if info.st_ino == path.stat().st_ino:
                    checks += 1
                    if checks == 3:
                        path.write_text(MARKER)
                return signature
            with patch.object(fs_canary, "_stable", change_after_read):
                with self.assertRaisesRegex(InputError, "changed"):
                    FilesystemCanaryScanner(path.parent).find(scope=".", marker=MARKER)

    def test_links_and_budgets_cannot_report_clean(self):
        with TemporaryDirectory() as work:
            folder = Path(work)
            root = folder / "root"
            root.mkdir()
            outside = folder / "outside"
            outside.mkdir()
            (outside / "hidden.md").write_text(MARKER)
            (root / "link").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(InputError, "symbolic"):
                FilesystemCanaryScanner(root).find(scope=".", marker=MARKER)
            (root / "link").unlink()
            (root / "large.md").write_bytes(b"x" * (1024 ** 2 + 1))
            with self.assertRaisesRegex(InputError, "budget"):
                FilesystemCanaryScanner(root).find(scope=".", marker=MARKER)


@unittest.skipUnless(shutil.which("git"), "requires Git to test real local object history")
class GitHistoryTests(unittest.TestCase):
    def test_all_paths_from_one_blob_and_reflog_only_history(self):
        with TemporaryDirectory() as work:
            root = Path(work)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-c", "user.name=Setrya test", "-c", "user.email=dev@example.test", *args],
                    cwd=root, env=_git_env(), stderr=subprocess.DEVNULL, timeout=10,
                ).decode().strip()

            git("init", "-b", "main", "--template=")
            git("config", "core.logAllRefUpdates", "true")
            (root / "readme.md").write_text("A new workspace")
            git("add", "readme.md")
            git("commit", "-m", "clean", "--no-gpg-sign")
            clean = git("rev-parse", "HEAD")
            (root / "memory").mkdir()
            for path in ("memory/first.md", "second.md"):
                (root / path).write_text(MARKER)
            git("add", ".")
            git("commit", "-m", "synthetic memory", "--no-gpg-sign")
            old = git("rev-parse", "HEAD")
            git("reset", "--hard", clean)
            self.assertFalse((root / "second.md").exists())
            self.assertEqual(git("rev-list", "--all"), clean)
            self.assertIn(old, git("rev-list", "--all", "--reflog"))
            scan = GitHistoryCanaryScanner(root)
            self.assertEqual(scan.find(scope=".", marker=MARKER), {old + ":memory/first.md", old + ":second.md"})
            self.assertEqual(scan.find(scope="memory", marker=MARKER), {old + ":memory/first.md"})
            git("reflog", "expire", "--expire=now", "--expire-unreachable=now", "--all")
            self.assertEqual(scan.find(scope=".", marker=MARKER), set())
            # Reachable content with only a raw tag and no commit:path is an explicit coverage gap.
            dangling_blob = git("rev-parse", old + ":second.md")
            git("tag", "unaddressable", dangling_blob)
            with self.assertRaisesRegex(InputError, "commit:path"):
                scan.find(scope=".", marker=MARKER)
            git("tag", "-d", "unaddressable")
            (root / ".git" / "refs" / "external").symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(InputError, "symbolic"):
                scan.find(scope=".", marker=MARKER)

    def test_demo_replays_the_same_drained_attempt_and_both_storage_boundaries(self):
        with TemporaryDirectory() as work:
            out = Path(work, "evidence")
            with redirect_stdout(StringIO()) as printed:
                self.assertEqual(main(["demo", "memory-files", "--output", str(out)]), 0, printed.getvalue())
            self.assertIn("FAIL  broken", printed.getvalue())
            self.assertIn("PASS  guarded", printed.getvalue())
            broken, guarded = (replay(out / lane) for lane in ("broken", "guarded"))
            self.assertEqual((broken["technical_verdict"], guarded["technical_verdict"]), ("FAIL", "PASS"))
            self.assertEqual(guarded["review_status"], "OPEN_ITEMS")
            self.assertEqual(guarded["open_items"][0]["store"], "provider")
            for lane in ("broken", "guarded"):
                e = json.loads((out / lane / "erasure-evidence.json").read_bytes())
                self.assertEqual(len(set(e["worker"].values())), 1)
                self.assertTrue(e["worker"]["drained"])
                self.assertEqual(e["journal_chain"]["status"], "verified")
                self.assertRegex(e["journal_chain"]["head"], r"^[0-9a-f]{64}$")
                self.assertTrue(e["case"]["require_lineage"])
                self.assertEqual(e["lineage"]["derivations"][0]["artifact"]["key"], DERIVED_FILE)
                self.assertEqual(e["lineage"]["derivations"][0]["inputs"][0]["key"], TARGET_FILE)
                late = [entry for entry in e["journal"] if entry["turn"] == "late-memory"]
                self.assertTrue(all(entry["parent_turn"] == "initial-memory" for entry in late))
                self.assertEqual([entry["action"] for entry in late],
                                 ["retrieved", "derived"] if lane == "broken" else ["retrieved"])
                self.assertEqual(set(e["baseline"]["scans"]["files"]), {TARGET_FILE, DERIVED_FILE})
                self.assertFalse(e["immediate"]["scans"]["files"])
                if lane == "broken":
                    self.assertTrue(e["immediate"]["scans"]["git"][0].endswith(":" + TARGET_FILE))
                    self.assertEqual(e["final"]["scans"]["files"], [DERIVED_FILE])
                    self.assertTrue(e["final"]["scans"]["git"])
                else:
                    self.assertEqual(e["final"]["scans"], {"files": [], "git": []})

    def test_missing_git_creates_no_output(self):
        with (TemporaryDirectory() as work, redirect_stderr(StringIO()),
              patch("setrya.examples.memory_files.shutil.which", return_value=None)):
            out = Path(work, "evidence")
            self.assertEqual(main(["demo", "memory-files", "--output", str(out)]), 2)
            self.assertFalse(out.exists())


class AgentFSTests(unittest.TestCase):
    def test_versioned_rows_and_cross_chunk_markers(self):
        with TemporaryDirectory() as work:
            db_path = Path(work, "memory.db")
            with closing(sqlite3.connect(db_path)) as db, db:
                db.executescript("""
                    CREATE TABLE fs_config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO fs_config VALUES ('schema_version', '0.4'), ('chunk_size','8');
                    CREATE TABLE fs_inode (ino INTEGER PRIMARY KEY, mode INTEGER, size INTEGER);
                    CREATE TABLE fs_dentry (name TEXT, parent_ino INTEGER, ino INTEGER);
                    CREATE TABLE fs_data (ino INTEGER, chunk_index INTEGER, data BLOB);
                    INSERT INTO fs_inode VALUES (1,16877,0), (2,16877,0), (3,33188,20), (4,33188,0);
                    INSERT INTO fs_dentry VALUES ('memory',1,2), ('saved.md',2,3), ('linked.jsonl',1,3), ('old.md',1,4);
                """)
                data = b"zz" + MARKER.encode()
                self.assertEqual(len(data), 20)
                db.executemany("INSERT INTO fs_data VALUES(3,?,?)",
                               [(offset // 8, data[offset:offset + 8]) for offset in range(0, len(data), 8)])
            before = {entry.name: entry.read_bytes() for entry in db_path.parent.iterdir()}
            scanner = AgentFSCanaryScanner(db_path)
            self.assertEqual(scanner.find(scope="memory", marker=MARKER), {"memory/saved.md"})
            self.assertEqual(scanner.find(scope=".", marker=MARKER), {"memory/saved.md", "linked.jsonl"})
            self.assertEqual(before, {entry.name: entry.read_bytes() for entry in db_path.parent.iterdir()})
            with closing(sqlite3.connect(db_path)) as db, db:
                db.execute("DELETE FROM fs_data WHERE chunk_index=1")
            with self.assertRaisesRegex(InputError, "incomplete"):
                scanner.find(scope=".", marker=MARKER)

    @unittest.skipUnless(importlib.util.find_spec("agentfs_sdk"), "install Setrya's agentfs extra for the native SDK")
    def test_official_sdk_snapshot_preserves_a_marker_across_wal_and_chunks(self):
        from agentfs_sdk import AgentFS, AgentFSOptions

        with TemporaryDirectory() as work:
            path = Path(work, "actual-agentfs.db")

            async def seed():
                store = await AgentFS.open(AgentFSOptions(path=str(path)))
                try:
                    await store.fs.mkdir("/memory")
                    await store.fs.write_file("/memory/handoff.md", b"z" * 4092 + MARKER.encode())
                finally:
                    await store.close()

            asyncio.run(seed())
            before = {entry.name: entry.read_bytes() for entry in path.parent.iterdir()}
            self.assertEqual(AgentFSCanaryScanner(path).find(scope=".", marker=MARKER), {"memory/handoff.md"})
            self.assertEqual(before, {entry.name: entry.read_bytes() for entry in path.parent.iterdir()})


if __name__ == "__main__":
    unittest.main()
