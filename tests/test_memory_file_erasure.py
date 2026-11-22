"""Native working-tree, reflog and SQLite AgentFS evidence for a synthetic subject."""
import asyncio
from collections import Counter
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
from setrya.erasure import Artifact, SharedCase, Stored, Subject, run_shared
from setrya.erasure.canary import AgentFSCanaryScanner, FilesystemCanaryScanner, GitHistoryCanaryScanner, ScanLimits
from setrya.erasure.fs_canary import decode_scan_location, encode_scan_location
from setrya.erasure.v3 import Answer
from setrya.examples.memory_files import DERIVED_FILE, TARGET_FILE, _git_env
from setrya.receipts import replay


MARKER = "erasure-canary-417"


class WorkingTreeTests(unittest.TestCase):
    def test_native_paths_roundtrip_through_a_receipt(self):
        class Application:
            def __init__(self, root, *, erase_file, scanner_only=False, lose_control=False):
                self.root = root
                self.erase_file = erase_file
                self.scanner_only = scanner_only
                self.lose_control = lose_control
                self.erased = False
                self.path = root / "Team Montréal" / "Alice Smith.md"
                self.path.parent.mkdir(parents=True)
                self.path.write_text(MARKER, encoding="utf-8")
                (root / "control.md").write_text("The deployment is Thursday.", encoding="utf-8")
                self.scanner = FilesystemCanaryScanner(root)

            def scan(self, subject, store):
                return self.scanner.find(scope=self.path.parent.name, marker=MARKER).encode_keys()

            def inspect(self, subject, store, key):
                path = self.root / decode_scan_location(key)
                if not path.exists():
                    return Stored(key, False, False, False, None)
                text = path.read_text(encoding="utf-8")
                return Stored(key, True, MARKER in text, "Thursday" in text, "r1")

            def read(self, subject, caller, conversation, question):
                return Answer(caller, conversation, "/incident", question,
                              not self.erased and question == "What was deleted?", question == "What stayed?")

            def erase(self, subject):
                if self.erase_file:
                    self.path.unlink()
                if self.scanner_only:
                    self.path.with_name("forgotten.md").write_text(MARKER)
                if self.lose_control:
                    (self.root / "control.md").unlink()
                self.erased = True

        with TemporaryDirectory() as work:
            folder = Path(work)
            subject = Subject("7" * 64, "synthetic")
            case = SharedCase("incident", "/incident", ("reviewer",), "What was deleted?", "What stayed?",
                              (Artifact("files", "control.md", "preserve"),), scan_stores=("files",))
            for lane, expected in (("broken", "FAIL"), ("guarded", "PASS")):
                with self.subTest(lane=lane):
                    app = Application(folder / (lane + "-root"), erase_file=lane == "guarded")
                    bundle = folder / lane
                    run_shared(subject, case=case, application=app, output=bundle, mode="deletion")
                    receipt = replay(bundle)
                    self.assertEqual(receipt["technical_verdict"], expected)
                    self.assertEqual(receipt["scan_coverage"]["files"]["patterns"], ["**/*.md", "**/*.jsonl"])
                    row = next(item for item in receipt["artifact_checks"] if item["discovered_by"] == "canary")
                    self.assertTrue(row["key"].startswith("path64:"))
                    self.assertEqual((app.root / decode_scan_location(row["key"])).resolve(), app.path.resolve())

            from setrya.casework.receipt_summary import receipt_summary

            for scanner_only, lose_control in ((True, False), (False, True), (True, True)):
                with self.subTest(scanner_only=scanner_only, lose_control=lose_control):
                    bundle = folder / f"summary-{scanner_only}-{lose_control}"
                    app = Application(bundle.with_suffix(".app"), erase_file=True,
                                      scanner_only=scanner_only, lose_control=lose_control)
                    run_shared(subject, case=case, application=app, output=bundle, mode="deletion")
                    text = receipt_summary(bundle, audience="customer")
                    self.assertEqual(replay(bundle)["technical_verdict"], "FAIL")
                    self.assertIn("The erased fact appeared in 0 of those reads.", text)
                    self.assertEqual("scanners found the erased fact in 1 location." in text, scanner_only)
                    self.assertEqual("a copy or an answer that should have been erased" in text, scanner_only)
                    self.assertEqual("information meant to remain was lost" in text, lose_control)

    def test_path_codec_preserves_safe_keys_and_reserves_its_prefix(self):
        for location in ("notes.md", "path64:event.md", "aaab:Team Montréal/Alice Smith.md"):
            with self.subTest(location=location):
                self.assertEqual(decode_scan_location(encode_scan_location(location)), location)
        self.assertEqual(encode_scan_location("notes.md"), "notes.md")
        self.assertNotEqual(encode_scan_location("path64:event.md"), "path64:event.md")
        for value in ("../notes.md", "root/../private.md", "/notes.md", "root/o\nn.md"):
            with self.subTest(value=value), self.assertRaises(InputError):
                encode_scan_location(value)
        for key in ("path64:", "path64:not+canonical/", "path64:bm90ZXMubWQ"):
            with self.subTest(key=key), self.assertRaises(InputError):
                decode_scan_location(key)

    def test_scope_patterns_nested_and_root_paths(self):
        with TemporaryDirectory() as work:
            folder = Path(work)
            for path in ("top.md", "team/one/a.jsonl", "team/one/private.txt", "outside/b.md"):
                file = folder / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(MARKER)
            scanner = FilesystemCanaryScanner(folder)
            results = scanner.find(scope="team", marker=MARKER)
            self.assertEqual(results, {"team/one/a.jsonl"})
            self.assertEqual(results.coverage["skipped"], {".txt": 1})
            self.assertEqual(results.encode_keys().coverage["patterns"], ["**/*.md", "**/*.jsonl"])
            self.assertEqual(scanner.find(scope=".", marker=MARKER), {"top.md", "team/one/a.jsonl", "outside/b.md"})
            with self.assertRaises(InputError):
                scanner.find(scope="team/../outside", marker=MARKER)

    def test_doctor_warns_about_in_scope_file_types_without_reading_them(self):
        from textwrap import dedent

        fixture = dedent("""
            from contextlib import contextmanager
            from pathlib import Path
            from setrya.erasure import Answer, Artifact, SharedCase, Stored, Subject
            from setrya.erasure.canary import FilesystemCanaryScanner

            ROOT = Path(__file__).parent
            CASE = SharedCase("team", "/test", ("reader",), "What was deleted?", "What stayed?",
                              [Artifact("files", "memory/note.md", "delete")], ("files",))

            class App:
                def read(self, subject, caller, conversation, question):
                    return Answer(caller, conversation, "/test", question,
                                  question == "What was deleted?", question == "What stayed?")

                def scan(self, subject, store):
                    return FilesystemCanaryScanner(ROOT).find(scope="memory", marker="erasure-canary-417")

                def inspect(self, subject, store, key):
                    return Stored(key, True, True, False, "baseline")

                def erase(self, subject):
                    raise RuntimeError("Doctor must never erase")

            @contextmanager
            def open_fixture():
                yield Subject("2" * 64, "synthetic"), App(), []
        """)
        with TemporaryDirectory() as work, redirect_stdout(StringIO()) as stdout:
            root = Path(work)
            (root / "memory").mkdir()
            (root / "outside.txt").write_text("outside declared scope")
            for name in ("note.md", "ignored.json", "ignored.txt", "ignored.yaml", "ignored.sqlite"):
                (root / "memory" / name).write_text(MARKER)
            case = root / "fixture.py"
            case.write_text(fixture)
            self.assertEqual(main(["doctor", "--starter", str(case)]), 0, stdout.getvalue())
            self.assertIn("WARNING", stdout.getvalue())
            self.assertIn("fixture.py:", stdout.getvalue())
            for extension in (".json", ".txt", ".yaml", ".sqlite"):
                self.assertIn(f"{extension} (1)", stdout.getvalue())
            self.assertNotIn("outside.txt", stdout.getvalue())
            self.assertNotIn(MARKER, stdout.getvalue())
            self.assertIn("READY", stdout.getvalue())

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
            (root / "large.jsonl").write_bytes(b"x" * (1024 ** 2 + 1) + MARKER.encode())
            self.assertEqual(FilesystemCanaryScanner(root).find(scope=".", marker=MARKER), {"large.jsonl"})
            with self.assertRaisesRegex(InputError, "budget"):
                FilesystemCanaryScanner(root, limits=ScanLimits(max_file_bytes=1024 ** 2)).find(scope=".", marker=MARKER)
            with self.assertRaises(InputError):
                ScanLimits(max_entries=0)


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
            self.assertEqual(scan.find(scope="memory", marker=MARKER), {old + ":memory/first.md"})
            git("update-ref", "-d", "ORIG_HEAD")
            self.assertEqual(scan.find(scope=".", marker=MARKER), {old + ":memory/first.md", old + ":second.md"})
            self.assertEqual(scan.find(scope="memory", marker=MARKER), {old + ":memory/first.md"})

            detached_blob = subprocess.check_output(
                ["git", "hash-object", "-w", "--stdin"], input=MARKER.encode() + b"\nextra",
                cwd=root, env=_git_env(), timeout=10,
            ).decode().strip()
            detached_tree = subprocess.check_output(
                ["git", "mktree"], input=f"100644 blob {detached_blob}\tsaved.md\n".encode(),
                cwd=root, env=_git_env(), timeout=10,
            ).decode().strip()
            self.assertEqual(scan.find(scope="memory", marker=MARKER),
                             {old + ":memory/first.md", f"tree:{detached_tree}:saved.md"})
            git("tag", "unaddressable", detached_blob)
            git("repack", "-ad")
            git("prune", "--expire=now")
            self.assertEqual(scan.find(scope=".", marker=MARKER), {f"blob:{detached_blob}"})
            git("tag", "-d", "unaddressable")
            # This blob remains packed after its last reference is removed.
            self.assertEqual(scan.find(scope=".", marker=MARKER), {f"blob:{detached_blob}"})
            git("repack", "-ad")
            git("prune", "--expire=now")
            self.assertEqual(scan.find(scope=".", marker=MARKER), set())
            (root / ".git" / "refs" / "external").symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(InputError, "symbolic"):
                scan.find(scope=".", marker=MARKER)

    def test_pseudo_ref_retains_a_scoped_alias_of_a_blob_reachable_elsewhere(self):
        from setrya.examples.memory_files import open_fixture

        with open_fixture(shutil.which("git"), guarded=True) as (_, app, _):
            outside = app.root / "outside.md"
            outside.write_text(MARKER)
            app.git("add", "outside.md")
            app.git("commit", "--no-gpg-sign", "-m", "Outside note")
            base = app.git("rev-parse", "HEAD").decode().strip()
            inside = app.root / "scoped" / "note.md"
            inside.parent.mkdir()
            inside.write_text(MARKER)
            app.git("add", "scoped/note.md")
            app.git("commit", "--no-gpg-sign", "-m", "Scoped copy")
            old = app.git("rev-parse", "HEAD").decode().strip()
            app.git("reset", "--hard", base)
            app.git("reflog", "expire", "--expire=now", "--expire-unreachable=now", "--all")
            self.assertEqual(app.git("show", "ORIG_HEAD:scoped/note.md").decode(), MARKER)
            self.assertEqual(app.history.find(scope="scoped", marker=MARKER), {old + ":scoped/note.md"})
            app.git("update-ref", "-d", "ORIG_HEAD")
            self.assertEqual(app.history.find(scope="scoped", marker=MARKER), {old + ":scoped/note.md"})

    def test_large_history_visits_each_unique_tree_once_and_obeys_commit_budget(self):
        from setrya.erasure import fs_canary
        from setrya.examples.memory_files import open_fixture

        with open_fixture(shutil.which("git"), guarded=True) as (_, app, _):
            for i in range(50):
                (app.root / f"entry-{i}.txt").write_text("unchanged")
            app.git("add", ".")
            app.git("commit", "--no-gpg-sign", "-m", "build tree once")
            for i in range(100):
                app.git("commit", "--allow-empty", "--no-gpg-sign", "-m", f"unchanged tree {i}")
            calls = Counter()
            original = fs_canary._git_read

            def record(command, *args, **kwargs):
                if "ls-tree" in command:
                    calls[command[-1]] += 1
                return original(command, *args, **kwargs)

            with patch.object(fs_canary, "_git_read", record):
                self.assertEqual(app.history.find(scope=".", marker=MARKER), set())
            self.assertTrue(calls)
            self.assertEqual(max(calls.values()), 1)
            with self.assertRaisesRegex(InputError, "commits.*budget"):
                GitHistoryCanaryScanner(app.root, limits=ScanLimits(max_commits=100)).find(scope=".", marker=MARKER)

    def test_remote_is_open_item_without_remote_url_and_replays(self):
        from setrya.examples.memory_files import open_fixture
        from setrya.examples.memory_files import TARGET

        with TemporaryDirectory() as work, open_fixture(shutil.which("git"), guarded=True) as (subject, app, items):
            # The fixture has a local-only synthetic remote URI and never fetches.
            app.git("remote", "add", "archive", "https://example.invalid/private-project")
            app.history = GitHistoryCanaryScanner(app.root, remote_owner="records-team")
            bundle = Path(work, "receipt")
            run_shared(subject, case=app.case(), application=app, external_items=items, journal=app.journal,
                       mode="deletion", output=bundle)
            receipt = replay(bundle)
            self.assertEqual(receipt["technical_verdict"], "PASS")
            self.assertTrue(receipt["scan_coverage"]["git"]["remote_configured"])
            item = next(item for item in receipt["open_items"] if item["store"] == "git")
            self.assertEqual((item["evidence"], item["owner"]), ("remote-copies-uninspected", "records-team"))
            for filename in bundle.iterdir():
                self.assertNotIn("private-project", filename.read_text())
            self.assertFalse(app.history.find(scope=".", marker=TARGET))

    def test_changed_scan_scope_cannot_prove_a_clean_run(self):
        from setrya.examples.memory_files import open_fixture, TARGET

        with TemporaryDirectory() as work, open_fixture(shutil.which("git"), guarded=True) as (subject, app, items):
            scan = app.scan
            def moved_scope(subject, store):
                if store == "files" and not (app.root / TARGET_FILE).exists():
                    return app.files.find(scope="clients", marker=TARGET)
                return scan(subject, store)
            app.scan = moved_scope
            bundle = Path(work, "receipt")
            run_shared(subject, case=app.case(), application=app, external_items=items, journal=app.journal,
                       mode="deletion", output=bundle)
            receipt = replay(bundle)
            self.assertEqual(receipt["technical_verdict"], "NOT TESTED")
            self.assertIn("Canary scan scope changed or was missing for files.", receipt["gaps"])

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
                    self.assertRegex(e["immediate"]["scans"]["git"][0], r"^[0-9a-f]{40,64}:")
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
