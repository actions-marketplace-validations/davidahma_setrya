"""Exercise the standalone core and its durable chain on actual SQLite files."""

import ast
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stdout, redirect_stderr
import copy
from io import StringIO
import json
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest

from setrya.cli import main
from setrya.core.inputs import InvalidReport
from setrya.core.journal import CopyJournal
from setrya.core.subject import Subject
from setrya.erasure.journal_merge import CollectedJournal, WorkerJournal


class Core(unittest.TestCase):
    def test_stdlib_only_and_stable_aliases(self):
        core = Path(__file__).resolve().parents[1] / "setrya/core"
        for file in core.glob("*.py"):
            for node in ast.walk(ast.parse(file.read_text())):
                if isinstance(node, ast.Import):
                    self.assertTrue(all(name.name.split(".")[0] in sys.stdlib_module_names for name in node.names), file)
                elif isinstance(node, ast.ImportFrom):
                    self.assertLessEqual(node.level, 1, file)
                    if not node.level:
                        self.assertIn(node.module.split(".")[0], sys.stdlib_module_names, file)
                elif isinstance(node, ast.Call):
                    method = getattr(node.func, "attr", getattr(node.func, "id", None))
                    self.assertNotIn(method, {"__import__", "import_module"}, file)
        from setrya.erasure import CopyJournal as LegacyJournal, SharedCase, Subject as FixtureSubject
        from setrya.erasure.v3 import SharedCase as VersionedCase
        from setrya.core.receipt_v3 import derive
        from setrya.erasure.v3_receipt import derive as legacy_derive

        self.assertIs(LegacyJournal, CopyJournal)
        self.assertIs(Subject, FixtureSubject)
        self.assertIs(SharedCase, VersionedCase)
        self.assertIs(derive, legacy_derive)


class Journal(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.subject = Subject("1" * 64, "synthetic")
        self.path = self.root / "journal.sqlite"

    def record(self, journal, i):
        return journal.record(self.subject, store="notes", key=f"row-{i}", source="test", action="stored")

    def verify(self, journal, *args):
        with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
            code = main(["journal", "verify", str(journal), "--json", *args])
        return code, json.loads(out.getvalue()) if code == 0 else err.getvalue()

    def test_concurrent_writes_and_tail_middle_or_modified_rows(self):
        journal = CopyJournal(self.path)
        with ThreadPoolExecutor(max_workers=6) as workers:
            list(workers.map(lambda i: self.record(journal, i), range(18)))
        code, anchor = self.verify(self.path)
        self.assertEqual((code, anchor["last_event"], anchor["status"]), (0, 18, "verified"))
        self.assertEqual(self.verify(self.path, "--expected-head", anchor["head"])[0], 0)
        self.assertEqual(self.verify(self.path, "--expected-head", "2" * 64)[0], 2)
        for index, sql in enumerate(("DELETE FROM copy_events WHERE event=1",
                                     "DELETE FROM copy_events WHERE event=18",
                                     "UPDATE copy_events SET source='changed' WHERE event=3")):
            edited = self.root / f"case-{index}.sqlite"
            edited.write_bytes(self.path.read_bytes())
            with closing(sqlite3.connect(edited)) as db, db:
                db.execute(sql)
            self.assertEqual(self.verify(edited)[0], 2)
            with self.assertRaises(InvalidReport):
                CopyJournal(edited).verified_history(self.subject)

    def test_legacy_rows_stay_unchained_then_new_suffix_is_verified(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE copy_events(
                      event INTEGER PRIMARY KEY, subject TEXT, store TEXT, copy_key TEXT, source TEXT,
                      action TEXT, classification TEXT, observed_at TEXT, details TEXT)""")
            db.execute("INSERT INTO copy_events VALUES(1,?,'notes','old','test','stored','synthetic','2026-01-01T00:00:00Z','{}')",
                       (self.subject.ref,))
        code, old = self.verify(self.path)
        self.assertEqual((code, old["status"]), (0, "unchained"))
        journal = CopyJournal(self.path)
        self.assertEqual(journal.copies(self.subject)[0].key, "old")
        self.record(journal, 1)
        code, new = self.verify(self.path)
        self.assertEqual((code, new["status"], new["first_event"]), (0, "partial", 2))

    def test_collector_keeps_each_verified_producer_and_detects_changes(self):
        collector = CollectedJournal(self.path, run_id="job")
        for name in ("worker", "web"):
            producer = WorkerJournal(self.root / f"{name}.sqlite", run_id="job", producer=name)
            self.record(producer, 1)
            packet = self.root / f"{name}.json"
            producer.seal(self.subject, packet)
            collector.ingest(packet, producer=name)
        code, verification = self.verify(self.path)
        self.assertEqual(code, 0)
        heads = verification["subjects"][0]["producer_chains"]
        self.assertEqual({name: chain["status"] for name, chain in heads.items()},
                         {"worker": "verified", "web": "verified"})
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM collected_events WHERE producer='worker'")
        self.assertEqual(self.verify(self.path)[0], 2)

    def test_v3_1_groups_samples_and_preserves_v3_sampled_rules(self):
        from setrya.core.receipt_v3 import answer_records, derive, EVIDENCE_FORMAT, FLAT_EVIDENCE_FORMAT
        from setrya.erasure import run_shared
        from setrya.examples.workspace import CASE, open_fixture

        bundle = self.root / "run"
        journal = CopyJournal(self.path)
        with open_fixture(shared=True) as (subject, app, items):
            result = run_shared(subject, case=CASE, application=app, external_items=items,
                                journal=journal, mode="deletion", output=bundle)
        new = json.loads((bundle / "erasure-evidence.json").read_bytes())
        self.assertEqual(new["format"], EVIDENCE_FORMAT)
        self.assertTrue(all(len(slot) == 3 for slot in new["final"]["answers"]))
        self.assertEqual(new["journal_chain"]["status"], "unchained")
        old = copy.deepcopy(new)
        del old["journal_chain"]
        for stage in ("baseline", "immediate", "final"):
            old[stage]["answers"] = answer_records(new, stage)
        old["format"] = FLAT_EVIDENCE_FORMAT
        old_result = derive(old, result["evidence"]["sha256"])
        expected = {key: value for key, value in result.items() if key not in ("journal_chain", "lexical_only")}
        self.assertEqual(old_result, expected)
        new["final"]["answers"][0].pop()
        with self.assertRaisesRegex(InvalidReport, "grouped endpoint samples"):
            derive(new, "0" * 64)
