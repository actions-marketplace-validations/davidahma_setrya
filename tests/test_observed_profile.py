import hashlib
import json
from pathlib import Path
from sqlite3 import connect
from contextlib import closing, redirect_stdout
from io import StringIO
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from setrya.casework import JournalObserver, observe_deletion
from setrya.casework.recheck import recheck
from setrya.cli import main
from setrya.erasure import ExternalItem, run_shared
from setrya.erasure.journal import CopyJournal
from setrya.erasure.subject import Subject
from setrya.examples.workspace import SIMPLE, open_fixture
from setrya.offboarding.inputs import InvalidReport
from setrya.receipts import replay


class ObservedDeletionTests(TestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.p = Path(root.name)
        self.journal = self.p / "journal.sqlite"
        self.store = self.p / "store.sqlite"
        self.mapping = self.p / "observer.toml"
        self.frame = self.p / "frame.json"
        self.subject = Subject.derive(b"s" * 32, "tenant", "subject", "restricted")
        self.control = Subject.derive(b"s" * 32, "tenant", "control", "restricted")
        self.log = CopyJournal(self.journal)
        self.log.record(self.subject, store="archive", key="exclusive-key", source="test", action="stored")
        self.frame.write_text(json.dumps({"format": "setrya.completed-requests.v1", "requests": [
            {"id": "N-42", "subject_ref": self.subject.ref, "stores": ["archive"], "completed_at": "2020-01-01T00:00:00Z"}]}))
        self.mapping.write_text(f"""[stores.archive]
kind="sqlite"
path="store.sqlite"
table="notes"
key_column="id"
control_key="keep"
subject_column="ref"
control_subject_ref="{self.control.ref}"
owner="case-owner"
follow_up="2020-01-02"
""")
        with closing(connect(self.store)) as db, db:
            db.execute("CREATE TABLE notes(id TEXT PRIMARY KEY, ref TEXT)")
            db.execute("INSERT INTO notes VALUES(?,?)", ("keep", self.control.ref))

    def observe(self, name, **kwargs):
        return observe_deletion(frame=self.frame, request="N-42", journal=self.journal,
                                inventory_file=self.mapping, output=self.p/name, **kwargs)

    def follow(self, source, name, **kwargs):
        return recheck(self.p/source, output=self.p/name, journal=self.journal, inventory_file=self.mapping, **kwargs)

    def test_independent_reads_replay_offline_and_public_entrypoints(self):
        before = [p.read_bytes() for p in (self.store, self.journal)]
        with redirect_stdout(StringIO()):
            self.assertEqual(main(["observe", "request", "--id", "N-42", "--population", str(self.frame),
                                   "--inventory", str(self.mapping), "--journal", str(self.journal),
                                   "--receipt", str(self.p/"issued")]), 0)
        self.assertEqual(before, [p.read_bytes() for p in (self.store, self.journal)])
        self.store.unlink()
        self.journal.unlink()
        result = replay(self.p/"issued")
        self.assertEqual(result["profile"], "observed-deletion")
        self.assertEqual(result["technical_verdict"], "PASS")
        self.assertEqual([(r["find"],r["verify_absent"]) for r in result["checks"]], [("ABSENT","ABSENT")])
        self.assertNotIn("exclusive-key", json.dumps(result))
        self.assertNotIn("store.sqlite", (self.p/"issued"/"observation-evidence.json").read_text())
        # A nonexistent journal does not get created by the reader.
        missing = self.observe("missing")
        self.assertEqual(missing["technical_verdict"], "NOT TESTED")
        self.assertFalse(self.journal.exists())

    def test_residual_in_either_snapshot_wins_and_changed_scope_is_uncertain(self):
        verify = JournalObserver.verify_absent
        def verify_after_restore(observer, req):
            with closing(connect(self.store)) as db, db:
                db.execute("INSERT INTO notes VALUES(?,?)", ("exclusive-key", self.subject.ref))
            return verify(observer, req)
        with patch.object(JournalObserver, "verify_absent", verify_after_restore):
            result = self.observe("restored")
        self.assertEqual(result["checks"][0]["status"], "PRESENT")
        self.assertEqual(replay(self.p/"restored")["technical_verdict"], "FAIL")

        def verify_after_journal_update(observer, req):
            self.log.record(self.subject, store="archive", key="changed", source="test", action="derived")
            return verify(observer, req)
        with closing(connect(self.store)) as db, db:
            db.execute("DELETE FROM notes WHERE id='exclusive-key'")
        with patch.object(JournalObserver, "verify_absent", verify_after_journal_update):
            result = self.observe("changed")
        self.assertEqual(result["technical_verdict"], "NOT TESTED")
        self.assertIn("journal-scope-changed", result["gaps"])

    def test_due_recheck_needs_direct_absence_and_scanned_subject_absence(self):
        # App-controlled subject and provider share a historical request; a
        # successful SQL read may close only the explicitly bound local item.
        with open_fixture(shared=False) as (subject, app, unused):
            self.log.record(subject, store="archive", key="held", source="test", action="stored")
            items = [
                ExternalItem("archive", "held", "support", "retained", "ticket", "2020-01-02", subject.ref),
                ExternalItem("provider", "held", "privacy", "configuration", "settings", "2020-01-02", subject.ref),
                ExternalItem("archive", "later", "support", "retained", "ticket", "2999-01-02", subject.ref),
            ]
            source = self.p / "original"
            original = run_shared(subject, case=SIMPLE, application=app, output=source, mode="deletion",
                                  external_items=items)
        self.assertEqual(original["technical_verdict"], "PASS")
        fingerprint = hashlib.sha256((source/"erasure-receipt.json").read_bytes()).hexdigest()
        with self.assertRaises(InvalidReport):
            self.follow("original", "wrong-pin", expected_parent_sha256="0"*64)
        self.assertFalse((self.p/"wrong-pin").exists())
        with closing(connect(self.store)) as db, db:
            db.execute("INSERT INTO notes VALUES(?,?)", ("other-id", subject.ref))
        live = self.follow("original", "scan-hit", expected_parent_sha256=fingerprint)
        self.assertEqual(live["technical_verdict"], "FAIL")
        self.assertEqual(live["items"][0]["reason"], "residual-found")
        self.assertEqual(live["parent_sha256"], fingerprint)
        with closing(connect(self.store)) as db, db:
            db.execute("DELETE FROM notes WHERE id='other-id'")
        guard = self.follow("original", "clear")
        self.assertEqual(guard["technical_verdict"], "PASS")
        self.assertEqual(guard["review_status"], "OPEN_ITEMS")
        self.assertEqual([i["status"] for i in guard["items"]], ["verified", "still open", "still open"])
        self.assertEqual([i["reason"] for i in guard["items"]], ["absent-in-both-reads", "configuration-only", "not-due"])
        code = self.p/"cli"
        with redirect_stdout(StringIO()):
            self.assertEqual(main(["recheck", str(source), "--output", str(code)]), 3)
        self.assertEqual(replay(code)["items"][0]["reason"], "unmapped-store")
        chained = self.follow("clear", "next")
        self.assertEqual(len(chained["items"]), 2)
        # The copied parent is sufficient to check the chain completely offline.
        self.store.unlink()
        self.journal.unlink()
        self.assertEqual(replay(self.p/"next"), chained)
        manifest = self.p/"next"/"parent"/"erasure-receipt.json"
        manifest.write_bytes(manifest.read_bytes()+b" ")
        with self.assertRaisesRegex(InvalidReport, "different receipt"):
            replay(self.p/"next")

    def test_recheck_requires_positive_scan_control_and_exclusive_journal_binding(self):
        with closing(connect(self.store)) as db, db:
            db.execute("INSERT INTO notes VALUES(?,?)", ("exclusive-key", self.subject.ref))
        controls = [{"framework":"SOC 2","reference":"C1.2"}]
        original = self.observe("observed", controls=controls)
        self.assertEqual(original["technical_verdict"], "FAIL")
        with closing(connect(self.store)) as db, db:
            db.execute("DELETE FROM notes WHERE id='exclusive-key'")
            db.execute("UPDATE notes SET ref=? WHERE id='keep'", ("mismatched",))
        after = self.follow("observed", "unproven")
        self.assertEqual(after["items"][0]["reason"], "read-or-scan-unavailable")
        self.assertEqual(after["items"][0]["status"], "still open")
        self.assertEqual(after["original_verdict"], "FAIL")
        self.assertEqual(after["controls"], controls)
        with closing(connect(self.store)) as db, db:
            db.execute("UPDATE notes SET ref=? WHERE id='keep'", (self.control.ref,))
        after = self.follow("observed", "verified")
        self.assertEqual(after["items"][0]["status"], "verified")
        self.assertEqual(after["technical_verdict"], "FAIL")  # Prior recorded residual still stands.
        self.log.record(self.control, store="archive", key="exclusive-key", source="test", action="stored")
        after = self.follow("observed", "shared")
        self.assertEqual(after["items"][0]["reason"], "no-exclusive-journal-key")
