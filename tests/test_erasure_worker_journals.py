"""Independent producer processes and a retried, partially observed handoff."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from contextlib import closing
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from setrya.erasure.journal_merge import CollectedJournal, WorkerJournal
from setrya.erasure.subject import Subject
from setrya.offboarding.inputs import InvalidReport


class DistributedJournals(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.subject = Subject("1" * 64, "restricted")
        self.run = "release-42"
        self.collector = CollectedJournal(self.root / "merged.db", run_id=self.run)

    def emit(self, producer):
        subprocess.run([sys.executable, "-c", """
import sys
from pathlib import Path
from setrya.erasure.journal_merge import WorkerJournal
from setrya.erasure.subject import Subject
root, run, producer = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
subject = Subject("1" * 64, "restricted")
journal = WorkerJournal(root/(producer+".db"), run_id=run, producer=producer)
journal.record(subject, store=producer, key="chart-7", source="doc-7", action="stored")
journal.seal(subject, root/(producer+".json"))
""", str(self.root), self.run, producer], check=True, env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])})
        return self.root / (producer + ".json")

    def coverage(self, subject=None):
        return self.collector.coverage(subject or self.subject, run_id=self.run, expected_producers=["web", "worker"])

    def test_merge_workers_retry_and_trace_cannot_hide_missing_producer(self):
        web, worker = self.emit("web"), self.emit("worker")
        self.collector.ingest(web, producer="web")
        row = json.loads(worker.read_text())["events"][0]
        trace = {**self.subject.metadata(), "setrya_run": self.run, "setrya_producer": "worker",
                 "setrya_sequence": row["sequence"], "store": "worker", "copy_key": row["key"], "source": row["source"],
                 "action": row["action"], "observed_at": row["observed_at"], "details_json": "{}"}
        self.collector.ingest_trace(trace, producer="worker")
        self.assertEqual(self.coverage()["missing"], ["worker"])
        self.assertEqual(len(self.collector.history(self.subject)), 2)
        for _ in range(2):
            self.collector.ingest(worker, producer="worker")
            self.collector.ingest(web, producer="web")
        self.assertEqual(self.coverage()["missing"], [])
        self.assertEqual(self.coverage(Subject("2" * 64, "restricted"))["received"], [])
        self.assertEqual(len(self.collector.history(self.subject)), 2)
        self.collector.ingest_trace(trace, producer="worker")
        with self.assertRaisesRegex(InvalidReport, "Trace event absent"):
            self.collector.ingest_trace({**trace, "setrya_sequence": 8}, producer="worker")
        with self.assertRaisesRegex(InvalidReport, "different observations"):
            self.collector.ingest_trace({**trace, "copy_key": "changed"}, producer="worker")

    def test_reject_run_producer_and_post_seal_write(self):
        packet = self.emit("web")
        with self.assertRaises(InvalidReport):
            self.collector.ingest(packet, producer="worker")
        collector = CollectedJournal(self.root / "other.db", run_id="another")
        with self.assertRaises(InvalidReport):
            collector.ingest(packet, producer="web")
        with self.assertRaises(InvalidReport):
            WorkerJournal(self.root / "web.db", run_id="other", producer="web")
        worker = WorkerJournal(self.root / "web.db", run_id=self.run, producer="web")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "sealed"):
            worker.record(self.subject, store="web", key="late", source="doc-7", action="stored")

    def test_retry_exports_the_first_subject_seal_after_another_subject_writes(self):
        path = self.root / "worker.db"
        worker = WorkerJournal(path, run_id=self.run, producer="worker")
        worker.record(self.subject, store="web", key="chart-7", source="doc-7", action="stored")
        first = self.root / "first.json"
        digest = worker.seal(self.subject, first)
        self.collector.ingest(first, producer="worker", expected_sha256=digest)

        worker = WorkerJournal(path, run_id=self.run, producer="worker")
        another = Subject("2" * 64, "restricted")
        worker.record(another, store="web", key="chart-8", source="doc-8", action="stored")
        other = self.root / "other.json"
        worker.seal(another, other)
        self.collector.ingest(other, producer="worker")
        self.assertEqual(json.loads(other.read_bytes())["chain"]["last_event"], 2)

        retry = self.root / "retry.json"
        self.assertEqual(worker.seal(self.subject, retry), digest)
        self.assertEqual(first.read_bytes(), retry.read_bytes())
        self.collector.ingest(retry, producer="worker", expected_sha256=digest)

    def test_upgraded_worker_reproduces_a_legacy_seal(self):
        path = self.root / "legacy.db"
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                CREATE TABLE copy_events (
                    event INTEGER PRIMARY KEY, subject TEXT NOT NULL, store TEXT NOT NULL,
                    copy_key TEXT NOT NULL, source TEXT NOT NULL, action TEXT NOT NULL,
                    classification TEXT NOT NULL, observed_at TEXT NOT NULL, details TEXT NOT NULL
                );
                CREATE TABLE journal_binding (
                    id INTEGER PRIMARY KEY CHECK(id=1), role TEXT, run_id TEXT, producer TEXT
                );
                CREATE TABLE sealed_subjects (subject TEXT PRIMARY KEY);
            """)
            db.execute("INSERT INTO journal_binding VALUES (1,'producer',?,'worker')", (self.run,))
            db.execute("INSERT INTO sealed_subjects VALUES (?)", (self.subject.ref,))
            db.execute("INSERT INTO copy_events VALUES (1,?,'web','chart-7','doc-7','stored',"
                       "'restricted','2026-11-01T00:00:00+00:00','{}')", (self.subject.ref,))
        original = self.root / "legacy.json"
        packet = {"format": "setrya.copy-journal.v1", "run_id": self.run, "producer": "worker",
                  "subject_ref": self.subject.ref, "events": [
                      {"sequence": 1, "store": "web", "key": "chart-7", "source": "doc-7",
                       "action": "stored", "classification": "restricted",
                       "observed_at": "2026-11-01T00:00:00+00:00", "details": {}},
                  ]}
        original.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")
        self.collector.ingest(original, producer="worker")
        worker = WorkerJournal(path, run_id=self.run, producer="worker")
        worker.record(Subject("2" * 64, "restricted"), store="web", key="chart-8", source="doc-8", action="stored")
        retry = self.root / "legacy-retry.json"
        worker.seal(self.subject, retry)
        self.assertEqual(original.read_bytes(), retry.read_bytes())
        self.collector.ingest(retry, producer="worker")

    def test_concurrent_packet_cannot_split_roster_and_events_across_snapshots(self):
        from contextlib import closing
        with closing(sqlite3.connect(self.collector.path)) as db:
            db.execute("PRAGMA journal_mode=WAL")
        self.collector.ingest(self.emit("web"), producer="web")
        packet = self.emit("worker")
        read_coverage = self.collector._coverage

        def receive_after_roster(*args):
            roster = read_coverage(*args)
            self.collector.ingest(packet, producer="worker")
            return roster

        options = {"run_id": self.run, "expected_producers": ("web", "worker")}
        with patch.object(self.collector, "_coverage", side_effect=receive_after_roster):
            roster, rows = self.collector.snapshot(self.subject, **options)
        self.assertEqual(roster["received"], ["web"])
        self.assertEqual([row.store for row in rows], ["web"])
        roster, rows = self.collector.snapshot(self.subject, **options)
        self.assertEqual(roster["received"], ["web", "worker"])
        self.assertEqual([row.store for row in rows], ["web", "worker"])

    def test_malformed_packet_cannot_partially_import_and_empty_producer_can_close(self):
        packet = self.emit("web")
        row = json.loads(packet.read_text())
        row["events"].append({**row["events"][0], "sequence": 0})
        packet.write_text(json.dumps(row))
        with self.assertRaises(InvalidReport):
            self.collector.ingest(packet, producer="web")
        self.assertEqual(self.collector.history(self.subject), ())
        self.assertEqual(self.coverage()["missing"], ["web", "worker"])
        empty = self.root / "idle.json"
        WorkerJournal(self.root / "worker.db", run_id=self.run, producer="worker").seal(self.subject, empty)
        self.collector.ingest(empty, producer="worker")
        self.assertEqual(self.coverage()["missing"], ["web"])
