"""Exercise the customer handoff, direct key checks, weekly coverage and optional primary database."""
from contextlib import closing, contextmanager, redirect_stdout, redirect_stderr
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from setrya.casework.customer import customer_receipt
from setrya.casework.observe import observe
from setrya.casework.sampling import statistics
from setrya.casework.stores import inventory, key_reader
from setrya.cli import main
from setrya.erasure.journal import CopyJournal
from setrya.erasure.lineage import VersionLineage, VersionRef
from setrya.erasure.subject import Subject
from setrya.offboarding.inputs import InvalidReport


class CustomerReceipt(unittest.TestCase):
    def test_replayed_drill_and_customer_safe_output(self):
        with TemporaryDirectory() as tmp, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            folder = Path(tmp, "demo")
            self.assertEqual(main(["demo", "--output", str(folder)]), 0)
            guarded = folder / "guarded"
            text = customer_receipt(guarded, case_id="N-204")
            self.assertIn("N-204", text)
            self.assertIn("delayed worker resumed", text)
            self.assertIn("follow-up", text)
            self.assertNotIn("cobalt-bridge", text)
            self.assertIn("At least one check", customer_receipt(folder / "broken"))
            receipt = guarded / "erasure-receipt.json"
            data = json.loads(receipt.read_bytes())
            data["review_status"] = "FAKE"
            receipt.write_text(json.dumps(data))
            self.assertEqual(main(["receipt", "render", str(guarded), "--audience", "customer"]), 2)

    def test_historical_v3_summary_preserves_sampling_limits(self):
        archived = Path(__file__).parent / "fixtures" / "erasure_v3_1_0_3"
        self.assertIn("did not record repeated-answer coverage", customer_receipt(archived))

    def test_discovery_distinguishes_catalog_from_drill_date(self):
        from setrya.receipt_format import FORMAT_V3
        result = {"format": FORMAT_V3, "profile": "discovery", "case_id": "N-204", "observed_at": "2020-08-12T22:00:00Z",
                  "services": [], "technical_verdict": "NOT TESTED", "review_status": "OPEN_ITEMS", "open_items": []}
        with patch("setrya.casework.customer.replay", return_value=result):
            self.assertIn("2020-08-12. No deletion drill was run.", customer_receipt("deferred-case"))
            result["drill_observed_at"] = "2024-08-13T09:15:00Z"
            text = customer_receipt("completed-case")
            self.assertIn("Observation date: 2024-08-13.", text)
            self.assertNotIn("2020-08-12", text)

    def test_tenant_receipt_is_bound_to_the_request(self):
        with TemporaryDirectory() as tmp, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            folder = Path(tmp, "tenant")
            self.assertEqual(main(["demo", "--scope", "tenant", "--output", str(folder)]), 0)
            text = customer_receipt(folder / "receipt")
            self.assertIn("tenant review", text)
            with self.assertRaises(InvalidReport):
                customer_receipt(folder / "receipt", case_id="unrelated")


class KnownKeyObserver(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.data = self.folder / "copies.db"
        self.journal = self.folder / "journal.db"
        self.mapping = self.folder / "stores.toml"
        self.frame = self.folder / "completed.json"
        self.log = CopyJournal(self.journal)
        self.subjects = [Subject.derive(b"X" * 32, "tenant", f"user-{i}", "test") for i in range(6)]
        self.requests = [{"id": f"N-{i}", "subject_ref": sub.ref, "completed_at": "2020-01-08T09:00:00Z",
                          "stores": ["desk"]} for i, sub in enumerate(self.subjects)]
        self.write_frame()
        self.mapping.write_text('[stores.desk]\nkind="sqlite"\npath="copies.db"\ntable="notes"\n'
                                'key_column="id"\ncontrol_key="permanent"\n')
        with closing(sqlite3.connect(self.data)) as db, db:
            db.execute("CREATE TABLE notes(id TEXT PRIMARY KEY, secret TEXT)")
            db.executemany("INSERT INTO notes VALUES(?,?)", [("permanent", "control"), ("key-1", "secret-answer")])
        for i, sub in enumerate(self.subjects[:-1]):
            self.log.record(sub, store="desk", key=f"key-{i}", source="source", action="stored")

    def write_frame(self):
        self.frame.write_text(json.dumps({"format": "setrya.completed-requests.v1", "requests": self.requests}))

    def request(self, i):
        return observe(frame=self.frame, config=self.mapping, journal=self.journal, request=f"N-{i}")

    def test_direct_reads_are_read_only_and_gaps_never_become_absence(self):
        inputs = [self.data, self.journal, self.frame, self.mapping]
        previous = [hashlib.sha256(p.read_bytes()).digest() for p in inputs]
        for i, expected, code in [(0, "ABSENT", 0), (1, "PRESENT", 1), (5, "UNKNOWN", 3)]:
            report, rc = self.request(i)
            self.assertEqual((report["requests"][0]["status"], rc), (expected, code))
            encoded = json.dumps(report)
            for private in ("secret-answer", "key-1", self.subjects[i].ref):
                self.assertNotIn(private, encoded)
        self.assertEqual(previous, [hashlib.sha256(p.read_bytes()).digest() for p in inputs])
        self.assertEqual(sorted(inputs), sorted(self.folder.iterdir()))

        self.log.record(self.subjects[0], store="unlisted", key="unknown", source="source", action="stored")
        self.assertEqual(self.request(0)[1], 3)
        self.log.record(self.subjects[3], store="desk", key="key-1", source="source", action="stored")
        self.assertEqual(self.request(1)[1], 3)
        self.log.record(self.subjects[1], store="desk", key="private-new", source="source", action="stored")
        with closing(sqlite3.connect(self.data)) as db, db:
            db.execute("INSERT INTO notes VALUES('private-new','residual')")
        self.assertEqual(self.request(1)[1], 1)
        with closing(sqlite3.connect(self.data)) as db, db:
            db.execute("DELETE FROM notes WHERE id='permanent'")
        self.assertEqual(self.request(1)[1], 3)
        self.journal.unlink()
        self.assertEqual(self.request(2)[1], 3)
        self.assertFalse(self.journal.exists())

    def test_tracks_transitive_lineage_and_shared_physical_keys(self):
        lineage = VersionLineage(self.log, "workspace")
        alice = VersionRef("desk", "key-0", "1")
        summary = VersionRef("desk", "summary", "1")
        cached = VersionRef("desk", "answer", "1")
        bob = VersionRef("desk", "key-3", "1")
        lineage.record(alice, subjects=[self.subjects[0]])
        lineage.record(summary, inputs=[alice])
        lineage.record(cached, inputs=[summary])
        with closing(sqlite3.connect(self.data)) as db, db:
            db.execute("INSERT INTO notes VALUES('answer', 'synthetic')")
        report, code = self.request(0)
        self.assertEqual(code, 1)
        present, = [f for f in report["requests"][0]["checks"] if f["state"] == "PRESENT"]
        self.assertIn("lineage_version", present)
        self.assertNotIn("journal_event", present)
        self.assertNotIn("answer", json.dumps(report))

        # A later version of the same physical key belongs to both people.
        lineage.record(bob, subjects=[self.subjects[3]])
        lineage.record(VersionRef("desk", "answer", "2"), inputs=[summary, bob])
        self.assertEqual(self.request(0)[1], 3)
        # Direct journal events alone can also establish shared ownership.
        self.log.record(self.subjects[1], store="desk", key="summary", source="test", action="stored")
        self.assertIn("external-or-shared-key", self.request(0)[0]["requests"][0]["gaps"])

    def test_sqlite_binary_or_mixed_keys_cannot_prove_absence(self):
        with closing(sqlite3.connect(self.data)) as db, db:
            db.execute("INSERT INTO notes VALUES(?, 'synthetic')", (b"key-2",))
        self.assertEqual(self.request(2)[1], 3)
        with closing(sqlite3.connect(self.data)) as db, db:
            db.execute("ALTER TABLE notes RENAME TO original")
            db.execute("CREATE TABLE notes(id TEXT COLLATE NOCASE PRIMARY KEY)")
            db.execute("INSERT INTO notes VALUES ('permanent')")
        self.assertEqual(self.request(2)[1], 3)

    def test_store_query_does_not_hold_production_journal_lock(self):
        writes = []

        @contextmanager
        def concurrent_read(spec):
            with closing(sqlite3.connect(self.journal, timeout=0.01)) as db, db:
                db.execute("UPDATE copy_events SET details=details WHERE event=1")
            writes.append(True)
            with key_reader(spec) as exists:
                yield exists

        with patch("setrya.casework.observe.key_reader", concurrent_read):
            report, code = self.request(0)
        self.assertEqual((code, writes), (0, [True]))
        row, = report["requests"]
        self.assertLessEqual(row["journal_read_at"], row["checked_at"])

    def test_weekly_frame_reproducible_and_census_bounds_include_unknowns(self):
        self.requests.append(dict(self.requests[0], id="outside", completed_at="2020-01-13T00:00:00Z"))
        self.write_frame()
        kwargs = dict(frame=self.frame, config=self.mapping, journal=self.journal, week="2020-01-06",
                      count=6, seed="01"*32)
        first, code = observe(**kwargs)
        self.assertEqual(code, 1)
        sampling = first["sampling"]
        self.assertEqual((sampling["sampled"], sampling["eligible"]), (6, 6))
        self.assertEqual(sampling["population_count_interval_95"], [1, 2])
        self.assertIsNone(sampling["residual_rate"])
        second = observe(**kwargs)[0]
        self.assertEqual(first["sampling"], second["sampling"])
        self.assertEqual([r["id"] for r in first["requests"]], [r["id"] for r in second["requests"]])
        self.requests[1]["subject_ref"] = self.requests[0]["subject_ref"]
        self.write_frame()
        with self.assertRaises(InvalidReport):
            observe(**kwargs)

    def test_uniform_sample_interval_and_empty_control(self):
        # For n=2 independent of the ordering of a finite frame of 10 with
        # zero positives, K=8 still yields P(X=0)=1/45 < .025.
        self.assertEqual(statistics(10, [{"status": "ABSENT"}] * 2)["population_count_interval_95"], [0, 7])
        self.assertEqual(statistics(10, [{"status": "PRESENT"}] * 2)["population_count_interval_95"], [3, 10])
        self.log.record(self.subjects[2], store="desk", key="permanent", source="s", action="stored")
        self.assertEqual(self.request(2)[1], 3)

    def test_cli_saves_without_overwrite_and_never_uses_views_or_wal(self):
        out = self.folder / "report.json"
        args = ["observe", "request", "--id", "N-0", "--population", str(self.frame), "--inventory",
                str(self.mapping), "--journal", str(self.journal), "--output", str(out)]
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(main(args), 0)
            saved = out.read_bytes()
            self.assertEqual(main(args), 2)
            self.assertEqual(out.read_bytes(), saved)
        with closing(sqlite3.connect(self.data)) as db, db:
            db.execute("ALTER TABLE notes RENAME TO real_notes")
            db.execute("CREATE VIEW notes AS SELECT * FROM real_notes WHERE id='permanent'")
        self.assertEqual(self.request(0)[1], 3)
        with closing(sqlite3.connect(self.journal)) as db:
            db.execute("PRAGMA journal_mode=WAL")
        self.assertEqual(self.request(0)[1], 3)


@unittest.skipUnless(os.environ.get("SETRYA_PGVECTOR_DSN"), "requires the disposable PostgreSQL test service")
class PostgresObserver(unittest.TestCase):
    def test_primary_fixed_reads_with_a_dedicated_role(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        admin = os.environ["SETRYA_PGVECTOR_DSN"]
        name = "setrya_observer_" + secrets.token_hex(8)
        identifier = sql.Identifier(name)
        password = secrets.token_hex(24)
        with psycopg.connect(admin, autocommit=True) as db:
            db.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(identifier, sql.Literal(password)))
            try:
                db.execute(sql.SQL("CREATE SCHEMA {}").format(identifier))
                db.execute(sql.SQL("CREATE TABLE {}.notes(id text PRIMARY KEY, body text)").format(identifier))
                db.execute(sql.SQL("INSERT INTO {}.notes VALUES ('control','sample'),('old','private')").format(identifier))
                db.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(identifier, identifier))
                db.execute(sql.SQL("GRANT SELECT(id) ON {}.notes TO {}").format(identifier, identifier))
                with TemporaryDirectory() as tmp, patch.dict(os.environ, OBSERVER_TEST=make_conninfo(admin, user=name, password=password)):
                    conf = Path(tmp) / "observer.toml"
                    conf.write_text(f'[stores.notes]\nkind="postgres"\nschema="{name}"\ntable="notes"\n'
                                    'key_column="id"\ndsn_env="OBSERVER_TEST"\ncontrol_key="control"\n')
                    spec = inventory(conf)["notes"]
                    with key_reader(spec) as lookup:
                        self.assertTrue(lookup("old"))
                        self.assertFalse(lookup("deleted"))
                    db.execute(sql.SQL("GRANT UPDATE(body) ON {}.notes TO {}").format(identifier, identifier))
                    with self.assertRaises(InvalidReport), key_reader(spec):
                        pass
                    db.execute(sql.SQL("REVOKE UPDATE(body) ON {}.notes FROM {}").format(identifier, identifier))
                    db.execute(sql.SQL("ALTER TABLE {}.notes ENABLE ROW LEVEL SECURITY").format(identifier))
                    with self.assertRaises(InvalidReport), key_reader(spec):
                        pass
            finally:
                db.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(identifier))
                db.execute(sql.SQL("DROP ROLE {}").format(identifier))
