import json
import sqlite3
from contextlib import closing, ExitStack, redirect_stdout, redirect_stderr
from dataclasses import replace
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from setrya.control_references import validate_controls
from setrya.casework.receipt_summary import receipt_summary
from setrya.cli import main
from setrya.coverage_drift import compare
from setrya.erasure.hooks import CopyHooks
from setrya.erasure.journal import CopyJournal
from setrya.erasure.journal_merge import CollectedJournal, WorkerJournal
from setrya.erasure.lineage import VersionLineage, VersionRef
from setrya.erasure.subject import Subject
from setrya.erasure.v3 import run_shared
from setrya.examples.workspace import CASE, SIMPLE, open_fixture
from setrya.offboarding.inputs import InvalidReport
from setrya.receipts import replay


def system(name, adapter):
    return (f'\n[[systems]]\nname="{name}"\nowner="infra-team"\nrole="store"\n'
            f'approved_labels=["private"]\nretention_days=0\nadapter="{adapter}"\n')


def binding(store, kind, name):
    return (f'\n[[coverage]]\nstore="{store}"\nkind="{kind}"\n'
            f'name="{name}"\nscanner="fixture-{kind}"\n')


class ReceiptViews(unittest.TestCase):
    def test_replay_sampling_open_items_and_bound_controls_all_audiences(self):
        refs = ({"framework": "SOC 2", "reference": "C1.2"}, {"framework": "DPA", "reference": "clause 4.2"})
        with TemporaryDirectory() as tmp, open_fixture(shared=True, guarded=False) as (subject, app, items):
            bundle = Path(tmp, "bundle")
            run_shared(subject, case=replace(CASE, controls=refs), application=app, external_items=items,
                       mode="late-write", output=bundle)
            decision = replay(bundle)
            self.assertEqual(decision["controls"], list(refs))
            due = decision["open_items"][0]["follow_up"]
            for audience in ("customer", "reviewer", "engineer"):
                for output in ("text", "markdown"):
                    with self.subTest(audience=audience, output=output):
                        rendered = receipt_summary(bundle, audience=audience, output_format=output)
                        self.assertIn("platform-team", rendered)
                        self.assertIn(due, rendered)
                        self.assertIn("clause 4.2", rendered)
                        self.assertIn("confirmed in 6 of 6 control answers", rendered)
                        self.assertIn("confirmed in 2 of 2 preservation checks", rendered)
                        self.assertIn("At the final read", rendered)
                        self.assertEqual(rendered.startswith("# "), output == "markdown")
                        if audience == "customer":
                            self.assertNotIn("handoffs/onboarding-team", rendered)
            manifest = bundle / "erasure-receipt.json"
            decision["controls"][1]["reference"] = "clause 7.8"
            manifest.write_text(json.dumps(decision))
            with self.assertRaisesRegex(InvalidReport, "differs"):
                receipt_summary(bundle)

    def test_delete_only_summary_counts_preservation_separately(self):
        with TemporaryDirectory() as tmp, open_fixture(shared=False, guarded=True) as (subject, app, items):
            bundle = Path(tmp, "bundle")
            receipt = run_shared(subject, case=SIMPLE, application=app, external_items=items,
                                 mode="deletion", output=bundle)
            self.assertEqual(receipt["technical_verdict"], "PASS")
            text = receipt_summary(bundle, audience="reviewer", output_format="markdown")
            self.assertIn("Person deletion drill", text)
            self.assertNotIn("Shared-record", text)
            self.assertIn("read 1 of 1 stored record.", text)
            self.assertIn("read 6 of 6 answers.", text)
            self.assertIn("confirmed in 3 of 3 control answers.", text)
            self.assertNotIn("preservation checks", text)
            self.assertIn("SHA-256 " + receipt["evidence"]["sha256"], text)
            self.assertIn("Technical verdict PASS\n\nReview status", text)
            customer = receipt_summary(bundle, audience="customer", output_format="md")
            self.assertIn("Observation date: ", customer)
            self.assertNotIn("&#58;", customer)

    def test_readable_markdown_does_not_link_receipt_identifiers(self):
        from setrya.casework.receipt_summary import _markdown

        self.assertEqual(_markdown("Observation date: today"), "Observation date: today")
        self.assertEqual(_markdown("blob:sha"), "blob:sha")
        rendered = _markdown("https://example.invalid <b> @team [label](www.example.invalid)")
        self.assertIn("https&#58;//example.invalid", rendered)
        self.assertIn("&lt;b&gt;", rendered)
        self.assertIn("&#64;team", rendered)
        self.assertIn("www&#46;example.invalid", rendered)

    def test_markdown_cli_alias_uses_the_same_local_renderer(self):
        from setrya.erasure.render import receipt_summary as render

        bundle = Path(__file__).parent / "fixtures" / "erasure_v3_1_0_3"
        stdout = StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(main(["receipt", "summary", str(bundle), "--format", "md"]), 0)
        self.assertEqual(stdout.getvalue(), render(bundle, output_format="markdown") + "\n")

    def test_all_audiences_can_render_a_linked_followup_without_a_run_id(self):
        from setrya.casework.recheck import recheck
        with TemporaryDirectory() as tmp, open_fixture(shared=True) as (subject, app, items):
            original, followup = Path(tmp, "initial"), Path(tmp, "followup")
            run_shared(subject, case=CASE, application=app, external_items=items, mode="deletion", output=original)
            recheck(original, output=followup)
            linked = replay(followup)
            self.assertEqual(linked["profile"], "follow-up")
            self.assertNotIn("run", linked)
            for audience in ("engineer", "reviewer", "customer"):
                with self.subTest(audience=audience):
                    text = receipt_summary(followup, audience=audience)
                    self.assertIn("platform-team", text)
                    if audience != "customer":
                        self.assertIn(linked["parent_sha256"], text)

    def test_archived_case_and_invalid_control_identifiers(self):
        bundle = Path(__file__).parent / "fixtures" / "erasure_v3_1_0_3"
        self.assertNotIn("Customer control references", receipt_summary(bundle))
        for value in ([], [{"framework": "test", "reference": "<private>"}],
                      [{"framework": "x", "reference": "clause 4"}] * 2):
            with self.assertRaises(InvalidReport):
                validate_controls(value)


class Drift(unittest.TestCase):
    def test_exact_store_trace_namespace_mapping(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            journal = CopyJournal(root / "journal.sqlite")
            subject = Subject.derive(b"a" * 32, "tenant", "person", "private")
            log = CopyHooks(journal, subject)
            class Memory:
                def put(self, ns, key, value):
                    self.ns = ns
            memory = Memory()
            log.put_memory(memory, "fixture-key", {}, store="notes", source="source-a")
            # A trace emitted by an older harness records its logical sink as the store.
            journal.record(subject, store="traces", key="trace-a/span", action="stored", source="source-a",
                           details={"operation": "langfuse.observation"})
            lineage = VersionLineage(journal, "derived")
            lineage.record(VersionRef("notes", "article", "v1"), subjects=[subject])
            inventory = root / "inventory.toml"
            content = "version=1\n" + system("notes", "postgres") + system("traces", "none")
            inventory.write_text(content)
            report, code = compare([journal.path], inventory)
            self.assertEqual(code, 3)
            self.assertEqual({(r["kind"], r["name"]) for r in report["boundaries"] if not r["mapped"]},
                             {("store", "traces"), ("trace", "traces"), ("namespace", "/".join(memory.ns))})
            content += (binding("notes", "namespace", "setrya/{subject}")
                        + binding("traces", "store", "traces") + binding("traces", "trace", "traces"))
            inventory.write_text(content)
            before = journal.path.read_bytes()
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(main(["coverage-drift", "--journal", str(journal.path), "--inventory", str(inventory)]), 0)
            self.assertEqual(before, journal.path.read_bytes())
            other = Subject.derive(b"a" * 32, "tenant", "other", "private")
            journal.record(other, store="notes", key="sibling", action="stored", source="source-b",
                           details={"boundary_kind": "namespace", "boundary": "/".join(memory.ns)})
            self.assertEqual(compare([journal.path], inventory)[1], 3)
            journal.record(subject, store="new-sink", key="z", action="stored", source="source-a")
            report, code = compare([journal.path], inventory)
            self.assertEqual(code, 3)
            self.assertIsNone(next(r for r in report["boundaries"] if r["store"] == "new-sink")["owner"])

    def test_retained_only_and_empty_namespaces_are_seen_without_claiming_subject_ownership(self):
        from setrya.erasure.case_stores import open_observer
        from setrya.erasure.casefile import StoreApplication

        with TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            app_db = root / "application.sqlite"
            with closing(sqlite3.connect(app_db)) as db, db:
                db.execute("CREATE TABLE records (id TEXT PRIMARY KEY, scope TEXT, answer TEXT)")
                db.executemany("INSERT INTO records VALUES(?,?,?)",
                               [("old", "mapped", "private-marker"), ("keep", "new-cache", "retained-fact")])
            config = {"kind": "sqlite", "table": "records", "key_column": "id",
                      "content_column": "answer", "scope_column": "scope"}
            stores = {name: open_observer(stack, {**config, "scope": scope}, app_db)
                      for name, scope in (("notes", "mapped"), ("cache", "new-cache"), ("summary", "empty"))}
            journal = CopyJournal(root / "journal.sqlite")
            app = StoreApplication(SimpleNamespace(markers=("private-marker",), store_facts=("private-marker", "retained-fact")),
                                   stores, journal)
            subject = Subject.derive(b"a" * 32, "tenant", "person", "private")
            self.assertIs(app.inspect(subject, "notes", "old").target_present, True)
            self.assertIs(app.inspect(subject, "cache", "keep").control_present, True)
            self.assertEqual(app.scan(subject, "summary"), set())
            self.assertEqual([(copy.store, copy.key) for copy in journal.copies(subject)], [("notes", "old")])
            inv = root / "inventory.toml"
            inv.write_text("version=1\n" + system("notes", "sqlite") + binding("notes", "namespace", "mapped"))
            report, code = compare([journal.path], inv)
            self.assertEqual(code, 3)
            self.assertEqual({(r["store"], r["name"]) for r in report["boundaries"]
                              if r["kind"] == "namespace" and not r["mapped"]},
                             {("cache", "new-cache"), ("summary", "empty")})

    def test_no_observations_and_invalid_journal(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            inv = root / "inventory.toml"
            inv.write_text("version=1\n" + system("notes", "postgres"))
            journal = CopyJournal(root / "empty.sqlite")
            self.assertEqual(compare([journal.path], inv)[1], 3)
            db = sqlite3.connect(root / "view.sqlite")
            db.execute("CREATE VIEW copy_events AS SELECT 'notes' AS store, '{}' AS details")
            db.close()
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(main(["coverage-drift", "--journal", str(root / "view.sqlite"), "--inventory", str(inv)]), 2)

    def test_deleted_copy_event_blocks_coverage_pass(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            subject = Subject.derive(b"a" * 32, "tenant", "person", "private")
            journal = CopyJournal(root / "copies.sqlite")
            journal.record(subject, store="notes", key="known", source="request", action="stored")
            journal.record(subject, store="unmapped", key="extra", source="request", action="stored")
            inv = root / "inventory.toml"
            inv.write_text("version=1\n" + system("notes", "sqlite"))
            self.assertEqual(compare([journal.path], inv)[1], 3)
            with closing(sqlite3.connect(journal.path)) as db, db:
                db.execute("DELETE FROM copy_events WHERE store='unmapped'")
            with self.assertRaisesRegex(InvalidReport, "Missing journal rows"):
                compare([journal.path], inv)

    def test_remote_trace_boundary_survives_packet_collection(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            subject = Subject.derive(b"a" * 32, "tenant", "person", "private")
            worker = WorkerJournal(root / "worker.sqlite", run_id="case-7", producer="retriever")
            worker.record(subject, store="traces", key="span-1", source="request", action="stored",
                          details={"boundary_kind": "trace", "boundary": "remote-sink"})
            worker.seal(subject, root / "packet.json")
            collector = CollectedJournal(root / "collected.sqlite", run_id="case-7")
            collector.ingest(root / "packet.json", producer="retriever")
            inv = root / "inventory.toml"
            stores = "version=1\n" + system("traces", "trace-reader")
            inv.write_text(stores)
            report, code = compare([collector.path], inv)
            self.assertEqual(code, 3)
            self.assertEqual([r["name"] for r in report["boundaries"] if not r["mapped"]], ["remote-sink"])
            inv.write_text(stores + binding("traces", "trace", "remote-sink"))
            self.assertEqual(compare([collector.path], inv)[1], 0)
            with closing(sqlite3.connect(collector.path)) as db, db:
                db.execute("DELETE FROM collected_events WHERE producer='retriever'")
            with self.assertRaisesRegex(InvalidReport, "differs from its seal"):
                compare([collector.path], inv)
