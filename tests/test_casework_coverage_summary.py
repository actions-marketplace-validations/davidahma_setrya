import json
import sqlite3
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from setrya.casework.controls import validate_controls
from setrya.casework.receipt_summary import receipt_summary
from setrya.cli import main
from setrya.coverage_drift import compare
from setrya.erasure.hooks import CopyHooks
from setrya.erasure.journal import CopyJournal
from setrya.erasure.lineage import VersionLineage, VersionRef
from setrya.erasure.subject import Subject
from setrya.erasure.v3 import run_shared
from setrya.examples.workspace import CASE, open_fixture
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
                        self.assertIn("retained fact appeared", rendered)
                        self.assertIn("At the final read", rendered)
                        self.assertEqual(rendered.startswith("# "), output == "markdown")
                        if audience == "customer":
                            self.assertNotIn("handoffs/onboarding-team", rendered)
            manifest = bundle / "erasure-receipt.json"
            decision["controls"][1]["reference"] = "clause 7.8"
            manifest.write_text(json.dumps(decision))
            with self.assertRaisesRegex(InvalidReport, "differs"):
                receipt_summary(bundle)

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
                             {("store", "traces"), ("trace", "traces"), ("namespace", "/".join(memory.ns)),
                              })
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
