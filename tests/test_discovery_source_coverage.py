"""Exercise the source mapping gate, case binding and Northline demo."""

import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from setrya.discovery.case import replay
from setrya.discovery.macie import load_finding
from setrya.discovery.mapping import bind_finding, load_mapping
from setrya.discovery.northline_source import demo, init_example
from setrya.discovery.source_coverage import (
    APPROVAL_FORMAT,
    assess,
    load_document,
    scan,
    scope_digest,
)
from setrya.offboarding.inputs import InvalidReport, publish_new


class SourceCoverageTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.root = Path(directory)
        self.example = self.root / "example"
        init_example(self.example)
        finding = load_finding(self.example / "finding.json")
        self.binding = bind_finding(finding, load_mapping(self.example / "mapping.json"))
        self.unmapped = bind_finding(finding, load_mapping(self.example / "unmapped.json"))

    def test_new_sites_and_removed_approvals_require_review(self):
        old = self.root / "old"
        head = self.root / "head"
        for folder in (old, head):
            folder.mkdir()
        write = 'from pathlib import Path\nPath("outputs/one.pdf").write_bytes(data)\n'
        (old / "exports.py").write_text(write)
        (head / "exports.py").write_text("\n" + write + 'open("outputs/two.pdf", "wb")\n')
        baseline = assess(old, self.binding)
        pending = assess(head, self.binding, baseline=baseline)
        existing, added = pending["sites"]
        self.assertEqual(existing["source"]["id"], baseline["sites"][0]["source"]["id"])
        self.assertFalse(existing["requires_review"])
        self.assertTrue(added["requires_review"])
        self.assertEqual(pending["review_required"], 1)
        self.assertTrue(all(row["runtime"] is row["deletion"] is None for row in pending["sites"]))

        approval = {
            "format": APPROVAL_FORMAT, "binding_sha256": scope_digest(self.binding),
            "sites": [{
                "candidate_id": existing["source"]["id"], "service_id": "archive-pdf",
                "store": "archive-exports", "key": "archive-f42.pdf",
            }],
        }
        reviewed = assess(old, self.binding, approvals=approval)
        self.assertEqual(reviewed["review_required"], 0)
        self.assertEqual(assess(head, self.unmapped, baseline=reviewed)["review_required"], 2)
        with self.assertRaisesRegex(InvalidReport, "exact discovery scope"):
            assess(head, self.unmapped, approvals=approval)
        invalid = deepcopy(approval)
        invalid["sites"][0]["key"] = "another.pdf"
        with self.assertRaisesRegex(InvalidReport, "exact direct service"):
            assess(head, self.binding, approvals=invalid)
        wrong_baseline = {**baseline, "case_sha256": "0" * 64}
        with self.assertRaisesRegex(InvalidReport, "this case and scanner"):
            assess(head, self.binding, baseline=wrong_baseline)

    def test_archive_receipt_gives_evidence_only_after_approval_and_bound_replay(self):
        result = self.root / "demo"
        with redirect_stdout(StringIO()) as transcript:
            self.assertEqual(demo(result), 0)
        self.assertIn("REVIEW REQUIRED", transcript.getvalue())
        self.assertEqual(load_document(result / "unmapped.json", "source check")["review_required"], 1)
        approvals = load_document(self.example / "source-approvals.json", "source approvals")
        source = self.example / "source"
        site, = scan(source)["candidates"]
        self.assertIsNone(site["destination"])
        self.assertEqual(site["hint"], "archive-f42.pdf")
        for lane, verdict, state in (("broken", "FAIL", "RESIDUAL_FOUND"), ("guarded", "PASS", "OPEN_ITEMS")):
            with self.subTest(lane=lane):
                case = result / lane
                self.assertEqual({p.suffix for p in case.rglob("*") if p.is_file()}, {".json"})
                checked = replay(case, expected_binding=self.binding)
                statuses = {row["id"]: row["status"] for row in checked["services"]}
                self.assertEqual(checked["review_status"], state)
                self.assertEqual(statuses["archive-pdf"], verdict)
                for service in ("pdf-export", "security-finding", "retained-detection", "investigation-api"):
                    self.assertEqual(statuses[service], "PASS")
                report = assess(source, self.binding, approvals=approvals, bundle=case)
                archive, = report["sites"]
                self.assertEqual(report["review_required"], 0)
                self.assertEqual(archive["runtime"]["baseline"], "CONFIRMED")
                self.assertIn("#/baseline/stored/", archive["runtime"]["evidence"][0])
                self.assertEqual(archive["deletion"]["status"], verdict)
                self.assertTrue(any("#/final/stored/" in value for value in archive["deletion"]["evidence"]))
                self.assertIsNone(assess(source, self.binding, bundle=case)["sites"][0]["deletion"])

        with self.assertRaises(InvalidReport):
            assess(source, self.unmapped, bundle=result / "guarded")
        persisted = result / "broken" / "case-result.json"
        tampered = load_document(persisted, "case result")
        tampered["technical_verdict"] = "PASS"
        persisted.unlink()
        publish_new(tampered, persisted)
        with self.assertRaisesRegex(InvalidReport, "differs from the replayed case"):
            assess(source, self.binding, approvals=approvals, bundle=result / "broken")
