"""Exercise the signed multi-repository assessment with ordinary receipts and checks."""

import json
import unittest
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
from unittest.mock import patch

from setrya.casework import assessment, assessment_comparison
from setrya.core.inputs import InvalidReport
from setrya.erasure import Artifact, run_shared
from setrya.examples.workspace import CASE, PRIVATE, WORKSPACE, demo, open_fixture


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.key = self.root / "trusted.pub"
        self.plan = self.root / "assessment-plan.json"
        self.revision = "2" * 40
        self.source = {"format": assessment.PLAN, "repositories": [
            {"name": "support", "commit": self.revision, "checks": ["review.json"],
             "receipts": ["workspace/guarded"]},
            {"name": "billing", "commit": self.revision, "checks": [], "receipts": []},
        ]}
        self.plan.write_text(json.dumps(self.source))
        self.review = {"format": "setrya.copy-review.v1", "candidate_commit": self.revision,
                       "sites": [{"status": "needs-review"}], "review_required": 1}
        self.check = self.root / "review.json"
        self.check.write_text(json.dumps(self.review))
        with patch("socket.getfqdn", side_effect=AssertionError("Loopback fixture attempted a DNS lookup.")):
            self.assertEqual(demo(self.root / "workspace", "late-write"), 0)

        def sign(data, output, *, key):
            output.write_bytes(sha256(data).digest())

        def verify(data, signature, *, key, **_):
            if key != self.key or sha256(data).digest() != signature:
                raise InvalidReport("Signature mismatch.")

        self.enterContext(patch.object(assessment.signing, "sign_bytes", side_effect=sign))
        self.enterContext(patch.object(assessment.signing, "verify_bytes", side_effect=verify))

    def test_assessment_keeps_replay_and_coverage_separate(self):
        output = self.root / "report"
        result = assessment.build(self.plan, output, key=self.key)
        self.assertEqual(len(list(output.iterdir())), 3)
        support, billing = result["repositories"]
        self.assertEqual(support["receipts"][0]["verdict"], "PASS")
        self.assertEqual(support["receipts"][0]["review"], "OPEN_ITEMS")
        self.assertEqual(support["checks"][0]["gaps"], 1)
        self.assertEqual(billing["receipts"], [])
        self.assertIn("1 of 1", assessment.verify(output, key=self.key))
        with self.assertRaisesRegex(InvalidReport, "Signature mismatch"):
            assessment.verify(output, key=self.root / "other.pub")
        path = output / assessment.SUMMARY
        path.write_bytes(path.read_bytes() + b"altered")
        with self.assertRaisesRegex(InvalidReport, "Summary differs"):
            assessment.verify(output, key=self.key)

    def test_mismatched_coverage_candidate_is_rejected_before_signing(self):
        self.review["candidate_commit"] = "3" * 40
        self.check.write_text(json.dumps(self.review))
        output = self.root / "report"
        with self.assertRaisesRegex(InvalidReport, "candidate differs"):
            assessment.build(self.plan, output, key=self.key)
        self.assertFalse(output.exists())

    def test_repeated_inputs_cannot_inflate_counts(self):
        output = self.root / "report"
        first = self.source["repositories"][0]
        duplicate = copytree(self.root / "workspace/guarded", self.root / "duplicate-receipt")
        manifest = duplicate / "erasure-receipt.json"
        manifest.write_text(json.dumps(json.loads(manifest.read_bytes()), indent=4))
        first["receipts"].append("duplicate-receipt")
        self.plan.write_text(json.dumps(self.source))
        with self.assertRaisesRegex(InvalidReport, "Duplicate receipt evidence digest"):
            assessment.build(self.plan, output, key=self.key)
        first["receipts"].pop()
        second_path = self.root / "same-review.json"
        second_path.write_text(json.dumps(self.review, indent=4))
        first["checks"].append(second_path.name)
        self.plan.write_text(json.dumps(self.source))
        with self.assertRaisesRegex(InvalidReport, "Duplicate coverage report digest"):
            assessment.build(self.plan, output, key=self.key)
        self.assertFalse(output.exists())

    def test_release_comparison_identifies_observed_gains_losses_and_residuals(self):
        behavior = replace(CASE, scan_stores=("handoffs",))

        def record(guarded, case, output):
            with open_fixture(shared=True, guarded=guarded) as (subject, app, items):
                def scan(target, store):
                    return {WORKSPACE} if app.inspect(target, store, WORKSPACE).target_present else set()

                app.scan = scan
                if not guarded:
                    app.db.execute("INSERT INTO notes VALUES ('secondary', '1', ?)", (PRIVATE,))
                    app.db.commit()
                return run_shared(subject, case=case, application=app, external_items=items, output=output,
                                  mode="late-write", cancel_hold=app.cancel_and_drain)

        self.source["client"] = "northline"
        self.source["repositories"] = self.source["repositories"][:1]
        baseline = self.root / "prior-receipt"
        self.assertEqual(record(True, behavior, baseline)["technical_verdict"], "PASS")
        self.source["repositories"][0]["receipts"] = [baseline.name]
        self.plan.write_text(json.dumps(self.source))
        previous = self.root / "previous"
        assessment.build(self.plan, previous, key=self.key)
        approved = sha256((previous / assessment.REPORT).read_bytes()).hexdigest()
        candidate_receipt = self.root / "current-receipt"
        case = replace(behavior, artifacts=(CASE.artifacts[0], CASE.artifacts[2], Artifact("notes", "secondary", "delete")))
        self.assertEqual(record(False, case, candidate_receipt)["technical_verdict"], "FAIL")
        self.source["repositories"][0]["receipts"] = [candidate_receipt.name]
        self.plan.write_text(json.dumps(self.source))
        candidate = self.root / "candidate"
        result = assessment.build(self.plan, candidate, key=self.key)
        self.assertIn(["scan", "handoffs"], result["repositories"][0]["receipts"][0]["details"]["observed"])
        output = self.root / "comparison"
        options = {"client": "northline", "output": output, "trust": {"key": self.key}, "key": self.key}
        with self.assertRaisesRegex(InvalidReport, "independently approved digest"):
            assessment_comparison.compare(previous, candidate, approved_sha256="0" * 64, **options)
        review = assessment_comparison.compare(previous, candidate, approved_sha256=approved, **options)
        self.assertIn("SEND BACK FOR REVIEW", review)
        self.assertIn("New observed coverage\n\n- Copy notes/secondary (delete)", review)
        self.assertIn("Lost observed coverage\n\n- Copy notes/team-calendar (preserve)", review)
        self.assertNotIn("Scanner handoffs", review)
        self.assertIn("FAIL · RESIDUAL_FOUND · Erased data found", review)
        self.assertIn("Owner platform-team · Due ", review)
        self.assertIn("a copy or an answer that should have been erased", (output / assessment_comparison.CUSTOMER).read_text())
        self.assertEqual(assessment_comparison.verify(output, key=self.key), review)
        (output / assessment_comparison.CUSTOMER).write_text("A different customer summary.")
        with self.assertRaisesRegex(InvalidReport, "attachment differs"):
            assessment_comparison.verify(output, key=self.key)

    def test_release_comparison_holds_a_passing_candidate_with_weaker_checks(self):
        self.source["client"] = "northline"
        self.source["repositories"] = self.source["repositories"][:1]
        repo = self.source["repositories"][0]
        route_review = {"format": "setrya.route-coverage.v1", "candidate_commit": self.revision,
                        "surfaces": [{"status": "NOT TESTED"}]}
        self.check.write_text(json.dumps(route_review))
        previous_checks = ("route-one.json", "route-two.json")
        for path in previous_checks:
            (self.root / path).write_text(json.dumps({**route_review, "surfaces": [{"status": "PASS", "id": path}]}))
        for name, mode, samples, checks in (("approved", "late-write", 3, list(previous_checks)),
                                              ("candidate", "deletion", 1, [self.check.name])):
            raw = self.root / f"{name}-receipt"
            with open_fixture(shared=True) as (subject, app, _):
                receipt = run_shared(subject, case=replace(CASE, samples=samples), application=app,
                                     output=raw, mode=mode, cancel_hold=app.cancel_and_drain)
            self.assertEqual(receipt["technical_verdict"], "PASS")
            repo.update(receipts=[raw.name], checks=checks)
            self.plan.write_text(json.dumps(self.source))
            assessment.build(self.plan, self.root / name, key=self.key)
        review = assessment_comparison.compare(
            self.root / "approved", self.root / "candidate", client="northline",
            approved_sha256=sha256((self.root / "approved" / assessment.REPORT).read_bytes()).hexdigest(),
            output=self.root / "approval", trust={"key": self.key}, key=self.key,
        )
        self.assertIn("SEND BACK FOR REVIEW", review)
        self.assertIn("3 → 1 samples", review)
        self.assertIn("Delayed worker on /workspaces/", review)
        self.assertIn("setrya.route-coverage.v1 · 1 of 1 need review", review)
        self.assertIn("setrya.route-coverage.v1 · 1 missing from the candidate assessment", review)

    def test_compare_detects_removed_route_rows_in_a_retained_report(self):
        self.source["client"] = "northline"
        self.source["repositories"] = self.source["repositories"][:1]
        self.source["repositories"][0]["receipts"] = ["observed"]
        with open_fixture(shared=True) as (subject, app, _):
            run_shared(subject, case=CASE, application=app, mode="deletion", output=self.root / "observed")
        self.plan.write_text(json.dumps(self.source))
        route_review = {"format": "setrya.route-coverage.v1", "candidate_commit": self.revision, "surfaces": []}

        def write_report(name, paths):
            rows = [{"component": "support", "path": path, "surface": "/answer", "status": "PASS"} for path in paths]
            self.check.write_text(json.dumps({**route_review, "surfaces": rows}))
            assessment.build(self.plan, self.root / name, key=self.key)

        write_report("approved", ["a.py", "b.py"])
        approved = self.root / "approved"
        digest = sha256((approved / assessment.REPORT).read_bytes()).hexdigest()
        for lane, paths, lost in (("empty", [], 2), ("replacement", ["a.py", "c.py"], 1),
                                  ("same", ["b.py", "a.py"], 0)):
            with self.subTest(lane=lane):
                candidate = self.root / lane
                write_report(lane, paths)
                review = assessment_comparison.compare(
                    approved, candidate, client="northline", approved_sha256=digest, output=self.root / f"review-{lane}",
                    trust={"key": self.key}, key=self.key,
                )
                if lost:
                    self.assertIn("SEND BACK FOR REVIEW", review)
                    self.assertIn(f"setrya.route-coverage.v1 · {lost} checked entries lost", review)
                else:
                    self.assertIn("READY FOR APPROVAL", review)
