"""Exercise the signed multi-repository assessment with ordinary receipts and checks."""

import json
import unittest
from hashlib import sha256
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
from unittest.mock import patch

from setrya.casework import assessment
from setrya.core.inputs import InvalidReport
from setrya.examples.workspace import demo


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
