"""Verify draft handoff evidence from a real read-only PostgreSQL role."""

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from setrya.receipts import replay


@unittest.skipUnless(os.environ.get("SETRYA_PGVECTOR_DSN"), "requires disposable PostgreSQL")
class PostgresReceiptTests(unittest.TestCase):
    def _produce(self):
        folder = Path(self.enterContext(TemporaryDirectory()))
        output = folder / "source"
        result = subprocess.run(
            [sys.executable, "-m", "setrya.examples.receipt_postgres", "--output", str(output)],
            text=True, capture_output=True, timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        pins = json.loads((output / "ticket-pins.json").read_bytes())
        return output, result.stdout, pins

    def test_public_observer_handoff_captures_absent_present_and_unknown(self):
        output, transcript, pins = self._produce()
        outcomes = {
            "passed": ("PASS", "READY_FOR_REVIEW", ["ABSENT", "ABSENT"]),
            "residual": ("FAIL", "RESIDUAL_FOUND", ["ABSENT", "PRESENT"]),
            "unavailable": ("NOT TESTED", "OPEN_ITEMS", ["UNKNOWN", "UNKNOWN"]),
        }
        self.assertEqual(set(pins), set(outcomes))
        expected_files = {"ticket-pins.json"} | {
            f"{lane}/{name}" for lane in outcomes
            for name in ("erasure-receipt.json", "observation-evidence.json")
        }
        self.assertEqual({item.relative_to(output).as_posix() for item in output.rglob("*") if item.is_file()},
                         expected_files)
        for lane, (verdict, review, states) in outcomes.items():
            with self.subTest(lane=lane):
                receipt = replay(output / lane)
                self.assertEqual(receipt["profile"], "observed-deletion")
                self.assertEqual((receipt["technical_verdict"], receipt["review_status"]), (verdict, review))
                self.assertEqual(receipt["request_id"], pins[lane]["ticket_id"])
                self.assertEqual(receipt["frame_sha256"], pins[lane]["frame_sha256"])
                self.assertCountEqual((row["status"] for row in receipt["checks"]), states)
                if lane == "unavailable":
                    self.assertIn("store-or-control-unavailable", receipt["gaps"])
                self.assertIn(f"{receipt['request_id']} · {verdict} · {review}", transcript)
                evidence = (output / lane / "observation-evidence.json").read_text(encoding="utf-8")
                for internal in ("setrya_handoff_", "-private-note", "-private-summary",
                                 "Synthetic private", "retained-support-note", "SETRYA_RECEIPT_OBSERVER_DSN"):
                    self.assertNotIn(internal, evidence)

    @unittest.skipUnless(shutil.which("cosign"), "requires Cosign 3")
    def test_reviewer_can_verify_the_completed_ticket_without_operator_inputs(self):
        originals, _, pins = self._produce()
        folder = originals.parent
        env = {**os.environ, "COSIGN_PASSWORD": ""}
        env.pop("SETRYA_PGVECTOR_DSN", None)
        env.pop("SETRYA_RECEIPT_OBSERVER_DSN", None)
        generated = subprocess.run(
            ["cosign", "generate-key-pair", "--output-key-prefix", str(folder / "issuer")],
            env=env, text=True, capture_output=True, timeout=20, check=False,
        )
        self.assertEqual(generated.returncode, 0, generated.stderr)
        reviewer = folder / "reviewer"
        reviewer.mkdir()
        shutil.copyfile(folder / "issuer.pub", reviewer / "trusted-issuer.pub")
        for lane, code, verdict in (("passed", 0, "PASS"), ("residual", 1, "FAIL"),
                                   ("unavailable", 3, "NOT TESTED")):
            with self.subTest(lane=lane):
                packed = subprocess.run(
                    [sys.executable, "-m", "setrya", "receipt", "pack", str(originals / lane),
                     "--output", str(folder / lane), "--system", "synthetic-support", "--system-version", "1",
                     "--key", str(folder / "issuer.key")],
                    env=env, text=True, capture_output=True, timeout=30, check=False,
                )
                self.assertEqual(packed.returncode, 0, packed.stderr)
                shutil.copytree(folder / lane, reviewer / lane)
                pin = pins[lane]
                checked = subprocess.run(
                    [sys.executable, "-I", "-m", "setrya", "receipt", "verify-exchange", lane,
                     "--key", "trusted-issuer.pub", "--expect-ticket", pin["ticket_id"],
                     "--expect-frame", pin["frame_sha256"]],
                    cwd=reviewer, env=env, text=True, capture_output=True, timeout=30, check=False,
                )
                self.assertEqual(checked.returncode, code, checked.stdout + checked.stderr)
                self.assertIn(f"Verified exchange · {verdict} ·", checked.stdout)
                self.assertIn("Completed ticket " + pin["ticket_id"], checked.stdout)
