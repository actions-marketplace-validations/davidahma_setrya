"""Exercise provenance capture along the normal CLI and historical replay paths."""

import json
import os
import shutil
import subprocess
import unittest
from contextlib import chdir, redirect_stderr, redirect_stdout
from hashlib import sha256
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from setrya import __version__, provenance
from setrya.cli import main
from setrya.core import receipt_v3
from setrya.core.inputs import InvalidReport
from setrya.core.provenance import verify_pins
from setrya.receipts import replay

_REPO = Path(__file__).resolve().parents[1]
_CI = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_WORKFLOW_REF": "team/sample/.github/workflows/deletion.yml@refs/heads/main",
    "GITHUB_WORKFLOW_SHA": "8" * 40,
    "GITHUB_RUN_ID": "201",
    "GITHUB_RUN_ATTEMPT": "2",
    "PYTHONPATH": str(_REPO),
}


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True).stdout.decode().strip()


@unittest.skipUnless(shutil.which("git"), "Requires Git to check checkout provenance.")
class ProvenanceRunTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(self.enterContext(TemporaryDirectory()))
        self.root = tmp / "app"
        self.root.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "fixture@example.invalid")
        git(self.root, "config", "user.name", "Setrya fixture")
        self.enterContext(chdir(self.root))
        self.enterContext(patch.dict(os.environ, _CI))
        self.enterContext(redirect_stdout(StringIO()))
        self.stderr = self.enterContext(redirect_stderr(StringIO()))
        self.starter = self.root / "case.py"
        self.starter.write_bytes((_REPO / "setrya/erasure/workspace_starter.py").read_bytes())
        self.test_file = self.root / "assertions.py"
        self.test_file.write_text("# Declared supporting test code\n", encoding="utf-8")
        git(self.root, "add", "case.py", "assertions.py")
        git(self.root, "commit", "-qm", "Fixture")
        self.commit = git(self.root, "rev-parse", "HEAD")
        self.output = tmp / "receipt"

    def run_starter(self):
        return main(["run", "--starter", str(self.starter), "--test-file", str(self.test_file),
                     "--output", str(self.output)])

    def test_checkout_fingerprints_and_independent_pins(self):
        self.assertEqual(self.run_starter(), 0, self.stderr.getvalue())
        receipt = replay(self.output, expected_app_commit=self.commit)
        self.assertEqual(receipt["evidence_format"], "setrya.erasure.evidence.v3.2")
        recorded = receipt["provenance"]
        self.assertEqual(recorded["setrya_version"], __version__)
        self.assertEqual(recorded["application"], {
            "checkout_commit": self.commit, "checkout_state": "clean",
            "asserted_deploy_commit": None, "execution": "local-starter",
        })
        tests = {row["path"]: row for row in recorded["test_files"]}
        for file, role in ((self.starter, "entrypoint"), (self.test_file, "test")):
            self.assertEqual(tests[file.name], {"path": file.name, "location": "checkout", "role": role,
                                                "sha256": sha256(file.read_bytes()).hexdigest(),
                                                "commit_bound": True})
        self.assertEqual(recorded["ci"], {"workflow_ref": _CI["GITHUB_WORKFLOW_REF"],
                                          "workflow_sha": _CI["GITHUB_WORKFLOW_SHA"],
                                          "run_id": "201", "run_attempt": "2"})
        pin = self.root / "review-pin.json"
        pin.write_text(json.dumps(recorded), encoding="utf-8")
        self.assertEqual(main(["replay", str(self.output), "--expect-provenance", str(pin)]), 0)
        self.assertEqual(main(["replay", str(self.output), "--expect-app-commit", "1" * 40]), 2)

        # The receipt projection must agree with its evidence, including producer data.
        path = self.output / "erasure-receipt.json"
        receipt["provenance"]["ci"]["run_id"] = "202"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaisesRegex(InvalidReport, "differs from the replayed"):
            replay(self.output)

    def test_exchange_checks_pins_during_verified_replay(self):
        from setrya.casework import exchange

        self.assertEqual(self.run_starter(), 0, self.stderr.getvalue())
        bundle = self.root / "exchange"
        key = self.root / "review.key"
        with (
            patch.object(exchange.signing, "sign_bytes", side_effect=lambda raw, path, **_: path.touch()),
            patch.object(exchange.signing, "verify_bytes"),
        ):
            exchange.pack(self.output, output=bundle, system="workspace", version="1", key=key, synthetic=True)
            args = ["receipt", "verify-exchange", str(bundle), "--key", str(key), "--expect-app-commit"]
            self.assertEqual(main([*args, self.commit]), 0)
            self.assertEqual(main([*args, "2" * 40]), 2)
            self.assertIn("expected clean application checkout", self.stderr.getvalue())

    def test_clean_checkout_excludes_untracked_files_from_pinned_coverage(self):
        path = self.root / "additional.py"
        path.write_text("# Untracked test input\n", encoding="utf-8")
        recorded = provenance.capture(self.starter, [path])
        self.assertEqual(recorded["application"]["checkout_state"], "clean")
        self.assertFalse(next(row for row in recorded["test_files"] if row["path"] == path.name)["commit_bound"])
        with self.assertRaisesRegex(InvalidReport, "committed test files"):
            verify_pins({"provenance": recorded}, expected_app_commit=self.commit)
        self.test_file.write_text("# Tracked modification\n", encoding="utf-8")
        recorded = provenance.capture(self.starter, [self.test_file])
        self.assertEqual(recorded["application"]["checkout_state"], "dirty")
        self.assertFalse(next(row for row in recorded["test_files"] if row["path"] == self.test_file.name)["commit_bound"])

    def test_changed_test_file_produces_no_published_receipt(self):
        self.starter.write_bytes(self.starter.read_bytes().replace(
            b"if __name__ == ", b"from pathlib import Path\nPath('assertions.py').write_text('changed')\n\nif __name__ == "
        ))
        self.assertEqual(self.run_starter(), 2)
        self.assertIn("declared test files changed", self.stderr.getvalue())
        self.assertFalse(self.output.exists())

    def test_http_or_asserted_deployment_cannot_prove_a_clean_checkout(self):
        yaml = self.root / "case.yaml"
        yaml.write_text("case: synthetic\n", encoding="utf-8")
        git(self.root, "add", yaml.name)
        git(self.root, "commit", "-qm", "Add HTTP case")
        commit = git(self.root, "rev-parse", "HEAD")
        recorded = provenance.capture(yaml, deployed_commit="3" * 40)
        self.assertEqual(recorded["application"]["execution"], "http-case")
        self.assertEqual(recorded["application"]["asserted_deploy_commit"], "3" * 40)
        with self.assertRaisesRegex(InvalidReport, "expected clean application checkout"):
            verify_pins({"provenance": recorded}, expected_app_commit=commit)

    def test_archived_grouped_receipts_replay_without_producer_claim(self):
        self.assertEqual(self.run_starter(), 0, self.stderr.getvalue())
        original = self.output / "erasure-evidence.json"
        observed = json.loads(original.read_bytes())
        del observed["provenance"]
        observed["format"] = receipt_v3.GROUPED_V31_FORMAT
        raw = json.dumps(observed).encode("utf-8")
        original.write_bytes(raw)
        receipt = receipt_v3.derive(observed, sha256(raw).hexdigest())
        (self.output / "erasure-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        result = replay(self.output)
        self.assertNotIn("provenance", result)
        self.assertEqual(result["technical_verdict"], "PASS")
        with self.assertRaisesRegex(InvalidReport, "committed test files"):
            replay(self.output, expected_app_commit=self.commit)
