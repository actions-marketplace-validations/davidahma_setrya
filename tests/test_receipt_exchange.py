"""Verify the draft v1 exchange against actual replayed v3 cases."""

import json
import unittest
from contextlib import redirect_stdout
from hashlib import sha256
from importlib.resources import files
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from setrya.casework import exchange
from setrya.casework.profiles import snapshot
from setrya.cli import main
from setrya.core.inputs import InvalidReport


class ReceiptExchangeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.originals = self.root / "workspace"
        with redirect_stdout(StringIO()):
            self.assertEqual(main(["demo", "--output", str(self.originals)]), 0)
        self.key = self.root / "separately-provisioned.key"

        def sign(raw, output, *, key):
            output.write_bytes(sha256(raw).digest())

        def verify(raw, signature, *, key, **policy):
            if signature != sha256(raw).digest():
                raise InvalidReport("Signature differs from the exact signed bytes.")

        self.enterContext(patch.object(exchange.signing, "sign_bytes", side_effect=sign))
        self.enterContext(patch.object(exchange.signing, "verify_bytes", side_effect=verify))

    def pack(self, lane="guarded"):
        directory = self.root / lane
        manifest = exchange.pack(self.originals / lane, output=directory, system="support-app", version="1.2",
                                 key=self.key, synthetic=True)
        return directory, manifest

    def test_signed_verdict_and_open_items_are_replayed(self):
        for lane, verdict, status, code in (("broken", "FAIL", "RESIDUAL_FOUND", 1),
                                             ("guarded", "PASS", "OPEN_ITEMS", 0)):
            with self.subTest(lane=lane):
                bundle, manifest = self.pack(lane)
                self.assertEqual(exchange.verify(bundle, key=self.key), manifest)
                self.assertEqual(manifest["technical_verdict"], verdict)
                self.assertEqual(manifest["review_status"], status)
                self.assertIsNone(manifest["ticket"])
                self.assertEqual(manifest["open_items"][0]["owner"], "platform-team")
                self.assertEqual(manifest["open_items"][0]["evidence"], "erasure-receipt.json#/open_items/0")
                self.assertNotIn("subject", manifest)
                args = ["receipt", "verify-exchange", str(bundle), "--key", str(self.key)]
                with redirect_stdout(StringIO()) as output:
                    self.assertEqual(main(args), code)
                    self.assertEqual(main([*args, "--case-review"]), 3 if code == 0 else code)
                self.assertIn(f"Verified exchange · {verdict} · {status}", output.getvalue())
                try:
                    import jsonschema
                except ImportError:
                    continue
                schema = files(exchange.__package__).joinpath("receipt-exchange-v1.schema.json").read_text()
                jsonschema.Draft202012Validator(json.loads(schema), format_checker=jsonschema.FormatChecker()).validate(
                    manifest
                )

    def test_authenticated_inconsistent_claim_is_rejected(self):
        bundle, manifest = self.pack("broken")
        manifest["technical_verdict"] = "PASS"
        raw = json.dumps(manifest).encode()
        (bundle / exchange.MANIFEST).write_bytes(raw)
        (bundle / exchange.SIGNATURE).write_bytes(sha256(raw).digest())
        with self.assertRaisesRegex(InvalidReport, "claims differ from the original"):
            exchange.verify(bundle, key=self.key)

    def test_file_bytes_and_signed_manifest_are_both_bound(self):
        bundle, _ = self.pack()
        evidence = bundle / exchange.DRILL_EVIDENCE
        evidence.write_bytes(evidence.read_bytes() + b"\n")
        with self.assertRaisesRegex(InvalidReport, "file digests differ"):
            exchange.verify(bundle, key=self.key)
        manifest = bundle / exchange.MANIFEST
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        with self.assertRaisesRegex(InvalidReport, "exact signed bytes"):
            exchange.verify(bundle, key=self.key)

    def test_bounds_and_trust_are_explicit(self):
        bundle, _ = self.pack()
        with self.assertRaisesRegex(InvalidReport, "signer policy"):
            exchange.verify(bundle)
        with self.assertRaisesRegex(InvalidReport, "independently supplied ticket"):
            exchange.verify(bundle, key=self.key, expect_ticket="TICKET-1")
        extra = bundle / "approved-mapping.toml"
        extra.touch()
        with self.assertRaisesRegex(InvalidReport, "Expected exactly"):
            exchange.verify(bundle, key=self.key)
        extra.unlink()
        manifest = bundle / exchange.MANIFEST
        renamed = manifest.rename(self.root / "outside.json")
        manifest.symlink_to(renamed)
        with self.assertRaisesRegex(InvalidReport, "stay inside"):
            exchange.verify(bundle, key=self.key)

    def test_pack_is_atomic_and_keeps_original_receipt(self):
        target = self.root / "target"
        source = self.originals / "guarded" / exchange.RECEIPT
        before = snapshot(source)
        kwargs = {"output": target, "system": "support-app", "version": "1", "key": self.key}
        with self.assertRaisesRegex(InvalidReport, "synthetic data"):
            exchange.pack(source.parent, **kwargs)
        with (
            patch.object(exchange.signing, "sign_bytes", side_effect=InvalidReport("Signing unavailable.")),
            self.assertRaisesRegex(InvalidReport, "Signing unavailable"),
        ):
            exchange.pack(source.parent, **kwargs, synthetic=True)
        self.assertFalse(target.exists())
        self.assertEqual(snapshot(source), before)
