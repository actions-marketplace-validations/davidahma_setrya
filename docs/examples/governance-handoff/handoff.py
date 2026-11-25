"""Attach verified results from a fictional workspace drill to a governance ticket."""

import argparse
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from setrya.casework import exchange
from setrya.core.inputs import InvalidReport, read_regular_bytes, require
from setrya.erasure import run_shared
from setrya.examples.workspace import CASE, open_fixture
from setrya.receipt_format import MAX_BUNDLE_FILE_BYTES, RECEIPT


CONTROL = {"framework": "Support governance", "reference": "ERASURE-07"}


def issue(output, key):
    with TemporaryDirectory(prefix="setrya-governance-") as scratch:
        original = Path(scratch) / "original"
        case = replace(CASE, controls=(CONTROL,))
        with open_fixture(shared=True, guarded=True, record_writes=True) as (subject, app, items):
            receipt = run_shared(subject, case=case, application=app, external_items=items,
                                 mode="late-write", output=original, journal=app.journal,
                                 cancel_hold=app.cancel_and_drain)
        require((receipt["technical_verdict"], receipt["review_status"]) == ("PASS", "OPEN_ITEMS"),
                "Expected the synthetic drill to pass with a provider follow-up.")
        exchange.pack(original, output=output, system="synthetic-support", version="1", synthetic=True, key=key)


def attachment(bundle, key):
    manifest = exchange.verify(bundle, key=key)
    digest = manifest["files"][RECEIPT]
    raw = read_regular_bytes(bundle / RECEIPT, "verified receipt", MAX_BUNDLE_FILE_BYTES)
    require(sha256(raw).hexdigest() == digest, "The receipt changed after exchange verification.")
    controls = json.loads(raw).get("controls", [])
    require(CONTROL in controls, "The verified receipt lacks the expected governance control.")
    return {
        "governance_ticket": "GOV-204",
        "control_reference": CONTROL,
        "exchange_attachment": bundle.name,
        "receipt_sha256": digest,
        "technical_verdict": manifest["technical_verdict"],
        "review_status": manifest["review_status"],
        "open_items": manifest["open_items"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    issuer = commands.add_parser("issue", help="run the fictional drill and sign its exchange")
    issuer.add_argument("output", type=Path, help="fresh exchange directory")
    issuer.add_argument("--key", required=True, type=Path, help="issuer's Cosign private key")
    reviewer = commands.add_parser("review", help="verify the exchange and print a ticket attachment record")
    reviewer.add_argument("bundle", type=Path, help="the received exchange directory")
    reviewer.add_argument("--key", required=True, type=Path, help="independently trusted Cosign public key")
    args = parser.parse_args(argv)
    try:
        if args.command == "issue":
            issue(args.output, args.key)
        else:
            print(json.dumps(attachment(args.bundle, args.key), indent=2))
    except (InvalidReport, OSError) as error:
        parser.exit(2, f"Governance handoff failed. {error}\n")


if __name__ == "__main__":
    main()
