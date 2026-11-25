"""Delete one synthetic customer's note and check the answer endpoint."""
import argparse
from pathlib import Path

from setrya.erasure.modes import CLI_MODES, evidence_mode
from setrya.erasure.v3 import run_shared
from setrya.examples.workspace import SIMPLE as CASE
from setrya.examples.workspace import open_fixture
from setrya.receipts import exit_code, report, summary

# Replace CASE and open_fixture with imports from your disposable application.
# CASE names the caller, questions, store keys and actions. open_fixture seeds
# the two facts and supplies (subject, application, external_items).
# Expose the worker's CopyJournal as application.journal to attribute a write-back.


def run(output, mode):
    with open_fixture() as (subject, application, items):
        return run_shared(subject, case=CASE, application=application, external_items=items,
                          mode=mode, output=output, journal=getattr(application, "journal", None),
                          cancel_hold=getattr(application, "cancel_and_drain", None))


def test_subject_erasure(tmp_path):
    output = tmp_path / "receipt"
    receipt = run(output, "deletion")
    assert exit_code(receipt) == 0, summary(receipt, bundle=output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mode", type=evidence_mode, choices=CLI_MODES, default="deletion")
    args = parser.parse_args()
    try:
        receipt = run(args.output, args.mode)
    except NotImplementedError:
        parser.exit(3, "NOT TESTED  Connect the fixture to your disposable application.\n")
    raise SystemExit(report(receipt, bundle=args.output))
