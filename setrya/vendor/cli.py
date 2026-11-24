"""Run and sign a disposable vendor conformance fixture."""

import argparse
from pathlib import Path
from shlex import join

from setrya.casework import profiles
from setrya.core import signing
from setrya.drill import InputError
from setrya.receipt_format import RECEIPT
from setrya.receipts import exit_code, replay

from . import hosted
from .fixtures import run_fixture
from .report import TARGETS, summary


def command(argv):
    parser = argparse.ArgumentParser(prog="setrya conformance", description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="operation", required=True)
    run = commands.add_parser("run", help="check a disposable backend and sign its evidence", allow_abbrev=False)
    run.add_argument("--target", choices=TARGETS, required=True)
    run.add_argument("--output", type=Path, default=Path("setrya-conformance"))
    baseline = commands.add_parser("baseline", help="record a read-only baseline in an authorized test project")
    baseline.add_argument("--target", choices=tuple(hosted.SURFACES), required=True)
    baseline.add_argument("--synthetic", action="store_true", required=True, help="use only synthetic target and control records")
    baseline.add_argument("--output", type=Path, required=True)
    readback = commands.add_parser("readback", help="read the same API after an operator-reported deletion and sign the result")
    readback.add_argument("baseline", type=Path)
    readback.add_argument("--after-delete", action="store_true", required=True, help="confirm deletion ran outside Setrya")
    readback.add_argument("--output", type=Path, required=True)
    for check in (baseline, readback):
        check.add_argument("--scope", help="parent identifier, or region[:session] for Bedrock")
        check.add_argument("--record", required=True, help="synthetic target identifier")
        check.add_argument("--retain", required=True, help="separate retained control identifier")
    for signed in (run, readback):
        signer = signed.add_mutually_exclusive_group(required=True)
        signer.add_argument("--key", type=Path, help="local Cosign private key (Cosign 3)")
        signer.add_argument("--keyless", action="store_true", help="sign online with Cosign and an OIDC identity")

    args = parser.parse_args(argv)
    if args.operation == "baseline":
        observation = hosted.capture(args.target, args.scope, args.record, args.retain, args.output)
        if observation == {"target": True, "retained": True}:
            print("Both synthetic baseline records were visible.")
            return 0
        print("The API did not establish both positive controls.")
        return 3
    if args.operation == "readback":
        result = _sign_evidence(lambda: hosted.follow(args.baseline, args.scope, args.record, args.retain),
                                args.output, key=args.key)
    else:
        result = run_and_sign(args.target, args.output, key=args.key)
    if result is None:
        return 2
    print(summary(result))
    print(join(["setrya", "replay", str(args.output)]))
    return exit_code(result)


def run_and_sign(target, output, *, key):
    return _sign_evidence(lambda: run_fixture(target), output, key=key)


def _sign_evidence(observe, output, *, key):
    if key is not None and not key.is_file():
        raise InputError("Choose an existing local Cosign signing key.")
    with profiles.new_bundle(output) as folder:
        result = profiles.issue("vendor-conformance", observe(), folder)
        manifest = folder / RECEIPT
        args = argparse.Namespace(receipt=manifest, bundle=folder / ("conformance.sig" if key else "sigstore.json"),
                                  key=key, offboarding_action="sign-receipt")
        code = signing.run(args, validate=lambda raw: profiles.replay_bytes(folder, raw))
        if code == 0:
            if replay(folder) != result:
                raise InputError("Replay differs from the observed fixture.")
        else:
            # Keep the observations available for diagnosis. An unsigned bundle
            # and its replay can never produce a successful conformance command.
            print("Unsigned evidence was saved for diagnosis.")
            return None
    return result
