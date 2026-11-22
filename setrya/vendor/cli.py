"""Run and sign a disposable vendor conformance fixture."""

import argparse
from pathlib import Path
from shlex import join

from setrya.casework import profiles
from setrya.core import signing
from setrya.drill import InputError
from setrya.receipt_format import RECEIPT
from setrya.receipts import exit_code, replay

from .fixtures import run_fixture
from .report import TARGETS, summary


def command(argv):
    parser = argparse.ArgumentParser(prog="setrya conformance", description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="operation", required=True)
    run = commands.add_parser("run", help="check a disposable backend and sign its evidence", allow_abbrev=False)
    run.add_argument("--target", choices=TARGETS, required=True)
    run.add_argument("--output", type=Path, default=Path("setrya-conformance"))
    signer = run.add_mutually_exclusive_group(required=True)
    signer.add_argument("--key", type=Path, help="local Cosign private key (Cosign 3)")
    signer.add_argument("--keyless", action="store_true", help="sign online with Cosign and an OIDC identity")
    args = parser.parse_args(argv)
    result = run_and_sign(args.target, args.output, key=args.key)
    if result is None:
        return 2
    print(summary(result))
    print(join(["setrya", "replay", str(args.output)]))
    return exit_code(result)


def run_and_sign(target, output, *, key):
    if key is not None and not key.is_file():
        raise InputError("Choose an existing local Cosign signing key.")
    with profiles.new_bundle(output) as folder:
        result = profiles.issue("vendor-conformance", run_fixture(target), folder)
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
