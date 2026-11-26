"""Customer summaries and read-only checks against completed requests."""
import argparse
import json
from pathlib import Path

from setrya.offboarding.inputs import publish_new

from .observe import observe


def command(argv):
    family, *tail = argv
    parser = argparse.ArgumentParser(prog=f"setrya {family}")
    commands = parser.add_subparsers(dest="action", required=True)
    if family == "receipt":
        from setrya.erasure.render import receipt_summary

        render = commands.add_parser("summary", aliases=["summarize", "render"], help="summarize a replayed receipt")
        render.add_argument("bundle", type=Path)
        render.add_argument("--audience", choices=("engineer", "reviewer", "customer"), default="reviewer")
        render.add_argument("--format", choices=("text", "md", "markdown"), default="text", dest="output_format")
        render.add_argument("--case-id", help="opaque reference for the customer copy")
        pack = commands.add_parser("pack", help="sign an original v3 person or vendor receipt in a draft v1 exchange")
        pack.add_argument("bundle", type=Path)
        pack.add_argument("--output", type=Path, required=True, help="new exchange directory")
        pack.add_argument("--system", required=True, help="system label supplied by the issuer")
        pack.add_argument("--system-version", required=True, help="version label supplied by the issuer")
        pack.add_argument("--synthetic", action="store_true", help="confirm that a person drill used synthetic data")
        pack.add_argument("--key", type=Path, help="local Cosign private key (default: keyless Sigstore signing)")

        verify = commands.add_parser("verify-exchange", help="authenticate and replay a draft v1 exchange offline")
        verify.add_argument("bundle", type=Path)
        verify.add_argument("--key", type=Path, help="independently trusted Cosign public key")
        verify.add_argument("--identity", help="exact trusted Sigstore certificate identity")
        verify.add_argument("--issuer", help="exact trusted Sigstore OIDC issuer")
        verify.add_argument("--trusted-root", type=Path, help="independently provisioned Sigstore root JSON")
        verify.add_argument("--expect-ticket", help="expected completed ticket ID from the originating case")
        verify.add_argument("--expect-frame", help="expected SHA-256 of the completed request export")
        verify.add_argument("--expect-provenance", type=Path, help="independent provenance JSON record")
        verify.add_argument("--expect-app-commit", help="expected clean local application checkout Git commit")
        verify.add_argument("--expect-deployment", type=Path, help="independent HTTP deployment identity JSON")
        verify.add_argument("--case-review", action="store_true", help="treat outstanding obligations as exit 3")

        args = parser.parse_args(tail)
        if args.action == "pack":
            from . import exchange
            exchange.pack(args.bundle, output=args.output, system=args.system, version=args.system_version,
                          key=args.key, synthetic=args.synthetic)
            print(f"Signed draft receipt exchange in {args.output}")
            return 0
        if args.action == "verify-exchange":
            from setrya.core.deployment import read_pin as read_deployment
            from setrya.core.provenance import read_pin
            from setrya.receipts import exit_code

            from . import exchange
            result = exchange.verify(args.bundle, key=args.key, identity=args.identity, issuer=args.issuer,
                                     trusted_root=args.trusted_root, expect_ticket=args.expect_ticket,
                                     expect_frame=args.expect_frame,
                                     expected_provenance=read_pin(args.expect_provenance),
                                     expected_app_commit=args.expect_app_commit,
                                     expected_deployment=read_deployment(args.expect_deployment))
            print(exchange.summary(result))
            return exit_code(result, case_review=args.case_review)
        print(receipt_summary(args.bundle, audience=args.audience, output_format=args.output_format, case_id=args.case_id))
        return 0

    one = commands.add_parser("request", help="read known keys for one completed request")
    one.add_argument("--id", required=True)
    one.add_argument("--receipt", type=Path, help="issue a replayable observed-deletion receipt in a fresh directory")
    one.add_argument("--controls", type=Path, help="JSON control-reference list to bind to --receipt")
    week = commands.add_parser("week", help="sample a completed UTC week")
    week.add_argument("--week", required=True, metavar="YYYY-MM-DD", help="Monday starting the week")
    week.add_argument("--sample", required=True, type=int)
    week.add_argument("--seed", help="reproduce a prior draw using its 64-character hex seed")
    for sub in (one, week):
        sub.add_argument("--population", type=Path, required=True, help="completed-request frame JSON")
        sub.add_argument("--inventory", type=Path, required=True, help="read-only store mapping TOML")
        sub.add_argument("--journal", type=Path, required=True, help="existing Setrya copy journal")
        sub.add_argument("--output", type=Path, help="save a new local JSON report (default: stdout)")
    args = parser.parse_args(tail)
    if getattr(args, "receipt", None) is not None:
        from setrya.control_references import read_controls
        from setrya.offboarding.inputs import require
        from setrya.receipts import report

        from .observed import observe_deletion
        require(args.output is None, "Choose --receipt or --output.")
        receipt = observe_deletion(frame=args.population, request=args.id, inventory_file=args.inventory,
                                   journal=args.journal, output=args.receipt, controls=read_controls(args.controls))
        return report(receipt)
    if getattr(args, "controls", None) is not None:
        parser.error("--controls requires --receipt")
    report, code = observe(frame=args.population, config=args.inventory, journal=args.journal,
                           request=getattr(args, "id", None), week=getattr(args, "week", None),
                           count=getattr(args, "sample", None), seed=getattr(args, "seed", None), output=args.output)
    if args.output is None:
        print(json.dumps(report, indent=2))
    else:
        publish_new(report, args.output, max_bytes=16 * 1024 * 1024)
        print(f"Saved {len(report['requests'])} request observation(s).")
    return code
