"""Customer summaries and read-only checks against completed requests."""
import argparse
import json
from pathlib import Path

from .receipt_summary import receipt_summary
from .observe import observe
from setrya.offboarding.inputs import publish_new


def command(argv):
    family, *tail = argv
    parser = argparse.ArgumentParser(prog=f"setrya {family}")
    commands = parser.add_subparsers(dest="action", required=True)
    if family == "receipt":
        render = commands.add_parser("summary", aliases=["summarize", "render"], help="summarize a replayed receipt")
        render.add_argument("bundle", type=Path)
        render.add_argument("--audience", choices=("engineer", "reviewer", "customer"), default="reviewer")
        render.add_argument("--format", choices=("text", "markdown"), default="text", dest="output_format")
        render.add_argument("--case-id", help="opaque reference for the customer copy")
        args = parser.parse_args(tail)
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
        from setrya.offboarding.inputs import require
        from setrya.receipts import report
        from setrya.control_references import read_controls
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
