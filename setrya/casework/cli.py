"""Customer summaries and read-only checks against completed requests."""
import argparse
import json
from pathlib import Path

from .customer import customer_receipt
from .observe import observe
from setrya.offboarding.inputs import publish_new


def command(argv):
    family, *tail = argv
    parser = argparse.ArgumentParser(prog=f"setrya {family}")
    commands = parser.add_subparsers(dest="action", required=True)
    if family == "receipt":
        render = commands.add_parser("render", help="render a replayed receipt in plain language")
        render.add_argument("bundle", type=Path)
        render.add_argument("--audience", choices=("customer",), required=True)
        render.add_argument("--case-id", help="opaque reference for the customer copy")
        args = parser.parse_args(tail)
        print(customer_receipt(args.bundle, case_id=args.case_id))
        return 0

    one = commands.add_parser("request", help="read known keys for one completed request")
    one.add_argument("--id", required=True)
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
    report, code = observe(frame=args.population, config=args.inventory, journal=args.journal,
                           request=getattr(args, "id", None), week=getattr(args, "week", None),
                           count=getattr(args, "sample", None), seed=getattr(args, "seed", None), output=args.output)
    if args.output is None:
        print(json.dumps(report, indent=2))
    else:
        publish_new(report, args.output, max_bytes=16 * 1024 * 1024)
        print(f"Saved {len(report['requests'])} request observation(s).")
    return code
