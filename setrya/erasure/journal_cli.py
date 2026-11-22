"""Verify copy journal integrity or import an authenticated trace export."""
import argparse
import json
from pathlib import Path

from setrya.core.branch_journal import verify_branches
from setrya.core.journal import _FIELDS
from setrya.core.journal_chain import reader, verify_snapshot
from setrya.offboarding.inputs import require
from .journal_merge import verify_seals


def command(argv):
    parser = argparse.ArgumentParser(prog="setrya journal")
    commands = parser.add_subparsers(dest="action", required=True)
    verify = commands.add_parser("verify", help="check a journal against its saved chain head")
    verify.add_argument("path", type=Path)
    verify.add_argument("--expected-head", help="independently saved exact head for a local or worker journal")
    verify.add_argument("--expected-branch-head", help="independently saved store-branch chain head")
    verify.add_argument("--json", action="store_true")
    ingest = commands.add_parser("import", help="add observed copy events from an OTLP/JSON export")
    ingest.add_argument("--otlp", required=True, type=Path, help="trusted OTLP trace export (JSON)")
    ingest.add_argument("--journal", required=True, type=Path, help="destination collector SQLite journal")
    ingest.add_argument("--run-id", required=True)
    ingest.add_argument("--producer", required=True)
    args = parser.parse_args(argv)
    if args.action == "import":
        from .journal_merge import CollectedJournal
        from .otlp import read_otlp

        events = read_otlp(args.otlp)
        require(args.otlp.resolve() != args.journal.resolve() and not args.journal.is_symlink(),
                "Choose a separate local collector journal.")
        CollectedJournal(args.journal, run_id=args.run_id).ingest_traces(events, producer=args.producer)
        print(f"Processed {len(events)} copy event(s). Trace events do not seal producer coverage.")
        return 0
    with reader(args.path) as db:
        tables = {name for name, in db.execute("SELECT name FROM main.sqlite_schema WHERE type='table'")}
        result = {}
        if "copy_events" in tables:
            result.update(verify_snapshot(db, _FIELDS))
        if {"store_branches", "store_branch_chain"} & tables:
            _, result["branch_chain"] = verify_branches(db)
        if {"collected_events", "collected_seals"} & tables:
            require({"journal_binding", "collected_events", "collected_seals"} <= tables, "Incomplete collector journal.")
            bindings = db.execute("SELECT role,run_id,producer FROM main.journal_binding LIMIT 2").fetchall()
            require(len(bindings) == 1 and bindings[0][0] == "collector" and bindings[0][2] is None,
                    "Invalid collector journal binding.")
            refs = [ref for ref, in db.execute("SELECT ref FROM main.collected_seals UNION "
                                              "SELECT ref FROM main.collected_events LIMIT 257")]
            require(len(refs) <= 256, "Collector exceeds the subject verification budget.")
            result["subjects"] = []
            for ref in refs:
                producers = verify_seals(db, bindings[0][1], ref)
                unsealed = [name for name, in db.execute("SELECT DISTINCT producer FROM main.collected_events "
                                                       "WHERE ref=? ORDER BY producer LIMIT 257", (ref,))
                            if name not in producers]
                require(len(unsealed) <= 256, "Collector exceeds the producer budget.")
                result["subjects"].append({"ref": ref, "producer_chains": producers, "unsealed": unsealed})
        require(result, "Expected a local, worker or collector copy journal.")
    if args.expected_head:
        require(result.get("head") is not None and result["head"] == args.expected_head,
                "Journal does not match the independently saved head.")
    if args.expected_branch_head:
        require(result.get("branch_chain", {}).get("head") == args.expected_branch_head,
                "Branch journal does not match the independently saved head.")
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        if "status" in result:
            print(f"{result['status']}  {result['head'] or 'no chain head'}")
        if "branch_chain" in result:
            print(f"verified  branch-chain  {result['branch_chain']['head']}")
        for subject in result.get("subjects", ()):
            for producer, chain in subject["producer_chains"].items():
                status = chain["status"] if chain else "unchained"
                head = chain["head"] if chain else None
                print(f"{status}  {producer}  {subject['ref']}  {head or 'no chain head'}")
            for producer in subject["unsealed"]:
                print(f"unsealed  {producer}  {subject['ref']}")
        if result.get("subjects") == []:
            print("No collector packets.")
    return 0
