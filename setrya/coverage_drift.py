"""Compare recorded storage boundaries to an application's owner and adapter inventory."""
import argparse
import json
import sqlite3
from pathlib import Path

from setrya.casework.stores import sqlite_reader
from setrya.erasure.inventory import load_coverage
from setrya.erasure.journal import identifier, validate_details
from setrya.offboarding.inputs import require, unique_fields


def observed(journals):
    found = set()
    total = size = 0
    for path in journals:
        with sqlite_reader(path) as db:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
            tables = dict(db.execute("SELECT name,type FROM pragma_table_list WHERE schema='main' "
                                     "AND name IN ('copy_events','collected_events','lineage_versions')"))
            require(tables and all(t == "table" for t in tables.values()), "Expected a concrete journal table.")
            readers = {
                "copy_events": "SELECT store, details FROM main.copy_events",
                "collected_events": "SELECT NULL, record FROM main.collected_events",
                "lineage_versions": "SELECT store, namespace FROM main.lineage_versions",
            }
            for table in tables:
                for store, raw in db.execute(readers[table]):
                    total += 1
                    require(isinstance(raw, str), "Invalid journal row.")
                    size += len(raw.encode())
                    require(total <= 100_000 and size <= 32 * 1024 * 1024, "Drift input exceeds the observation budget.")
                    if table == "lineage_versions":
                        details = {"boundary_kind": "namespace", "boundary": raw}
                    else:
                        details = json.loads(raw, object_pairs_hook=unique_fields)
                        if table == "collected_events":
                            require(isinstance(details, dict) and {"store", "details"} <= details.keys(),
                                    "Invalid collected event.")
                            store, details = details["store"], details["details"]
                    identifier(store, "journal store")
                    require(isinstance(details, dict), "Invalid journal event details.")
                    validate_details(details)
                    found.add((store, "store", store))
                    if "boundary" in details:
                        found.add((store, details["boundary_kind"], details["boundary"]))
                    elif details.get("operation") == "langfuse.observation":
                        found.add((store, "trace", store))
    return sorted(found)


def compare(journals, inventory):
    systems, bindings = load_coverage(inventory)
    rows = []
    for store, kind, name in observed(journals):
        declared = systems.get(store, {})
        mapped = bindings.get((store, kind, name), ())
        if kind == "store" and declared.get("adapter", "none") != "none":
            mapped = (declared["adapter"], *mapped)
        rows.append({"store": store, "kind": kind, "name": name, "owner": declared.get("owner"),
                     "mapped": bool(mapped), "bindings": sorted(set(mapped))})
    clean = bool(rows) and all(r["mapped"] for r in rows)
    return {"status": "MAPPED" if clean else "NOT TESTED", "boundaries": rows}, 0 if clean else 3


def main(argv=None):
    parser = argparse.ArgumentParser(prog="setrya coverage-drift", description=__doc__)
    parser.add_argument("--journal", required=True, action="append", type=Path, help="existing SQLite copy, lineage or collected journal (repeatable)")
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    require(len(args.journal) <= 32, "Supply at most 32 journals.")
    report, code = compare(args.journal, args.inventory)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(report["status"], " Observed storage coverage")
        if not report["boundaries"]:
            print("No recorded boundaries. Exercise the fixture before checking coverage.")
        for row in report["boundaries"]:
            mapping = ", ".join(row["bindings"]) or "no adapter or scanner mapped"
            print(f"{row['store']}  {row['kind']} {row['name']}  {mapping}  owner {row['owner'] or 'unassigned'}")
    return code
