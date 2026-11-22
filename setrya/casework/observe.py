"""Read known keys for completed requests without invoking application or erasure hooks."""
from contextlib import ExitStack
from datetime import UTC, datetime
from itertools import groupby
from pathlib import Path

from .sampling import draw_week, load_population, statistics
from .stores import inventory, journal_rows, key_reader, sqlite_reader
from setrya.offboarding.inputs import require


def check_request(row, journal, stores):
    findings, gaps = [], []
    try:
        with sqlite_reader(journal) as db:
            copies = journal_rows(db, row["subject_ref"])
            snapshot_at = datetime.now(UTC).isoformat()
    except Exception:
        copies = None
        snapshot_at = None
    if copies is None:
        gaps.append("journal-unavailable")
    else:
        if len(copies) > 512:
            gaps.append("key-limit")
        observed = set()
        for store, group in groupby(copies[:512], key=lambda item: item[0]):
            keys = list(group)
            observed.add(store)
            spec = stores.get(store)
            # Store names in receipts come from the trusted frame or inventory.
            known = store in row["stores"] or spec is not None
            label = store if known else "unmapped"
            if store not in row["stores"] or spec is None:
                gaps.append("unmapped-journal-store")
            with ExitStack() as stack:
                lookup = None
                if spec and store in row["stores"]:
                    try:
                        lookup = stack.enter_context(key_reader(spec))
                    except Exception:
                        gaps.append("store-or-control-unavailable")
                for _, key, event, version, sent, shared in keys:
                    state = "UNKNOWN"
                    if sent or shared:
                        gaps.append("external-or-shared-key")
                    elif lookup and key != spec["control_key"]:
                        try:
                            state = "PRESENT" if lookup(key) else "ABSENT"
                        except Exception:
                            gaps.append("key-read-unavailable")
                    elif lookup:
                        gaps.append("control-is-subject-key")
                    location = {"store": label, "state": state}
                    if event is not None:
                        location["journal_event"] = event
                    if version is not None:
                        location["lineage_version"] = version
                    findings.append(location)
        if set(row["stores"]) - observed:
            gaps.append("expected-store-missing-from-journal")
    states = {f["state"] for f in findings}
    result = "PRESENT" if "PRESENT" in states else "UNKNOWN" if gaps or states != {"ABSENT"} else "ABSENT"
    return {"id": row["id"], "completed_at": row["completed_at"], "checked_at": datetime.now(UTC).isoformat(),
            "journal_read_at": snapshot_at, "status": result, "checks": findings, "gaps": sorted(set(gaps))}


def observe(*, frame, config, journal, request=None, week=None, count=None, seed=None, output=None):
    rows, digest = load_population(frame)
    stores = inventory(config)
    if output is not None:
        destination = Path(output).resolve()
        inputs = [Path(frame), Path(config), Path(journal), *(s["path"] for s in stores.values() if s["kind"] == "sqlite")]
        for source in inputs:
            path = source.resolve()
            require(destination != path and path not in destination.parents, "Write the report outside all input files.")
    draw = None
    if request is not None:
        require(request in rows, "Request was not in the supplied frame.")
        selected = [rows[request]]
    else:
        selected, draw = draw_week(rows, week=week, count=count, seed=seed)
    results = [check_request(row, journal, stores) for row in selected]
    report = {"format": "setrya.key-observation.v1", "population_sha256": digest, "requests": results}
    if draw is not None:
        report["sampling"] = {**draw, **statistics(draw["eligible"], results)}
    statuses = {r["status"] for r in results}
    return report, 1 if "PRESENT" in statuses else 3 if "UNKNOWN" in statuses else 0
