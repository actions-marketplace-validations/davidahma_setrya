"""Replay observations of branches and declared point-in-time restore windows."""
from datetime import UTC, datetime, timedelta

from setrya.casework.profiles import fields, stamp
from setrya.core.branch_journal import (
    MAX_BRANCHES,
    branch_head,
    check_graph,
    validate_branch,
)
from setrya.core.inputs import require
from setrya.core.subject import identifier

PROFILE = "branch-lineage"
FORMAT = "setrya.branch-lineage.v1"
KIND = {"sqlite", "git-clones", "git-worktrees", "neon"}
MAX_SCANNERS = 64
MAX_WINDOW_SECONDS = 10 * 366 * 24 * 3600


def _timestamp(value):
    timestamp = stamp(value)
    require(timestamp.astimezone(UTC).isoformat() == value, "Branch evidence needs canonical UTC timestamps.")
    return timestamp


def _topology(edges, root):
    """Propagate the oldest known source snapshot through all reachable generations."""
    reachable = {root: (None, False)}
    pending = dict(edges)
    pending.pop(root, None)
    while pending:
        advanced = False
        for child, edge in list(pending.items()):
            if edge["parent"] not in reachable:
                continue
            oldest, incomplete = reachable[edge["parent"]]
            snapshot = _timestamp(edge["as_of"]) if edge["as_of"] is not None else None
            reachable[child] = (min(t for t in (oldest, snapshot) if t is not None)
                                if oldest is not None or snapshot is not None else None,
                                incomplete or snapshot is None)
            del pending[child]
            advanced = True
        if not advanced:
            break
    return reachable


def _check_status(age, incomplete, observed, erased, origin_confirmed):
    if observed == "gone":
        return "GONE"
    if age is not None and age < erased:
        return "RESIDUAL" if observed == "live" else "UNKNOWN"
    return ("POST_ERASURE" if observed == "live" and origin_confirmed and not incomplete
            and age is not None and age > erased else "UNKNOWN")


def _scan_rows(scanners, root, edges):
    checks, findings, summaries = {}, [], []
    require(isinstance(scanners, list) and len(scanners) <= MAX_SCANNERS, "Invalid branch scanner count.")
    seen = set()
    for scan in scanners:
        fields(scan, "id kind complete remote checks")
        name = identifier(scan["id"], "scanner ID")
        require(name not in seen and scan["kind"] in KIND and type(scan["complete"]) is bool
                and type(scan["remote"]) is bool and isinstance(scan["checks"], list)
                and len(scan["checks"]) <= MAX_BRANCHES, "Invalid branch scanner observation.")
        seen.add(name)
        summaries.append({k: v for k, v in scan.items() if k != "checks"})
        if not scan["complete"]:
            findings.append(f"Branch scanner {name} did not finish its inventory.")
        for check in scan["checks"]:
            fields(check, "child state", ("edge",))
            child = identifier(check["child"], "observed branch")
            state = check["state"]
            require(state in ("live", "gone", "unknown") and child != root and child not in checks,
                    "Repeated or invalid branch observation.")
            require(state != "gone" or scan["complete"], "An incomplete scan cannot establish that a branch is gone.")
            checks[child] = (name, state, scan["kind"] == "neon" and "edge" in check)
            if "edge" in check:
                new = check["edge"]
                validate_branch(new)
                require(new["child"] == child and (scan["kind"] == "neon" or
                        new["as_of"] is None and new["parent"] == root and "turn" not in new),
                        "Branch ancestry differs from scanner provenance.")
                previous = edges.get(child)
                if previous is not None:
                    # Provider evidence must not contradict a journalled edge.
                    # An older confirmed timestamp can still demonstrate a risk.
                    if (previous["parent"] != new["parent"] or new["as_of"] is not None
                            and previous["as_of"] != new["as_of"]):
                        findings.append(f"Branch {child} has conflicting ancestry.")
                        checks[child] = (name, "unknown", False)
                else:
                    edges[child] = new
            require(child in edges, "Branch observation has no ancestry event.")
    return checks, findings, summaries


def _windows(rows, erased, observed, root):
    windows, items = [], []
    require(isinstance(rows, list) and len(rows) <= MAX_SCANNERS, "Invalid restore window list.")
    seen = set()
    for spec in rows:
        fields(spec, "id store owner seconds", ("postgres_archiving",))
        archiving = spec.get("postgres_archiving")
        if "postgres_archiving" in spec:
            require(archiving in ("unavailable", "off", "on", "always"), "Invalid PostgreSQL archive mode.")
        name = identifier(spec["id"], "restore window ID")
        store = identifier(spec["store"], "restore window store")
        identifier(spec["owner"], "restore window owner")
        seconds = spec["seconds"]
        require(name not in seen and store == root and type(seconds) is int
                and 0 <= seconds <= MAX_WINDOW_SECONDS, "Invalid restore window configuration.")
        seen.add(name)
        expires = erased + timedelta(seconds=seconds)
        elapsed = seconds == 0 or observed >= expires
        windows.append({**spec, "expires_at": expires.isoformat(), "elapsed": elapsed})
        if archiving == "unavailable":
            items.append({"store": store, "kind": "configuration", "owner": spec["owner"],
                          "evidence": "postgres-archive-setting-unavailable"})
        if not elapsed:
            items.append({"store": store, "kind": "restore-window", "owner": spec["owner"],
                          "expires_at": expires.isoformat(), "follow_up": expires.date().isoformat(),
                          "evidence": "declared-postgres-restore-window"})
    return windows, items


def derive_branches(evidence):
    fields(evidence, "format store erased_at observed_at journal journal_head scanners windows")
    require(evidence["format"] == FORMAT, "Unsupported branch lineage evidence.")
    root = identifier(evidence["store"], "original store")
    erased, observed = (_timestamp(evidence[name]) for name in ("erased_at", "observed_at"))
    require(erased <= observed <= datetime.now(UTC), "Branch observations must fall between erasure and the verifier clock.")
    journal = evidence["journal"]
    require(isinstance(journal, list) and len(journal) <= MAX_BRANCHES, "Invalid store branch journal.")
    edges = {}
    for edge in journal:
        validate_branch(edge)
        require(edge["child"] not in edges and edge["as_of"] is not None, "Invalid store branch journal edge.")
        edges[edge["child"]] = edge
    require(evidence["journal_head"] == branch_head(journal), "Branch journal checkpoint differs from its ordered events.")
    checks, gaps, scans = _scan_rows(evidence["scanners"], root, edges)
    require(len(edges) <= MAX_BRANCHES, "Branch graph exceeds the receipt budget.")
    require(all(e["as_of"] is None or _timestamp(e["as_of"]) <= observed for e in edges.values()),
            "A branch source snapshot cannot be later than the scan.")
    check_graph(edges)
    reachable = _topology(edges, root)
    failures, branches = [], []
    for child in sorted((set(reachable) - {root}) | (set(checks) - set(reachable))):
        scanner, observation, origin_confirmed = checks.get(child, (None, "unknown", False))
        if child not in reachable:
            status = "UNKNOWN"
            gaps.append(f"Branch {child} is in the scanned inventory but does not have a path to {root}.")
        else:
            age, incomplete = reachable[child]
            status = _check_status(age, incomplete, observation, erased, origin_confirmed)
            if status == "UNKNOWN":
                gaps.append(f"Branch {child} has no decisive copy time or live-state observation.")
            elif status == "RESIDUAL":
                failures.append(f"Live branch {child} descends from pre-erasure state.")
        branches.append({**edges[child], "status": status, "observer": scanner})
    if not scans:
        gaps.append("No branch inventories were scanned.")
    windows, items = _windows(evidence["windows"], erased, observed, root)
    items.extend({"store": scan["id"], "kind": "configuration", "owner": root,
                  "evidence": "remote-copies-uninspected"} for scan in scans if scan["remote"])
    verdict = "FAIL" if failures else "NOT TESTED" if gaps else "PASS"
    return {"scope": "person", "case_id": root, "erased_at": evidence["erased_at"],
            "observed_at": evidence["observed_at"], "technical_verdict": verdict,
            "review_status": "RESIDUAL_FOUND" if failures else "OPEN_ITEMS" if gaps or items else "READY_FOR_REVIEW",
            "branches": branches, "scanners": scans, "restore_windows": windows, "journal_head": evidence["journal_head"],
            "failures": failures, "gaps": gaps, "open_items": items}


def observations(receipt):
    lines = [f"Checked branch and restore scope for {receipt['case_id']} after {receipt['erased_at']}."]
    for item in receipt["branches"]:
        turn = item.get("turn", {}).get("turn")
        lines.append(f"{item['status']}  {item['child']} from {item['parent']} as of {item['as_of'] or 'unknown'}"
                     + (f"  turn {turn}" if turn else ""))
    lines.extend(f"Declared restore window for {item['store']} expires {item['expires_at']}."
                 for item in receipt["restore_windows"] if item["seconds"])
    lines.extend(f"PostgreSQL archiving setting for {item['store']}: {item['postgres_archiving']}."
                 for item in receipt["restore_windows"] if "postgres_archiving" in item)
    return lines


def branch_summary(receipt):
    lines = [f"Technical verdict {receipt['technical_verdict']} · Review status {receipt['review_status']}",
             *observations(receipt), *receipt["failures"], *receipt["gaps"]]
    if any(item["evidence"] == "remote-copies-uninspected" for item in receipt["open_items"]):
        lines.append("Remote Git copies were not inspected.")
    return "\n".join(lines)
