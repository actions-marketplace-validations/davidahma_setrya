"""Replay and disclose the scope of native filesystem and Git scans."""

import json

from .inputs import keys_match, require
from .journal import identifier

METADATA_BUDGET = 128 * 1024
SKIPPED_EXTENSIONS = frozenset((".json", ".txt", ".yaml", ".yml", ".sqlite", ".sqlite3", ".db"))


def _relative(value, *, length, allow_root=False):
    return (isinstance(value, str) and 0 < len(value) <= length and value.isprintable()
            and chr(92) not in value and (allow_root and value == "." or
                                          all(part not in ("", ".", "..") for part in value.split("/"))))


def validate(row):
    """Validate bounded public metadata, excluding host paths and remote URLs."""
    require(isinstance(row, dict) and row.get("kind") in ("filesystem", "git")
            and _relative(row.get("scope"), length=1024, allow_root=True), "Invalid canary scan scope.")
    fields = {"kind", "scope"}
    if row["kind"] == "git":
        require(keys_match(row, fields | {"objects", "remote_configured", "remote_owner"})
                and row["objects"] == "all-local-blobs"
                and type(row["remote_configured"]) is bool, "Invalid Git scan coverage.")
        identifier(row["remote_owner"], "remote review owner")
        return
    require(keys_match(row, fields | {"patterns", "skipped"}), "Invalid filesystem scan coverage.")
    patterns, skipped = row["patterns"], row["skipped"]
    require(isinstance(patterns, list) and 1 <= len(patterns) <= 16
            and all(_relative(pattern, length=256) for pattern in patterns), "Invalid filesystem scan patterns.")
    require(isinstance(skipped, dict) and skipped.keys() <= SKIPPED_EXTENSIONS
            and all(type(count) is int and 0 < count <= 1_000_000 for count in skipped.values()),
            "Invalid excluded file counts.")


def check_stage(details, scans):
    require(isinstance(details, dict) and details and details.keys() <= scans.keys(), "Invalid scanner coverage slots.")
    for store, row in details.items():
        require(scans[store] is not None, "Scanner coverage lacks a completed observation.")
        validate(row)
    require(len(json.dumps(details, ensure_ascii=False).encode()) <= METADATA_BUDGET, "Scanner coverage exceeds its budget.")


def _policy(details):
    return {field: value for field, value in details.items() if field not in ("skipped", "remote_configured")}


def same_scope(first, last, store):
    """Compare two completed scans with recorded native scope."""
    earlier = first.get("scan_details", {}).get(store)
    later = last.get("scan_details", {}).get(store)
    return earlier is not None and later is not None and _policy(earlier) == _policy(later)


def summarize(evidence):
    stages = [evidence[phase] for phase in ("baseline", "immediate", "final") if evidence[phase] is not None]
    coverage, remotes, gaps = {}, {}, set()
    baseline = stages[0].get("scan_details", {})
    for stage in stages:
        for store, row in stage.get("scan_details", {}).items():
            coverage[store] = row
            if row.get("remote_configured"):
                remotes[store] = {"store": store, "key": "remote-copies", "owner": row["remote_owner"],
                                  "kind": "configuration", "evidence": "remote-copies-uninspected",
                                  "follow_up": None, "subject_ref": evidence["subject"]["ref"]}
    for store in coverage:
        for stage in stages:
            current = stage.get("scan_details", {}).get(store)
            if store not in baseline or current is None or _policy(current) != _policy(baseline[store]):
                gaps.add(f"Canary scan scope changed or was missing for {store}.")
                break
    return coverage, list(remotes.values()), gaps
