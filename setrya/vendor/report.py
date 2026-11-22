"""Replayable rules for the first vendor conformance profile."""

import re

from setrya.casework.profiles import fields, require, stamp

TARGETS = {
    "pgvector": ("store", "index"),
    "langgraph-store": ("store", "index"),
    "mem0": ("store", "index", "history"),
}
PHASES = ("baseline", "after_delete", "after_retry")
UNTESTED = {
    "derived-summaries": "The fixture did not rebuild and reread a shared summary.",
    "cache": "The fixture did not exercise an answer cache and late fill.",
    "branches": "The fixture did not inspect detached live copies or an isolated restore.",
    "backups": "The fixture did not establish the backup inventory and retention evidence.",
}
SETUP = {
    "pgvector": ("psycopg", "postgresql", "vector"),
    "langgraph-store": ("langgraph", "langgraph-checkpoint"),
    "mem0": ("mem0ai", "qdrant-client"),
}
ERRORS = {
    None: None,
    "missing-dsn": "Set SETRYA_PGVECTOR_DSN for a disposable local database with pgvector installed.",
    "missing-extra": "Install the extra for the selected target.",
    "fixture-error": "The fixture could not finish the target operations.",
}


def derive(evidence):
    fields(evidence, "target observed_at versions observations error")
    observed_at = evidence["observed_at"]
    stamp(observed_at)
    target = evidence["target"]
    require(isinstance(target, str) and target in TARGETS, "Unsupported conformance target.")
    error = evidence["error"]
    require(error is None or isinstance(error, str) and error in ERRORS, "Invalid conformance error.")
    require(error != "missing-dsn" or target == "pgvector", "The target does not use PostgreSQL.")
    versions = evidence["versions"]
    require(isinstance(versions, dict) and set(versions) <= set(SETUP[target]), "Invalid target versions.")
    for version in versions.values():
        require(isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9.+_-]{1,80}", version),
                "Invalid target version.")
    observations = evidence["observations"]
    require(isinstance(observations, dict) and set(observations) <= set(PHASES), "Invalid observation stages.")
    require(set(observations) == set(PHASES[: len(observations)]), "Conformance observation stages are out of order.")
    if error is None:
        require(set(versions) == set(SETUP[target]) and set(observations) == set(PHASES),
                "A completed conformance run needs versions and all observations.")
    if error in ("missing-extra", "missing-dsn"):
        require(not observations, "An unavailable target cannot report observations.")
    for stage in observations.values():
        require(isinstance(stage, dict) and set(stage) == set(TARGETS[target]), "Missing or unexpected surface.")
        for row in stage.values():
            fields(row, "target retained")
            require(all(type(value) is bool or value is None for value in row.values()), "Invalid probe observation.")

    checks = []
    residual_found = False
    for surface in TARGETS[target]:
        readings = [observations[phase][surface] for phase in PHASES if phase in observations]
        baseline = bool(readings and all(value is True for value in readings[0].values()))
        later = readings[1:]
        residual = any(reading["target"] is True for reading in later)
        control_lost = baseline and any(reading["retained"] is False for reading in later)
        residual_found |= residual
        if residual and control_lost:
            status, reason = "FAIL", "The target remained readable and the retained control disappeared after deletion."
        elif residual:
            status, reason = "FAIL", "The target record was readable after deletion."
        elif control_lost:
            status, reason = "FAIL", "The retained control disappeared after deletion."
        elif not baseline:
            status, reason = "NOT TESTED", "The fixture did not establish both positive controls."
        elif len(readings) != len(PHASES) or any(None in reading.values() for reading in later):
            status, reason = "NOT TESTED", "A required follow-up observation was unavailable."
        else:
            status, reason = "PASS", "The target disappeared and the retained control survived both follow-ups."
        checks.append({"surface": surface, "status": status, "reason": reason})
    checks.extend({"surface": name, "status": "NOT TESTED", "reason": reason} for name, reason in UNTESTED.items())

    failures = [f"{row['surface']}: {row['reason']}" for row in checks if row["status"] == "FAIL"]
    gaps = [f"{row['surface']}: {row['reason']}" for row in checks if row["status"] == "NOT TESTED"]
    if error is not None:
        gaps.append(ERRORS[error])
    open_items = [{"store": row["surface"], "kind": "coverage", "evidence": f"erasure-receipt.json#/checks/{index}"}
                  for index, row in enumerate(checks) if row["status"] == "NOT TESTED"]
    if failures:
        verdict, review = "FAIL", "RESIDUAL_FOUND" if residual_found else "OPEN_ITEMS"
    elif error == "fixture-error":
        verdict, review = "ERROR", "OPEN_ITEMS"
    elif error is not None or any(row["status"] == "NOT TESTED" for row in checks[: len(TARGETS[target])]):
        verdict, review = "NOT TESTED", "OPEN_ITEMS"
    else:
        verdict, review = "PASS", "OPEN_ITEMS"
    # This version has no fixtures for every certification surface. Keep
    # certification impossible in v1 even with a correctly replayed self-check.
    return {"scope": "vendor", "target": target, "observed_at": observed_at, "versions": versions,
            "checks": checks, "technical_verdict": verdict, "review_status": review,
            "certification": "UNQUALIFIED", "failures": failures, "gaps": gaps, "open_items": open_items}


def summary(receipt):
    versions = ", ".join(f"{name} {version}" for name, version in sorted(receipt["versions"].items()))
    lines = [f"Fixture verdict {receipt['technical_verdict']} · Setrya Verified status {receipt['certification']}",
             f"Target {receipt['target']}" + (f" ({versions})" if versions else ".")]
    lines.extend(f"{row['status']}  {row['surface']}  {row['reason']}" for row in receipt["checks"])
    rows = {f"{row['surface']}: {row['reason']}" for row in receipt["checks"]}
    lines.extend(f"Gap  {gap}" for gap in receipt["gaps"] if gap not in rows)
    lines.append(f"Evidence SHA-256 {receipt['evidence']['sha256']}")
    return "\n".join(lines)
