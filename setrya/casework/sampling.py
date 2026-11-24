"""Uniform sampling without replacement and exact finite-population limits."""
from datetime import UTC, date, datetime, time, timedelta
import hashlib
import hmac
import json
from math import comb
import re
import secrets

from setrya.offboarding.inputs import read_json, require


def load_population(path):
    frame, digest = read_json(path, "completed requests")
    require(isinstance(frame, dict) and set(frame) == {"format", "requests"}
            and frame["format"] == "setrya.completed-requests.v1", "Invalid completed-request frame.")
    rows = frame["requests"]
    require(isinstance(rows, list) and 0 < len(rows) <= 5000, "Supply 1 to 5,000 completed requests.")
    by_id = {}
    now = datetime.now(UTC)
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"id", "subject_ref", "completed_at", "stores"},
                "Invalid completed-request fields.")
        require(isinstance(row["id"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", row["id"])
                and row["id"] not in by_id, "Use a unique opaque request ID.")
        require(isinstance(row["subject_ref"], str) and re.fullmatch(r"[0-9a-f]{64}", row["subject_ref"]),
                "Supply a tenant-bound subject reference.")
        require(isinstance(row["completed_at"], str), "Supply a completion timestamp with a timezone.")
        try:
            instant = datetime.fromisoformat(row["completed_at"])
            require(instant.tzinfo and instant <= now, "Completion must be in the past and include a timezone.")
        except ValueError as exc:
            raise ValueError("Invalid completion time.") from exc
        stores = row["stores"]
        require(isinstance(stores, list) and 0 < len(stores) <= 64 and all(isinstance(s, str) and
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", s) for s in stores)
                and len(set(stores)) == len(stores), "Declare each expected store once per request.")
        by_id[row["id"]] = row
    return by_id, digest


def draw_week(by_id, *, week, count, seed=None):
    try:
        monday = date.fromisoformat(week)
    except ValueError:
        raise ValueError("Supply the week's Monday in YYYY-MM-DD format.") from None
    require(week == monday.isoformat() and monday.weekday() == 0, "Supply a UTC Monday in YYYY-MM-DD format.")
    start = datetime.combine(monday, time.min, UTC)
    stop = start + timedelta(days=7)
    require(stop <= datetime.now(UTC), "Select a completed UTC week.")
    frame = sorted((r for r in by_id.values() if start <= datetime.fromisoformat(r["completed_at"]) < stop),
                   key=lambda row: row["id"])
    require(frame and len({r["subject_ref"] for r in frame}) == len(frame),
            "A weekly frame must contain completed requests with distinct tenant-bound subjects.")
    require(type(count) is int and 1 <= count <= min(len(frame), 256), "Choose 1 to 256 requests within the week size.")
    seed = secrets.token_hex(32) if seed is None else seed
    require(isinstance(seed, str) and re.fullmatch(r"[0-9a-f]{64}", seed), "Use a 64-character lowercase hex draw seed.")
    digest = hashlib.sha256(json.dumps(frame, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    key = bytes.fromhex(seed)
    selected = sorted(frame, key=lambda row: hmac.digest(key, f"{digest}/{row['id']}".encode(), "sha256"))[:count]
    return selected, {"week": week, "eligible": len(frame), "sampled": count, "frame_sha256": digest, "seed": seed}


def _upper(population, sampled, positives):
    """Invert the lower hypergeometric tail at 1/40, with integer arithmetic."""
    total = comb(population, sampled)

    def compatible(residuals):
        first = max(0, sampled + residuals - population)
        last = min(sampled, residuals)
        if positives < first:
            return False
        if positives >= last:
            return True
        mass = comb(residuals, first) * comb(population - residuals, sampled - first)
        cumulative = mass
        for i in range(first, positives):
            mass = mass * (residuals - i) * (sampled - i) // ((i + 1) * (population - residuals - sampled + i + 1))
            cumulative += mass
        return cumulative * 40 >= total

    low, high = positives, population - sampled + positives
    while low < high:
        guess = (low + high + 1) // 2
        if compatible(guess):
            low = guess
        else:
            high = guess - 1
    return low


def statistics(population, outcomes):
    sampled = len(outcomes)
    found = sum(r["status"] == "PRESENT" for r in outcomes)
    unknown = sum(r["status"] == "UNKNOWN" for r in outcomes)
    low = population - _upper(population, sampled, sampled - found)
    high = _upper(population, sampled, found + unknown)
    return {"present": found, "absent": sampled - unknown - found, "unknown": unknown,
            "residual_rate": None if unknown else found / sampled,
            "sample_rate_bounds": [found / sampled, (found + unknown) / sampled],
            "population_count_interval_95": [low, high],
            "population_rate_interval_95": [low / population, high / population]}
