"""Declared erasure boundary, handling labels and owners."""
import tomllib
from pathlib import Path

from setrya.offboarding.inputs import read_regular_bytes, require
from .journal import identifier


def label(value):
    require(isinstance(value, str) and value.strip() and value.isprintable() and len(value) <= 128,
            "Expected a printable classification label.")
    return value


def systems(value):
    require(isinstance(value, list) and 0 < len(value) <= 256, "Declare one to 256 inventory systems.")
    result = {}
    for row in value:
        require(isinstance(row, dict) and set(row) == {
            "name", "owner", "role", "approved_labels", "retention_days", "adapter"
        }, "Invalid inventory system fields.")
        for key in ("name", "owner", "role", "adapter"):
            identifier(row[key], key)
        labels = row["approved_labels"]
        require(isinstance(labels, list) and labels and all(label(x) for x in labels)
                and len(set(labels)) == len(labels), "List each approved handling label once.")
        require(type(row["retention_days"]) is int and row["retention_days"] >= 0,
                "Expected nonnegative retention days.")
        require(row["name"] not in result, "Duplicate inventory system.")
        result[row["name"]] = row
    bound = [row["adapter"] for row in result.values() if row["adapter"] != "none"]
    require(len(bound) == len(set(bound)), "Give each deletion boundary a distinct adapter name.")
    return result


def load(path: Path):
    return load_coverage(path)[0]


def load_coverage(path):
    value = tomllib.loads(read_regular_bytes(path, "inventory").decode("utf-8"))
    require(isinstance(value, dict) and {"version", "systems"} <= value.keys()
            and not value.keys() - {"version", "systems", "coverage"}
            and type(value["version"]) is int and value["version"] == 1, "Expected inventory version 1.")
    declared = systems(value["systems"])
    rows = value.get("coverage", [])
    require(isinstance(rows, list) and len(rows) <= 1024, "Invalid inventory coverage list.")
    mapped = {}
    for row in rows:
        require(isinstance(row, dict) and {"store", "kind", "name"} <= row.keys()
                and not row.keys() - {"store", "kind", "name", "adapter", "scanner"},
                "Invalid coverage boundary fields.")
        store = identifier(row["store"], "coverage store")
        kind = row["kind"]
        name = row["name"]
        if (kind, name) != ("namespace", "setrya/{subject}"):
            identifier(name, "coverage boundary")
        require(store in declared and kind in ("store", "namespace", "trace")
                and (kind != "store" or name == store), "Invalid inventory coverage boundary.")
        key = store, kind, name
        require(key not in mapped, "Duplicate coverage boundary.")
        mapped[key] = tuple(identifier(row[k], k) for k in ("adapter", "scanner")
                            if k in row and row[k] != "none")
    return declared, mapped
