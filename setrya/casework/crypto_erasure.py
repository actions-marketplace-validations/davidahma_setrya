"""Capture ciphertext references and verify AWS KMS destruction without writes."""
import argparse
import os
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from setrya.drill import InputError
from setrya.offboarding.inputs import InvalidReport, publish_new, read_json, require

from ._crypto_aws import AWSKeyObserver, deletion_event, key_parts, key_status
from ._crypto_sqlite import MAX_COPIES, inventory, observe_store, store_id
from .profiles import decode, fields, issue, new_bundle, sha, snapshot, stamp

PROFILE = "crypto-erasure"
_BASELINE = "setrya.crypto-capture.v1"
_EVIDENCE = "setrya.crypto-erasure.v1"


def _now(now):
    when = now or datetime.now(UTC)
    require(when.tzinfo is not None, "Crypto-erasure observations require a timezone.")
    return when


def _ciphertext(row):
    fields(row, "key_sha256 ciphertext_sha256 key_arn")
    sha(row["key_sha256"])
    sha(row["ciphertext_sha256"])
    key_parts(row["key_arn"])


def _store_data(store):
    fields(store, "control copies")
    _ciphertext(store["control"])
    copies = store["copies"]
    require(isinstance(copies, list) and len(copies) <= MAX_COPIES * 2, "Too many ciphertext rows.")
    result = {}
    for row in copies:
        _ciphertext(row)
        key = row["key_sha256"]
        require(key not in result and key != store["control"]["key_sha256"], "Duplicate ciphertext key.")
        result[key] = row
    return result


def _baseline(doc):
    fields(doc, "format inventory_sha256 subject_sha256 key_arn retained_key_arn owner recovery_scope captured_at "
                "account target_key retained_key stores")
    require(doc["format"] == _BASELINE and doc["recovery_scope"] == "exclusive-kms-key",
            "Unsupported crypto-erasure capture.")
    sha(doc["inventory_sha256"])
    sha(doc["subject_sha256"])
    store_id(doc["owner"])
    target, retained = doc["key_arn"], doc["retained_key_arn"]
    region, account, _ = key_parts(target)
    when = stamp(doc["captured_at"])
    require(doc["account"] == account and key_parts(retained)[:2] == (region, account) and target != retained
            and key_status(doc["target_key"], target, when) == "Enabled"
            and key_status(doc["retained_key"], retained, when) == "Enabled",
            "Capture requires direct visibility of two eligible enabled AWS KMS keys.")
    stores = doc["stores"]
    require(isinstance(stores, dict) and 0 < len(stores) <= 16, "Invalid ciphertext store inventory.")
    count = 0
    for name, rows in stores.items():
        store_id(name)
        copies = _store_data(rows)
        require(rows["control"]["key_arn"] == retained and all(row["key_arn"] == target for row in copies.values()),
                "Captured ciphertext does not name its exact expected wrapping key.")
        count += len(copies)
    require(0 < count <= MAX_COPIES, "Capture requires one to 512 target ciphertext copies.")
    return when


def _load_inventory(path):
    path = Path(path)
    config, digest = read_json(path, "crypto-erasure inventory")
    inventory(config)
    binding = sha256(b"setrya.crypto-inventory-bindings.v1\x00" + bytes.fromhex(digest))
    for name, store in sorted(config["stores"].items()):
        database = path.parent / store["database"]
        actual = database.parent.resolve() / database.name
        store["database"] = str(actual)
        binding.update(name.encode("ascii") + b"\x00" + os.fsencode(actual) + b"\x00")
    return config, binding.hexdigest()


def capture(*, inventory_path, output, observer=None, now=None):
    """Write an independent pre-erasure manifest of eligible ciphertext copies."""
    config, digest = _load_inventory(inventory_path)
    when = _now(now)
    key, retained = config["key_arn"], config["retained_key_arn"]
    source = observer or AWSKeyObserver.connect(key)
    account = source.account(key)
    require(account is not None, "Capture requires an observer in the exact AWS account and Region.")
    manifest = {"format": _BASELINE, "inventory_sha256": digest,
                "subject_sha256": sha256(config["subject_ref"].encode("ascii")).hexdigest(),
                "key_arn": key, "retained_key_arn": retained, "owner": config["owner"],
                "recovery_scope": config["recovery_scope"], "captured_at": when.isoformat(), "account": account,
                "target_key": source.describe(key, when), "retained_key": source.describe(retained, when), "stores": {}}
    for name in sorted(config["stores"]):
        try:
            manifest["stores"][name] = observe_store(config, Path(inventory_path).parent, name, ())
        except (InputError, OSError, ValueError, sqlite3.Error) as exc:
            detail = f" {exc}" if isinstance(exc, InvalidReport) else ""
            raise InvalidReport(f"Could not capture ciphertext in {name}.{detail}") from None
    _baseline(manifest)
    return publish_new(manifest, Path(output))


def observe(*, inventory_path, manifest_path, expect_manifest, output, observer=None, now=None):
    """Check an independently pinned capture and save a portable v3 receipt."""
    config, digest = _load_inventory(inventory_path)
    raw = snapshot(Path(manifest_path))
    require(sha(expect_manifest) == sha256(raw).hexdigest(), "Capture differs from its independently pinned digest.")
    manifest = decode(raw)
    captured = _baseline(manifest)
    require(manifest["inventory_sha256"] == digest, "Capture belongs to a different ciphertext inventory.")
    when = _now(now)
    require(captured < when, "Verification must follow capture.")
    key, retained = manifest["key_arn"], manifest["retained_key_arn"]
    require(key == config["key_arn"] and retained == config["retained_key_arn"]
            and set(manifest["stores"]) == set(config["stores"])
            and manifest["subject_sha256"] == sha256(config["subject_ref"].encode("ascii")).hexdigest(),
            "Capture differs from the declared verification scope.")
    source = observer or AWSKeyObserver.connect(key)
    account = source.account(key)
    target, control = {"status": "unavailable"}, {"status": "unavailable"}
    event = None
    if account is not None:
        target, control = source.describe(key, when), source.describe(retained, when)
        if key_status(target, key, when) == "not-found" and key_status(control, retained, when) == "Enabled":
            event = source.deletion(key, captured, when)
    stores = {}
    new_copies = 0
    for name, previous in manifest["stores"].items():
        expected = _store_data(previous)
        try:
            reading = observe_store(config, Path(inventory_path).parent, name, sorted(expected))
            new_count = len(_store_data(reading).keys() - expected.keys())
            require(new_copies + new_count <= MAX_COPIES, "Too many new ciphertext copies.")
            new_copies += new_count
            stores[name] = reading
        except (InputError, OSError, ValueError, sqlite3.Error):
            stores[name] = None
    evidence = {"format": _EVIDENCE, "manifest": raw.decode("utf-8"), "manifest_sha256": expect_manifest,
                "checked_at": when.isoformat(), "account": account,
                "target_key": target, "retained_key": control, "deletion_event": event, "stores": stores}
    with new_bundle(output) as bundle:
        return issue(PROFILE, evidence, bundle)


def _provider_status(evidence, original, captured, checked):
    target, retained = original["key_arn"], original["retained_key_arn"]
    state = key_status(evidence["target_key"], target, checked)
    retained_state = key_status(evidence["retained_key"], retained, checked)
    event = evidence["deletion_event"]
    if event is not None:
        deletion_event(event, target, captured, checked)
    if evidence["account"] != original["account"]:
        return "unproven", "AWS observer did not establish the captured account and Region."
    if (retained_state != "Enabled" or stamp(evidence["retained_key"]["metadata"]["created_at"])
            != stamp(original["retained_key"]["metadata"]["created_at"])):
        return "unproven", "The captured retained KMS key could not be confirmed enabled."
    if (state == "Enabled" and stamp(evidence["target_key"]["metadata"]["created_at"])
            == stamp(original["target_key"]["metadata"]["created_at"])):
        return "available", None
    if state == "not-found" and event is not None:
        return "deleted", None
    if state == "not-found":
        return "unproven", "CloudTrail did not establish completed destruction of the missing KMS key."
    return "unproven", f"KMS key observation {state} does not establish permanent destruction."


def derive_crypto(evidence):
    """Derive the verdict from the saved scope, provider and ciphertext observations."""
    fields(evidence, "format manifest manifest_sha256 checked_at account target_key retained_key deletion_event stores")
    require(evidence["format"] == _EVIDENCE and isinstance(evidence["manifest"], str), "Invalid crypto-erasure evidence.")
    raw = evidence["manifest"].encode("utf-8")
    pin = sha(evidence["manifest_sha256"])
    require(len(raw) <= 1024 * 1024 and sha256(raw).hexdigest() == pin, "Invalid capture digest.")
    original = decode(raw)
    captured, checked = _baseline(original), stamp(evidence["checked_at"])
    require(captured < checked, "Crypto-erasure verification predates the capture.")
    readings = evidence["stores"]
    require(isinstance(readings, dict) and set(readings) == set(original["stores"]),
            "Ciphertext observation scope differs from its capture.")
    key_state, provider_gap = _provider_status(evidence, original, captured, checked)
    failures = ["The exact captured KMS key is still enabled."] if key_state == "available" else []
    gaps, open_items = [], []
    if provider_gap:
        gaps.append(provider_gap)
        open_items.append({"store": "aws-kms", "owner": original["owner"], "kind": "verification",
                           "evidence": "observation-evidence.json#/target_key"})
    rows = []
    for store, old in sorted(original["stores"].items()):
        before = _store_data(old)
        reading = readings[store]
        after = _store_data(reading) if reading is not None else {}
        confirmed = reading is not None and old["control"] == reading["control"]
        if not confirmed:
            gaps.append(f"{store} did not complete a ciphertext read with the captured retained control.")
        for key in sorted(before.keys() | after.keys()):
            status = "unknown"
            if confirmed and key in before:
                if key not in after:
                    status = "absent"
                elif before[key] == after[key]:
                    status = {"deleted": "crypto-erased", "available": "recoverable", "unproven": "unknown"}[key_state]
                else:
                    gaps.append(f"{store} captured ciphertext changed after the baseline.")
            if confirmed and key not in before:
                gaps.append(f"{store} contains ciphertext outside the captured scope.")
            selected = before[key] if key in before else after[key]
            rows.append({"store": store, "key_sha256": key, "ciphertext_sha256": selected["ciphertext_sha256"],
                         "status": status})
            if status == "unknown" and (confirmed or reading is not None):
                open_items.append({"store": store, "key_sha256": key, "owner": original["owner"],
                                   "kind": "verification", "evidence": f"erasure-receipt.json#/copies/{len(rows) - 1}"})
        if not confirmed:
            open_items.append({"store": store, "owner": original["owner"], "kind": "coverage",
                               "evidence": f"observation-evidence.json#/stores/{store}"})
    require(len(rows) <= MAX_COPIES * 2, "Too many ciphertext copies for a crypto-erasure receipt.")
    verdict = "FAIL" if failures else "NOT TESTED" if gaps else "PASS"
    result = {"scope": "person", "subject": {"ref": original["subject_sha256"]}, "observed_at": evidence["checked_at"],
              "capture_manifest_sha256": pin, "inventory_sha256": original["inventory_sha256"],
              "key_arn": original["key_arn"], "key_status": key_state, "copies": rows,
              "technical_verdict": verdict,
              "review_status": {"FAIL": "RESIDUAL_FOUND", "PASS": "READY_FOR_REVIEW", "NOT TESTED": "OPEN_ITEMS"}[verdict],
              "failures": failures, "gaps": sorted(set(gaps)), "open_items": open_items}
    if key_state == "deleted":
        event = evidence["deletion_event"]
        result["key_event"] = {name: event[name] for name in ("event_id", "occurred_at")}
    return result


def summary(receipt):
    counts = Counter(row["status"] for row in receipt["copies"])
    lines = [f"Technical verdict {receipt['technical_verdict']} · Review status {receipt['review_status']}",
             f"KMS key {receipt['key_status']}. Examined {len(receipt['copies'])} captured or newly observed copies.",
             (f"{counts['crypto-erased']} crypto-erased · {counts['absent']} absent · "
              f"{counts['recoverable']} have an available key · {counts['unknown']} unknown")]
    lines.extend(receipt["failures"] + receipt["gaps"])
    return "\n".join(lines)


def command(argv):
    """CLI for pre-erasure capture and read-only verification."""
    parser = argparse.ArgumentParser(prog="setrya crypto-erasure", description="Verify completed AWS KMS key destruction.")
    operations = parser.add_subparsers(dest="operation", required=True)
    before = operations.add_parser("capture", help="capture encrypted copies and two eligible KMS keys")
    after = operations.add_parser("verify", help="verify an independently pinned capture and write a receipt")
    for operation in (before, after):
        operation.add_argument("--inventory", dest="inventory_path", type=Path, required=True)
        operation.add_argument("--output", type=Path, required=True)
    after.add_argument("--manifest", dest="manifest_path", type=Path, required=True)
    after.add_argument("--expect-manifest", required=True)
    args = vars(parser.parse_args(argv))
    if args.pop("operation") == "capture":
        digest = capture(**args)
        print(f"Captured eligible ciphertext and its AWS KMS scope. Keep this SHA-256 independently: {digest}")
        return 0
    from setrya.receipts import report
    return report(observe(**args))
