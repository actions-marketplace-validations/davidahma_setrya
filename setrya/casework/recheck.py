"""Recheck due, journal-linked obligations using read-only observers. Keep the original evidence."""
import argparse
from datetime import UTC, datetime
from hashlib import sha256
from itertools import groupby
from pathlib import Path
from secrets import token_hex

from setrya.evidence import bundle_manifest
from setrya.offboarding.inputs import InvalidReport, MAX_JSON_BYTES, publish_new_bytes, require
from setrya.receipt_format import FORMAT_V3, MAX_BUNDLE_FILE_BYTES, RECEIPT
from .observe import key_digest
from .profiles import BRANCHES, CRYPTO, EVIDENCE, FOLLOWUP, PROFILES, VENDOR, day, decode, fields, issue, new_bundle, sha, snapshot, stamp
from .stores import journal_rows, key_reader, observer_config, sqlite_reader

PARENT = "parent"
MAX_LINKS = 8


def copy_source(source, target, budget, depth=0, *, read=snapshot):
    """Copy only protocol-defined inputs needed for replay. Never archive neighbouring application files."""
    from setrya.discovery import case as discovery
    from setrya.erasure.receipt import EVIDENCE as drill_evidence
    from setrya.offboarding import tenant_v3
    from setrya.offboarding.receipt import MAX_ITEMS
    from setrya.offboarding.receipt_cli import MAX_DOCUMENT_BYTES

    require(depth <= MAX_LINKS and source.is_dir() and not source.is_symlink(), "Invalid or overlong receipt chain.")
    name = bundle_manifest(source)
    require(name in (RECEIPT, discovery.RESULT), "Recheck needs a version 3 receipt bundle.")
    target.mkdir()

    def copy(name, cap=MAX_BUNDLE_FILE_BYTES):
        raw = read(source / name, min(cap, budget[0]))
        budget[0] -= len(raw)
        publish_new_bytes(raw, target / name, max_bytes=cap)
        return raw

    receipt = decode(copy(name))
    require(receipt.get("format") == FORMAT_V3 and receipt.get("version") == 3, "Recheck needs a version 3 receipt.")
    profile = receipt.get("profile")
    if name == discovery.RESULT:
        copy(discovery.INPUT)
        if (source / discovery.DRILL).exists():
            copy_source(source / discovery.DRILL, target / discovery.DRILL, budget, depth + 1, read=read)
    elif profile in PROFILES:
        copy(EVIDENCE)
        if profile == FOLLOWUP:
            copy_source(source / PARENT, target / PARENT, budget, depth + 1, read=read)
    elif receipt.get("scope") == "tenant":
        manifest = decode(copy(tenant_v3.MANIFEST))
        records = manifest["records"]
        require(type(records) is int and 0 <= records <= MAX_ITEMS, "Invalid tenant exhibit count.")
        for filename in ("request.json", "policy.json", "evidence.json"):
            copy(filename, MAX_JSON_BYTES)
        for i in range(records):
            copy(f"record-{i}.json", MAX_JSON_BYTES)
            copy(f"record-{i}.bin", MAX_DOCUMENT_BYTES)
    else:
        copy(drill_evidence)


def parent_receipt(folder):
    from setrya.receipts import replay_bytes

    # Bound nesting before invoking replay on any nested follow-up. A symlink
    # could otherwise take an offline reviewer into a different receipt tree.
    nested = folder
    for _ in range(MAX_LINKS + 1):
        nested = nested / PARENT
        require(not nested.is_symlink(), "Linked receipt directories must be in the evidence bundle.")
        if not nested.exists():
            break
    else:
        raise InvalidReport("Too many linked follow-ups.")
    parent = folder / PARENT
    name = bundle_manifest(parent)
    require(name in (RECEIPT, "case-result.json"), "Missing original receipt.")
    raw = snapshot(parent / name)
    receipt = replay_bytes(parent, raw)
    require(receipt["version"] == 3, "Supply a verified v3 parent receipt.")
    return receipt, sha256(raw).hexdigest()


def subject_of(receipt):
    return receipt.get("subject", {}).get("ref") or receipt.get("subject_ref")


def item_identity(item, subject):
    if "key_sha256" in item:
        return sha(item["key_sha256"])
    if subject and item.get("store") and item.get("key"):
        return key_digest(subject, item["store"], item["key"])
    return None


def eligibility(item, subject, today, checked_at):
    if item.get("kind") == "restore-window":
        return "configured-window-elapsed" if checked_at >= stamp(item["expires_at"]) else "not-due"
    due = item.get("follow_up")
    if due is None:
        return "no-follow-up-date"
    if day(due) >= today:
        return "not-due"
    if item.get("kind") == "configuration":
        return "configuration-only"
    if not subject or item_identity(item, subject) is None or item.get("kind") not in ("verification", "retained", "attested"):
        return "no-direct-subject-key"
    return None


def observe_due(parent, checked_at, journal, inventory_file):
    subject = subject_of(parent)
    observed = stamp(checked_at).astimezone(UTC)
    today = observed.date().isoformat()
    rows, planned = [], []
    for i, item in enumerate(parent["open_items"]):
        skip = eligibility(item, subject, today, observed)
        rows.append({"index": i, "reason": skip, "target": None, "direct": None, "scan": None})
        if not skip:
            planned.append((item["store"], item_identity(item, subject), i))
    if not planned:
        return rows
    # All I/O destinations come from the operator's local inventory. The
    # previous receipt supplies an opaque target only; never a connection URL.
    stores, roster = observer_config(inventory_file) if inventory_file is not None else ({}, None)
    copies = {}
    if journal is not None:
        try:
            with sqlite_reader(journal) as db:
                observed, collector = journal_rows(db, subject, roster)
            if len(observed) <= 512:
                copies = {(store, key_digest(subject, store, key)): (key, sent or shared, event, version)
                          for store, key, event, version, sent, shared in observed}
        except Exception:
            pass  # An unreadable or truncated journal cannot authorize an absence claim.
    for store, group in groupby(sorted(planned), key=lambda target: target[0]):
        spec = stores.get(store)
        reads = []
        for _, digest, i in group:
            known = copies.get((store, digest))
            if spec is None:
                rows[i]["reason"] = "unmapped-store"
            elif known is None or known[1] or known[0] == spec["control_key"]:
                rows[i]["reason"] = "no-exclusive-journal-key"
            else:
                key, _, event, version = known
                rows[i]["target"] = {"store": store, "key_sha256": digest, "subject_ref": subject,
                                     **({"journal_event": event} if event is not None else {}),
                                     **({"lineage_version": version} if version is not None else {}),
                                     **({"collector_sha256": collector} if collector is not None else {})}
                reads.append((key, i))
        if not reads:
            continue
        try:
            with key_reader(spec) as lookup:
                for key, i in reads:
                    rows[i]["direct"] = lookup(key)
        except Exception:
            pass
        scan = None
        if "subject_column" in spec and spec["control_subject_ref"] != subject:
            try:
                with key_reader(spec, scan=True) as lookup:
                    scan = lookup(subject)
            except Exception:
                pass
        for _, i in reads:
            rows[i]["scan"] = scan
    return rows


def derive_followup(e, folder):
    fields(e, "format parent_sha256 observed_at checks")
    require(e["format"] == "setrya.follow-up.v1", "Unexpected follow-up evidence.")
    parent, digest = parent_receipt(folder)
    require(e["parent_sha256"] == digest, "Follow-up is linked to a different receipt.")
    observed = stamp(e["observed_at"])
    require(observed >= stamp(parent.get("drill_observed_at") or parent["observed_at"]), "Follow-up precedes the original observation.")
    today = observed.astimezone(UTC).date().isoformat()
    subject = subject_of(parent)
    original = parent["open_items"]
    checks = e["checks"]
    require(isinstance(checks, list) and len(checks) == len(original), "Every original open item needs a disposition.")
    items, remaining = [], []
    found = False
    for index, (item, read) in enumerate(zip(original, checks)):
        fields(read, "index reason target direct scan")
        reason, direct, scan = read["reason"], read["direct"], read["scan"]
        require(type(read["index"]) is int and read["index"] == index
                and all(type(v) in (bool, type(None)) for v in (direct, scan)), "Invalid follow-up observation.")
        skip = eligibility(item, subject, today, observed)
        require(reason == skip if skip else reason in (None, "no-exclusive-journal-key", "unmapped-store"),
                "Review disposition disagrees with item identity or due date.")
        require(reason is None or direct is None and scan is None, "Unexpected reads for an inaccessible or deferred item.")
        target = read["target"]
        if reason is None:
            fields(target, "store key_sha256 subject_ref", ("journal_event", "lineage_version", "collector_sha256"))
            pointers = [target[k] for k in ("journal_event", "lineage_version") if k in target]
            collector = sha(target["collector_sha256"]) if "collector_sha256" in target else None
            require(target["store"] == item["store"] and target["key_sha256"] == item_identity(item, subject)
                    and target["subject_ref"] == subject and (pointers or collector) and all(type(n) is int and n > 0 for n in pointers),
                    "Follow-up read target differs from the original obligation.")
        else:
            require(target is None, "Unexpected follow-up target.")
        if reason == "configured-window-elapsed":
            require(observed <= datetime.now(UTC), "Restore window follow-up is ahead of the verifier clock.")
        verified = reason == "configured-window-elapsed" or direct is False and scan is False
        found |= direct is True or scan is True
        reason = reason or ("residual-found" if direct is True or scan is True else
                            "read-or-scan-unavailable" if not verified else "absent-in-both-reads")
        items.append({**item, "status": "verified" if verified else "still open", "reason": reason,
                      "recheck_evidence": f"{EVIDENCE}#/checks/{index}"})
        if not verified:
            remaining.append(item)
    original_verdict = parent["technical_verdict"]
    verdict = "FAIL" if found else original_verdict
    review = "RESIDUAL_FOUND" if verdict == "FAIL" else "OPEN_ITEMS" if remaining or verdict != "PASS" else "READY_FOR_REVIEW"
    references = ("request_id",) if parent.get("profile") == BRANCHES else ("case_id", "request_id")
    return {"scope": parent["scope"], **({"subject": {"ref": subject}} if subject else {}),
            **{key: parent[key] for key in references if key in parent},
            "parent_sha256": digest, "observed_at": e["observed_at"], "original_verdict": original_verdict,
            "technical_verdict": verdict, "review_status": review, "items": items, "open_items": remaining,
            **({"controls": parent["controls"]} if "controls" in parent else {})}


def recheck(receipt, *, output, inventory_file=None, journal=None, expected_parent_sha256=None):
    """Recheck due obligations using only trusted local store mappings and the historical journal."""
    source = Path(receipt)
    if source.is_file():
        require(not source.is_symlink() and source.name == bundle_manifest(source.parent), "Supply the bundle's manifest.")
        source = source.parent
    with new_bundle(output) as folder:
        copy_source(source, folder / PARENT, [128 * 1024 * 1024])
        parent, digest = parent_receipt(folder)
        require(parent.get("profile") not in (CRYPTO, VENDOR),
                "Repeat the original crypto-erasure verification or vendor self-check to obtain a new observation.")
        require(expected_parent_sha256 in (None, digest), "Original receipt fingerprint differs from the supplied pin.")
        at = datetime.now(UTC).isoformat()
        checks = observe_due(parent, at, journal, inventory_file)
        return issue(FOLLOWUP, {"format": "setrya.follow-up.v1", "parent_sha256": digest,
                                "observed_at": at, "checks": checks}, folder)


def command(argv):
    from setrya.receipts import report
    parser = argparse.ArgumentParser(prog="setrya recheck", description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--inventory", type=Path, help="read-only observer mapping")
    parser.add_argument("--journal", type=Path, help="existing copy journal")
    parser.add_argument("--expect-parent", help="SHA-256 of the independently supplied original receipt")
    parser.add_argument("--output", type=Path, help="fresh output directory")
    args = parser.parse_args(argv)
    output = args.output or Path("recheck-" + token_hex(5))
    receipt = recheck(args.receipt, output=output, inventory_file=args.inventory, journal=args.journal,
                      expected_parent_sha256=args.expect_parent)
    print(f"Saved linked evidence to {output}")
    return report(receipt, case_review=True)
