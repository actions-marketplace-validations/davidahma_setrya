"""Draft portable manifest for replaying an original v3 person receipt."""

import json
import re
from datetime import UTC
from hashlib import sha256
from itertools import islice
from pathlib import Path
from tempfile import TemporaryDirectory

from setrya.core import signing
from setrya.core.inputs import (
    MAX_JSON_BYTES,
    publish_new_bytes,
    read_regular_bytes,
    require,
)
from setrya.evidence import bundle_manifest
from setrya.receipt_format import EVIDENCE as DRILL_EVIDENCE
from setrya.receipt_format import FORMAT_V3, MAX_BUNDLE_FILE_BYTES, RECEIPT
from setrya.receipts import replay_bytes

from .profiles import EVIDENCE as OBSERVED_EVIDENCE
from .profiles import OBSERVED, decode, fields, new_bundle, snapshot, stamp

FORMAT = "setrya.deletion-receipt-exchange.v1"
MANIFEST = "exchange.json"
SIGNATURE = "exchange.sig"
_SYSTEM_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+:-]{0,95}")
_OBSERVED = "read-only-observation"
_SYNTHETIC = "synthetic-drill"


def _digest(raw):
    return sha256(raw).hexdigest()


def _system(name, version):
    require(all(isinstance(item, str) and _SYSTEM_LABEL.fullmatch(item) for item in (name, version)),
            "System and version must be short ASCII labels without spaces.")
    return {"name": name, "version": version}


def _signature_type(key):
    return "cosign-detached" if key is not None else "sigstore-bundle"


def _source(directory):
    require(directory.is_dir() and not directory.is_symlink() and bundle_manifest(directory) == RECEIPT,
            "Supply a v3 person receipt directory.")
    raw = snapshot(directory / RECEIPT)
    header = decode(raw)
    require(isinstance(header, dict) and header.get("format") == FORMAT_V3
            and header.get("version") == 3 and header.get("scope") == "person"
            and (header.get("profile") == OBSERVED or "profile" not in header),
            "Exchange supports v3 person drills and observed-deletion receipts.")
    observed = header.get("profile") == OBSERVED
    evidence_name = OBSERVED_EVIDENCE if observed else DRILL_EVIDENCE
    return raw, evidence_name, snapshot(directory / evidence_name)


def _open_items(receipt):
    return [
        {"kind": item["kind"], "surface": item["store"], "evidence": f"{RECEIPT}#/open_items/{index}",
         **{name: item[name] for name in ("owner", "follow_up") if item.get(name) is not None}}
        for index, item in enumerate(receipt["open_items"])
    ]


def _file_digests(source):
    raw, evidence_name, evidence = source
    return {RECEIPT: _digest(raw), evidence_name: _digest(evidence)}


def _utc(value):
    return stamp(value).astimezone(UTC).isoformat()


def _project(source, system, signature_type):
    raw, evidence_name, evidence = source
    # Replay the same bytes that are hashed into the manifest and copied to the bundle.
    with TemporaryDirectory() as path:
        folder = Path(path)
        (folder / RECEIPT).write_bytes(raw)
        (folder / evidence_name).write_bytes(evidence)
        receipt = replay_bytes(folder, raw)

    ticket = None
    observation = {"last_checked_at": _utc(receipt["observed_at"])}
    if evidence_name == OBSERVED_EVIDENCE:
        data = decode(evidence)
        first_end = data["find"]["checked_at"]
        next_snapshot = data["verify_absent"]["journal_read_at"]
        require(next_snapshot is None or stamp(first_end) <= stamp(next_snapshot),
                "The second journal snapshot must follow the first completed observation.")
        observation["first_checked_at"] = _utc(first_end)
        ticket = {"id": receipt["request_id"], "frame_sha256": receipt["frame_sha256"]}
        stores, routes = sorted(data["request"]["stores"]), []
        kind = _OBSERVED
    else:
        case = receipt["case"]
        observation["drill_duration_ms"] = receipt["drill_duration_ms"]
        stores = sorted(set(case["scan_stores"]) | {row["store"] for row in case["artifacts"]})
        routes = [case["route"]]
        kind = _SYNTHETIC
    return {
        "format": FORMAT, "status": "draft", "evidence_kind": kind, "scope": "person", "system": system,
        "signature_type": signature_type, "observation": observation, "ticket": ticket,
        "surfaces": {"stores": stores, "routes": routes},
        "technical_verdict": receipt["technical_verdict"], "review_status": receipt["review_status"],
        "open_items": _open_items(receipt),
        "files": _file_digests(source),
    }


def pack(directory, *, output, system, version, key=None, synthetic=False):
    """Validate, copy and sign the original evidence into a fresh exchange directory."""
    source = _source(Path(directory))
    require(synthetic == (source[1] == DRILL_EVIDENCE),
            "Use --synthetic only for a person drill with synthetic data.")
    manifest = _project(source, _system(system, version), _signature_type(key))
    encoded = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    raw, evidence_name, evidence = source
    with new_bundle(output) as folder:
        publish_new_bytes(raw, folder / RECEIPT, max_bytes=MAX_BUNDLE_FILE_BYTES)
        publish_new_bytes(evidence, folder / evidence_name, max_bytes=MAX_BUNDLE_FILE_BYTES)
        publish_new_bytes(encoded, folder / MANIFEST)
        signing.sign_bytes(encoded, folder / SIGNATURE, key=key)
    return manifest


def verify(directory, *, key=None, identity=None, issuer=None, trusted_root=None, expect_ticket=None, expect_frame=None):
    """Authenticate and independently replay one exchange with caller-owned trust."""
    folder = Path(directory)
    require(folder.is_dir() and not folder.is_symlink(), "Supply an exchange bundle directory.")
    raw = snapshot(folder / MANIFEST, MAX_JSON_BYTES)
    manifest = decode(raw)
    fields(manifest, "format status evidence_kind scope system signature_type observation ticket surfaces "
                     "technical_verdict review_status open_items files")
    signature_type = _signature_type(key)
    require(manifest["format"] == FORMAT and manifest["status"] == "draft"
            and manifest["signature_type"] == signature_type, "Unsupported exchange format or signer policy.")
    require(not key or not any((identity, issuer, trusted_root)), "Choose one signer policy.")
    require(key or (identity and issuer and trusted_root), "Supply a trusted key or exact Sigstore identity, issuer and root.")
    signature = snapshot(folder / SIGNATURE, MAX_JSON_BYTES if key else signing.MAX_SIGSTORE_BYTES)
    root = read_regular_bytes(trusted_root, "trusted root", signing.MAX_SIGSTORE_BYTES) if trusted_root else None
    signing.verify_bytes(raw, signature, key=key, identity=identity, issuer=issuer, trusted_root=root)

    fields(manifest["system"], "name version")
    system = _system(**manifest["system"])
    source = _source(folder)
    expected_files = {MANIFEST, SIGNATURE, RECEIPT, source[1]}
    require({path.name for path in islice(folder.iterdir(), len(expected_files) + 1)} == expected_files,
            "Expected exactly the manifest, signature, original receipt and original evidence.")
    require(manifest["files"] == _file_digests(source), "Exchange file digests differ from the signed manifest.")
    result = _project(source, system, signature_type)
    require(json.dumps(manifest, sort_keys=True) == json.dumps(result, sort_keys=True),
            "Exchange claims differ from the original evidence.")
    if expect_ticket is not None or expect_frame is not None:
        ticket = result["ticket"]
        require(ticket and (expect_ticket is None or ticket["id"] == expect_ticket)
                and (expect_frame is None or ticket["frame_sha256"] == expect_frame),
                "Exchange does not match the independently supplied ticket or completed frame.")
    return result


def summary(manifest):
    observation = manifest["observation"]
    system = manifest["system"]
    verdict, review = manifest["technical_verdict"], manifest["review_status"]
    lines = [
        f"Verified exchange · {verdict} · {review}",
        f"{system['name']} {system['version']} · {manifest['evidence_kind']} · draft v1",
        f"Last observation {observation['last_checked_at']}",
    ]
    if manifest["ticket"]:
        lines.append(f"Completed ticket {manifest['ticket']['id']}")
    lines.append("Declared stores " + ", ".join(manifest["surfaces"]["stores"]))
    lines.extend(f"Declared route {route}" for route in manifest["surfaces"]["routes"])
    for item in manifest["open_items"]:
        owner = f" · owner {item['owner']}" if "owner" in item else ""
        due = f" · due {item['follow_up']}" if "follow_up" in item else ""
        lines.append(f"Open item {item['surface']} · {item['kind']}{owner}{due} · {item['evidence']}")
    return "\n".join(lines)
