"""Review possible PDF writes against an approved discovery case."""
import re
from dataclasses import asdict
from hashlib import sha256

from setrya.offboarding.inputs import keys_match, read_json, require

from .case import RESULT, _canonical, replay_bytes
from .mapping import DIRECT_ROLES, validate_binding
from .source_scan import MAX_SOURCE_CANDIDATES, scan_pdf_writes

SCAN_FORMAT = "setrya.pdf-source-scan.v1"
REVIEW_FORMAT = "setrya.pdf-source-review.v1"
APPROVAL_FORMAT = "setrya.pdf-source-approvals.v1"
_ID = re.compile(r"[a-f0-9]{64}")


def scope_digest(binding):
    return sha256(_canonical(validate_binding(binding))).hexdigest()


def scan(root):
    return {"format": SCAN_FORMAT, "candidates": [asdict(site) for site in scan_pdf_writes(root)]}


def _id(value):
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _approvals(data, digest, services):
    if data is None:
        return {}
    require(keys_match(data, {"format", "binding_sha256", "sites"})
            and data["format"] == APPROVAL_FORMAT and data["binding_sha256"] == digest,
            "Source approvals must bind the exact discovery scope.")
    require(isinstance(data["sites"], list) and len(data["sites"]) <= MAX_SOURCE_CANDIDATES,
            "Expected a list of up to 512 source approvals.")
    approved = {}
    for row in data["sites"]:
        require(keys_match(row, {"candidate_id", "service_id", "store", "key"})
                and _id(row["candidate_id"]) and row["candidate_id"] not in approved
                and isinstance(row["service_id"], str), "Invalid or duplicate source approval.")
        service = services.get(row["service_id"])
        require(service is not None and (service["store"], service["key"]) == (row["store"], row["key"]),
                "Source approval does not match an exact direct service in the discovery mapping.")
        approved[row["candidate_id"]] = {k: row[k] for k in ("service_id", "store", "key")}
    return approved


def _baseline(data, case_digest):
    if data is None:
        return {}
    require(isinstance(data, dict) and data.get("format") == REVIEW_FORMAT
            and data.get("scanner") == SCAN_FORMAT and data.get("case_sha256") == case_digest
            and isinstance(data.get("sites"), list)
            and len(data["sites"]) <= MAX_SOURCE_CANDIDATES, "Expected a baseline review for this case and scanner format.")
    sites = {}
    for row in data["sites"]:
        require(isinstance(row, dict) and isinstance(row.get("source"), dict)
                and "approval" in row and _id(row["source"].get("id")), "Invalid baseline source site.")
        site = row["source"]["id"]
        require(site not in sites, "Duplicate baseline source site.")
        approved = row["approval"]
        require(approved is None or (keys_match(approved, {"service_id", "store", "key"})
                                     and all(isinstance(value, str) and value for value in approved.values())),
                "Invalid baseline source approval.")
        sites[site] = approved is not None
    return sites


def _receipt(bundle, binding):
    if bundle is None:
        return None, {}
    from setrya.erasure.receipt import MAX_BUNDLE_FILE_BYTES
    from setrya.offboarding.inputs import read_regular_bytes

    raw = read_regular_bytes(bundle / RESULT, "discovery receipt", MAX_BUNDLE_FILE_BYTES)
    result = replay_bytes(bundle, raw, expected_binding=binding)
    return sha256(raw).hexdigest(), {row["id"]: row for row in result["services"]}


def assess(root, binding, *, approvals=None, baseline=None, bundle=None):
    """Correlate a fresh static scan with reviewed scope and optional bound replay."""
    digest = scope_digest(binding)
    services = {row["id"]: row for row in binding["services"] if row["role"] in DIRECT_ROLES
                and row["action"] in ("delete", "rewrite")}
    approved = _approvals(approvals, digest, services)
    case = {key: binding[key] for key in ("case_id", "subject_ref", "asset_sha256", "environment")}
    case_digest = sha256(_canonical(case)).hexdigest()
    previous = _baseline(baseline, case_digest)
    candidates = scan(root)["candidates"]
    receipt_digest, observed = _receipt(bundle, binding)
    sites = []
    for candidate in candidates:
        site = candidate["id"]
        approval = approved.get(site)
        result = observed.get(approval["service_id"]) if approval else None
        baseline_reads = [] if result is None else [link for link in result["evidence"] if "#/baseline/" in link]
        later_reads = [] if result is None else [link for link in result["evidence"] if "#/baseline/" not in link]
        sites.append({
            "source": candidate,
            "approval": approval,
            "runtime": None if result is None else {"baseline": result.get("baseline", "UNRECORDED"), "evidence": baseline_reads},
            "deletion": None if result is None else {"status": result["status"], "evidence": later_reads},
            "requires_review": approval is None and (site not in previous or previous[site]),
        })
    return {"format": REVIEW_FORMAT, "scanner": SCAN_FORMAT, "binding_sha256": digest,
            "case_sha256": case_digest, "revision": binding["revision"],
            "receipt_sha256": receipt_digest, "sites": sites,
            "review_required": sum(row["requires_review"] for row in sites)}


def _evidence_label(candidate):
    if candidate["destination"] is not None:
        return candidate["destination"]
    return "unresolved" + (f" (ends in {candidate['hint']})" if candidate.get("hint") else "")


def summarize(document):
    if document["format"] == SCAN_FORMAT:
        return "\n".join(
            f"PDF WRITE  {site['path']}:{site['line']} · {_evidence_label(site)} · candidate {site['id']}"
            for site in document["candidates"]
        ) or "No supported PDF writes detected within the scanned source."
    lines = []
    if document["receipt_sha256"] is not None:
        lines.append(f"Replayed discovery case for mapped application revision {document['revision']}.")
    for row in document["sites"]:
        site = row["source"]
        state = "REVIEW REQUIRED" if row["requires_review"] else "APPROVED" if row["approval"] else "EXISTING GAP"
        lines.append(f"{state}  {site['path']}:{site['line']} · {_evidence_label(site)} · candidate {site['id']}")
        if row["approval"]:
            lines.append(f"  Approved service {row['approval']['service_id']}")
        if row["runtime"] is not None:
            lines.append(f"  Mapped service runtime baseline {row['runtime']['baseline']} · deletion check {row['deletion']['status']}")
    lines.append(f"{document['review_required']} source candidate(s) require mapping review.")
    return "\n".join(lines)


def load_document(path, label):
    return read_json(path, label)[0] if path is not None else None
