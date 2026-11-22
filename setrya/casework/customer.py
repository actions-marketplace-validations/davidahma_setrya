"""Render bounded customer-facing text from a replayed erasure receipt."""
from collections import Counter
from datetime import datetime
import re

from setrya.offboarding.inputs import require
from setrya.receipt_format import FORMAT_V3
from setrya.receipts import replay


def _count(number, singular, plural=None):
    return f"{number} {singular if number == 1 else plural or singular + 's'}"


def customer_receipt(bundle, *, case_id=None):
    return customer_text(replay(bundle), case_id=case_id)


def customer_text(receipt, *, case_id=None):
    require(receipt.get("format") == FORMAT_V3, "Customer rendering requires a v3 receipt and its evidence.")
    attached = receipt.get("case_id") or receipt.get("request_id")
    if case_id:
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", case_id), "Use an opaque customer case number.")
        require(attached in (None, case_id), "Case number differs from the replayed evidence.")
    reference = case_id or attached
    title = "Deletion review"
    if reference:
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,127}", reference), "Unsupported public case reference.")
        title += f" for {reference}"
    discovery = receipt.get("profile") == "discovery"
    stamp = receipt.get("drill_observed_at") if discovery else receipt["observed_at"]
    lines = [title]
    if stamp is not None:
        lines.append(f"Observation date: {datetime.fromisoformat(stamp).date().isoformat()}.")
    else:
        catalog_date = datetime.fromisoformat(receipt["observed_at"]).date().isoformat()
        lines.append(f"The catalog recorded the finding on {catalog_date}. No deletion drill was run.")
    if not attached and case_id:
        lines.append("The case number was supplied when this summary was prepared.")
    if receipt.get("profile") == "discovery":
        lines.append(f"The approved discovery case covered {len(receipt['services'])} declared services.")
    elif receipt.get("profile") == "observed-deletion":
        lines.append(f"The observer checked {_count(len(receipt['checks']), 'recorded copy', 'recorded copies')} for the completed request.")
    elif receipt.get("profile") == "follow-up":
        lines.append("This review revisited outstanding items from an earlier deletion record.")
    elif receipt["scope"] == "tenant":
        lines.append(f"The tenant review covered {len(receipt['probes'])} recorded application checks.")
    else:
        actions = Counter(row["action"] for row in receipt["artifact_checks"])
        descriptions = [f"{actions[k]} {one if actions[k] == 1 else many}" for k, one, many in (
            ("delete", "copy marked for deletion", "copies marked for deletion"),
            ("rewrite", "shared record marked for rewriting", "shared records marked for rewriting"),
            ("preserve", "record to preserve", "records to preserve"),
        ) if actions[k]]
        lines.append("The application drill covered " + ", ".join(descriptions) + ".")
        lines.append(f"It checked answers for {_count(len(receipt['case']['callers']), 'reader')}.")
        sampling = receipt.get("answer_sampling")
        if sampling:
            lines.append(f"The drill requested {_count(sampling['samples_per_question'], 'answer')} for each question per reader at each stage.")
            if "lexical-only" in (sampling["target_coverage"], sampling["control_coverage"]):
                lines.append("Some answers were judged only by matching words or patterns. A paraphrase could go undetected.")
        else:
            lines.append("This earlier receipt did not record repeated-answer coverage.")
    verdict = receipt["technical_verdict"]
    lines.append({
        "PASS": "The recorded checks met their deletion and preservation requirements.",
        "FAIL": "At least one check found information that should have disappeared or lost information that should remain.",
        "ERROR": "An error prevented a reliable conclusion.",
        "NOT TESTED": "The evidence was insufficient to confirm the requested checks.",
    }[verdict])
    if receipt.get("race") in ("exercised", "incomplete", "not exercised"):
        lines.append({"exercised": "The drill also checked what happened after a delayed worker resumed.",
                      "incomplete": "The delayed-worker check could not be completed.",
                      "not exercised": "This run did not test a delayed worker."}[receipt["race"]])
    items = receipt["open_items"]
    if items:
        lines.append(f"{_count(len(items), 'follow-up item')} {'remains' if len(items) == 1 else 'remain'}.")
        groups = Counter()
        for item in items:
            kind = item.get("kind", "").lower()
            status = item.get("status", "").lower()
            if "retain" in status or kind in ("retained", "backup") or "retention" in status:
                label = "Record retention"
            elif kind in ("configuration", "provider") or status == "configuration":
                label = "Provider configuration"
            elif kind == "attested" or status == "attested":
                label = "Owner attestation"
            else:
                label = "Evidence review"
            groups[(label, item.get("owner") or "unassigned", item.get("follow_up") or "")] += 1
        for (label, owner, due), count in sorted(groups.items()):
            date = f"Follow up on {due}." if due else "A follow-up date has not been recorded."
            lines.append(f"- {label} ({count}). Owner: {owner}. {date}")
    elif receipt["review_status"] in ("READY_FOR_REVIEW", "COMPLETE"):
        lines.append("No outstanding items were recorded for these checks.")
    else:
        lines.append("The case owner should review the evidence before closing the request.")
    lines.append("This summary covers the locations and observations in the evidence bundle.")
    return "\n".join(lines)
