"""Audience-specific summaries of decisions reconstructed from a v3 evidence bundle."""
from collections import Counter
from hashlib import sha256
import html
import json
from pathlib import Path
import re

from setrya.offboarding.inputs import read_regular_bytes, require, unique_fields
from setrya.receipt_format import FORMAT_V3, MAX_BUNDLE_FILE_BYTES
from setrya.receipts import replay, summary as technical_summary
from .customer import customer_text


def _markdown(text):
    # Prevent links, mentions, HTML, and Markdown from being introduced by receipt identifiers.
    return re.sub(r"([\\`*_{}\[\]<>|#~!])", r"\\\1", html.escape(text)).replace("@", "&#64;").replace(":", "&#58;")


def _format(title, sections, markdown):
    escaped = _markdown if markdown else str
    lines = [("# " if markdown else "") + escaped(title)]
    for heading, content in sections:
        if not content:
            continue
        if heading:
            lines.extend(("", ("## " if markdown else "") + escaped(heading)))
        for line in content:
            bullet = line.startswith("- ")
            lines.append(("- " if bullet else "") + escaped(line[2:] if bullet else line))
    return "\n".join(lines)


def _outcome(bundle, receipt):
    profile = receipt.get("profile")
    if profile == "observed-deletion":
        counts = Counter(c["status"] for c in receipt["checks"])
        return [f"Recorded copies: {counts['PRESENT']} present, {counts['ABSENT']} absent, {counts['UNKNOWN']} unknown."]
    if profile == "follow-up":
        verified = sum(item["status"] == "verified" for item in receipt["items"])
        return [f"Follow-up observations verified {verified} of {len(receipt['items'])} recorded items."]
    if profile == "discovery" or receipt["scope"] == "tenant":
        rows = receipt["services"] if profile == "discovery" else receipt["probes"]
        counts = Counter(r.get("status") or r.get("verdict") or "unknown" for r in rows)
        return ["Recorded results: " + ", ".join(f"{n} {label}" for label, n in sorted(counts.items())) + "."]
    folder = Path(bundle)
    if folder.is_file():
        folder = folder.parent
    evidence = receipt["evidence"]
    raw = read_regular_bytes(folder / evidence["file"], "summary evidence", MAX_BUNDLE_FILE_BYTES)
    require(sha256(raw).hexdigest() == evidence["sha256"], "Summary evidence changed after replay.")
    observed = json.loads(raw.decode(), object_pairs_hook=unique_fields)
    results = []
    for key, label in (("immediate", "After erasure"), ("final", "At the final read")):
        stage = observed[key]
        if stage is None:
            results.append(f"{label}, no observations were recorded.")
            continue
        answers = [row for row in stage["answers"] if row is not None]
        stores = [row for row in (*stage["stored"], *stage["discovered"]) if row is not None]
        for rows, name in ((stores, "stored records"), (answers, "answers")):
            target = Counter(row["target_present"] for row in rows)
            retained = sum(row["control_present"] is True for row in rows)
            results.append(f"{label}, {len(rows)} {name} were read. The deleted fact appeared in {target[True]}. "
                           f"{target[None]} readings were uncertain. The retained fact appeared in {retained}.")
    return results


def receipt_summary(bundle, *, audience="reviewer", output_format="text", case_id=None):
    require(audience in ("engineer", "reviewer", "customer") and output_format in ("text", "markdown"),
            "Choose an audience and output format.")
    require(not case_id or audience == "customer", "A display case number applies only to the customer copy.")
    receipt = replay(bundle)
    require(receipt.get("format") == FORMAT_V3, "Summaries require a replayable v3 evidence bundle.")
    outcomes = _outcome(bundle, receipt)
    controls = [f"- {row['framework']} / {row['reference']}" for row in receipt.get("controls", ())]
    if audience == "customer":
        title, *body = customer_text(receipt, case_id=case_id).splitlines()
        sections = [(None, body), ("Recorded observations", outcomes)]
    else:
        title = f"Deletion review for {receipt.get('request_id') or receipt.get('case_id') or receipt['run']}"
        sections = [("Decision", [f"Technical verdict {receipt['technical_verdict']}",
                                  f"Review status {receipt['review_status']}"])]
        if audience == "engineer":
            sections.append(("Observations", technical_summary(receipt).splitlines()))
            anchors = [f"- {item['store']}/{item['key']}  {', '.join(item['evidence'])}"
                       for item in receipt.get("artifact_checks", ())]
            evidence = receipt.get("evidence", {})
            if "file" in evidence:
                anchors.insert(0, f"{evidence['file']}  SHA-256 {evidence['sha256']}")
            sections.append(("Evidence", anchors))
        else:
            profile = receipt.get("profile") or receipt["scope"]
            scope = {"person": "Shared-record deletion drill", "tenant": "Tenant offboarding",
                     "discovery": "Discovery case", "observed-deletion": "Read-only verification",
                     "follow-up": "Open-item follow-up"}.get(profile, profile)
            sections.append(("Scope", [scope, *(["Worker race " + receipt["race"]] if receipt.get("race") else [])]))
            issues = [*receipt.get("failures", ()), *receipt.get("gaps", ())]
            issues.extend(f"{e['operation']} ({e['error']})" for e in receipt.get("errors", ()))
            sections.append(("Findings", ["- " + issue for issue in issues]))
        sections.append(("Recorded observations", outcomes))
        items = []
        for item in receipt["open_items"]:
            label = item.get("store") or item.get("service") or item.get("id") or "Follow-up"
            kind = item.get("kind") or item.get("status") or "review"
            owner = item.get("owner") or "unassigned"
            date = item.get("follow_up") or "unscheduled"
            items.append(f"- {label} ({kind})  owner {owner}  follow-up {date}")
        sections.append(("Open items", items or ["No open items recorded."]))
    if controls:
        sections.append(("Customer control references", ["The case owner supplied these references.", *controls]))
    return _format(title, sections, output_format == "markdown")
