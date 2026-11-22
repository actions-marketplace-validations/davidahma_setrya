"""Portable read-only receipt envelopes. Replay never opens an application connection."""
from collections import Counter
from contextlib import contextmanager
from datetime import date, datetime
from hashlib import sha256
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from setrya.offboarding.inputs import publish_new, read_regular_bytes, require, unique_fields
from setrya.receipt_format import FORMAT_V3, MAX_BUNDLE_FILE_BYTES, RECEIPT

OBSERVED = "observed-deletion"
FOLLOWUP = "follow-up"
EVIDENCE = "observation-evidence.json"


def sha(value):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value), "Invalid evidence fingerprint.")
    return value


def stamp(value):
    require(isinstance(value, str), "Expected an ISO timestamp.")
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None, "Observation timestamps must include a timezone.")
    return result


def day(value):
    require(isinstance(value, str) and date.fromisoformat(value).isoformat() == value, "Invalid follow-up date.")
    return value


def fields(obj, names, optional=()):
    required = set(names.split())
    require(isinstance(obj, dict) and required <= set(obj) <= required | set(optional), "Invalid evidence fields.")


def snapshot(path, limit=MAX_BUNDLE_FILE_BYTES):
    require(not path.is_symlink(), "Evidence files must stay inside their bundle.")
    return read_regular_bytes(path, path.name, limit)


def decode(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)


@contextmanager
def new_bundle(output):
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), "Choose a fresh receipt directory.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output.parent) as temp:
        folder = Path(temp) / "bundle"
        folder.mkdir()
        yield folder
        # Claim a new destination before atomically publishing the completed bundle.
        output.mkdir()
        try:
            folder.replace(output)
        except OSError:
            output.rmdir()
            raise


def derive(profile, evidence, digest, folder):
    if profile == OBSERVED:
        from .observed import derive_observed
        result = derive_observed(evidence)
    else:
        require(profile == FOLLOWUP, "Unsupported observation profile.")
        from .recheck import derive_followup
        result = derive_followup(evidence, folder)
    return {"format": FORMAT_V3, "version": 3, "profile": profile, **result,
            "evidence": {"file": EVIDENCE, "sha256": digest}}


def issue(profile, evidence, folder):
    digest = publish_new(evidence, folder / EVIDENCE, max_bytes=MAX_BUNDLE_FILE_BYTES)
    result = derive(profile, evidence, digest, folder)
    publish_new(result, folder / RECEIPT, max_bytes=MAX_BUNDLE_FILE_BYTES)
    return result


def replay_bytes(directory, raw):
    receipt = decode(raw)
    evidence = snapshot(directory / EVIDENCE)
    result = derive(receipt["profile"], decode(evidence), sha256(evidence).hexdigest(), directory)
    require(json.dumps(receipt, sort_keys=True) == json.dumps(result, sort_keys=True),
            "Receipt differs from its read-only evidence.")
    return result


def summary(receipt):
    lines = [f"Technical verdict {receipt['technical_verdict']} · Review status {receipt['review_status']}"]
    if receipt["profile"] == OBSERVED:
        counts = Counter(c["status"] for c in receipt["checks"])
        lines.append(f"Observed deletion request {receipt['request_id']}. Examined {len(receipt['checks'])} journalled keys "
                     f"({counts['ABSENT']} absent, {counts['PRESENT']} present, {counts['UNKNOWN']} unknown).")
        lines.append("Scope covers the mapped journalled keys. The observer used direct reads only.")
        lines.extend("Gap: " + gap for gap in receipt["gaps"])
    else:
        verified = sum(i["status"] == "verified" for i in receipt["items"])
        lines.append(f"Follow-up for receipt {receipt['parent_sha256']}. Original verdict {receipt['original_verdict']}.")
        lines.append(f"{verified} items verified; {len(receipt['items']) - verified} still open.")
    return "\n".join(lines)
