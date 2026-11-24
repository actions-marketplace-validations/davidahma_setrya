"""Names and limits shared by replayable erasure bundles."""
from datetime import datetime
import re

from .inputs import require

FORMAT_V3 = "setrya.erasure.receipt.v3"
RECEIPT = "erasure-receipt.json"
MAX_BUNDLE_FILE_BYTES = 16 * 1024 * 1024

EVIDENCE = "erasure-evidence.json"
EXIT = {"PASS": 0, "FAIL": 1, "ERROR": 2, "NOT TESTED": 3}


def _hex(value, length):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value)


def _timestamp(value):
    require(isinstance(value, str), "Missing evidence timestamp.")
    stamp = datetime.fromisoformat(value)
    require(stamp.utcoffset() is not None, "Evidence timestamps need an offset.")
    return stamp
