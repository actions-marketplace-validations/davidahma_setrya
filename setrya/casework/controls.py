"""Customer-supplied control identifiers attached to the observations in a receipt."""
import re

from setrya.offboarding.inputs import require


# A control is an identifier suitable for display, not free-form contractual text.
REFERENCE = r"[A-Za-z0-9](?:[A-Za-z0-9 .:/()_-]{0,94}[A-Za-z0-9)])?"


def validate_controls(value):
    require(isinstance(value, list) and 1 <= len(value) <= 32, "Declare one to 32 control references.")
    seen = set()
    rows = []
    for row in value:
        require(isinstance(row, dict) and set(row) == {"framework", "reference"}, "Invalid control reference fields.")
        for field in ("framework", "reference"):
            require(isinstance(row[field], str) and re.fullmatch(REFERENCE, row[field]), "Invalid control reference.")
        pair = row["framework"], row["reference"]
        require(pair not in seen, "Duplicate control reference.")
        seen.add(pair)
        rows.append(dict(row))
    return rows
