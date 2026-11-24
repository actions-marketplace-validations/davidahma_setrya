"""Observe EDK references in ciphertext envelopes from a read-only SQLite snapshot."""
import re
import sqlite3
import time
from hashlib import sha256
from io import BytesIO
from pathlib import Path

from setrya.erasure.adapters import _sql_name
from setrya.offboarding.inputs import require

from ._crypto_aws import key_parts
from .profiles import fields, sha
from .stores import _sqlite_table, sqlite_reader

MAX_COPIES = 512
_MAX_CIPHERTEXT = 16 * 1024 * 1024
_MAX_READ_BYTES = 64 * 1024 * 1024


def store_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value),
            "Invalid crypto-erasure store or owner identifier.")
    return value


def inventory(config):
    fields(config, "format subject_ref retained_ref key_arn retained_key_arn owner recovery_scope stores")
    require(config["format"] == "setrya.crypto-inventory.v1" and config["recovery_scope"] == "exclusive-kms-key",
            "Declare whether the in-scope ciphertext uses an exclusive KMS recovery key.")
    store_id(config["owner"])
    require(sha(config["subject_ref"]) != sha(config["retained_ref"]), "Use a distinct retained control subject.")
    target, retained = config["key_arn"], config["retained_key_arn"]
    require(key_parts(target)[:2] == key_parts(retained)[:2] and target != retained,
            "Select a distinct retained key in the same AWS account and Region.")
    stores = config["stores"]
    require(isinstance(stores, dict) and 0 < len(stores) <= 16, "Declare one to 16 ciphertext stores.")
    for name, store in stores.items():
        store_id(name)
        fields(store, "database table")
        _sql_name(store["table"])
        require(isinstance(store["database"], str) and 0 < len(store["database"]) <= 1024
                and store["database"].isprintable(), "Supply an existing SQLite database path.")


def _wrapping_key(blob):
    """Read a version 2 AWS Encryption SDK header, rejecting alternate EDKs."""
    stream = BytesIO(blob)

    def take(n):
        value = stream.read(n)
        require(len(value) == n, "Incomplete ciphertext envelope.")
        return value

    def integer(n):
        return int.from_bytes(take(n), "big")

    def field():
        return take(integer(2))

    require(take(3) in (b"\x02\x04\x78", b"\x02\x05\x78"), "Use the AWS Encryption SDK version 2 message format.")
    take(32)  # Message ID
    field()  # Additional authenticated data
    require(integer(2) == 1 and field() == b"aws-kms", "Use a single AWS KMS encrypted data key.")
    arn = field().decode("ascii")
    key_parts(arn)
    require(bool(field()), "Missing encrypted data key.")
    content_type, frame_length = integer(1), integer(4)
    require((content_type == 1 and frame_length == 0) or (content_type == 2 and frame_length > 0),
            "Invalid AWS Encryption SDK content format.")
    take(32 + 16)  # Key commitment and header authentication tag
    take(36 if content_type == 1 else 40)  # Minimum message body framing and authentication tag
    return arn


def observe_store(config, base, store, expected):
    """Read both subjects and re-check captured copy keys even after retagging."""
    settings = config["stores"][store]
    table = _sql_name(settings["table"])
    path = Path(base) / settings["database"]
    with sqlite_reader(path) as conn:
        _sqlite_table(conn, settings["table"])
        columns = {row[1]: (row[2].upper(), row[3], row[5])
                   for row in conn.execute(f"PRAGMA main.table_info({table})")}
        require([column for column, (_, _, order) in columns.items() if order] == ["copy_ref"]
                and columns["copy_ref"][0] == "TEXT" and columns.get("subject_ref") == ("TEXT", 1, 0)
                and columns.get("ciphertext") == ("BLOB", 1, 0),
                "Ciphertext storage requires a single TEXT copy_ref key and non-null subject_ref and ciphertext fields.")
        stop = time.monotonic() + 5
        conn.set_progress_handler(lambda: int(time.monotonic() > stop), 10_000)
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_CIPHERTEXT + 4096)
        fixtures = [config["subject_ref"], config["retained_ref"], *expected]
        lookup = ""
        if expected:
            lookup = " OR copy_ref COLLATE BINARY IN (" + ",".join("?" for _ in expected) + ")"
        try:
            malformed = conn.execute(f"""
                SELECT 1 FROM main.{table}
                WHERE typeof(copy_ref) != 'text' OR typeof(subject_ref) != 'text' LIMIT 1
            """).fetchone()
            require(malformed is None, "Ambiguous SQLite subject or ciphertext key encoding.")
            rows = conn.execute(f"""
                SELECT copy_ref, subject_ref, ciphertext FROM main.{table}
                WHERE subject_ref COLLATE BINARY IN (?, ?) {lookup} LIMIT {MAX_COPIES * 2 + 2}
            """, fixtures)
            targets, control, seen = {}, None, set()
            total = 0
            for copy_ref, subject_ref, blob in rows:
                sha(copy_ref)
                sha(subject_ref)
                require(copy_ref not in seen and len(seen) <= MAX_COPIES * 2, "Duplicate or excess ciphertext rows.")
                seen.add(copy_ref)
                require(isinstance(blob, bytes) and 0 < len(blob) <= _MAX_CIPHERTEXT, "Invalid ciphertext size.")
                total += len(blob)
                require(total <= _MAX_READ_BYTES, "Store exceeded the ciphertext observation byte limit.")
                reading = {"key_sha256": copy_ref, "ciphertext_sha256": sha256(blob).hexdigest(),
                           "key_arn": _wrapping_key(blob)}
                if subject_ref == config["retained_ref"]:
                    require(control is None and copy_ref not in expected, "Retained control copy is not distinct.")
                    require(reading["key_arn"] == config["retained_key_arn"], "Retained copy names the wrong key.")
                    control = reading
                else:
                    require(subject_ref == config["subject_ref"], "A captured copy changed subjects.")
                    targets[copy_ref] = reading
        finally:
            conn.set_progress_handler(None, 0)
    require(control is not None, "Retained ciphertext could not be read.")
    return {"control": control, "copies": [targets[key] for key in sorted(targets)]}
