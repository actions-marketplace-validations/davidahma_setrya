"""Verify copy events against a durable SQLite checkpoint."""

from contextlib import closing, contextmanager
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3

from .inputs import require

ZERO = "0" * 64
MAX_ROWS = 200_000
MAX_BYTES = 128 * 1024 * 1024
_HASH_FIELDS = {"prev_hash", "row_hash"}


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return sha256(raw.encode("ascii")).hexdigest()


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def migrate(db, columns):
    if _HASH_FIELDS & columns:
        require(_HASH_FIELDS <= columns, "Incomplete copy chain columns.")
        head(db)
        return
    start = db.execute("SELECT coalesce(max(event), 0) + 1 FROM copy_events").fetchone()[0]
    db.execute("ALTER TABLE copy_events ADD COLUMN prev_hash TEXT")
    db.execute("ALTER TABLE copy_events ADD COLUMN row_hash TEXT")
    db.execute("""CREATE TABLE copy_chain (
        id INTEGER PRIMARY KEY CHECK(id=1), first_event INTEGER NOT NULL,
        last_event INTEGER NOT NULL, head TEXT NOT NULL
    )""")
    db.execute("INSERT INTO copy_chain VALUES (1,?,?,?)", (start, start - 1, ZERO))


def head(db):
    table = db.execute("SELECT type FROM main.sqlite_schema WHERE name='copy_chain'").fetchone()
    require(table == ("table",), "Missing the journal chain checkpoint.")
    rows = db.execute("SELECT id,first_event,last_event,head FROM main.copy_chain LIMIT 2").fetchall()
    require(len(rows) == 1 and rows[0][0] == 1, "Invalid journal chain checkpoint.")
    first, last, anchor = rows[0][1:]
    require(type(first) is int and type(last) is int and 1 <= first <= last + 1 and is_digest(anchor),
            "Invalid journal chain checkpoint.")
    return first, last, anchor


def row_hash(previous, sequence, columns):
    return digest(["setrya.copy-chain.v1", previous, sequence, list(columns)])


def check_summary(value):
    require(isinstance(value, dict) and value.keys() == {"status", "first_event", "last_event", "head"},
            "Invalid journal chain evidence.")
    first, last, anchor = value["first_event"], value["last_event"], value["head"]
    status = value["status"]
    require(type(first) is int and type(last) is int and first > 0
            and ((status == "unchained" and last == first - 1 and anchor is None)
                 or (status == ("verified" if first == 1 else "partial")
                     and first <= last and is_digest(anchor))), "Invalid journal chain evidence.")


def verify_snapshot(db, fields):
    table = db.execute("SELECT type FROM main.sqlite_schema WHERE name='copy_events'").fetchone()
    require(table == ("table",), "Expected a physical copy journal.")
    columns = {cell[1] for cell in db.execute("PRAGMA main.table_xinfo(copy_events)")}
    if not _HASH_FIELDS & columns:
        require(not db.execute("SELECT 1 FROM main.sqlite_schema WHERE name='copy_chain'").fetchone(),
                "Missing hash columns in a chained journal.")
        last = db.execute("SELECT coalesce(max(event),0) FROM main.copy_events").fetchone()[0]
        return {"status": "unchained", "first_event": last + 1, "last_event": last, "head": None}

    require(_HASH_FIELDS <= columns and set(fields.split(", ")) <= columns, "Incomplete copy chain columns.")
    first, last, anchor = head(db)
    pending, previous, size = first, ZERO, 0
    require(last - first < MAX_ROWS, "Journal exceeds the verification row budget.")
    require(not db.execute("SELECT 1 FROM main.copy_events WHERE event < ? AND "
                           "(prev_hash IS NOT NULL OR row_hash IS NOT NULL) LIMIT 1", (first,)).fetchone(),
            "Journal contains chained rows before the checkpoint.")
    for seq, *values, stored_prev, stored_hash in db.execute(
            f"SELECT event,subject,{fields},prev_hash,row_hash FROM main.copy_events "
            "WHERE event >= ? ORDER BY event", (first,)):
        size += sum(len(cell.encode("utf-8")) for cell in values if isinstance(cell, str)) + 128
        require(seq <= last and size <= MAX_BYTES, "Journal exceeds its checkpoint or verification budget.")
        require(seq == pending and stored_prev == previous and is_digest(stored_hash)
                and stored_hash == row_hash(previous, seq, values), "Journal chain mismatch.")
        pending += 1
        previous = stored_hash
    require(pending == last + 1 and anchor == previous, "Missing journal rows or a changed chain checkpoint.")
    status = "unchained" if first > last else "verified" if first == 1 else "partial"
    return {"status": status, "first_event": first, "last_event": last, "head": anchor if first <= last else None}


@contextmanager
def reader(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "Choose an existing local journal file.")
    with closing(sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4 * 1024 * 1024)
        db.execute("BEGIN")
        yield db
