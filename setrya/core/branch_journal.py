"""Store copy ancestry alongside the subject-level copy journal."""
from contextlib import closing
from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3

from . import journal_chain
from .errors import InputError
from .inputs import require, unique_fields
from .subject import Turn, identifier

MAX_BRANCHES = 1024


def branch(parent, child, as_of, *, turn=None):
    parent = identifier(parent, "parent store")
    child = identifier(child, "child store")
    require(parent != child, "A branch cannot derive from itself.")
    if as_of is not None:
        if isinstance(as_of, datetime):
            as_of = as_of.isoformat()
        require(isinstance(as_of, str), "Branch snapshot time needs an ISO timestamp.")
        timestamp = datetime.fromisoformat(as_of)
        require(timestamp.tzinfo is not None, "Branch snapshot time needs a timezone.")
        as_of = timestamp.astimezone(UTC).isoformat()
    require(turn is None or isinstance(turn, Turn), "Expected a Setrya Turn.")
    return {"parent": parent, "child": child, "as_of": as_of,
            **({"turn": turn.copy_fields()} if turn is not None else {})}


def validate_branch(value):
    keys = {"parent", "child", "as_of"}
    require(isinstance(value, dict) and keys <= value.keys() <= keys | {"turn"}, "Invalid branch ancestry event.")
    turn = Turn.from_copy_fields(value["turn"]) if "turn" in value else None
    require(value == branch(value["parent"], value["child"], value["as_of"], turn=turn),
            "Invalid branch ancestry event.")


def check_graph(edges):
    visited = set()
    for child in edges:
        pending, ancestor = set(), child
        while ancestor in edges and ancestor not in visited:
            require(ancestor not in pending, "Store branch ancestry contains a cycle.")
            pending.add(ancestor)
            ancestor = edges[ancestor]["parent"]
        visited.update(pending)


def _hash_event(previous, sequence, edge):
    return journal_chain.digest(["setrya.store-branch-chain.v1", previous, sequence, edge])


def branch_head(edges):
    """Fingerprint the ordered branch exhibits for an independent checkpoint."""
    head = journal_chain.ZERO
    for sequence, edge in enumerate(edges, start=1):
        head = _hash_event(head, sequence, edge)
    return head


def record_branch(path, parent, child, as_of, turn=None):
    """Append an immutable child identity after the application creates a copy."""
    require(as_of is not None, "Journalled branches need a source snapshot time.")
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "Choose an existing copy journal.")
    row = branch(parent, child, as_of, turn=Turn.current() if turn is None else turn)
    require(datetime.fromisoformat(row["as_of"]) <= datetime.now(UTC), "Branch snapshot time cannot be in the future.")
    try:
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN IMMEDIATE")
            rows, checkpoint = verify_branches(db)
            if not checkpoint["last_event"]:
                db.execute("""CREATE TABLE IF NOT EXISTS store_branches (
                    event INTEGER PRIMARY KEY, child TEXT NOT NULL UNIQUE, edge TEXT NOT NULL,
                    previous TEXT NOT NULL, digest TEXT NOT NULL
                )""")
                db.execute("""CREATE TABLE IF NOT EXISTS store_branch_chain (
                    id INTEGER PRIMARY KEY CHECK (id=1), last_event INTEGER NOT NULL, head TEXT NOT NULL
                )""")
                db.execute("INSERT INTO store_branch_chain VALUES (1,0,?)", (journal_chain.ZERO,))
            edges = {edge["child"]: edge for edge in rows}
            require(row["child"] not in edges and len(edges) < MAX_BRANCHES,
                    "The branch identity already exists or the journal is full.")
            edges[row["child"]] = row
            check_graph(edges)
            sequence = checkpoint["last_event"] + 1
            digest = _hash_event(checkpoint["head"], sequence, row)
            db.execute("INSERT INTO store_branches VALUES (?,?,?,?,?)",
                       (sequence, row["child"], json.dumps(row, sort_keys=True), checkpoint["head"], digest))
            db.execute("UPDATE store_branch_chain SET last_event=?,head=? WHERE id=1", (sequence, digest))
    except sqlite3.IntegrityError as exc:
        raise InputError("This branch child identity has already been recorded.") from exc
    return row


def verify_branches(db):
    """Check both the ordered event rows and the durable head in one SQLite read."""
    copy_table = db.execute("SELECT type FROM main.sqlite_schema WHERE name='copy_events'").fetchone()
    require(copy_table == ("table",), "Expected a physical copy journal for branch ancestry.")
    tables = dict(db.execute("SELECT name,type FROM main.sqlite_schema "
                             "WHERE name IN ('store_branches','store_branch_chain')"))
    if not tables:
        return [], {"last_event": 0, "head": journal_chain.ZERO}
    require(tables == {"store_branches": "table", "store_branch_chain": "table"},
            "Expected a physical store branch journal and chain checkpoint.")
    checkpoints = db.execute("SELECT id,last_event,head FROM main.store_branch_chain LIMIT 2").fetchall()
    require(len(checkpoints) == 1 and checkpoints[0][0] == 1, "Invalid store branch checkpoint.")
    _, last_event, head = checkpoints[0]
    require(type(last_event) is int and 1 <= last_event <= MAX_BRANCHES and journal_chain.is_digest(head),
            "Invalid store branch checkpoint.")
    records = db.execute("SELECT event,child,edge,previous,digest FROM main.store_branches ORDER BY event LIMIT ?",
                         (MAX_BRANCHES + 1,)).fetchall()
    require(len(records) == last_event, "Store branch events differ from the saved checkpoint.")
    result, previous = [], journal_chain.ZERO
    for expected, (sequence, child, raw, anchor, digest) in enumerate(records, start=1):
        require(sequence == expected and anchor == previous and isinstance(raw, str) and len(raw) <= 10_000,
                "Malformed or missing store branch journal event.")
        edge = json.loads(raw, object_pairs_hook=unique_fields)
        validate_branch(edge)
        require(edge["child"] == child and digest == _hash_event(previous, sequence, edge),
                "Store branch journal event fingerprint changed.")
        result.append(edge)
        previous = digest
    require(head == previous, "Store branch head differs from the saved checkpoint.")
    return result, {"last_event": last_event, "head": head}


def read_branch_snapshot(path):
    with journal_chain.reader(path) as db:
        return verify_branches(db)


def read_branches(path):
    return read_branch_snapshot(path)[0]
