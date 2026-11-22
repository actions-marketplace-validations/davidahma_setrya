"""Append-only, local SQLite inventory of observed subject-linked copies."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Mapping
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .errors import InputError
from .inputs import require

from .subject import Subject, Turn, _TURN_FIELDS, identifier
from . import journal_chain


_trace_observer = None
_ACTIONS = {"retrieved", "stored", "derived", "sent"}
_COPY_FIELDS = "store, copy_key, source, action, classification, observed_at, details"
_FIELDS = _COPY_FIELDS + ", " + ", ".join(_TURN_FIELDS.values())


def validate_details(values: Mapping | None) -> dict:
    if values is not None and not isinstance(values, Mapping):
        raise InputError("copy details must be a mapping")
    fields = dict(values or {})
    if {"provider", "model", "region", "invocation_logging", "prompt_caching"} & fields.keys():
        if fields.get("evidence_level", "configuration") != "configuration":
            raise InputError("provider settings support configuration evidence only")
        fields["evidence_level"] = "configuration"
    if {"boundary", "boundary_kind"} & fields.keys():
        identifier(fields.get("boundary"), "observed boundary")
        if fields.get("boundary_kind") not in ("trace", "namespace"):
            raise InputError("observed boundary requires kind trace or namespace")
    for key, value in fields.items():
        if key in {"invocation_logging", "prompt_caching"}:
            if value is not None and type(value) is not bool:
                raise InputError(f"{key} must be a boolean or unknown (None)")
        elif key in {"model", "provider", "region", "tool", "direction", "stage", "evidence_level", "operation", "boundary", "boundary_kind", "revision"}:
            if value is not None:
                identifier(value, key)
        elif key == "payload_hmac":
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise InputError("invalid payload HMAC")
        elif key in {"sources", "components"}:
            if not isinstance(value, (list, tuple)) or len(value) > 1024:
                raise InputError(f"{key} must be a bounded list of opaque identifiers")
            fields[key] = [identifier(v, "source identifier") for v in value]
        else:
            raise InputError("unsupported copy detail field")
    return fields


@dataclass(frozen=True, slots=True)
class Copy:
    store: str
    key: str
    source: str
    action: str
    classification: str
    observed_at: str
    details: dict

    def wire(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TurnCopy(Copy):
    turn: str
    initiator: str
    agent: str
    on_behalf_of: str | None = None
    parent_turn: str | None = None

    def wire(self):
        values = asdict(self)
        return {field: value for field, value in values.items() if value is not None}


def _copy_from_row(row):
    values = (*row[:6], json.loads(row[6]))
    fields = dict(zip(_TURN_FIELDS.values(), row[7:], strict=True))
    turn = Turn.from_copy_fields(fields)
    return TurnCopy(*values, **turn.copy_fields()) if turn else Copy(*values)


class CopyJournal:
    def __init__(self, path: str | Path, *, export_trace_events: bool = False):
        if type(export_trace_events) is not bool:
            raise InputError("export_trace_events must be a boolean")
        if export_trace_events and _trace_observer is None:
            raise InputError("enable trace export through setrya.erasure")
        self.export_trace_events = export_trace_events
        self.path = Path(path)
        # SQLite opens new files with the caller's umask. Restrict the new file
        # before SQLite creates its schema, including when two workers race.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""CREATE TABLE IF NOT EXISTS copy_events (
                event INTEGER PRIMARY KEY, subject TEXT NOT NULL, store TEXT NOT NULL,
                copy_key TEXT NOT NULL, source TEXT NOT NULL, action TEXT NOT NULL,
                classification TEXT NOT NULL, observed_at TEXT NOT NULL, details TEXT NOT NULL
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(copy_events)")}
            for column in _TURN_FIELDS.values():
                if column not in columns:
                    db.execute(f"ALTER TABLE copy_events ADD COLUMN {column} TEXT")
            journal_chain.migrate(db, columns)
            db.execute("CREATE INDEX IF NOT EXISTS by_turn ON copy_events(turn, event)")
            db.execute("CREATE INDEX IF NOT EXISTS by_subject ON copy_events(subject, store, copy_key)")

    def record_boundary(self, subject: Subject, *, store: str, kind: str, name: str) -> None:
        """Record a store that was read, including when the read found no subject copy."""
        if not isinstance(subject, Subject):
            raise InputError("expected a Subject for the inspected boundary")
        identifier(store, "store")
        details = validate_details({"boundary_kind": kind, "boundary": name})
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS observed_boundaries (
                subject TEXT NOT NULL, store TEXT NOT NULL, details TEXT NOT NULL,
                PRIMARY KEY(subject, store, details)
            ) WITHOUT ROWID""")
            db.execute("INSERT OR IGNORE INTO observed_boundaries(subject,store,details) VALUES(?,?,?)",
                       (subject.ref, store, json.dumps(details, sort_keys=True, separators=(",", ":"))))

    def record(self, subject: Subject, *, store: str, key: str, source: str, action: str,
               details: Mapping | None = None) -> Copy:
        if not isinstance(subject, Subject) or action not in _ACTIONS:
            raise InputError("expected a Subject and a copy action (retrieved, sent, stored, derived)")
        turn = Turn.current()
        turn_fields = turn.copy_fields() if turn else {}
        row = (TurnCopy if turn else Copy)(identifier(store, "store"), identifier(key, "copy key"), identifier(source, "source"),
                   action, subject.classification, datetime.now(timezone.utc).isoformat(), validate_details(details),
                   **turn_fields)
        details_json = json.dumps(row.details, separators=(",", ":"), sort_keys=True)
        values = (subject.ref, row.store, row.key, row.source, row.action, row.classification,
                  row.observed_at, details_json, *(turn_fields.get(field) for field in _TURN_FIELDS.values()))
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            _, last, prior = journal_chain.head(db)
            sequence = last + 1
            current = journal_chain.row_hash(prior, sequence, values)
            db.execute(f"INSERT INTO copy_events(event,subject,{_FIELDS},prev_hash,row_hash) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sequence, *values, prior, current))
            db.execute("UPDATE copy_chain SET last_event=?,head=? WHERE id=1", (sequence, current))
        if self.export_trace_events:
            attributes = {**subject.metadata(), **(turn.metadata() if turn else {}), **self._trace_identity(sequence),
                          "store": row.store, "copy_key": row.key, "source": row.source, "action": row.action,
                          "observed_at": row.observed_at, "details_json": details_json}
            _trace_observer("setrya.copy.v1", attributes)
        return row

    def _trace_identity(self, sequence):
        return {}

    def _read(self, subject, latest, max_bytes=None):
        with journal_chain.reader(self.path) as db:
            return self._rows(db, subject, latest, max_bytes)

    @staticmethod
    def _rows(db, subject, latest, max_bytes=None):
        if not isinstance(subject, Subject):
            raise InputError("expected a Subject")
        where = ("event IN (SELECT MAX(event) FROM copy_events WHERE subject=? GROUP BY store, copy_key)"
                 if latest else "subject=?")
        order = "store, copy_key" if latest else "event"
        if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 1):
            raise InputError("expected a positive journal byte budget")
        rows = []
        size = 0
        for row in db.execute(f"SELECT {_FIELDS} FROM copy_events WHERE {where} ORDER BY {order}", (subject.ref,)):
            if max_bytes is not None:
                size += sum(len(field.encode()) for field in row if field is not None) + 100
                if size > max_bytes:
                    raise InputError("subject history exceeds the drill journal budget")
            rows.append(_copy_from_row(row))
        return tuple(rows)

    def verified_history(self, subject, *, max_bytes=None):
        """Read a verified chain checkpoint and subject observations in the same snapshot."""
        with journal_chain.reader(self.path) as db:
            return journal_chain.verify_snapshot(db, _FIELDS), self._rows(db, subject, False, max_bytes)

    def mark(self):
        """Record the current durable chain position without copying journal rows."""
        with journal_chain.reader(self.path) as db:
            return journal_chain.head(db)

    def verified_window(self, subject, start, stop, *, max_bytes=None):
        """Read the evidence and locate a pair of earlier marks in its verified chain."""
        with journal_chain.reader(self.path) as db:
            head = journal_chain.verify_snapshot(db, _FIELDS)
            offsets = []
            for first, sequence, digest in (start, stop):
                require(first == head["first_event"] and first - 1 <= sequence <= head["last_event"],
                        "Journal marks no longer refer to the observed chain.")
                if sequence == first - 1:
                    actual = (journal_chain.ZERO,)
                else:
                    actual = db.execute("SELECT row_hash FROM copy_events WHERE event=?", (sequence,)).fetchone()
                require(actual == (digest,), "Journal marks no longer refer to the observed chain.")
                count = db.execute("SELECT count(*) FROM copy_events WHERE subject=? AND event<=?",
                                   (subject.ref, sequence)).fetchone()[0]
                offsets.append(count)
            require(offsets[0] <= offsets[1], "Journal marks are out of order.")
            rows = self._rows(db, subject, False, max_bytes)
            return head, rows, {"start": offsets[0], "stop": offsets[1]}

    def copies(self, subject: Subject) -> tuple[Copy, ...]:
        """Return one entry for each reported physical location, with its latest observation."""
        return self._read(subject, latest=True)

    def history(self, subject: Subject, *, max_bytes: int | None = None) -> tuple[Copy, ...]:
        """Keep the original sequence when several operations touched the same location."""
        return self._read(subject, latest=False, max_bytes=max_bytes)
