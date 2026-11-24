"""Exercise a completed deletion ticket against a disposable PostgreSQL support app."""

import argparse
import os
import secrets
import subprocess
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from setrya.casework.profiles import new_bundle
from setrya.core.inputs import InvalidReport, publish_new, require
from setrya.erasure.journal import CopyJournal
from setrya.erasure.subject import Subject
from setrya.receipts import replay

_ADMIN_DSN = "SETRYA_PGVECTOR_DSN"
_OBSERVER_DSN = "SETRYA_RECEIPT_OBSERVER_DSN"
_CONTROL = "retained-support-note"
_STORE = "support-notes"
_LANES = (
    ("passed", "HD-101", 0),
    ("residual", "HD-102", 1),
    ("unavailable", "HD-103", 3),
)


@contextmanager
def _support_app(admin_dsn):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    name = "setrya_handoff_" + secrets.token_hex(8)
    namespace, table = sql.Identifier(name), sql.Identifier(name, "notes")
    password = secrets.token_hex(24)
    with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=5) as db:
        db.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(namespace, sql.Literal(password)))
        try:
            db.execute(sql.SQL("CREATE SCHEMA {}").format(namespace))
            try:
                db.execute(sql.SQL("CREATE TABLE {} (id TEXT PRIMARY KEY, body TEXT NOT NULL)").format(table))
                db.execute(sql.SQL("INSERT INTO {} VALUES (%s, %s)").format(table),
                           (_CONTROL, "Retained control for a different fictional customer."))
                db.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(namespace, namespace))
                db.execute(sql.SQL("GRANT SELECT(id) ON {} TO {}").format(table, namespace))
                observer_dsn = make_conninfo(admin_dsn, user=name, password=password)
                yield db, table, name, observer_dsn
            finally:
                db.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(namespace))
        finally:
            db.execute(sql.SQL("DROP ROLE {}").format(namespace))


def _complete_ticket(db, table, journal, subject, ticket, *, leave_summary):
    from psycopg import sql

    source = f"{ticket}-private-note"
    summary = f"{ticket}-private-summary"
    insert = sql.SQL("INSERT INTO {} VALUES (%s, %s)").format(table)
    db.execute(insert, (source, "Synthetic private support note."))
    db.execute(insert, (summary, "Synthetic private summary derived from the note."))
    journal.record(subject, store=_STORE, key=source, source="support-app", action="stored")
    journal.record(subject, store=_STORE, key=summary, source=source, action="derived")
    with db.transaction():
        query = sql.SQL("DELETE FROM {} WHERE id = %s").format(table)
        require(db.execute(query, (source,)).rowcount == 1, "The fixture did not delete its original note.")
        if not leave_summary:
            require(db.execute(query, (summary,)).rowcount == 1, "The fixture did not delete its derived summary.")
    return datetime.now(UTC).isoformat()


def _observe(ticket, frame, inventory, journal, output, env, expected_code):
    result = subprocess.run(
        [sys.executable, "-m", "setrya", "observe", "request", "--id", ticket,
         "--population", str(frame), "--inventory", str(inventory), "--journal", str(journal),
         "--receipt", str(output)],
        env=env, capture_output=True, timeout=45, check=False,
    )
    require(result.returncode == expected_code,
            f"The read-only observer returned {result.returncode} for {ticket}. Expected {expected_code}.")


def demo(output, *, admin_dsn):
    """Save only original observed-deletion bundles and an independent ticket record."""
    pins = {}
    subject_key = secrets.token_bytes(32)
    with new_bundle(output) as staged, TemporaryDirectory(prefix="setrya-postgres-handoff-") as private:
        scratch = Path(private)
        journal_path = scratch / "copies.sqlite"
        journal = CopyJournal(journal_path)
        with _support_app(admin_dsn) as (db, table, schema, observer_dsn):
            env = {**os.environ, _OBSERVER_DSN: observer_dsn}
            env.pop(_ADMIN_DSN, None)
            for lane, ticket, code in _LANES:
                subject = Subject.derive(subject_key, "support-sample", ticket, "synthetic")
                completed_at = _complete_ticket(db, table, journal, subject, ticket, leave_summary=lane == "residual")
                frame = scratch / f"{ticket}.json"
                digest = publish_new({"format": "setrya.completed-requests.v1", "requests": [
                    {"id": ticket, "subject_ref": subject.ref, "completed_at": completed_at, "stores": [_STORE]}
                ]}, frame)
                inventory = scratch / f"{ticket}.toml"
                control = "absent-visibility-control" if lane == "unavailable" else _CONTROL
                inventory.write_text(
                    f'[stores.{_STORE}]\nkind = "postgres"\nschema = "{schema}"\ntable = "notes"\n'
                    f'key_column = "id"\ndsn_env = "{_OBSERVER_DSN}"\ncontrol_key = "{control}"\n'
                    'owner = "support-platform"\n',
                    encoding="utf-8",
                )
                output_dir = staged / lane
                _observe(ticket, frame, inventory, journal_path, output_dir, env, code)
                receipt = replay(output_dir)
                require(receipt["request_id"] == ticket and receipt["frame_sha256"] == digest,
                        "The original receipt does not match the synthetic ticket.")
                pins[lane] = {"ticket_id": ticket, "frame_sha256": digest}
        publish_new(pins, staged / "ticket-pins.json")
    return pins


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory for synthetic evidence")
    args = parser.parse_args(argv)
    admin_dsn = os.environ.get(_ADMIN_DSN)
    if not admin_dsn:
        parser.error(f"Set {_ADMIN_DSN} to the admin DSN for a disposable test database.")
    try:
        from psycopg import Error
    except ImportError:
        parser.error("Install 'setrya[pgvector]' to run the PostgreSQL handoff.")
    try:
        for lane, pin in demo(args.output, admin_dsn=admin_dsn).items():
            receipt = replay(args.output / lane)
            print(f"{pin['ticket_id']} · {receipt['technical_verdict']} · {receipt['review_status']}")
    except InvalidReport as error:
        print(f"Handoff demo failed. {error}", file=sys.stderr)
        return 2
    except (Error, OSError, subprocess.TimeoutExpired):
        print("Handoff demo failed. Check the disposable database and output directory.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
