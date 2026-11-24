"""Direct existence reads. Neither backend accepts SQL or callbacks from a request."""
from contextlib import closing, contextmanager
from datetime import date
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import tomllib

from setrya.core.journal import _FIELDS
from setrya.core.journal_chain import verify_snapshot
from setrya.erasure.journal_merge import verify_seals
from setrya.erasure.adapters import _require_sqlite_base_table, _sql_name
from setrya.erasure.journal import identifier
from setrya.offboarding.inputs import read_regular_bytes, require


def inventory(path):
    return observer_config(path)[0]


def observer_config(path):
    config = tomllib.loads(read_regular_bytes(path, "observer inventory").decode())
    require({"stores"} <= set(config) <= {"stores", "journal"} and isinstance(config["stores"], dict)
            and 0 < len(config["stores"]) <= 64, "Declare 1 to 64 observer stores.")
    for name, spec in config["stores"].items():
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name)
                and isinstance(spec, dict), "Invalid store alias.")
        common = {"kind", "table", "key_column", "control_key"}
        kind = spec.get("kind")
        require(kind in ("sqlite", "postgres"), "Observer stores must be sqlite or postgres.")
        fields = {"path"} if kind == "sqlite" else {"dsn_env", "schema"}
        optional = {"owner", "follow_up", "subject_column", "control_subject_ref"}
        require(common | fields <= set(spec) <= common | fields | optional, "Unexpected or missing observer store settings.")
        require(("subject_column" in spec) == ("control_subject_ref" in spec),
                "Scope scans need both a subject column and its retained control reference.")
        if "subject_column" in spec:
            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", spec["subject_column"])
                    and re.fullmatch(r"[0-9a-f]{64}", spec["control_subject_ref"]),
                    "Supply a subject column and tenant-bound retained control reference.")
        if "owner" in spec:
            identifier(spec["owner"], "observer owner")
        if "follow_up" in spec:
            require(date.fromisoformat(spec["follow_up"]).isoformat() == spec["follow_up"], "Supply an ISO follow-up date.")
        require(all(isinstance(v, str) and 0 < len(v) <= 1024 and v.isprintable() for v in spec.values()),
                "Invalid observer settings.")
        for field in ("table", "key_column", *(("schema",) if kind == "postgres" else ())):
            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", spec[field]),
                    "Use simple SQL identifiers for the observed relation.")
        if kind == "sqlite":
            spec["path"] = Path(path).parent / spec["path"]
        else:
            require(re.fullmatch(r"[A-Z_][A-Z0-9_]{0,95}", spec["dsn_env"]),
                    "Supply the environment variable name for a read-only PostgreSQL connection.")
    roster = config.get("journal")
    if roster is not None:
        require(isinstance(roster, dict) and set(roster) == {"run_id", "expected_producers"},
                "A distributed observer needs a run ID and its expected producer list.")
        identifier(roster["run_id"], "journal run")
        names = roster["expected_producers"]
        require(isinstance(names, list) and 0 < len(names) <= 64
                and all(identifier(name, "producer") for name in names) and len(set(names)) == len(names),
                "Declare each expected producer once, up to 64.")
    return config["stores"], roster


@contextmanager
def sqlite_reader(path):
    """Read the current rollback-mode DB under a SQLite read lock; avoid WAL sidecar writes."""
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink(), "The observer needs an existing SQLite file.")
    with path.open("rb") as source:
        header = source.read(20)
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode) and header[:16] == b"SQLite format 3\x00"
                and header[18:20] == b"\x01\x01", "Use a rollback-mode SQLite database for read-only observation.")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3)) as conn:
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        require(conn.execute("PRAGMA journal_mode").fetchone()[0] != "wal",
                "Use a rollback-mode SQLite database for read-only observation.")
        yield conn


def _sqlite_table(conn, name):
    _require_sqlite_base_table(conn, _sql_name(name))


class IncompleteProducerCoverage(ValueError):
    """A distributed journal cannot establish complete subject coverage."""


def collector_scope(conn, subject, roster):
    """Bind the subject to the expected sealed packets before permitting any absence claim."""
    binding = conn.execute("SELECT role,run_id,producer FROM main.journal_binding LIMIT 2").fetchall()
    if roster is None or binding != [("collector", roster["run_id"], None)]:
        raise IncompleteProducerCoverage("Supply a collector and its configured run and producer list.")
    for table in ("collected_events", "collected_seals"):
        _sqlite_table(conn, table)
    seals = conn.execute("SELECT producer,digest FROM main.collected_seals WHERE ref=? ORDER BY producer LIMIT 65",
                         (subject,)).fetchall()
    observed = conn.execute("SELECT DISTINCT producer FROM main.collected_events WHERE ref=? LIMIT 65",
                            (subject,)).fetchall()
    expected = set(roster["expected_producers"])
    if {name for name, _ in seals} != expected or not {name for name, in observed} <= expected:
        raise IncompleteProducerCoverage("Expected a sealed packet from every declared producer and no other producers.")
    verify_seals(conn, roster["run_id"], subject)
    require(all(isinstance(digest, str) and re.fullmatch("[0-9a-f]{64}", digest) for _, digest in seals),
            "Invalid sealed packet digest.")
    return sha256(json.dumps([subject, roster["run_id"], seals], separators=(",", ":")).encode()).hexdigest()


def journal_rows(conn, subject_ref, roster=None):
    names = {name for name, in conn.execute("SELECT name FROM main.sqlite_schema WHERE name IN "
                                            "('copy_events','collected_events','collected_seals','journal_binding')")}
    collected = bool(names - {"copy_events"})
    scope = None
    sources = []
    if "copy_events" in names:
        _sqlite_table(conn, "copy_events")
        verify_snapshot(conn, _FIELDS)
        sources.append("SELECT event,subject,store,copy_key,action FROM main.copy_events")
    if collected:
        _sqlite_table(conn, "journal_binding")
        scope = collector_scope(conn, subject_ref, roster)
        sources.append("""SELECT NULL,ref,json_extract(record,'$.store'),json_extract(record,'$.key'),
                          json_extract(record,'$.action') FROM main.collected_events""")
    if roster is not None and not collected:
        raise IncompleteProducerCoverage("The journal mapping declares a distributed collector.")
    require(sources, "Missing the declared copy journal.")
    direct_events = " UNION ALL ".join(sources)
    lineage = {"lineage_versions", "lineage_inputs", "lineage_subjects"}
    installed = {r[0] for r in conn.execute(
        "SELECT name FROM main.sqlite_schema WHERE name IN ('lineage_versions','lineage_inputs','lineage_subjects')"
    )}
    require(not installed or installed == lineage, "Incomplete version-lineage journal.")
    for table in installed:
        _sqlite_table(conn, table)

    # CopyJournal and VersionLineage share a database. Start at the target's
    # versions, follow every derived revision, then check all owners of each
    # physical key (including other subjects' revisions and direct copy events).
    graph = """
        affected(id) AS (
            SELECT version FROM lineage_subjects WHERE subject = :subject
            UNION SELECT i.artifact FROM affected a JOIN lineage_inputs i ON i.input = a.id
        ),
        derived(store, copy_key, version) AS (
            SELECT v.store, v.key, MAX(v.id) FROM affected a JOIN lineage_versions v ON v.id = a.id
            GROUP BY v.store, v.key ORDER BY v.store, v.key LIMIT 513
        ),
    """ if installed else "derived(store, copy_key, version) AS (SELECT NULL, NULL, NULL WHERE 0),"
    ownership = """
        ancestors(store, copy_key, id) AS (
            SELECT w.store, w.copy_key, v.id FROM wanted w JOIN lineage_versions v
                ON v.store = w.store AND v.key = w.copy_key
            UNION SELECT a.store, a.copy_key, i.input FROM ancestors a JOIN lineage_inputs i ON i.artifact = a.id
        ),
        shared_versions AS (
            SELECT DISTINCT a.store, a.copy_key FROM ancestors a JOIN lineage_subjects s
                ON s.version = a.id WHERE s.subject <> :subject
        )
    """ if installed else "shared_versions(store, copy_key) AS (SELECT NULL, NULL WHERE 0)"

    end = time.monotonic() + 5
    conn.set_progress_handler(lambda: int(time.monotonic() > end), 10000)
    try:
        rows = conn.execute(f"""
            WITH RECURSIVE events(event,subject,store,copy_key,action) AS NOT MATERIALIZED ({direct_events}), {graph}
            direct AS (
                SELECT store, copy_key, MAX(event) AS event, MAX(action = 'sent') AS sent
                FROM events WHERE subject = :subject GROUP BY store, copy_key
                ORDER BY store, copy_key LIMIT 513
            ), wanted AS (
                SELECT store, copy_key FROM direct UNION SELECT store, copy_key FROM derived
                ORDER BY store, copy_key LIMIT 513
            ), {ownership}, shared AS (
                SELECT store, copy_key FROM shared_versions
                UNION SELECT e.store, e.copy_key FROM events e JOIN wanted w USING (store, copy_key)
                      WHERE e.subject <> :subject
            )
            SELECT w.store, w.copy_key, d.event, v.version, COALESCE(d.sent,0), s.copy_key IS NOT NULL
            FROM wanted w LEFT JOIN direct d USING (store, copy_key) LEFT JOIN derived v USING (store, copy_key)
            LEFT JOIN shared s USING (store, copy_key) ORDER BY w.store, w.copy_key
        """, {"subject": subject_ref}).fetchall()
    finally:
        conn.set_progress_handler(None, 0)
    for store, key, event, version, sent, shared in rows:
        references = [n for n in (event, version) if n is not None]
        require(isinstance(store, str) and isinstance(key, str) and 0 < len(key) <= 1024
                and (references or scope) and all(type(n) is int and n > 0 for n in references)
                and sent in (0, 1) and shared in (0, 1), "Invalid copy-journal location.")
    return rows, scope


@contextmanager
def store_readers(spec):
    """Yield a direct reader and a subject-scan factory on one authorized snapshot."""
    if spec["kind"] == "sqlite":
        with sqlite_reader(spec["path"]) as db:
            deadline = time.monotonic() + 5
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            table, column = spec["table"], spec["key_column"]
            _sqlite_table(db, table)
            columns = db.execute("SELECT name, UPPER(type) FROM pragma_table_info(?) WHERE pk>0", (table,)).fetchall()
            require(columns == [(column, "TEXT")], "Map a single TEXT primary key of the observed table.")
            collations = db.execute("""
                SELECT x.coll FROM pragma_index_list(?) i, pragma_index_xinfo(i.name) x
                WHERE i.origin='pk' AND x.key=1
            """, (table,)).fetchall()
            require(collations == [("BINARY",)], "Use a binary-collated TEXT primary key.")
            # SQLite allows a BLOB in a non-STRICT TEXT key. Its sort order puts
            # BLOBs after all text, so the PK index can detect mixed encodings.
            storage = db.execute(f'SELECT typeof("{column}") FROM main."{table}" '
                                 f'ORDER BY "{column}" COLLATE BINARY DESC LIMIT 1').fetchone()
            require(storage == ("text",), "The mapped SQLite table must use text keys throughout.")
            # Both interpolated names have been restricted by inventory().
            query = f'SELECT 1 FROM main."{table}" WHERE "{column}" COLLATE BINARY = ? LIMIT 1'
            def exists(key):
                return db.execute(query, (key,)).fetchone() is not None
            require(exists(spec["control_key"]), "The positive visibility control was missing.")
            def subject_lookup():
                field = spec["subject_column"]
                dtype = db.execute("SELECT UPPER(type) FROM pragma_table_info(?) WHERE name=?", (table, field)).fetchone()
                require(dtype == ("TEXT",), "Use a TEXT subject column.")
                # A BLOB can inhabit a SQLite TEXT column and compare differently.
                malformed = db.execute(f'SELECT 1 FROM main."{table}" WHERE "{field}" IS NOT NULL '
                                       f'''AND typeof("{field}") != 'text' LIMIT 1''').fetchone()
                require(malformed is None, "Ambiguous SQLite subject encoding.")
                ctrl = db.execute(f'SELECT "{field}" FROM main."{table}" WHERE "{column}" COLLATE BINARY=?',
                                  (spec["control_key"],)).fetchone()
                require(ctrl == (spec["control_subject_ref"],), "Missing retained subject scan control.")
                subject_query = f'SELECT 1 FROM main."{table}" WHERE "{field}" COLLATE BINARY=? LIMIT 1'
                return lambda subject: db.execute(subject_query, (subject,)).fetchone() is not None

            yield exists, subject_lookup
        return

    import psycopg
    from psycopg import sql

    dsn = os.environ.get(spec["dsn_env"])
    require(dsn, "The observer connection setting is missing.")
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as db, db.transaction():
        db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        db.execute("SET LOCAL search_path = pg_catalog")
        db.execute("SET LOCAL statement_timeout = '5s'")
        db.execute("SET LOCAL lock_timeout = '3s'")
        table = sql.Identifier(spec["schema"], spec["table"])
        key_column = sql.Identifier(spec["key_column"])
        # Hold an ACCESS SHARE lock on the exact relation before classifying it.
        # Selecting the key preserves support for a column-only SELECT grant.
        db.execute(sql.SQL("SELECT {} FROM ONLY {} LIMIT 0").format(key_column, table))
        # pg_has_role rejects inherited owner rights; the catalog check excludes
        # views, partitions, RLS-filtered reads, composite keys and writable roles.
        eligible = db.execute("""
            SELECT NOT pg_is_in_recovery() AND NOT c.relrowsecurity AND NOT c.relispartition
                   AND c.relkind='r' AND c.relpersistence='p'
                   AND NOT EXISTS (SELECT 1 FROM pg_inherits WHERE inhparent=c.oid OR inhrelid=c.oid)
                   AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
                   AND NOT pg_has_role(current_user, c.relowner, 'MEMBER')
                   AND NOT has_table_privilege(c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
                   AND NOT has_any_column_privilege(c.oid, 'INSERT,UPDATE')
                   AND EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=c.oid
                               AND a.attnum=i.indkey[0] WHERE i.indrelid=c.oid AND i.indisprimary
                               AND i.indnkeyatts=1 AND a.attname=%s AND i.indisvalid
                               AND a.atttypid IN ('text'::regtype, 'varchar'::regtype, 'uuid'::regtype))
              FROM pg_class c JOIN pg_roles r ON r.rolname=current_user
             WHERE c.oid = to_regclass(%s)
        """, (spec["key_column"], table.as_string(db))).fetchone()
        require(eligible == (True,), "Require an unfiltered primary table and a dedicated read-only role.")
        db.execute("SET LOCAL row_security = off")
        query = sql.SQL("SELECT 1 FROM ONLY {} WHERE {} = %s LIMIT 1").format(table, key_column)
        def exists(key):
            return db.execute(query, (key,)).fetchone() is not None
        require(exists(spec["control_key"]), "The positive visibility control was missing.")
        def subject_lookup():
            field = sql.Identifier(spec["subject_column"])
            kind = db.execute("""
                SELECT a.atttypid IN ('text'::regtype,'varchar'::regtype) FROM pg_attribute a
                JOIN pg_class c ON a.attrelid=c.oid JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname=%s AND c.relname=%s AND a.attname=%s AND NOT a.attisdropped
            """, (spec["schema"], spec["table"], spec["subject_column"])).fetchone()
            require(kind == (True,), "Use a text subject column.")
            ctrl = db.execute(sql.SQL("SELECT {} FROM ONLY {} WHERE {} = %s").format(
                field, table, key_column), (spec["control_key"],)).fetchone()
            require(ctrl == (spec["control_subject_ref"],), "Missing retained subject scan control.")
            subject_query = sql.SQL('SELECT 1 FROM ONLY {} WHERE {} COLLATE "C" = %s LIMIT 1').format(table, field)
            return lambda subject: db.execute(subject_query, (subject,)).fetchone() is not None

        yield exists, subject_lookup


@contextmanager
def key_reader(spec, *, scan=False):
    with store_readers(spec) as (direct, subject_lookup):
        yield subject_lookup() if scan else direct
