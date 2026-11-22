"""Direct existence reads. Neither backend accepts SQL or callbacks from a request."""
from contextlib import closing, contextmanager
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import tomllib

from setrya.offboarding.inputs import read_regular_bytes, require


def inventory(path):
    config = tomllib.loads(read_regular_bytes(path, "observer inventory").decode())
    require(set(config) == {"stores"} and isinstance(config["stores"], dict)
            and 0 < len(config["stores"]) <= 64, "Declare 1 to 64 observer stores.")
    for name, spec in config["stores"].items():
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name)
                and isinstance(spec, dict), "Invalid store alias.")
        common = {"kind", "table", "key_column", "control_key"}
        kind = spec.get("kind")
        require(kind in ("sqlite", "postgres"), "Observer stores must be sqlite or postgres.")
        fields = {"path"} if kind == "sqlite" else {"dsn_env", "schema"}
        require(set(spec) == common | fields, "Unexpected or missing observer store settings.")
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
    return config["stores"]


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
    entry = conn.execute("SELECT type FROM pragma_table_list WHERE schema = 'main' AND name = ?", (name,)).fetchone()
    require(entry == ("table",), "Require a concrete SQLite base table.")


def journal_rows(conn, subject_ref):
    _sqlite_table(conn, "copy_events")
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
            WITH RECURSIVE {graph}
            direct AS (
                SELECT store, copy_key, MAX(event) AS event, MAX(action = 'sent') AS sent
                FROM copy_events WHERE subject = :subject GROUP BY store, copy_key
                ORDER BY store, copy_key LIMIT 513
            ), wanted AS (
                SELECT store, copy_key FROM direct UNION SELECT store, copy_key FROM derived
                ORDER BY store, copy_key LIMIT 513
            ), {ownership}, shared AS (
                SELECT store, copy_key FROM shared_versions
                UNION SELECT e.store, e.copy_key FROM copy_events e JOIN wanted w USING (store, copy_key)
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
                and references and all(type(n) is int and n > 0 for n in references)
                and sent in (0, 1) and shared in (0, 1), "Invalid copy-journal location.")
    return rows


@contextmanager
def key_reader(spec):
    if spec["kind"] == "sqlite":
        with sqlite_reader(spec["path"]) as db:
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
            yield exists
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
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              JOIN pg_roles r ON r.rolname=current_user
             WHERE n.nspname=%s AND c.relname=%s
        """, (spec["key_column"], spec["schema"], spec["table"])).fetchone()
        require(eligible == (True,), "Require an unfiltered primary table and a dedicated read-only role.")
        query = sql.SQL("SELECT 1 FROM ONLY {}.{} WHERE {} = %s LIMIT 1").format(
            sql.Identifier(spec["schema"]), sql.Identifier(spec["table"]), sql.Identifier(spec["key_column"]))
        def exists(key):
            return db.execute(query, (key,)).fetchone() is not None
        require(exists(spec["control_key"]), "The positive visibility control was missing.")
        yield exists
