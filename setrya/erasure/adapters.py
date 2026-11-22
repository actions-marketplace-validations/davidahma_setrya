"""Subject-scoped direct reads and erasure for declared application storage."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from contextlib import closing, contextmanager
from typing import Literal, Protocol

from setrya.drill import InputError

from .elastic import ElasticsearchAdapter as ElasticsearchAdapter
from .journal import identifier
from .subject import Subject


class ErasureAdapter(Protocol):
    proof: Literal["direct", "configuration", "none"]

    def find(self, subject: Subject) -> set[str]: ...
    def delete(self, subject: Subject) -> None: ...
    def verify_absent(self, subject: Subject) -> set[str]:
        """Return copy keys still present after an independent read."""
        ...


def _ref(subject):
    if not isinstance(subject, Subject):
        raise InputError("expected a tenant-scoped Subject")
    return subject.ref


def checkpoint_thread(subject: Subject, thread: str) -> str:
    return identifier(f"setrya:{_ref(subject)}:{identifier(thread, 'thread')}", "checkpoint thread")


def memory_namespace(subject: Subject) -> tuple[str, str]:
    return ("setrya", _ref(subject))


def redis_key(subject: Subject, key: str) -> str:
    return f"setrya:copy:{_ref(subject)}:{identifier(key, 'Redis copy key')}"


def _sql_name(value):
    if not isinstance(value, str) or not re.fullmatch("[A-Za-z_][A-Za-z0-9_]{0,62}", value):
        raise InputError("expected an unqualified SQL identifier (up to 63 ASCII characters)")
    return '"' + value + '"'


def _keys(rows):
    result = set()
    for row in rows:
        key = row["copy_key"] if isinstance(row, Mapping) else row[0]
        if isinstance(key, int):
            key = str(key)
        key = identifier(key, "stored copy key")
        if key in result:
            raise ValueError("multiple store rows use the same logical copy key")
        result.add(key)
    return result


class _Direct:
    proof = "direct"

    def verify_absent(self, subject: Subject) -> set[str]:
        return self.find(subject)


def _require_sqlite_base_table(db, quoted_table):
    cursor = db.cursor()
    cursor.row_factory = None
    with closing(cursor):
        # PRAGMA cannot be shadowed by an application table of the same name.
        rows = cursor.execute(f"PRAGMA main.table_list({quoted_table})").fetchall()
    if len(rows) != 1 or rows[0][0] != "main" or rows[0][2] != "table":
        raise InputError("direct SQLite observation requires a base table in main")


@contextmanager
def _sqlite_snapshot(db, tables, *, write=False):
    if db.in_transaction:
        raise InputError("use a SQLite connection with committed application writes")
    db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
    try:
        for table in tables:
            _require_sqlite_base_table(db, table)
        yield db
        db.execute("COMMIT" if write else "ROLLBACK")
    finally:
        if db.in_transaction:
            db.execute("ROLLBACK")


class SQLiteAdapter(_Direct):
    """Rows in an application-owned table with an exact subject column."""

    def __init__(self, connection: sqlite3.Connection, table: str, *, key_column="id", subject_column="setrya_subject"):
        self.db = connection
        self.table = _sql_name(table)
        self.key = _sql_name(key_column)
        self.scope = _sql_name(subject_column)

    def find(self, subject):
        with _sqlite_snapshot(self.db, (self.table,)) as db:
            return _keys(db.execute(
                f"SELECT s.{self.key} AS copy_key FROM main.{self.table} AS s WHERE s.{self.scope} COLLATE BINARY = ?",
                (_ref(subject),),
            ))

    def delete(self, subject):
        with _sqlite_snapshot(self.db, (self.table,), write=True) as db:
            db.execute(f"DELETE FROM main.{self.table} WHERE {self.table}.{self.scope} COLLATE BINARY = ?",
                       (_ref(subject),))


@contextmanager
def _pg_connection(client):
    """Use either an autocommit connection or a pool configured for autocommit."""
    from contextlib import nullcontext
    from psycopg.pq import TransactionStatus

    with (client.connection() if hasattr(client, "getconn") else nullcontext(client)) as conn:
        if not conn.autocommit or conn.info.transaction_status != TransactionStatus.IDLE:
            raise ValueError("use a dedicated idle PostgreSQL connection with autocommit=True")
        with conn.transaction():
            # PostgreSQL raises if row-level security would hide evidence for this role.
            conn.execute("SET LOCAL row_security = off")
            yield conn


_PG_PHYSICAL_TABLE = """
    SELECT NOT pg_catalog.pg_is_in_recovery() AND c.relkind = 'r'
           AND c.relpersistence <> 't' AND NOT c.relrowsecurity AND NOT c.relispartition
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits WHERE inhparent = c.oid OR inhrelid = c.oid) AS visible
    FROM pg_catalog.pg_class c WHERE c.oid = pg_catalog.to_regclass(%s)
"""


def _check_pg_visibility(row):
    if row is None or (row["visible"] if isinstance(row, Mapping) else row[0]) is not True:
        raise InputError("direct observation requires an unfiltered PostgreSQL primary base table")


def _require_pg_base_table(conn, table):
    # The lock binds the catalog check and subsequent data reads to the same relation.
    conn.execute(f"SELECT 1 FROM ONLY {table} LIMIT 0")
    _check_pg_visibility(conn.execute(_PG_PHYSICAL_TABLE, (table,)).fetchone())


class PgvectorAdapter(_Direct):
    """Read actual rows in a pgvector table, including rows outside nearest-neighbor results."""

    def __init__(self, connection, table: str, *, key_column="id", subject_column="setrya_subject", metadata_column=None):
        self.db = connection
        self.table = _sql_name(table)
        self.key = _sql_name(key_column)
        self.metadata = None if metadata_column is None else _sql_name(metadata_column)
        self.scope = _sql_name(subject_column) if self.metadata is None else f"({self.metadata} ->> 'setrya_subject')"

    def _require_single_owner(self, conn, subject):
        if self.metadata is not None:
            owner = f"({self.metadata}::jsonb -> 'setrya_subject')"
            mixed = conn.execute(
                f"SELECT 1 FROM {self.table} WHERE jsonb_typeof({owner}) = 'array' AND {owner} ? %s LIMIT 1",
                (_ref(subject),),
            ).fetchone()
            if mixed:
                raise ValueError("shared PostgreSQL documents require an application erasure adapter")

    def find(self, subject):
        with _pg_connection(self.db) as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            _require_pg_base_table(conn, self.table)
            self._require_single_owner(conn, subject)
            return _keys(conn.execute(
                f"SELECT {self.key}::text AS copy_key FROM {self.table} WHERE {self.scope}::text COLLATE \"C\" = %s", (_ref(subject),)
            ))

    def delete(self, subject):
        with _pg_connection(self.db) as conn:
            _require_pg_base_table(conn, self.table)
            self._require_single_owner(conn, subject)
            conn.execute(f"DELETE FROM {self.table} WHERE {self.scope}::text COLLATE \"C\" = %s", (_ref(subject),))


class RedisAdapter(_Direct):
    """Scan a standalone primary for exact keys in the subject's exclusive partition."""

    def __init__(self, client):
        self.client = client

    def find(self, subject):
        prefix = f"setrya:copy:{_ref(subject)}:"
        if self.client.role()[0] not in ("master", b"master"):
            raise ValueError("Redis direct checks require a writable primary")
        if self.client.info("cluster").get("cluster_enabled") != 0:
            raise ValueError("Redis direct checks require a standalone instance")
        result = set()
        for raw in self.client.scan_iter(match=prefix + "*", count=256):
            key = raw if isinstance(raw, str) else raw.decode("utf-8")
            if not key.startswith(prefix):
                raise ValueError("Redis returned a key outside the selected partition")
            result.add(identifier(key[len(prefix):], "Redis copy key"))
        return result

    def delete(self, subject):
        keys = sorted(self.find(subject))
        for start in range(0, len(keys), 256):
            self.client.delete(*(redis_key(subject, key) for key in keys[start:start + 256]))


class LangGraphSQLiteCheckpointAdapter(_Direct):
    """Each subject-exclusive thread is one unit, including its pending writes."""

    def __init__(self, saver):
        from langgraph.checkpoint.sqlite import SqliteSaver
        if not isinstance(saver, SqliteSaver):
            raise TypeError("expected LangGraph's synchronous SqliteSaver")
        self.saver = saver

    def find(self, subject):
        prefix = f"setrya:{_ref(subject)}:"
        tables = ("checkpoints", "writes")
        query = " UNION ".join(
            f"SELECT thread_id AS copy_key FROM main.{table} WHERE substr(thread_id, 1, ?) = ? COLLATE BINARY" for table in tables
        )
        with self.saver.lock, _sqlite_snapshot(self.saver.conn, tables) as db:
            return _keys(db.execute(query, (len(prefix), prefix) * len(tables)))

    def delete(self, subject):
        for thread in self.find(subject):
            self.saver.delete_thread(thread)


_PG_CHECKPOINT_TABLES = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")


def _checkpoint_rows(subject):
    prefix = f"setrya:{_ref(subject)}:"
    query = " UNION ".join(
        f"SELECT thread_id AS copy_key FROM {table} WHERE starts_with(thread_id, %s)" for table in _PG_CHECKPOINT_TABLES
    )
    return query, (prefix,) * len(_PG_CHECKPOINT_TABLES)


class LangGraphPostgresCheckpointAdapter(_Direct):
    """The full PostgresSaver layout, including blobs and writes orphaned from their checkpoints."""

    def __init__(self, saver):
        from langgraph.checkpoint.postgres import PostgresSaver
        if not isinstance(saver, PostgresSaver):
            raise TypeError("expected LangGraph's synchronous full PostgresSaver")
        self.saver = saver

    def find(self, subject):
        with self.saver.lock, _pg_connection(self.saver.conn) as conn:
            for table in _PG_CHECKPOINT_TABLES:
                _require_pg_base_table(conn, table)
            return _keys(conn.execute(*_checkpoint_rows(subject)))

    def delete(self, subject):
        for thread in self.find(subject):
            self.saver.delete_thread(thread)


def memory_item_key(subject: Subject, namespace: tuple[str, ...], key: str) -> str:
    return _scoped_memory_key(memory_namespace(subject), namespace, key)


def _scoped_memory_key(root, namespace, key):
    if tuple(namespace[:len(root)]) != root:
        raise InputError("memory item is outside the subject's namespace")
    key = identifier(key, "memory item key")
    path = namespace[len(root):]
    if not path:
        return key
    encoded = json.dumps([*path, key], ensure_ascii=True, separators=(",", ":")).encode()
    return "memory:" + hashlib.sha256(encoded).hexdigest()


class LangGraphMemoryAdapter(_Direct):
    """Read each key via the synchronous InMemoryStore within the subject's namespace."""

    def __init__(self, store):
        from langgraph.store.memory import InMemoryStore
        if not isinstance(store, InMemoryStore):
            raise TypeError("use LangGraphPostgresMemoryAdapter for PostgreSQL memory")
        self.store = store

    def _locations(self, subject):
        namespace = memory_namespace(subject)
        locations = {}
        offset = 0
        while True:
            page = self.store.search(namespace, limit=128, offset=offset)
            for item in page:
                key = memory_item_key(subject, item.namespace, item.key)
                if key in locations:
                    raise ValueError("duplicate LangGraph copy key during enumeration")
                locations[key] = (item.namespace, item.key)
            if len(page) < 128:
                return locations
            offset += len(page)

    def find(self, subject):
        return set(self._locations(subject))

    def delete(self, subject):
        for namespace, key in self._locations(subject).values():
            self.store.delete(namespace, key)


_MEMORY_SCHEMA = """SELECT n.nspname AS schema FROM pg_catalog.pg_class c
                    JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid WHERE c.oid = 'store'::regclass"""


def _memory_relations(row):
    schema = _sql_name(row["schema"] if isinstance(row, Mapping) else row[0])
    return schema + '."store"', schema + '."store_vectors"'


def _memory_tables(table, vectors, row, index_config):
    present = row["present"] if isinstance(row, Mapping) else row[0]
    if present:
        return (table, vectors)
    if index_config:
        raise ValueError("LangGraph memory has no embedding table in its schema")
    return (table,)


def _memory_rows(tables, subject):
    root = ".".join(memory_namespace(subject))
    query = " UNION ".join(
        f"SELECT prefix, key FROM {table} WHERE prefix = %s OR starts_with(prefix, %s)" for table in tables
    )
    return query, (root, root + ".") * len(tables)


def _memory_keys(rows, subject):
    result = set()
    for row in rows:
        prefix, key = (row["prefix"], row["key"]) if isinstance(row, Mapping) else row
        logical = memory_item_key(subject, tuple(prefix.split(".")), key)
        if logical in result:
            raise ValueError("duplicate LangGraph memory copy key")
        result.add(logical)
    return result


class LangGraphPostgresMemoryAdapter(_Direct):
    """Read persisted items (including expired items) and optional embedding rows."""

    def __init__(self, store):
        from langgraph.store.postgres import PostgresStore
        if not isinstance(store, PostgresStore):
            raise TypeError("expected LangGraph's synchronous PostgresStore")
        self.store = store

    def _tables(self, conn):
        table, vectors = _memory_relations(conn.execute(_MEMORY_SCHEMA).fetchone())
        row = conn.execute("SELECT to_regclass(%s) IS NOT NULL AS present", (vectors,)).fetchone()
        tables = _memory_tables(table, vectors, row, self.store.index_config)
        for relation in tables:
            _require_pg_base_table(conn, relation)
        return tables

    def find(self, subject):
        with _pg_connection(self.store.conn) as conn:
            return _memory_keys(conn.execute(*_memory_rows(self._tables(conn), subject)), subject)

    def delete(self, subject):
        root = ".".join(memory_namespace(subject))
        with _pg_connection(self.store.conn) as conn:
            for table in reversed(self._tables(conn)):
                conn.execute(f"DELETE FROM {table} WHERE prefix = %s OR starts_with(prefix, %s)", (root, root + "."))
