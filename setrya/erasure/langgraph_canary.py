"""Exact-marker reads of full LangGraph checkpoints and declared memory namespaces."""
import json
from collections.abc import Mapping

from setrya.drill import InputError
from .adapters import _pg_checkpoint_payloads, _pg_connection, _require_pg_base_table, _scoped_memory_key, _sqlite_snapshot
from .canary import LIMIT, contains_marker, validate_probe
from .journal import identifier


class SQLiteCheckpointCanaryScanner:
    """Scan raw checkpoint and pending-write payloads, including orphan writes."""

    def __init__(self, connection):
        self.db = connection

    def find(self, *, scope: str, marker: str) -> set[str]:
        validate_probe(scope, marker)
        with _sqlite_snapshot(self.db, ("checkpoints", "writes")) as db:
            rows = db.execute("""
                SELECT type, checkpoint, metadata FROM main.checkpoints WHERE thread_id=? COLLATE BINARY
                UNION ALL SELECT type, value, NULL FROM main.writes WHERE thread_id=? COLLATE BINARY LIMIT 4097
            """, (scope, scope))
            return _checkpoint_hits(rows, scope, marker)


class PostgresCheckpointCanaryScanner:
    """Scan a full PostgresSaver's JSONB checkpoint, plus all blobs and pending writes."""

    def __init__(self, connection):
        self.db = connection

    def find(self, *, scope: str, marker: str) -> set[str]:
        validate_probe(scope, marker)
        # Match bytea values in their original encoding. The adapter’s JSON display
        # form is only for direct-read evidence digests.
        rows = _pg_checkpoint_payloads(self.db, scope)
        return {scope} if any(contains_marker(payload, marker) or contains_marker(metadata, marker)
                              for _, payload, metadata in rows) else set()


def _checkpoint_hits(rows, scope, marker):
    found = False
    for index, row in enumerate(rows):
        kind, payload, metadata = row.values() if isinstance(row, Mapping) else row
        if index >= LIMIT or kind not in {"bytes", "msgpack", "json", "null", "empty"}:
            raise InputError("oversized checkpoint scan or unsupported checkpoint encoding")
        if kind == "json" and isinstance(payload, bytes):
            payload = json.loads(payload)
        if isinstance(metadata, bytes):
            metadata = json.loads(metadata)
        found |= contains_marker(payload, marker) or contains_marker(metadata, marker)
    return {scope} if found else set()


class LangGraphMemoryCanaryScanner:
    """Scan all readable memory values at and below a declared LangGraph namespace."""

    def __init__(self, store, *, namespace=()):
        from langgraph.store.memory import InMemoryStore
        if not isinstance(store, InMemoryStore):
            raise TypeError("use PostgresMemoryCanaryScanner for persisted LangGraph memory")
        self.store = store
        self.namespace = tuple(identifier(part, "memory namespace") for part in namespace)

    def find(self, *, scope: str, marker: str) -> set[str]:
        validate_probe(scope, marker)
        root = (*self.namespace, scope)
        found, seen = set(), set()
        while True:
            page = self.store.search(root, limit=128, offset=len(seen))
            for item in page:
                key = _scoped_memory_key(root, item.namespace, item.key)
                if key in seen or len(seen) >= LIMIT:
                    raise InputError("duplicate key or oversized LangGraph memory scan")
                seen.add(key)
                if contains_marker(item.value, marker):
                    found.add(key)
            if len(page) < 128:
                return found


class PostgresMemoryCanaryScanner:
    """Read stored LangGraph JSON values, including expired rows the Store API omits."""

    def __init__(self, connection, *, namespace=(), descendants=True):
        self.connection = connection
        self.descendants = descendants
        self.namespace = tuple(identifier(part, "memory namespace") for part in namespace)

    def find(self, *, scope: str, marker: str) -> set[str]:
        validate_probe(scope, marker)
        scope_parts = (scope,) if self.descendants else tuple(scope.split("."))
        root = (*self.namespace, *scope_parts)
        if any(not part or "." in part for part in root):
            raise InputError("LangGraph namespace components cannot contain periods")
        prefix = ".".join(root)
        with _pg_connection(self.connection) as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            _require_pg_base_table(conn, "store")
            rows = conn.execute("""
                SELECT prefix, key, value FROM store WHERE prefix COLLATE "C" = %s
                   OR (%s AND starts_with(prefix, %s)) LIMIT 4097
            """, (prefix, self.descendants, prefix + "."))
            found = set()
            for index, row in enumerate(rows):
                if index >= LIMIT:
                    raise InputError("oversized LangGraph memory scan")
                location, key, value = row.values() if isinstance(row, Mapping) else row
                if contains_marker(value, marker):
                    found.add(_scoped_memory_key(root, tuple(location.split(".")), key))
            return found
