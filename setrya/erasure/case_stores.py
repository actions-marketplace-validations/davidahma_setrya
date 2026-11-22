"""Scoped, read-only observations for a disposable application's declarative case."""
from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit
from typing import Callable

from setrya.drill import InputError
from setrya.offboarding.inputs import unique_fields
from setrya.integrations.agent_harnesses import ClaudeTranscriptCanaryScanner, OpenAISessionCanaryScanner
from .adapters import _sql_name
from .canary import PostgresCanaryScanner, RedisCanaryScanner, SQLiteCanaryScanner, contains_marker
from .v3 import Stored


MISSING = object()
MAX_CONTENT = 1 << 20
SQL_COLUMNS = {"table", "key_column", "content_column", "scope_column"}
STORE_OPTIONS = {
    "sqlite": SQL_COLUMNS, "postgres": SQL_COLUMNS, "redis-cache": {"prefix"},
    "langgraph-postgres": set(), "openai-agents": set(), "claude-agent": set(),
}

def content_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass(frozen=True)
class StoredFact:
    present: tuple[str, ...]
    absent_digests: frozenset[str] = frozenset()

    def evaluate(self, value, digest):
        if any(contains_marker(value, phrase) for phrase in self.present):
            return True
        return False if digest in self.absent_digests else None


@dataclass
class Observer:
    scope: str
    scanner: object
    load: Callable[[str], object]

    def scan(self, marker):
        return self.scanner.find(scope=self.scope, marker=marker)

    def inspect(self, key, target, control):
        value = self.load(key)
        if value is MISSING:
            return Stored(key, False, False, False, None)
        # A missing or unreadable payload is never an observation of absence.
        if value is None:
            raise InputError("store row has no observable content")
        payload = content_bytes(value)
        if len(payload) > MAX_CONTENT:
            raise InputError("fixture copy exceeds the observation budget")
        digest = sha256(payload).hexdigest()
        # A lone marker can establish presence. Only a reviewed whole payload can
        # establish absence in an existing, potentially shared copy.
        facts = (StoredFact((fact,)) if isinstance(fact, str) else fact for fact in (target, control))
        target_present, control_present = (fact.evaluate(value, digest) for fact in facts)
        return Stored(key, True, target_present, control_present, digest)


def single(rows):
    if len(rows) > 1:
        raise InputError("a scoped copy key matched multiple records")
    return rows[0][0] if rows else MISSING


def open_observer(stack, config, location):
    kind, scope = config["kind"], config["scope"]
    if kind == "claude-agent":
        scanner = ClaudeTranscriptCanaryScanner(location, missing_is_absence=True)

        def load(key):
            if key != scope:
                raise InputError("a Claude transcript key must match its declared session")
            value = scanner.records(scope)
            return MISSING if value is None else value
        return Observer(scope, scanner, load)

    if kind == "redis-cache":
        from redis import Redis
        if urlsplit(location).scheme not in ("redis", "rediss"):
            raise InputError("expected a Redis connection URL")
        client = stack.enter_context(Redis.from_url(location, socket_timeout=5, socket_connect_timeout=5))
        scanner = RedisCanaryScanner(client, prefix=config["prefix"])

        def load(key):
            full = f"{scanner.prefix}:{scope}:{key}"
            # Read presence and bytes together so deletion between reads cannot
            # turn a missing result into an empty string.
            with client.pipeline(transaction=True) as pipe:
                present, raw = pipe.exists(full).getrange(full, 0, MAX_CONTENT).execute()
            if len(raw) > MAX_CONTENT:
                raise InputError("Redis fixture copy exceeds the observation budget")
            return raw.decode() if present else MISSING
        return Observer(scope, scanner, load)

    if kind in ("openai-agents", "sqlite"):
        path = Path(location).resolve(strict=True)
        db = stack.enter_context(closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)))
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_CONTENT + 8192)
        if kind == "openai-agents":
            scanner = OpenAISessionCanaryScanner(db)
            def load(key):
                with scanner.snapshot() as conn:
                    value = single(conn.execute("SELECT message_data FROM main.agent_messages "
                                                "WHERE CAST(session_id AS TEXT) COLLATE BINARY=? "
                                                "AND CAST(id AS TEXT)=? LIMIT 2", (scope, key)).fetchall())
                return json.loads(value, object_pairs_hook=unique_fields) if value is not MISSING else MISSING
        else:
            table, key_col, content, scope_col = columns(config)
            scanner = SQLiteCanaryScanner(db, table=config["table"], key=config["key_column"],
                                          content=config["content_column"], scope_column=config["scope_column"])
            def load(key):
                with scanner.snapshot() as conn:
                    return single(conn.execute(f"SELECT t.{content} FROM main.{table} t "
                                               f"WHERE CAST(t.{scope_col} AS TEXT) COLLATE BINARY=? "
                                               f"AND CAST(t.{key_col} AS TEXT) COLLATE BINARY=? LIMIT 2",
                                               (scope, key)).fetchall())
        return Observer(scope, scanner, load)

    import psycopg
    if urlsplit(location).scheme not in ("postgresql", "postgres"):
        raise InputError("expected a PostgreSQL connection URL")
    db = stack.enter_context(psycopg.connect(location, connect_timeout=5, autocommit=True))
    db.execute("SET default_transaction_read_only = on")
    db.execute("SET statement_timeout = 5000")
    values = config
    if kind == "langgraph-postgres":
        values = {"table": "store", "key_column": "key", "content_column": "value", "scope_column": "prefix"}
    table, key_col, content, scope_col = columns(values)
    scanner = PostgresCanaryScanner(db, table=values["table"], key=values["key_column"],
                                    content=values["content_column"], scope_column=values["scope_column"],
                                    jsonb=kind == "langgraph-postgres")
    def load(key):
        with scanner.snapshot() as conn:
            # A NULL here marks either genuine NULL or oversize. Both are gaps.
            rows = conn.execute(f"SELECT CASE WHEN octet_length(t.{content}::text) <= %s THEN t.{content} END "
                                f"FROM {table} t WHERE t.{scope_col}::text COLLATE \"C\"=%s "
                                f"AND t.{key_col}::text COLLATE \"C\"=%s LIMIT 2", (MAX_CONTENT, scope, key)).fetchall()
            return single(rows)
    return Observer(scope, scanner, load)


def columns(config):
    return tuple(_sql_name(config[name]) for name in ("table", "key_column", "content_column", "scope_column"))
