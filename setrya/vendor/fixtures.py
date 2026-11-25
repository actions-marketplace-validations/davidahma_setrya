"""Run built-in conformance cases against disposable backend resources."""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from tempfile import TemporaryDirectory

from ._mem0 import observation
from .report import LOCAL_AGENT_TARGETS

MARKER = "iridium-670a"
TEXT = {"target": f"Setrya synthetic target {MARKER}", "retained": "Setrya synthetic control cobalt-82bb"}
IDENTITIES = {role: role for role in TEXT}


class MissingDSN(ValueError):
    pass


def pgvector(evidence):
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    dsn = os.environ.get("SETRYA_PGVECTOR_DSN")
    if not dsn:
        raise MissingDSN
    params = conninfo_to_dict(dsn)
    host = params.get("host")
    address = {"127.0.0.1": "127.0.0.1", "localhost": "127.0.0.1", "::1": "::1"}.get(host)
    if not address or params.get("hostaddr", address) != address or not set(params) <= {
        "host", "hostaddr", "port", "user", "password", "dbname", "sslmode", "connect_timeout"
    }:
        raise MissingDSN
    evidence["versions"]["psycopg"] = version("psycopg")
    with psycopg.connect(dsn, hostaddr=address, connect_timeout=5, options="", autocommit=True) as connection, connection.cursor() as sql:
        # Qualified temp names keep all fixture writes in this session's own resource.
        sql.execute("SET statement_timeout = '10s'")
        sql.execute("SHOW server_version_num")
        evidence["versions"]["postgresql"] = sql.fetchone()[0]
        sql.execute("SELECT extversion, nspname FROM pg_catalog.pg_extension JOIN pg_catalog.pg_namespace ON "
                    "extnamespace = pg_namespace.oid WHERE extname = 'vector'")
        result = sql.fetchone()
        if result is None:
            raise MissingDSN
        extension, namespace = result
        evidence["versions"]["vector"] = extension
        if namespace in ("pg_catalog", "pg_temp"):
            raise MissingDSN
        from psycopg.sql import SQL, Identifier

        extension_schema = Identifier(namespace)
        sql.execute(SQL(
            "CREATE TEMP TABLE setrya_vendor_fixture "
            "(id text PRIMARY KEY, body text NOT NULL, embedding {}.vector(3) NOT NULL)"
        ).format(extension_schema))
        sql.execute(SQL(
            "CREATE INDEX setrya_vendor_fixture_hnsw ON pg_temp.setrya_vendor_fixture USING hnsw "
            "(embedding {}.vector_l2_ops)"
        ).format(extension_schema))
        for case_id, point in zip(TEXT, ("[1,0,0]", "[0,1,0]"), strict=True):
            sql.execute("INSERT INTO pg_temp.setrya_vendor_fixture VALUES (%s, %s, %s)", (case_id, TEXT[case_id], point))
        sql.execute("SET enable_seqscan = off")
        query = SQL("SELECT id, body FROM pg_temp.setrya_vendor_fixture "
                    "ORDER BY embedding OPERATOR({}.<->) '[1,0,0]'::{}.vector LIMIT 10").format(
                        extension_schema, extension_schema)

        for phase in ("baseline", "after_delete", "after_retry"):
            if phase != "baseline":
                sql.execute("DELETE FROM pg_temp.setrya_vendor_fixture WHERE id = 'target'")
            sql.execute("SELECT id, body FROM pg_temp.setrya_vendor_fixture")
            stored = sql.fetchall()
            sql.execute(SQL("EXPLAIN (FORMAT JSON) ") + query)
            plan = sql.fetchone()[0][0]["Plan"]
            sql.execute(query)
            index = observation(sql.fetchall(), IDENTITIES, TEXT, MARKER, phase)
            if "setrya_vendor_fixture_hnsw" not in json.dumps(plan):
                index["retained"] = None
                if phase == "baseline" or not index["target"]:
                    index["target"] = None
            evidence["observations"][phase] = {"store": observation(stored, IDENTITIES, TEXT, MARKER, phase),
                                               "index": index}


def langgraph_store(evidence):
    from langgraph.store.memory import InMemoryStore

    evidence["versions"].update({name: version(name) for name in ("langgraph", "langgraph-checkpoint")})
    store = InMemoryStore(index={"dims": 2, "embed": embed, "fields": ["body"]})
    namespace = ("setrya", "conformance")
    for case_id, content in TEXT.items():
        store.put(namespace, case_id, {"body": content})
    for phase in ("baseline", "after_delete", "after_retry"):
        if phase != "baseline":
            store.delete(namespace, "target")
        stored = [(key, item.value.get("body")) for key in TEXT if (item := store.get(namespace, key)) is not None]
        results = store.search(namespace, query=TEXT["target"], limit=10)
        scored = [(item.key, item.value.get("body")) for item in results if item.score is not None]
        index = observation(scored, IDENTITIES, TEXT, MARKER, phase)
        if phase != "baseline":
            unscored = ((item.key, item.value.get("body")) for item in results if item.score is None)
            index["target"] |= observation(unscored, IDENTITIES, TEXT, MARKER, phase)["target"]
        evidence["observations"][phase] = {"store": observation(stored, IDENTITIES, TEXT, MARKER, phase),
                                           "index": index}


def embed(texts):
    return [[1.0, 0.0] if MARKER in value else [0.0, 1.0] for value in texts]


def mem0(evidence):
    # Set Mem0's process-wide directories and telemetry before importing it.
    # Pass no ambient application or provider credentials to the child.
    version("mem0ai")
    with TemporaryDirectory(prefix="setrya-mem0-") as directory:
        env = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT") if name in os.environ}
        env.update(MEM0_DIR=directory, MEM0_TELEMETRY="false")
        raw = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("_mem0.py"))],
                             env=env, capture_output=True, input=json.dumps((TEXT, MARKER)).encode(), timeout=60,
                             check=True).stdout
    result = json.loads(raw)
    evidence.update({field: result[field] for field in ("versions", "observations", "error")})


def agent_memory(evidence):
    with TemporaryDirectory(prefix="setrya-agent-memory-") as directory:
        env = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT") if name in os.environ}
        env.update(HOME=directory, USERPROFILE=directory, OTEL_SDK_DISABLED="true",
                   CREWAI_DISABLE_TELEMETRY="true", TELEMETRY_DISABLED="true", HF_HUB_OFFLINE="1",
                   LITELLM_LOCAL_MODEL_COST_MAP="true", COGNEE_SKIP_CONNECTION_TEST="true",
                   SYSTEM_ROOT_DIRECTORY=str(Path(directory) / "system"),
                   DATA_ROOT_DIRECTORY=str(Path(directory) / "data"), MOCK_EMBEDDING="true",
                   EMBEDDING_PROVIDER="openai", EMBEDDING_MODEL="text-embedding-3-small", EMBEDDING_DIMENSIONS="1536")
        # Pin the child to the same checkout or installation as this process.
        launch = ("import runpy, sys; sys.path.insert(0, sys.argv[1]); "
                  "runpy.run_module('setrya.vendor._agent_memory', run_name='__main__')")
        subprocess.run([sys.executable, "-I", "-c", launch, str(Path(__file__).resolve().parents[2])],
                       cwd=directory, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       input=json.dumps((evidence["target"], TEXT, MARKER)).encode(), timeout=120, check=True)
        result = json.loads((Path(directory) / "observations.json").read_bytes())
    evidence.update({field: result[field] for field in ("versions", "observations", "error")})


def run_fixture(target):
    fixture = agent_memory if target in LOCAL_AGENT_TARGETS else {
        "pgvector": pgvector, "langgraph-store": langgraph_store, "mem0": mem0,
    }[target]
    evidence = {"target": target, "versions": {}, "observations": {}, "error": None}
    try:
        fixture(evidence)
    except MissingDSN:
        evidence["error"] = "missing-dsn"
    except (ModuleNotFoundError, PackageNotFoundError):
        evidence["error"] = "missing-extra" if not evidence["observations"] else "fixture-error"
    except Exception:  # noqa: BLE001
        # SDK exceptions may include a DSN or credentials. Keep observations
        # already taken and report only this fixed diagnostic.
        evidence["error"] = "fixture-error"
    evidence["observed_at"] = datetime.now(UTC).isoformat()
    return evidence
