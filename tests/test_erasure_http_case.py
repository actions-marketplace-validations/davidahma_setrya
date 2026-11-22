"""Exercise the public YAML contract using real authenticated requests and storage."""
from contextlib import chdir, ExitStack, redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import find_spec
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import sqlite3
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch
from uuid import uuid4

from setrya.cli import main


@unittest.skipUnless(find_spec("yaml"), "install setrya[case-yaml]")
class HttpCaseTests(unittest.TestCase):
    def setUp(self):
        import yaml
        self.yaml = yaml
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.deleted, self.erase_calls, self.answer_calls = False, 0, 0
        self.leak, self.on_erase = False, lambda: None
        self.target, self.control = "Harbor-17", "Thursday"
        self.reader, self.eraser = uuid4().hex, uuid4().hex
        self.subject = uuid4().hex * 2
        case = self

        class Endpoint(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if self.path != "/answer" or self.headers.get("Authorization") != "Bearer " + case.reader:
                    self.send_error(403)
                    return
                case.answer_calls += 1
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                text = case.control if body["question"] == "When is dispatch?" else case.target
                if text == case.target and case.deleted and not case.leak:
                    text = "No matching note."
                reply = json.dumps(dict(caller="duty-agent", route="/answer", text=text, **body)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(reply)

            def do_DELETE(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if (self.path != "/erasure" or self.headers.get("Authorization") != "Bearer " + case.eraser
                        or body != {"subject_ref": case.subject, "conversation": "ticket-204"}):
                    self.send_error(403)
                    return
                case.on_erase()
                case.deleted = True
                case.erase_calls += 1
                self.send_response(204)
                self.end_headers()

        server = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        env = patch.dict(os.environ, SETRYA_READER_TOKEN=self.reader, SETRYA_ERASER_TOKEN=self.eraser,
                         SETRYA_SUBJECT_REF=self.subject, SETRYA_TEST_ORIGIN=f"http://127.0.0.1:{server.server_port}")
        env.start()
        self.addCleanup(env.stop)

    def cli(self, code, *args):
        out = StringIO()
        with redirect_stdout(out), redirect_stderr(out):
            actual = main(list(map(str, args)))
        self.assertEqual(actual, code, out.getvalue())
        return out.getvalue()

    def case_file(self, stack):
        folder = self.root / stack
        self.cli(0, "init", "--stack", stack, "--output", folder)
        return folder / "case.yml"

    def verify(self, path, code=0):
        self.cli(0, "doctor", "--case", path)
        self.assertEqual(self.erase_calls, 0)
        self.assertGreaterEqual(self.answer_calls, 9)
        output = self.root / "receipt"
        self.cli(code, "run", "--case", path, "--output", output)
        self.assertEqual(self.erase_calls, 1)
        result = self.cli(code, "replay", output)
        self.assertIn("FAIL" if code == 1 else "PASS", result)
        for f in output.iterdir():
            raw = f.read_text()
            for forbidden in (self.reader, self.eraser, self.target):
                self.assertNotIn(forbidden, raw)

    def test_doctor_names_all_missing_bindings_and_worker_hooks(self):
        for name in ("langgraph-postgres", "openai-agents", "claude-agent", "redis-cache"):
            path = self.case_file(name)
            with patch.dict(os.environ, {}, clear=True):
                message = self.cli(3, "doctor", "--case", path, "--mode", "late-write")
            for hook in ("subject", "read/erase origin", "read as duty-agent", "erase authorization",
                         "inspect/scan memory", "hold", "checkpoint", "release_and_drain"):
                self.assertIn(hook, message)
            if name == "langgraph-postgres":
                self.assertRegex(message, r"case.yml:\d+  inspect/scan checkpoints")
                self.assertRegex(message, r"case.yml:\d+  inspect/scan vectors")
        self.assertEqual(self.erase_calls, 0)

    def test_doctor_names_key_scanner_and_source_lines(self):
        path = self.case_file("openai-agents")
        config = self.yaml.safe_load(path.read_text())
        store = config["stores"]["memory"]
        store.update(kind="sqlite", table="memo", key_column="id", scope_column="scope", content_column="body")
        path.write_text(self.yaml.safe_dump(config, sort_keys=False))
        db = self.root / "app.sqlite"
        os.environ[store["connection_env"]] = str(db)
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE memo (id TEXT PRIMARY KEY, scope TEXT, body TEXT)")
        output = self.cli(3, "doctor", "--case", path)
        for hook, text in (("inspect", "memory/1: required key was missing"),
                           ("scan", "memory: scanner needs a positive marker baseline")):
            self.assertRegex(output, rf"case.yml:\d+  {hook}: {text}")
        self.assertEqual(self.erase_calls, 0)
        db.unlink()
        output = self.cli(3, "doctor", "--case", path)
        self.assertRegex(output, r"case.yml:\d+  memory: observer could not open \(FileNotFoundError\)")
        starter_output = self.cli(3, "doctor", "--starter", path.with_name("test_erasure.py"))
        self.assertRegex(starter_output, r"test_erasure.py:\d+  Connect read")
        self.assertRegex(starter_output, r"test_erasure.py:\d+  Connect erase")
        self.assertRegex(starter_output, r"case.yml:\d+  memory: observer could not open")

    def test_positional_case_saves_same_receipt_and_records_observed_keys(self):
        from setrya.erasure import CopyJournal, Subject
        path = self.case_file("openai-agents")
        cfg = self.yaml.safe_load(path.read_text())
        store = cfg["stores"]["memory"]
        store.update(kind="sqlite", table="memo", key_column="id", scope_column="scope", content_column="body")
        path.write_text(self.yaml.safe_dump(cfg, sort_keys=False))
        db, journal = self.root / "app.sqlite", self.root / "copies.sqlite"
        os.environ[store["connection_env"]] = str(db)
        os.environ["SETRYA_COPY_JOURNAL"] = str(journal)
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE memo(id TEXT PRIMARY KEY, scope TEXT, body TEXT)")
            conn.execute("INSERT INTO memo VALUES ('1','ticket-204',?)", (self.target,))
        with patch.dict(os.environ, SETRYA_COPY_JOURNAL=str(db)):
            self.assertIn("separate local file", self.cli(2, "doctor", "--case", path))
        with sqlite3.connect(db) as conn:
            self.assertEqual(conn.execute("SELECT name FROM sqlite_schema WHERE name='copy_events'").fetchall(), [])
        def erase():
            with sqlite3.connect(db) as conn:
                conn.execute("DELETE FROM memo WHERE id='1'")
        self.on_erase = erase
        with chdir(self.root):
            self.cli(0, "run", path)
            self.cli(0, "replay", "setrya-receipt")
            self.cli(2, "run", path)
            self.cli(2, "run", path, "--case", path)
        self.assertEqual(self.erase_calls, 1)
        evidence = json.loads((self.root / "setrya-receipt" / "erasure-evidence.json").read_text())
        self.assertEqual({(r["action"], r["details"]["operation"], r["store"], r["key"]) for r in evidence["journal"]},
                         {("retrieved", op, "memory", "1") for op in ("fixture.inspect", "fixture.scan")})
        events = CopyJournal(journal).history(Subject(self.subject, "synthetic-test"))
        self.assertEqual([event.details for event in events], [row["details"] for row in evidence["journal"]])
        self.assertTrue(all(event.details["boundary"] == "ticket-204" for event in events))

    def test_sqlite_read_and_residual_answer(self):
        path = self.case_file("openai-agents")
        config = self.yaml.safe_load(path.read_text())
        store = config["stores"]["memory"]
        store.update(kind="sqlite", table="memo", key_column="id", scope_column="scope", content_column="body")
        path.write_text(self.yaml.safe_dump(config))
        db = self.root / "app.sqlite"
        os.environ[store["connection_env"]] = str(db)
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE memo (id TEXT, scope TEXT, body TEXT)")
            conn.execute("INSERT INTO memo VALUES ('1','ticket-204',?)", (self.target,))
        def erase():
            with sqlite3.connect(db) as conn:
                conn.execute("DELETE FROM memo WHERE id='1'")
        self.on_erase, self.leak = erase, True
        self.verify(path, 1)

    def test_filtered_sqlite_view_cannot_certify_soft_deletion(self):
        path = self.case_file("openai-agents")
        config = self.yaml.safe_load(path.read_text())
        store = config["stores"]["memory"]
        store.update(kind="sqlite", table="active_memos", key_column="id", scope_column="scope", content_column="body")
        path.write_text(self.yaml.safe_dump(config))
        db = self.root / "app.sqlite"
        os.environ[store["connection_env"]] = str(db)
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE notes (id text, scope text, body text, deleted integer)")
            conn.execute("INSERT INTO notes VALUES ('1','ticket-204',?,0)", (self.target,))
            conn.execute("CREATE VIEW active_memos AS SELECT * FROM notes WHERE deleted=0")
        self.cli(2, "run", "--case", path, "--output", self.root / "receipt")
        self.cli(2, "replay", self.root / "receipt")
        self.assertEqual(self.erase_calls, 0)

    def test_sqlite_scope_ignores_numeric_affinity_and_views_swapped_after_baseline(self):
        from setrya.drill import InputError
        from setrya.erasure.case_stores import open_observer
        db = self.root / "app.sqlite"
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE notes (id text, scope integer, body text)")
            conn.execute("INSERT INTO notes VALUES ('note', 1, ?)", (self.target,))
        config = dict(kind="sqlite", scope="001", table="notes", key_column="id", content_column="body", scope_column="scope")
        with ExitStack() as stack:
            observer = open_observer(stack, config, str(db))
            self.assertFalse(observer.inspect("note", self.target, self.control).exists)
            self.assertEqual(observer.scan(self.target), set())
            config["scope"] = "1"
            actual = open_observer(stack, config, str(db))
            self.assertTrue(actual.inspect("note", self.target, self.control).exists)
            self.assertEqual(actual.scan(self.target), {"note"})
            with sqlite3.connect(db) as conn:
                conn.execute("ALTER TABLE notes RENAME TO real_notes")
                conn.execute("CREATE VIEW notes AS SELECT * FROM real_notes WHERE 0")
            with self.assertRaises(InputError):
                actual.inspect("note", self.target, self.control)
            with self.assertRaises(InputError):
                actual.scan(self.target)

    def test_openai_session_history(self):
        path = self.case_file("openai-agents")
        db = self.root / "agent.sqlite"
        os.environ["SETRYA_TEST_AGENTS_DB"] = str(db)
        if not find_spec("agents"):
            self.skipTest("install setrya[agent-openai]")
        import asyncio
        from agents import SQLiteSession
        session = SQLiteSession("ticket-204", str(db))
        self.addCleanup(session.close)
        asyncio.run(session.add_items([{"role": "user", "content": self.target}]))
        self.on_erase = lambda: asyncio.run(session.clear_session())
        self.verify(path)

    def test_python_stack_starter_wires_storage_and_names_missing_app_hooks(self):
        path = self.case_file("claude-agent")
        scope = self.yaml.safe_load(path.read_text())["stores"]["memory"]["scope"]
        os.environ["SETRYA_TEST_TRANSCRIPTS"] = str(self.root)
        (self.root / (scope + ".jsonl")).write_text(json.dumps({"sessionId": scope, "content": self.target}))
        starter = path.with_name("test_erasure.py")
        result = self.cli(3, "doctor", "--starter", starter)
        self.assertIn("Missing fixture methods: read, erase", result)
        import runpy
        hooks = runpy.run_path(str(starter))
        with hooks["open_fixture"]() as (subject, app, _items):
            self.assertEqual(app.scan(subject, "memory"), {scope})
            self.assertTrue(app.inspect(subject, "memory", scope).target_present)

    def test_yaml_rejects_duplicate_fields_and_literal_credentials(self):
        path = self.case_file("openai-agents")
        original = path.read_text()
        path.write_text(original + "conversation: another-ticket\n")
        self.cli(2, "doctor", "--case", path)
        path.write_text(original.replace("SETRYA_READER_TOKEN", "not-a-secret-token"))
        message = self.cli(2, "doctor", "--case", path)
        self.assertNotIn("not-a-secret-token", message)
        self.assertEqual(self.erase_calls, 0)

    def test_claude_transcript_is_rewritten_in_place(self):
        path = self.case_file("claude-agent")
        scope = self.yaml.safe_load(path.read_text())["stores"]["memory"]["scope"]
        transcript = self.root / (scope + ".jsonl")
        os.environ["SETRYA_TEST_TRANSCRIPTS"] = str(self.root)
        def write(msg):
            transcript.write_text(json.dumps({"sessionId": scope, "message": {"content": msg}}))
        write(self.target + " " + self.control)
        self.on_erase = lambda: write(self.control)
        self.verify(path)

    @unittest.skipUnless(os.environ.get("SETRYA_REDIS_URL"), "requires isolated Redis")
    def test_redis_cache(self):
        import redis
        url = os.environ["SETRYA_REDIS_URL"]
        path = self.case_file("redis-cache")
        os.environ["SETRYA_TEST_REDIS_URL"] = url
        cfg = self.yaml.safe_load(path.read_text())
        prefix = cfg["stores"]["memory"]["prefix"] = "fixture-" + uuid4().hex
        path.write_text(self.yaml.safe_dump(cfg))
        client = redis.Redis.from_url(url)
        self.addCleanup(client.close)
        key = prefix + ":ticket-204:note"
        self.addCleanup(client.delete, key)
        client.set(key, self.target)
        self.on_erase = lambda: client.delete(key)
        self.verify(path)

    @unittest.skipUnless(os.environ.get("SETRYA_PGVECTOR_DSN"), "requires isolated Postgres")
    def test_postgres_sql_table(self):
        import psycopg
        from psycopg.sql import Identifier, SQL
        dsn = os.environ["SETRYA_PGVECTOR_DSN"]
        path = self.case_file("langgraph-postgres")
        os.environ["SETRYA_TEST_POSTGRES_URL"] = dsn
        cfg = self.yaml.safe_load(path.read_text())
        name = "fixture_" + uuid4().hex
        cfg["stores"]["memory"].update(kind="postgres", table=name, key_column="id", content_column="body",
                                       scope_column="ticket")
        cfg["stores"] = {"memory": cfg["stores"]["memory"]}  # Existing one-store case files still work.
        path.write_text(self.yaml.safe_dump(cfg))
        table = Identifier(name)
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SQL("CREATE TABLE {} (id text primary key, ticket text, body text)").format(table))
            try:
                conn.execute(SQL("INSERT INTO {} VALUES ('note','ticket-204',%s)").format(table), (self.target,))
                self.on_erase = lambda: conn.execute(SQL("DELETE FROM {} WHERE id='note'").format(table))
                self.verify(path)
            finally:
                conn.execute(SQL("DROP TABLE {}").format(table))

    @unittest.skipUnless(os.environ.get("SETRYA_PGVECTOR_DSN"), "requires isolated Postgres")
    def test_postgres_filters_and_changed_visibility_fail_closed(self):
        import psycopg
        from psycopg.sql import Identifier, SQL
        from setrya.drill import InputError
        from setrya.erasure.case_stores import open_observer

        dsn = os.environ["SETRYA_PGVECTOR_DSN"]
        name = "fixture_" + uuid4().hex
        table = Identifier(name)
        view = Identifier(name + "_visible")
        config = dict(kind="postgres", scope="ticket-204", table=name, key_column="id",
                      content_column="body", scope_column="ticket")
        with psycopg.connect(dsn, autocommit=True) as db:
            db.execute(SQL("CREATE TABLE {} (id text, ticket text, body text)").format(table))
            try:
                db.execute(SQL("INSERT INTO {} VALUES ('note','ticket-204',%s)").format(table), (self.target,))
                db.execute(SQL("CREATE VIEW {} AS SELECT * FROM {} WHERE FALSE").format(view, table))
                with ExitStack() as stack:
                    direct = open_observer(stack, config, dsn)
                    filtered = open_observer(stack, dict(config, table=name + "_visible"), dsn)
                    self.assertTrue(direct.inspect("note", self.target, self.control).exists)
                    with self.assertRaises(InputError):
                        filtered.scan(self.target)
                    db.execute(SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(table))
                    with self.assertRaises(InputError):
                        direct.inspect("note", self.target, self.control)
                    with self.assertRaises(InputError):
                        direct.scan(self.target)
            finally:
                db.execute(SQL("DROP TABLE {} CASCADE").format(table))

    @unittest.skipUnless(os.environ.get("SETRYA_PGVECTOR_DSN"), "requires isolated Postgres")
    def test_native_langgraph_checkpoint_memory_and_vector_recipe(self):
        from hashlib import sha256
        from typing import TypedDict
        import psycopg
        from langgraph.checkpoint.postgres import PostgresSaver
        from langgraph.graph import END, START, StateGraph
        from langgraph.store.postgres import PostgresStore
        from psycopg.sql import Identifier, SQL
        from setrya.erasure.adapters import LangGraphPostgresCheckpointAdapter
        from setrya.erasure.case_stores import content_bytes

        class State(TypedDict):
            summary: str

        dsn = os.environ["SETRYA_PGVECTOR_DSN"]
        path = self.case_file("langgraph-postgres")
        os.environ["SETRYA_TEST_POSTGRES_URL"] = dsn
        cfg = self.yaml.safe_load(path.read_text())
        scope = "ticket-" + uuid4().hex
        retained = scope + ".other"
        thread = {"configurable": {"thread_id": scope}}
        table_name = "documents_" + uuid4().hex
        table = Identifier(table_name)
        for store in cfg["stores"].values():
            store["scope"] = scope
        cfg["stores"]["checkpoints"]["artifacts"] = {scope: "delete"}
        cfg["stores"]["vectors"]["table"] = table_name
        path.write_text(self.yaml.safe_dump(cfg, sort_keys=False))
        with PostgresStore.from_conn_string(dsn) as store, PostgresSaver.from_conn_string(dsn) as checkpoints, \
                psycopg.connect(dsn, autocommit=True) as vector:
            store.setup()
            checkpoints.setup()
            vector.execute(SQL("CREATE TABLE {} (id text PRIMARY KEY, ticket_id text, body text, embedding vector(2))").format(table))
            graph = StateGraph(State)
            graph.add_node("save", lambda state: {"summary": state["summary"]})
            graph.add_edge(START, "save")
            graph.add_edge("save", END)
            app = graph.compile(checkpointer=checkpoints)
            adapter = LangGraphPostgresCheckpointAdapter(checkpoints)
            try:
                for namespace in (scope, retained):
                    store.put(tuple(namespace.split(".")), "note", {"memo": self.target})
                    vector.execute(SQL("INSERT INTO {} VALUES (%s,%s,%s,'[1,0]')").format(table),
                                   ("document" if namespace == scope else "retained-document", namespace, self.target))
                    app.invoke({"summary": self.target}, {"configurable": {"thread_id": namespace}})
                hint = self.cli(3, "doctor", "--case", path)
                self.assertRegex(hint, r"case.yml:\d+  Review the full test checkpoint")
                self.assertEqual(self.erase_calls, 0)
                # The test owns these synthetic bytes. Approve the complete target-only
                # thread and the separate vector row, never a marker-only negative.
                snapshot = sorted(adapter.read_thread(scope), key=content_bytes)
                self.assertIn(self.target.encode(), content_bytes(snapshot))
                self.assertNotIn(self.control.encode(), content_bytes(snapshot))
                control = cfg["facts"]["control"]["stored"]
                control["absent_sha256"] = [sha256(content_bytes(snapshot)).hexdigest()]
                control["absent"].append(self.target)
                path.write_text(self.yaml.safe_dump(cfg, sort_keys=False))

                def erase_rows():
                    store.delete((scope,), "note")
                    vector.execute(SQL("DELETE FROM {} WHERE ticket_id=%s").format(table), (scope,))

                self.on_erase = erase_rows  # The graph thread remains readable after ordinary cleanup.
                self.verify(path, 1)
                broken = self.root / "receipt"
                receipt = json.loads((broken / "erasure-receipt.json").read_text())
                self.assertTrue(any(f"checkpoints/{scope}" in line for line in receipt["failures"]), receipt)
                broken.rename(self.root / "broken")
                self.deleted, self.erase_calls = False, 0
                store.put((scope,), "note", {"memo": self.target})
                vector.execute(SQL("INSERT INTO {} VALUES ('document',%s,%s,'[1,0]')").format(table),
                               (scope, self.target))

                def erase_all():
                    erase_rows()
                    checkpoints.delete_thread(scope)

                self.on_erase = erase_all
                self.verify(path)
                self.assertIsNotNone(store.get((scope, "other"), "note"))
                self.assertTrue(adapter.read_thread(retained))
                self.assertEqual(vector.execute(SQL("SELECT id FROM {} WHERE ticket_id=%s").format(table),
                                                (retained,)).fetchone(), ("retained-document",))
            finally:
                for namespace in (scope, retained):
                    store.delete(tuple(namespace.split(".")), "note")
                    checkpoints.delete_thread(namespace)
                vector.execute(SQL("DROP TABLE {}").format(table))

    def test_language_neutral_case_against_node_application(self):
        node = shutil.which("node")
        if not node or subprocess.run([node, "--input-type=module", "-e", "import 'node:sqlite'"],
                                     capture_output=True).returncode:
            self.skipTest("requires Node.js with node:sqlite")
        folder = Path(__file__).resolve().parents[1] / "docs/examples/http-case"
        os.environ["SETRYA_TEST_DB"] = str(self.root / "node.sqlite")
        proc = subprocess.Popen([node, folder / "fixture.mjs"], stdout=subprocess.PIPE, text=True)
        try:
            os.environ["SETRYA_TEST_ORIGIN"] = proc.stdout.readline().strip()
            self.assertTrue(os.environ["SETRYA_TEST_ORIGIN"].startswith("http://127.0.0.1:"))
            path = folder / "case.yml"
            self.cli(0, "doctor", "--case", path)
            self.cli(0, "run", "--case", path, "--output", self.root / "receipt")
            self.cli(0, "replay", self.root / "receipt")
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            proc.stdout.close()
