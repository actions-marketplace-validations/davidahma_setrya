"""Turn identity and automatic provenance through real journal and application boundaries."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import SkipTest, TestCase
from unittest.mock import patch

from setrya.drill import InputError
from setrya.erasure import CopyJournal, Subject, Turn, run_shared
from setrya.erasure.hooks import CopyHooks
from setrya.erasure.lineage import VersionRef
from setrya.examples.workspace import CASE, WORKSPACE, open_fixture
from setrya.receipts import replay
from setrya.store_signals import passage_metadata


class TurnProvenance(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.subject = Subject("7" * 64, "restricted")
        self.turn = Turn("turn-1", "operator-7", "summarizer", "principal-9", "parent-turn")

    def journal(self):
        return CopyJournal(self.root / "copies.sqlite")

    def test_open_legacy_journal_records_optional_turns_and_keeps_old_fields(self):
        path = self.root / "copies.sqlite"
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("""CREATE TABLE copy_events (
                event INTEGER PRIMARY KEY, subject TEXT NOT NULL, store TEXT NOT NULL,
                copy_key TEXT NOT NULL, source TEXT NOT NULL, action TEXT NOT NULL,
                classification TEXT NOT NULL, observed_at TEXT NOT NULL, details TEXT NOT NULL
            )""")
            db.execute("INSERT INTO copy_events VALUES(1,?,?,?,?,?,?,?,?)",
                       (self.subject.ref, "files", "old", "source", "stored", self.subject.classification,
                        "2026-11-22T00:00:00+00:00", "{}"))
        journal = self.journal()
        child = Turn("turn-2", "worker", "rewriter", parent=self.turn.id)
        with self.turn.activate():
            self.assertEqual(Turn.current(), self.turn)
            with child.activate():
                journal.record(self.subject, store="files", key="child", source="source", action="retrieved")
            journal.record(self.subject, store="files", key="parent", source="source", action="stored")
        old, observed_child, observed_parent = journal.history(self.subject)
        self.assertEqual(old.wire().keys(), {"store", "key", "source", "action", "classification", "observed_at", "details"})
        self.assertEqual(Turn.from_copy_fields(observed_child.wire()), child)
        self.assertEqual(Turn.from_copy_fields(observed_parent.wire()), self.turn)
        self.assertIsNone(Turn.current())
        with closing(sqlite3.connect(path)) as db:
            self.assertIn("by_turn", {row[1] for row in db.execute("PRAGMA index_list(copy_events)")})

    def test_trusted_headers_graph_metadata_and_baggage(self):
        with self.turn.activate():
            headers = self.subject.headers({"trace": "fixture"})
            self.assertEqual(Turn.from_metadata(headers), self.turn)
            config = self.subject.langgraph_config("workspace", {"metadata": {"trial": "synthetic"}})
            self.assertEqual(Turn.from_metadata(config["metadata"]), self.turn)
            self.assertEqual(config["metadata"]["trial"], "synthetic")
            self.assertNotIn("setrya_turn", self.subject.headers(include_turn=False))
            with self.assertRaisesRegex(InputError, "turn metadata"):
                self.subject.headers(Turn("another", "operator-7", "summarizer").metadata())
        with self.assertRaisesRegex(InputError, "incomplete"):
            Turn.from_metadata({"setrya_turn": "partial"})
        with self.assertRaises(InputError):
            Turn("valid", "invalid actor", "worker")

    def test_wire_baggage_and_journal_trace_carry_delegation(self):
        try:
            from opentelemetry import trace
            from opentelemetry.baggage.propagation import W3CBaggagePropagator
        except ImportError:
            raise SkipTest("OpenTelemetry API required")
        with self.turn.activate():
            wire = {}
            propagator = W3CBaggagePropagator()
            propagator.inject(wire, context=self.subject.otel_context())
            restored = propagator.extract(wire)
            self.assertEqual(Subject.from_baggage(restored), self.subject)
            self.assertEqual(Turn.from_baggage(restored), self.turn)
            journal = CopyJournal(self.root / "trace.db", export_trace_events=True)
            with patch.object(trace, "get_current_span") as span:
                journal.record(self.subject, store="cache", key="answer", source="fixture", action="stored")
            _, attributes = span.return_value.add_event.call_args.args
            self.assertEqual(Turn.from_metadata(attributes), self.turn)

    def test_celery_task_restores_turn(self):
        try:
            from celery import Celery
        except ImportError:
            raise SkipTest("Celery required")
        celery = Celery("provenance-trial", broker="memory://")
        self.addCleanup(celery.close)
        path = self.root / "task.db"

        @celery.task(bind=True)
        def receive(task):
            headers = task.request.headers
            with Subject.from_metadata(headers).activate(), Turn.from_metadata(headers).activate():
                CopyJournal(path).record(Subject.current(), store="worker", key="memo", source="source", action="stored")

        with self.turn.activate():
            headers = self.subject.headers()
        receive.apply(headers=headers).get()
        self.assertEqual(Turn.from_copy_fields(CopyJournal(path).history(self.subject)[0].wire()), self.turn)

    def test_distinct_and_closed_turns_never_supply_inputs(self):
        hooks = CopyHooks(self.journal(), self.subject, infer_lineage=True)
        left = VersionRef("notes", "left", "1")
        right = VersionRef("notes", "right", "1")

        async def summarize(turn, source):
            with turn.activate():
                hooks.record_copy(source, action="retrieved")
                await asyncio.sleep(0)
                hooks.record_copy(VersionRef("summaries", source.key, "1"), action="derived")

        async def run():
            await asyncio.gather(summarize(self.turn, left), summarize(Turn("right-turn", "worker", "agent"), right))
            ready = asyncio.Event()

            async def detached():
                await ready.wait()
                with self.assertRaisesRegex(InputError, "turn has already finished"):
                    hooks.record_copy(VersionRef("notes", "late", "1"), action="retrieved")

            with self.turn.activate():
                task = asyncio.create_task(detached())
            ready.set()
            await task

        asyncio.run(run())
        self.assertEqual({(e["artifact"]["key"], e["inputs"][0]["key"]) for e in hooks.lineage(self.subject)["derivations"]},
                         {("left", "left"), ("right", "right")})

    def test_shared_observed_source_extends_both_owner_graphs_without_reparenting_a_derivation(self):
        journal = self.journal()
        bob = Subject("8" * 64, "restricted")
        alice_hooks = CopyHooks(journal, self.subject, infer_lineage=True)
        bob_hooks = CopyHooks(journal, bob, infer_lineage=True)
        shared = VersionRef("notes", "shared", "1")
        for hooks, name in ((alice_hooks, "alice"), (bob_hooks, "bob")):
            with Turn("summarize-" + name, "operator", "agent").activate():
                hooks.record_copy(shared, action="retrieved")
                hooks.record_copy(VersionRef("handoffs", name, "1"), action="derived")
        for hooks in (alice_hooks, bob_hooks):
            self.assertEqual({item["artifact"]["key"] for item in hooks.lineage(hooks.subject)["derivations"]},
                             {"alice", "bob"})
        private = VersionRef("notes", "private", "1")
        derived = VersionRef("handoffs", "alice-only", "1")
        with Turn("private-summary", "operator", "agent").activate():
            alice_hooks.record_copy(private, action="retrieved")
            alice_hooks.record_copy(derived, action="derived")
        with Turn("another-reader", "operator", "agent").activate():
            with self.assertRaisesRegex(InputError, "no known input path"):
                bob_hooks.record_copy(derived, action="retrieved")
        self.assertNotIn("alice-only", {item["artifact"]["key"] for item in bob_hooks.lineage(bob)["derivations"]})

    def test_tagged_retrieval_and_provider_inputs_extend_turn_provenance(self):
        hooks = CopyHooks(self.journal(), self.subject, infer_lineage=True)
        doc = SimpleNamespace(id="chunk-17", metadata={
            **self.subject.metadata(), **passage_metadata("chart", "revision-3", "segment-1")})
        additional = VersionRef("notes", "shared-control", "2026-11-22")
        client = SimpleNamespace(messages=SimpleNamespace(create=lambda **_: "fake-local-response"))
        memory = SimpleNamespace(put=lambda *_: None)
        with self.turn.activate(), patch("setrya.integrations.langchain.retrieve_with_evidence", return_value=([doc], {})):
            hooks.retrieve(None, "find the subject", store="vectors", route="read", scope="private")
            hooks.anthropic(client, {"model": "local-fixture"}, key="call-1", store="provider", source="prompt",
                            input_versions=[additional])
            hooks.put_memory(memory, "handoff", {}, store="memory", source="generator", copy_revision="written-1")
        derivation, = hooks.lineage(self.subject)["derivations"]
        self.assertEqual(derivation["artifact"], {"store": "memory", "key": "handoff", "revision": "written-1"})
        self.assertEqual({(e["store"], e["key"], e["revision"]) for e in derivation["inputs"]},
                         {("vectors", "chunk-17", "revision-3"), ("notes", "shared-control", "2026-11-22")})

    def test_background_summarizer_drill_uses_inferred_rewrite_and_replays(self):
        with open_fixture(shared=True) as (subject, app, items):
            journal = self.journal()
            hooks = CopyHooks(journal, subject, infer_lineage=True)

            def summarize(headers):
                turn = Turn.from_metadata(headers)
                with turn.activate(), app.lock, app.db:
                    sources = app._sources()
                    for key, revision, _ in sources:
                        if key == "customer-note":
                            hooks.record_copy(VersionRef("notes", key, revision), action="retrieved")
                    app._save(sources)
                    row = app.inspect(subject, "handoffs", WORKSPACE)
                    hooks.record_copy(VersionRef("handoffs", WORKSPACE, row.revision), action="derived")

            with self.turn.activate():
                headers = subject.headers()
            with ThreadPoolExecutor(max_workers=1) as worker:
                worker.submit(summarize, headers).result(timeout=5)
            app.lineage = hooks.lineage
            output = self.root / "receipt"
            from setrya.erasure import observe_baseline
            case = replace(CASE, require_lineage=True)
            self.assertTrue(observe_baseline(subject, case, app, external_items=items))
            result = run_shared(subject, case=case, application=app, mode="deletion",
                                external_items=items, journal=journal, output=output)
            self.assertEqual(result["technical_verdict"], "PASS")
            self.assertEqual(replay(output), result)
            evidence = json.loads((output / "erasure-evidence.json").read_text())
            self.assertEqual([Turn.from_copy_fields(row) for row in evidence["journal"]], [self.turn, self.turn])
            self.assertEqual(evidence["lineage"]["derivations"][0]["artifact"]["key"], WORKSPACE)
