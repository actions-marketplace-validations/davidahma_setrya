"""Verify OTLP wire import, identity conflicts, and incomplete coverage."""

import json
from pathlib import Path
import sqlite3

from setrya.cli import main
from setrya.erasure.journal_merge import CollectedJournal
from setrya.erasure.subject import Subject


def test_otlp_import_is_atomic_and_unsealed(tmp_path):
    subject = Subject("a" * 64, "synthetic")
    trace = tmp_path / "trace.json"
    destination = tmp_path / "collector.sqlite"
    args = ["journal", "import", "--otlp", str(trace), "--journal", str(destination),
            "--run-id", "trial", "--producer", "worker"]

    def event(sequence, **changes):
        attrs = {
            **subject.metadata(), "setrya_run": "trial", "setrya_producer": "worker",
            "setrya_sequence": sequence, "store": "memory", "copy_key": "handoff",
            "source": "note", "action": "derived", "observed_at": "2026-11-20T10:00:00Z",
            "details_json": '{"sources":["note"]}', "setrya_turn": "turn-1",
            "setrya_initiator": "synthetic-user", "setrya_agent": "support",
        }
        attrs.update(changes)
        return {"name": "setrya.copy.v1", "attributes": [
            {"key": key, "value": {"intValue": str(value)} if key == "setrya_sequence" else {"stringValue": value}}
            for key, value in attrs.items()
        ]}

    def export(*events):
        trace.write_text(json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [{"events": [
            {"name": "other", "attributes": [{"key": "ignored", "value": {"stringValue": "not imported"}}]},
            *events,
        ]}]}]}]}))

    export(event(1))
    assert main(args) == main(args) == 0
    collector = CollectedJournal(destination, run_id="trial")
    rows = collector.history(subject)
    assert len(rows) == 1
    assert rows[0].turn == "turn-1"
    assert rows[0].details["sources"] == ["note"]
    assert collector.coverage(subject, run_id="trial", expected_producers=["worker"])["missing"] == ["worker"]
    export(event(2), event(1, copy_key="conflict"))
    assert main(args) == 2
    assert len(collector.history(subject)) == 1
    export(event(2), event(3, setrya_producer="another"))
    assert main(args) == 2
    assert len(collector.history(subject)) == 1
    verify = main(["journal", "verify", str(destination), "--json"])
    assert verify == 0
    with sqlite3.connect(destination) as database:
        assert not list(database.execute("SELECT * FROM collected_seals"))


def test_copy_event_schema_ships_and_covers_turn_fields():
    schema = Path(__file__).parents[1] / "setrya/erasure/copy-event.v1.schema.json"
    document = json.loads(schema.read_bytes())
    assert document["$id"] == "urn:setrya:copy-event:v1"
    assert document["dependentRequired"]["parent_turn"] == ["turn", "initiator", "agent"]
