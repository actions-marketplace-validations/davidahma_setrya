from copy import deepcopy
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

try:
    import pytest
except ImportError as error:
    raise unittest.SkipTest("vendor conformance tests use pytest") from error

import setrya
from setrya.casework import profiles
from setrya.offboarding.inputs import InvalidReport
from setrya.receipt_format import RECEIPT
from setrya.receipts import replay
from setrya.vendor import fixtures, report
from setrya.vendor._mem0 import observation

ROOT = Path(__file__).resolve().parents[1]


def observations():
    present = {"target": True, "retained": True}
    absent = {"target": False, "retained": True}
    phases = [present, absent, absent]
    return {"target": "langgraph-store", "observed_at": "2026-11-22T10:15:00+00:00",
            "versions": {"langgraph": "1.2.24", "langgraph-checkpoint": "4.3.2"}, "error": None,
            "observations": {stage: {"store": values.copy(), "index": values.copy()}
                             for stage, values in zip(report.PHASES, phases, strict=True)}}


def test_clean_checks_cannot_qualify_incomplete_vendor():
    result = report.derive(observations())
    assert result["technical_verdict"] == "PASS"
    assert result["review_status"] == "OPEN_ITEMS"
    assert result["certification"] == "UNQUALIFIED"
    assert set(report.UNTESTED) == {item["store"] for item in result["open_items"]}


def test_duplicate_delete_followup_catches_residual_and_control_loss():
    for target, retained, diagnostic in ((True, True, "readable"), (False, False, "disappeared")):
        evidence = observations()
        evidence["observations"]["after_retry"]["store"] = {"target": target, "retained": retained}
        result = report.derive(evidence)
        assert result["technical_verdict"] == "FAIL"
        assert diagnostic in result["failures"][0]


def test_followup_residual_survives_later_adapter_error():
    evidence = observations()
    evidence["error"] = "fixture-error"
    del evidence["observations"]["after_retry"]
    evidence["observations"]["after_delete"]["index"]["target"] = True
    assert report.derive(evidence)["technical_verdict"] == "FAIL"


def test_unavailable_index_and_failed_positive_control_are_incomplete():
    evidence = observations()
    evidence["observations"]["after_delete"]["index"] = {"target": None, "retained": None}
    assert report.derive(evidence)["technical_verdict"] == "NOT TESTED"
    evidence = observations()
    evidence["observations"]["baseline"]["index"]["retained"] = False
    assert report.derive(evidence)["technical_verdict"] == "NOT TESTED"


def test_invented_or_skipped_observations_cannot_be_replayed():
    evidence = observations()
    for row in evidence["observations"].values():
        row["cache"] = {"target": False, "retained": True}
    with pytest.raises(InvalidReport, match="surface"):
        report.derive(evidence)
    evidence = observations()
    del evidence["observations"]["baseline"]
    with pytest.raises(InvalidReport, match="order"):
        report.derive(evidence)


def test_tampered_receipt_differs_from_evidence(tmp_path):
    raw = observations()
    result = profiles.issue("vendor-conformance", raw, tmp_path)
    assert replay(tmp_path) == result
    path = tmp_path / RECEIPT
    edited = deepcopy(result)
    edited["certification"] = "QUALIFIED"
    path.write_text(json.dumps(edited), encoding="utf-8")
    with pytest.raises(InvalidReport, match="differs"):
        replay(tmp_path)


def test_live_langgraph_store():
    pytest.importorskip("langgraph")
    result = report.derive(fixtures.run_fixture("langgraph-store"))
    assert [row["status"] for row in result["checks"][:2]] == ["PASS", "PASS"]


@pytest.mark.parametrize("remnant, failing", [
    ("target", ("store", "index")),
    ("different-key", ("index",)),
])
def test_live_replacement_with_altered_target_or_rekeyed_marker_fails(monkeypatch, remnant, failing):
    store_module = pytest.importorskip("langgraph.store.memory")
    delete = store_module.InMemoryStore.delete

    def rewrite(store, namespace, key):
        delete(store, namespace, key)
        body = "Changed content" if remnant == key else f"Derived text includes {fixtures.MARKER}"
        store.put(namespace, remnant, {"body": body})

    monkeypatch.setattr(store_module.InMemoryStore, "delete", rewrite)
    result = report.derive(fixtures.run_fixture("langgraph-store"))
    assert result["technical_verdict"] == "FAIL"
    assert tuple(row["surface"] for row in result["checks"] if row["status"] == "FAIL") == failing


def test_exact_content_required_before_erasure_and_any_history_copy_after():
    fixtures_rows = [("target", "Changed text"), ("retained", fixtures.TEXT["retained"]),
                     ("new-id", f"Original marker {fixtures.MARKER} retained in history")]
    assert observation(fixtures_rows, fixtures.IDENTITIES, fixtures.TEXT, fixtures.MARKER, "baseline") == {
        "target": False, "retained": True}
    for removed_position in (0, 2):
        rows = [value for index, value in enumerate(fixtures_rows) if index != removed_position]
        assert observation(rows, fixtures.IDENTITIES, fixtures.TEXT, fixtures.MARKER, "after_delete") == {
            "target": True, "retained": True}


def test_live_pgvector_index():
    if not os.environ.get("SETRYA_PGVECTOR_DSN"):
        pytest.skip("requires a disposable pgvector database")
    pytest.importorskip("psycopg")
    result = report.derive(fixtures.run_fixture("pgvector"))
    assert [row["status"] for row in result["checks"][:2]] == ["PASS", "PASS"]


def test_pgvector_refuses_nonlocal_destination(monkeypatch):
    pytest.importorskip("psycopg")
    monkeypatch.setenv("SETRYA_PGVECTOR_DSN", "postgresql://fixture:example@database.invalid/setrya_fixture")
    assert fixtures.run_fixture("pgvector")["error"] == "missing-dsn"
    monkeypatch.setenv("SETRYA_PGVECTOR_DSN",
                       "postgresql://fixture:example@localhost:5432/setrya_fixture?hostaddr=192.0.2.1")
    assert fixtures.run_fixture("pgvector")["error"] == "missing-dsn"


def test_live_mem0_records_remnant_in_history():
    try:
        installed = version("mem0ai")
    except PackageNotFoundError:
        pytest.skip("requires the conformance-mem0 extra")
    if installed != "2.2.1":
        pytest.skip("the published history result was qualified at Mem0 OSS 2.2.1")
    result = report.derive(fixtures.run_fixture("mem0"))
    assert [row["status"] for row in result["checks"][:3]] == ["PASS", "PASS", "FAIL"]
    assert result["technical_verdict"] == "FAIL"


def test_signed_conformance_action_and_offline_verification(tmp_path, monkeypatch):
    if shutil.which("cosign") is None:
        pytest.skip("requires Cosign 3")
    cosign = subprocess.check_output(["cosign", "version"], text=True)
    if "GitVersion:    v3." not in cosign:
        pytest.skip("requires Cosign 3")
    pytest.importorskip("langgraph")
    installed = subprocess.run([sys.executable, "-I", "-c", "from importlib.metadata import version; print(version('setrya'))"],
                               capture_output=True, text=True)
    if installed.returncode or installed.stdout.strip() != setrya.__version__:
        pytest.skip("the Action requires the matching installed candidate")
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    prefix = tmp_path / "signer"
    subprocess.run(["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)], check=True)
    output = tmp_path / "bundle"
    env = {**os.environ, "SETRYA_CONFORMANCE_TARGET": "langgraph-store",
           "SETRYA_CONFORMANCE_KEY": str(prefix.with_suffix(".key")), "SETRYA_CONFORMANCE_KEYLESS": "false",
           "SETRYA_OUTPUT": str(output), "GITHUB_OUTPUT": str(tmp_path / "action"),
           "GITHUB_STEP_SUMMARY": str(tmp_path / "summary")}
    run = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/action.py"), "conformance"], env=env,
                         cwd=ROOT, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert "exit-code=0\nreview-status=OPEN_ITEMS" in (tmp_path / "action").read_text(encoding="utf-8")
    assert "UNQUALIFIED" in (tmp_path / "summary").read_text(encoding="utf-8")
    argv = [sys.executable, "-m", "setrya", "verify", "--receipt", str(output / RECEIPT),
            "--key", str(prefix.with_suffix(".pub")), "--bundle", str(output / "conformance.sig")]
    subprocess.run(argv, check=True, cwd=ROOT)
