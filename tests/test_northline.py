"""Prove the chart, PDF, investigation and discovery handoff end to end."""
import json
import os
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from importlib.resources import files
from io import StringIO
from pathlib import Path
from shutil import which
from tempfile import TemporaryDirectory
from unittest.mock import patch

from setrya.cli import main
from setrya.core.receipt_v3 import answer_slots, sample_rows
from setrya.discovery import northline
from setrya.discovery.case import replay, run_case
from setrya.discovery.macie import load_finding
from setrya.discovery.mapping import bind_finding, load_mapping
from setrya.examples import northline_app as fixture
from setrya.offboarding.inputs import InvalidReport


def cli(*args):
    stream = StringIO()
    with redirect_stdout(stream), redirect_stderr(stream):
        code = main(list(map(str, args)))
    return code, stream.getvalue()


class NorthlineTest(unittest.TestCase):
    def setUp(self):
        self.folder = Path(self.enterContext(TemporaryDirectory()))
        self.inputs = self.folder / "approval"
        code, text = cli("discovery", "init", "--example", "northline", "--output", self.inputs)
        self.assertEqual(code, 0, text)
        self.finding = self.inputs / "finding.json"
        self.mapping = self.inputs / "mapping.json"
        self.binding = bind_finding(load_finding(self.finding), load_mapping(self.mapping))

    @unittest.skipUnless(which("git"), "requires Git to reconstruct the fixture commit independently")
    def test_mapping_identifies_the_packaged_application(self):
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_AUTHOR_NAME="Setrya", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                   GIT_COMMITTER_NAME="Setrya", GIT_COMMITTER_EMAIL="fixture@example.invalid",
                   GIT_AUTHOR_DATE="2000-01-01T00:00:00+00:00", GIT_COMMITTER_DATE="2000-01-01T00:00:00+00:00")

        def git(*args, payload=None):
            return subprocess.run(["git", *args], cwd=self.folder, check=True, input=payload,
                                  env=env, capture_output=True, timeout=10).stdout.strip()

        git("init", "--quiet", "--object-format=sha1")
        entries = []
        for name in ("northline_app.py", "northline_pdf.py"):
            body = files("setrya.examples").joinpath(name).read_bytes()
            blob = git("hash-object", "-w", "--stdin", payload=body)
            entries.append(b"100644 blob " + blob + b"\t" + name.encode("ascii") + b"\n")
        tree = git("mktree", payload=b"".join(entries)).decode("ascii")
        revision = git("commit-tree", tree, "-m", "Northline fixture").decode("ascii")
        self.assertEqual(self.binding["revision"], revision)

    def test_same_investigation_and_pdf_are_checked_before_and_after_the_worker(self):
        output = self.folder / "demo"
        code, text = cli("demo", "northline", "--output", output)
        self.assertEqual(code, 0, text)
        self.assertIn("Technical verdict FAIL · Review status RESIDUAL_FOUND", text)
        self.assertIn("Technical verdict PASS · Review status OPEN_ITEMS", text)
        self.assertEqual({p.name for p in output.iterdir()}, {"broken", "guarded", "example"})
        approval = ("--finding", self.finding, "--mapping", self.mapping)
        reviewer = cli("receipt", "summary", output / "guarded", "--audience", "reviewer")[1]
        self.assertIn("Invocation unobserved. Provider retention evidence is unavailable.", reviewer)
        customer = cli("receipt", "summary", output / "guarded", "--audience", "customer")[1]
        self.assertIn("Provider evidence unavailable", customer)
        self.assertNotIn("Provider configuration", customer)
        broken_review = cli("receipt", "summary", output / "broken", "--audience", "reviewer")[1]
        self.assertIn("turn northline-refresh", broken_review)
        self.assertIn("erasure/erasure-evidence.json#/journal/", broken_review)
        for lane, expected, verdict in (("broken", 1, "FAIL"), ("guarded", 0, "PASS")):
            with self.subTest(lane=lane):
                bundle = output / lane
                result = replay(bundle, expected_binding=self.binding)
                self.assertEqual(result["technical_verdict"], verdict)
                self.assertEqual(result["race"], "exercised")
                self.assertEqual(result["case_id"], fixture.CASE_ID)
                services = {row["id"]: row for row in result["services"]}
                provider = services[fixture.PROVIDER_ID]
                self.assertEqual(provider["status"], "OPEN")
                self.assertEqual(provider["owner"], fixture.PROVIDER_OWNER)
                self.assertEqual(provider["invocation"]["status"], "UNOBSERVED")
                self.assertFalse(provider["evidence"])
                source = next(row for row in result["services"] if row["role"] == "source")
                self.assertEqual((source["key"], source["action"], source["status"]), ("F-42", "rewrite", "PASS"))
                self.assertEqual(cli("discovery", "replay", bundle, *approval)[0], expected)
                self.assertEqual(cli("replay", bundle, "--case-review")[0], 3 if expected == 0 else 1)
                evidence_path = bundle / "erasure" / "erasure-evidence.json"
                raw = evidence_path.read_text()
                self.assertNotIn(fixture.TARGET_FACT, raw)
                self.assertNotIn("setrya-northline-fixture", (bundle / "case-input.json").read_text())
                e = json.loads(raw)
                self.assertEqual(len(set(e["worker"].values())), 1)
                self.assertTrue(e["worker"]["drained"])
                spec = e["case"]
                self.assertEqual(spec["conversation"], fixture.CONVERSATION)
                self.assertEqual(spec["callers"], list(fixture.CALLERS))
                inputs = {(row["artifact"]["store"], parents["store"]) for row in e["lineage"]["derivations"]
                          for parents in row["inputs"]}
                self.assertIn((fixture.CHART_STORE, fixture.SOURCE_STORE), inputs)
                self.assertIn((fixture.PDF_STORE, fixture.CHART_STORE), inputs)
                for stage, restored in (("baseline", True), ("immediate", False), ("final", lane == "broken")):
                    stored = {row["store"]: row for row in e[stage]["stored"]}
                    for store in (fixture.PDF_STORE, fixture.CHART_STORE, fixture.CHAT_STORE):
                        row = stored[store]
                        self.assertTrue(row["exists"])
                        self.assertEqual(row["target_present"], restored)
                        self.assertTrue(row["control_present"])
                    origin = stored[fixture.SOURCE_STORE]
                    self.assertEqual(origin["key"], fixture.SOURCE_KEY)
                    self.assertEqual(origin["target_present"], stage == "baseline")
                    self.assertTrue(origin["control_present"])
                    slots = zip(answer_slots(spec), sample_rows(e[stage], spec, grouped=True), strict=True)
                    seen = set()
                    for (caller, _, role, _), (_, answer) in slots:
                        self.assertEqual(answer["caller"], caller)
                        self.assertEqual(answer["conversation"], fixture.CONVERSATION)
                        self.assertEqual(answer["route"], fixture.ROUTE)
                        self.assertTrue(answer["control_present"] if role == "control" else
                                        answer["target_present"] is restored)
                        seen.add((caller, role))
                    self.assertEqual(seen, {(caller, role) for caller in fixture.CALLERS for role in ("target", "control")})
                attribution = json.loads((bundle / "erasure" / "erasure-receipt.json").read_bytes())
                late = {row["store"] for row in attribution.get("write_attribution", [])}
                self.assertEqual(late, {fixture.PDF_STORE, fixture.CHART_STORE, fixture.CHAT_STORE} if expected else set())

    def test_unread_required_pdf_cannot_authorize_deletion_or_release(self):
        bundle = self.folder / "unread-pdf"
        with northline.open_fixture(self.binding) as settings:
            app = settings["application"]
            inspect = app.inspect

            def without_pdf(subject, store, key):
                return None if store == fixture.PDF_STORE else inspect(subject, store, key)

            with patch.object(app, "inspect", side_effect=without_pdf):
                run_case(self.binding, **settings, mode="late-write", output=bundle)
        result = replay(bundle, expected_binding=self.binding)
        self.assertEqual(result["technical_verdict"], "NOT TESTED")
        e = json.loads((bundle / "erasure" / "erasure-evidence.json").read_bytes())
        self.assertIsNone(e["erased"])
        self.assertIsNone(e["worker"]["held"])
        self.assertTrue(any(row.get("store") == fixture.PDF_STORE and row["baseline"] == "UNREAD"
                            for row in result["services"]))

    def test_run_import_export_and_independent_scope_pin(self):
        approved = self.folder / "normalized.json"
        bundle = self.folder / "run"
        self.assertEqual(cli("discovery", "import", "--finding", self.finding, "--output", approved)[0], 0)
        approval = ("--finding", approved, "--mapping", self.mapping)
        result, transcript = cli("discovery", "run", *approval, "--fixture", self.inputs / "fixture.py",
                                 "--mode", "late-write", "--output", bundle)
        self.assertEqual(result, 0, transcript)
        exported = self.folder / "N-204.json"
        self.assertEqual(cli("discovery", "export", bundle, *approval, "--output", exported)[0], 0)
        self.assertEqual(exported.read_bytes(), (bundle / "case-result.json").read_bytes())
        finding = json.loads(self.finding.read_bytes())
        finding["detail"]["resourcesAffected"]["s3Object"]["versionId"] = "a-different-version"
        replaced = self.folder / "other.json"
        replaced.write_text(json.dumps(finding))
        self.assertEqual(cli("discovery", "replay", bundle, "--finding", replaced, "--mapping", self.mapping)[0], 2)
        binding = deepcopy(self.binding)
        binding["source"]["revision"] = "incorrect-revision"
        with self.assertRaisesRegex(InvalidReport, "independently supplied"):
            replay(bundle, expected_binding=binding)
        mismatched = self.folder / "wrong-source"
        with northline.open_fixture(binding) as settings:
            run_case(binding, **settings, output=mismatched)
        wrong_source = replay(mismatched, expected_binding=binding)
        self.assertEqual(wrong_source["technical_verdict"], "NOT TESTED")
        self.assertIn("source read does not match the revision approved", " ".join(wrong_source["gaps"]))
        binding = deepcopy(self.binding)
        binding["revision"] = "0" * 40
        rejected = self.folder / "wrong-app"
        with northline.open_fixture(binding) as settings, self.assertRaisesRegex(InvalidReport, "Fixture revision"):
            run_case(binding, **settings, output=rejected)
        self.assertFalse(rejected.exists())

    @unittest.skipUnless(which("pdftotext"), "requires an independent PDF reader")
    def test_pdf_contains_the_actual_rendered_labels(self):
        with northline.open_fixture(self.binding) as settings:
            app = settings["application"]
            parsed = subprocess.check_output(["pdftotext", str(app.pdf_path), "-"], text=True, timeout=10)
            self.assertIn(fixture.TARGET_FACT, parsed)
            self.assertIn(fixture.CONTROL_FACT, parsed)
            source = self.binding["source"]
            actions = tuple({"store": a.store, "key": a.key, "action": a.action} for a in fixture.ARTIFACTS)
            self.assertTrue(app.erase_approved(settings["subject"], source, actions))
            parsed = subprocess.check_output(["pdftotext", str(app.pdf_path), "-"], text=True, timeout=10)
            self.assertNotIn(fixture.TARGET_FACT, parsed)
            self.assertIn(fixture.CONTROL_FACT, parsed)
