"""Bind a turn to a reappearing revision through a real held-worker run."""

from contextlib import redirect_stdout
from copy import deepcopy
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from setrya.casework.receipt_summary import receipt_summary
from setrya.cli import main
from setrya.core.receipt_v3 import derive
from setrya.erasure import Stored, run_shared
from setrya.erasure.lineage import VersionRef
from setrya.examples.memory_files import DERIVED_FILE, TARGET, TARGET_FILE, open_fixture
from setrya.examples.workspace import demo as workspace_demo
from setrya.offboarding.inputs import InvalidReport
from setrya.receipts import STALE_WRITE_BACK_LEAD, replay, stale_write_back_entry, summary, write_back_lead


@unittest.skipUnless(shutil.which("git"), "Git is required for the memory-file fixture")
class Attribution(unittest.TestCase):
    def test_match_version_turn_and_observed_release_window(self):
        with (TemporaryDirectory() as work,
              open_fixture(shutil.which("git"), guarded=False) as (subject, app, items)):
            root = Path(work, "case")
            receipt = run_shared(subject, case=app.case(), application=app, output=root, external_items=items,
                                 journal=app.journal, cancel_hold=app.cancel_and_drain)
            self.assertEqual(receipt["technical_verdict"], "FAIL")
            self.assertEqual(replay(root), receipt)

            attribution, = receipt["write_attribution"]
            self.assertEqual((attribution["store"], attribution["key"], attribution["turn"], attribution["agent"]),
                             ("files", DERIVED_FILE, "late-memory", "dreaming-agent"))
            evidence = json.loads((root / "erasure-evidence.json").read_bytes())
            index = attribution["journal_entry"]
            self.assertEqual(evidence["journal"][index]["details"]["revision"], attribution["revision"])
            self.assertLessEqual(evidence["late_write_window"]["start"], index)
            self.assertGreater(evidence["late_write_window"]["stop"], index)
            self.assertIn("turn late-memory", summary(receipt))
            self.assertIn("turn late-memory", receipt_summary(root, audience="reviewer"))
            self.assertNotIn("late-memory", receipt_summary(root, audience="customer"))
            lead = STALE_WRITE_BACK_LEAD.format(entry=index)
            self.assertEqual(stale_write_back_entry(receipt, root), index)
            self.assertEqual(summary(receipt, bundle=root).splitlines()[0], lead)
            for audience in ("engineer", "reviewer", "customer"):
                for output_format in ("text", "markdown"):
                    text = receipt_summary(root, audience=audience, output_format=output_format)
                    self.assertEqual(text.splitlines()[0], lead)
            self.assertNotIn(" at after erasure.", summary(receipt))
            self.assertNotIn(" at after erasure.", receipt_summary(root, audience="reviewer"))

            for reason in ("different revision", "different key", "attempt", "failed write", "ambiguous writes", "outside drain window"):
                with self.subTest(reason=reason):
                    changed = deepcopy(evidence)
                    row = changed["journal"][index]
                    if reason == "different revision":
                        row["details"]["revision"] = "different-revision"
                    elif reason == "different key":
                        row["key"] = "related"
                    elif reason in ("attempt", "failed write"):
                        row["details"]["stage"] = "attempted" if reason == "attempt" else "failed"
                    elif reason == "ambiguous writes":
                        changed["journal"].append({**row, "turn": "another-write"})
                        changed["late_write_window"]["stop"] += 1
                    else:
                        changed["late_write_window"] = {"start": 0, "stop": index}
                    result = derive(changed, receipt["evidence"]["sha256"])
                    self.assertEqual(result["technical_verdict"], "FAIL")
                    self.assertNotIn("write_attribution", result)

            for reason, present in (("inconclusive direct read", None), ("clean direct read", False),
                                    ("unchanged revision", True)):
                with self.subTest(reason=reason):
                    observed = deepcopy(evidence)
                    if present is True:
                        earlier = next(row for row in observed["immediate"]["stored"] if row["key"] == DERIVED_FILE)
                        self.assertFalse(earlier["target_present"])
                        earlier["revision"] = attribution["revision"]
                    else:
                        later = next(row for row in observed["final"]["stored"] if row["key"] == DERIVED_FILE)
                        later["target_present"] = present
                    raw = json.dumps(observed).encode()
                    result = derive(observed, sha256(raw).hexdigest())
                    self.assertEqual(result["technical_verdict"], "FAIL")
                    self.assertEqual(result["write_attribution"], [attribution])
                    historical = root.parent / reason
                    historical.mkdir()
                    (historical / "erasure-evidence.json").write_bytes(raw)
                    (historical / "erasure-receipt.json").write_text(json.dumps(result))
                    self.assertEqual(replay(historical), result)
                    self.assertIsNone(stale_write_back_entry(result, historical))
                    self.assertNotIn("Stale write-back:", receipt_summary(historical, audience="reviewer"))

            # A verified journal can correlate a residual to a different writer
            # active during the hold. That does not reveal when it read the input.
            unbound = deepcopy(evidence)
            unbound["worker"] = dict.fromkeys(evidence["worker"], "other-worker")
            raw = json.dumps(unbound).encode()
            changed = derive(unbound, sha256(raw).hexdigest())
            self.assertEqual(changed["write_attribution"], [attribution])
            historical = root.parent / "unbound"
            historical.mkdir()
            (historical / "erasure-evidence.json").write_bytes(raw)
            (historical / "erasure-receipt.json").write_text(json.dumps(changed))
            self.assertEqual(replay(historical), changed)
            self.assertIsNone(stale_write_back_entry(changed, historical))
            self.assertNotIn("Stale write-back:", receipt_summary(historical, audience="reviewer"))

            (historical / "erasure-evidence.json").write_bytes((root / "erasure-evidence.json").read_bytes())
            with self.assertRaisesRegex(InvalidReport, "changed after replay"):
                stale_write_back_entry(changed, historical)

            malformed = deepcopy(evidence)
            malformed["late_write_window"]["stop"] = len(evidence["journal"]) + 1
            with self.assertRaisesRegex(InvalidReport, "Invalid journal window"):
                derive(malformed, receipt["evidence"]["sha256"])

    def test_new_late_scan_location_has_an_independent_revision_read(self):
        with (TemporaryDirectory() as work,
              open_fixture(shutil.which("git"), guarded=False) as (subject, app, items)):
            extra = "clients/acme/unexpected_new_copy.md"
            original_publish = app._publish
            original_read = app.inspect
            canary = TARGET.encode()
            revision = sha256(canary).hexdigest()

            def publish(sources):
                original_publish(sources)
                if TARGET_FILE in sources:
                    app._write(extra, canary)
                    app.hooks.record_copy(VersionRef("files", extra, revision), action="derived")

            def inspect(subject, store, key):
                if key == extra and store == "files":
                    self.assertTrue((app.root / extra).is_file())
                    body = (app.root / extra).read_bytes()
                    return Stored(key, True, canary in body, None, sha256(body).hexdigest())
                return original_read(subject, store, key)

            app._publish, app.inspect = publish, inspect
            root = Path(work, "case")
            result = run_shared(subject, case=app.case(), application=app, output=root, external_items=items,
                                journal=app.journal, cancel_hold=app.cancel_and_drain)
            self.assertEqual(result["technical_verdict"], "FAIL")
            self.assertEqual(result, replay(root))
            evidence = json.loads((root / "erasure-evidence.json").read_bytes())
            self.assertIn(extra, evidence["final"]["scans"]["files"])
            self.assertNotIn(extra, evidence["immediate"]["scans"]["files"])
            self.assertEqual([row["key"] for row in evidence["late_residuals"] if row and row["store"] == "files"],
                             [extra])
            new, = [row for row in result["write_attribution"] if row["key"] == extra]
            self.assertEqual((new["revision"], new["turn"]), (revision, "late-memory"))

            observed = deepcopy(evidence)
            primary = next(row for row in observed["final"]["stored"] if row["key"] == DERIVED_FILE)
            primary["target_present"] = None
            raw = json.dumps(observed).encode()
            (root / "erasure-evidence.json").write_bytes(raw)
            changed = derive(observed, sha256(raw).hexdigest())
            (root / "erasure-receipt.json").write_text(json.dumps(changed))
            self.assertEqual(replay(root), changed)
            self.assertEqual(changed["write_attribution"], result["write_attribution"])
            self.assertEqual(stale_write_back_entry(changed, root), new["journal_entry"])

            evidence["immediate"]["scan_details"]["files"]["patterns"] = ["**/*.jsonl"]
            changed = derive(evidence, result["evidence"]["sha256"])
            self.assertEqual(changed["technical_verdict"], "FAIL")
            self.assertNotIn(extra, {row["key"] for row in changed["write_attribution"]})

    def test_review_discloses_native_scan_scope_and_remote_follow_up(self):
        with (TemporaryDirectory() as work,
              open_fixture(shutil.which("git"), guarded=True) as (subject, app, items)):
            root = Path(work, "case")
            app.git("remote", "add", "origin", "https://example.invalid/project.git")
            (app.root / "unmatched.txt").write_text("synthetic fixture")
            receipt = run_shared(subject, case=app.case(), application=app, output=root, external_items=items,
                                 journal=app.journal, cancel_hold=app.cancel_and_drain)
            self.assertEqual(receipt["technical_verdict"], "PASS")
            self.assertEqual(receipt["review_status"], "OPEN_ITEMS")
            self.assertEqual(replay(root), receipt)
            reviewer = receipt_summary(root, audience="reviewer")
            self.assertIn("Local Git blobs, including unreachable objects", reviewer)
            self.assertIn("Include patterns: **/*.md, **/*.jsonl", reviewer)
            excluded = next(line for line in reviewer.splitlines() if "Files outside those patterns:" in line)
            self.assertIn("1 .txt", excluded)
            self.assertIn("Remote copies were not inspected.", reviewer)
            self.assertIn("Remote copies were not inspected", receipt_summary(root, audience="customer"))
            self.assertNotIn("example.invalid", reviewer)


class WorkspaceWriteBack(unittest.TestCase):
    def test_workspace_proves_write_back_in_the_broken_lane_only(self):
        with TemporaryDirectory() as work, redirect_stdout(StringIO()) as transcript:
            bundle = Path(work, "workspace")
            self.assertEqual(workspace_demo(bundle, "late-write"), 0)
            self.assertIn("Stale write-back:", transcript.getvalue())
            for lane, code, expected in (("broken", 1, True), ("guarded", 0, False)):
                folder = bundle / lane
                receipt = replay(folder)
                lead = write_back_lead(receipt, folder)
                self.assertEqual(lead is not None, expected)
                for path in (folder, folder / "erasure-receipt.json"):
                    transcript.seek(0)
                    transcript.truncate()
                    self.assertEqual(main(["replay", str(path)]), code)
                    if expected:
                        self.assertTrue(transcript.getvalue().startswith(lead))
                    else:
                        self.assertNotIn("Stale write-back:", transcript.getvalue())
