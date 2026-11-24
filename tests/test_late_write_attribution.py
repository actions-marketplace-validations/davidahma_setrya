"""Bind a turn to a reappearing revision through a real held-worker run."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from setrya.casework.receipt_summary import receipt_summary
from setrya.core.receipt_v3 import derive
from setrya.erasure import Stored, run_shared
from setrya.erasure.lineage import VersionRef
from setrya.examples.memory_files import DERIVED_FILE, TARGET, TARGET_FILE, open_fixture
from setrya.offboarding.inputs import InvalidReport
from setrya.receipts import replay, summary


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

            scanner_only = deepcopy(evidence)
            retained = next(row for row in scanner_only["final"]["stored"] if row["key"] == DERIVED_FILE)
            retained["target_present"] = None
            result = derive(scanner_only, receipt["evidence"]["sha256"])
            self.assertEqual(result["technical_verdict"], "FAIL")
            self.assertEqual(result["write_attribution"], [attribution])

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
                    actual = sha256((app.root / extra).read_bytes()).hexdigest()
                    return Stored(key, True, None, None, actual)
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
