import argparse
from contextlib import closing, redirect_stdout
from datetime import UTC, datetime, timedelta
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from setrya.branches.cli import check_branches
from setrya.core.branch_journal import read_branches
from setrya.branches.scanners import neon_branches, postgres_archiving
from setrya.casework import recheck
from setrya.casework.receipt_summary import receipt_summary
from setrya.cli import main
from setrya.core.inputs import InvalidReport
from setrya.core.journal import CopyJournal
from setrya.core.subject import Turn
from setrya.receipts import replay


def configuration(tmp_path):
    journal = CopyJournal(tmp_path / "journal.sqlite")
    inventory = tmp_path / "branch-inventory.toml"
    backups = tmp_path / "copies"
    backups.mkdir()
    now = datetime.now(UTC)
    erased = now - timedelta(seconds=2)
    return argparse.Namespace(root=tmp_path, journal=journal, inventory=inventory, backups=backups,
                              erased=erased, snapshot=erased - timedelta(seconds=3))


def run(case, name="receipt"):
    return check_branches(store="app-db", erased_at=case.erased.isoformat(), inventory=case.inventory,
                          journal=case.journal.path, output=case.root / name)


def inventory(case, seconds=0):
    case.inventory.write_text(f'''[[scanners]]
id = "copies"
kind = "sqlite"
path = "copies"

[scanners.aliases]
"backup.sqlite" = "backup"
"restored.sqlite" = "restored"

[[restore_windows]]
id = "pitr"
owner = "platform-db"
seconds = {seconds}
''', encoding="utf-8")


def database(path):
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE TABLE subjects(id TEXT)")
        db.execute("INSERT INTO subjects VALUES ('synthetic-only')")


def git(path, *args):
    subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, env={**os.environ,
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "Setrya", "GIT_AUTHOR_EMAIL": "test@example.invalid",
                   "GIT_COMMITTER_NAME": "Setrya", "GIT_COMMITTER_EMAIL": "test@example.invalid"})


class BranchLineage(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.case = configuration(Path(directory))

    def test_sqlite_restored_descendant_is_residual_after_parent_removed(self):
        case = self.case
        inventory(case)
        case.journal.record_branch("app-db", "backup", case.snapshot)
        with Turn("restore-turn", "reviewer", "agent").activate():
            case.journal.record_branch("backup", "restored", case.erased + timedelta(seconds=1))
        database(case.backups / "restored.sqlite")
        receipt = run(case)
        self.assertEqual(receipt["technical_verdict"], "FAIL")
        self.assertEqual(receipt["review_status"], "RESIDUAL_FOUND")
        self.assertEqual([(b["child"], b["status"]) for b in receipt["branches"]], [("backup", "GONE"), ("restored", "RESIDUAL")])
        self.assertEqual(receipt["branches"][1]["turn"]["turn"], "restore-turn")
        self.assertEqual(replay(case.root / "receipt"), receipt)
        self.assertNotIn("synthetic-only", (case.root / "receipt" / "observation-evidence.json").read_text())

    def test_unjournalled_backup_and_mutable_post_erasure_alias_are_unknown(self):
        case = self.case
        inventory(case)
        case.journal.record_branch("app-db", "backup", case.snapshot)
        case.journal.record_branch("app-db", "restored", case.erased + timedelta(seconds=1))
        database(case.backups / "restored.sqlite")
        database(case.backups / "unmapped.sqlite")
        receipt = run(case)
        self.assertEqual(receipt["technical_verdict"], "NOT TESTED")
        rows = {b["child"]: b["status"] for b in receipt["branches"]}
        self.assertEqual(rows["restored"], "UNKNOWN")
        self.assertEqual(list(rows.values()).count("UNKNOWN"), 2)

    def test_in_place_restore_cannot_use_the_older_alias_generation(self):
        case = self.case
        inventory(case)
        snapshot = case.root / "before.sqlite"
        current = case.backups / "restored.sqlite"
        database(snapshot)
        database(current)
        with sqlite3.connect(current) as live:
            live.execute("DELETE FROM subjects")
        case.journal.record_branch("app-db", "restored", case.erased + timedelta(seconds=1))
        with closing(sqlite3.connect(snapshot)) as original, closing(sqlite3.connect(current)) as live:
            original.backup(live)
            self.assertEqual(live.execute("SELECT id FROM subjects").fetchone(), ("synthetic-only",))
        result = run(case)
        self.assertEqual(result["technical_verdict"], "NOT TESTED")
        self.assertEqual(replay(case.root / "receipt"), result)

    @unittest.skipUnless(os.environ.get("SETRYA_PGVECTOR_DSN"), "requires disposable PostgreSQL")
    def test_native_archive_mode(self):
        self.assertIn(postgres_archiving("SETRYA_PGVECTOR_DSN"), ("off", "on", "always"))

    def test_postgres_archive_mode_is_configuration_only(self):
        case = self.case
        inventory(case, seconds=3600)
        with case.inventory.open("a", encoding="utf-8") as stream:
            stream.write('postgres_dsn_env = "TRIAL_DSN"\n')
        with patch("setrya.branches.cli.postgres_archiving", return_value="on") as observe:
            result = run(case)
        observe.assert_called_once_with("TRIAL_DSN")
        self.assertEqual(result["restore_windows"][0]["postgres_archiving"], "on")
        self.assertEqual(result["review_status"], "OPEN_ITEMS")
        self.assertEqual(result["open_items"][0]["evidence"], "declared-postgres-restore-window")
        self.assertEqual(replay(case.root / "receipt"), result)

    def test_missing_scanner_root_preserves_other_residual(self):
        case = self.case
        inventory(case)
        with case.inventory.open("a", encoding="utf-8") as stream:
            stream.write('''
    [[scanners]]
    id = "unreachable"
    kind = "sqlite"
    path = "missing"
    ''')
        case.journal.record_branch("app-db", "backup", case.snapshot)
        case.journal.record_branch("app-db", "restored", case.snapshot)
        database(case.backups / "backup.sqlite")
        receipt = run(case)
        self.assertEqual(receipt["technical_verdict"], "FAIL")
        self.assertTrue(any("unreachable" in gap for gap in receipt["gaps"]))

    def test_recheck_closes_only_elapsed_backup_configuration(self):
        case = self.case
        inventory(case, seconds=60)
        case.journal.record_branch("app-db", "backup", case.snapshot)
        case.journal.record_branch("app-db", "restored", case.snapshot)
        receipt = run(case)
        self.assertEqual(receipt["technical_verdict"], "PASS")
        self.assertEqual(receipt["review_status"], "OPEN_ITEMS")
        self.assertEqual(receipt["open_items"][0]["evidence"], "declared-postgres-restore-window")
        original = case.root / "receipt"
        waiting = case.root / "waiting"
        self.assertEqual(recheck.recheck(original, output=waiting)["items"][0]["reason"], "not-due")
        expiry = datetime.fromisoformat(receipt["open_items"][0]["expires_at"])

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return expiry.astimezone(tz)

        closed = case.root / "closed"
        with patch.object(recheck, "datetime", Clock):
            followup = recheck.recheck(waiting, output=closed)
        self.assertEqual(followup["items"][0]["reason"], "configured-window-elapsed")
        self.assertEqual(followup["items"][0]["status"], "verified")
        self.assertEqual(followup["items"][0]["kind"], "restore-window")
        self.assertEqual(followup["review_status"], "READY_FOR_REVIEW")
        with self.assertRaisesRegex(InvalidReport, "ahead of the verifier clock"):
            replay(closed)
        with patch.object(recheck, "datetime", Clock):
            self.assertEqual(replay(closed), followup)
            parent = closed / "parent" / "parent" / "observation-evidence.json"
            parent.write_text(parent.read_text() + "\n")
            with self.assertRaisesRegex(InvalidReport, "differs"):
                replay(closed)

    def test_incomplete_copy_and_exact_erasure_time_stay_unknown(self):
        case = self.case
        inventory(case)
        case.journal.record_branch("app-db", "backup", case.snapshot)
        case.journal.record_branch("app-db", "restored", case.erased)
        database(case.backups / "backup.sqlite")
        database(case.backups / "restored.sqlite")
        (case.backups / "backup.sqlite-wal").write_bytes(b"not recovered")
        receipt = run(case)
        self.assertEqual(receipt["technical_verdict"], "NOT TESTED")
        self.assertEqual({row["status"] for row in receipt["branches"]}, {"UNKNOWN"})

    def test_empty_branch_checkpoint_can_be_pinned(self):
        case = self.case
        inventory(case)
        receipt = run(case)
        with redirect_stdout(StringIO()):
            self.assertEqual(main(["journal", "verify", str(case.journal.path),
                                   "--expected-branch-head", receipt["journal_head"]]), 0)

    def test_journal_keeps_original_edge_and_rejects_cycles(self):
        case = self.case
        edge = case.journal.record_branch("app-db", "backup", case.snapshot)
        with self.assertRaises(InvalidReport):
            case.journal.record_branch("another-db", "backup", case.snapshot)
        with self.assertRaisesRegex(InvalidReport, "cycle"):
            case.journal.record_branch("backup", "app-db", case.snapshot)
        self.assertEqual(read_branches(case.journal.path), [edge])

    def test_saved_branch_chain_detects_edit_and_rollbacks(self):
        case = self.case
        inventory(case)
        case.journal.record_branch("app-db", "backup", case.snapshot)
        first = run(case)
        case.journal.record_branch("backup", "restored", case.snapshot)
        new = run(case, "new")
        first_head, new_head = first["journal_head"], new["journal_head"]
        self.assertNotEqual(first_head, new_head)
        with self.assertRaisesRegex(InvalidReport, "independently saved head"):
            check_branches(store="app-db", erased_at=case.erased.isoformat(), inventory=case.inventory,
                           journal=case.journal.path, output=case.root / "pin", expect_journal=first_head)
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["journal", "verify", str(case.journal.path), "--expected-branch-head", new_head,
                                   "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["branch_chain"], {"head": new_head, "last_event": 2})
        with closing(sqlite3.connect(case.journal.path)) as db, db:
            db.execute("DELETE FROM store_branches WHERE event=2")
        with self.assertRaisesRegex(InvalidReport, "checkpoint"):
            read_branches(case.journal.path)

    def test_git_clone_and_worktree_inventory_reports_residuals_and_remote_gap(self):
        case = self.case
        source, clone, worktree = case.root / "source", case.backups / "clone", case.root / "worktree"
        source.mkdir()
        git(source, "init", "-q")
        git(source, "commit", "--allow-empty", "-m", "synthetic")
        git(case.backups, "clone", str(source), str(clone))
        git(source, "worktree", "add", "-b", "older", str(worktree))
        source_path = str(worktree.resolve()).replace("\\", "\\\\").replace('"', '\\"')
        case.inventory.write_text(f'''[[scanners]]
    id = "clones"
    kind = "git-clones"
    path = "copies"

    [scanners.aliases]
    clone = "dev-clone"

    [[scanners]]
    id = "worktrees"
    kind = "git-worktrees"
    path = "source"

    [scanners.aliases]
    "{source_path}" = "dev-worktree"
    ''', encoding="utf-8")
        case.journal.record_branch("app-db", "dev-clone", case.snapshot)
        case.journal.record_branch("app-db", "dev-worktree", case.snapshot)
        receipt = run(case)
        self.assertEqual([row["status"] for row in receipt["branches"]], ["RESIDUAL", "RESIDUAL"])
        self.assertEqual(receipt["open_items"][0]["evidence"], "remote-copies-uninspected")
        self.assertNotIn(str(case.root), (case.root / "receipt" / "observation-evidence.json").read_text())

    def test_bare_git_clone_and_indirect_remote_configuration(self):
        case = self.case
        bare = case.backups / "cache.git"
        bare.mkdir()
        git(bare, "init", "--bare", "-q")
        git(bare, "config", "include.path", "extra.gitconfig")
        case.inventory.write_text("""[[scanners]]
id = "clones"
kind = "git-clones"
path = "copies"

[scanners.aliases]
"cache.git" = "bare-clone"
""", encoding="utf-8")
        case.journal.record_branch("app-db", "bare-clone", case.snapshot)
        receipt = run(case)
        self.assertEqual(receipt["branches"][0]["status"], "RESIDUAL")
        self.assertEqual(receipt["open_items"][0]["evidence"], "remote-copies-uninspected")

    def test_neon_parent_timestamp_with_pagination_and_soft_deletes(self):
        case = self.case
        seen = []

        def page(project, token, cursor):
            self.assertTrue(project == "project" and token == "test-key")
            seen.append(cursor)
            if cursor is None:
                return {"branches": [{"id": "br-root", "current_state": "ready"},
                                      {"id": "br-a", "parent_id": "br-root", "current_state": "ready",
                                       "parent_timestamp": case.snapshot.isoformat()}], "pagination": {"next": "page-2"}}
            return {"branches": [{"id": "br-b", "parent_id": "br-a", "current_state": "ready",
                                  "created_at": case.erased.isoformat()},
                                 {"id": "br-c", "parent_id": "br-root", "current_state": "ready",
                                  "parent_timestamp": case.snapshot.isoformat(), "recovery": {"deleted_at": "redacted"}}]}

        rows, complete = neon_branches("project", "br-root", "test-key", "app-db", set(), case.erased, page=page)
        self.assertTrue(complete and seen == [None, "page-2"])
        self.assertEqual(rows[0]["edge"]["parent"], "app-db")
        self.assertEqual(rows[0]["edge"]["as_of"], case.snapshot.isoformat())
        self.assertEqual(rows[1]["edge"]["parent"], "neon:project:br-a")
        self.assertIs(rows[1]["edge"]["as_of"], None)
        self.assertEqual(rows[2]["state"], "unknown")

    def test_neon_same_id_reset_after_erasure_stays_unknown(self):
        case = self.case
        later = (case.erased + timedelta(seconds=1)).isoformat()

        def page(project, token, cursor):
            return {"branches": [{"id": "br-root", "current_state": "ready"},
                                 {"id": "br-reused", "parent_id": "br-root", "current_state": "ready",
                                  "last_reset_at": later, "parent_timestamp": later}]}

        rows, complete = neon_branches("project", "br-root", "test-key", "app-db",
                                       {"neon:project:br-reused"}, case.erased, page=page)
        self.assertTrue(complete)
        self.assertEqual(rows, [{"child": "neon:project:br-reused", "state": "unknown"}])

    def test_cli_runs_branch_demo_and_renders_every_audience(self):
        output = self.case.root / "demo"
        transcript = StringIO()
        with redirect_stdout(transcript):
            self.assertEqual(main(["demo", "branches", "--output", str(output)]), 0)
        self.assertIn("source absent · live fork present · restored copy present", transcript.getvalue())
        with redirect_stdout(StringIO()):
            self.assertEqual(main(["replay", str(output / "broken")]), 1)
            self.assertEqual(main(["replay", str(output / "fixed")]), 0)
        for audience in ("engineer", "reviewer", "customer"):
            rendered = receipt_summary(output / "fixed", audience=audience)
            if audience == "customer":
                self.assertNotIn("security-db", rendered)
                self.assertNotIn("restore-run", rendered)
            else:
                self.assertIn("security-db", rendered)
            self.assertIn("restore", rendered.lower())
        receipt = replay(output / "fixed")
        original = json.loads((output / "fixed" / "erasure-receipt.json").read_text())
        self.assertEqual(original, receipt)
