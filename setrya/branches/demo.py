"""Demonstrate a live SQLite fork and a restored copy serving erased data."""
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from shlex import join

from setrya.core.journal import CopyJournal
from setrya.core.subject import Turn
from setrya.receipts import summary

from .cli import check_branches


def _backup(source, destination):
    with closing(sqlite3.connect(source)) as main, closing(sqlite3.connect(destination)) as branch:
        main.backup(branch)


def _visible(database):
    with closing(sqlite3.connect(database)) as db:
        return bool(db.execute("SELECT 1 FROM findings WHERE subject='alice' LIMIT 1").fetchone())


def demo(output):
    output = Path(output)
    output.mkdir(parents=True)
    main, journal = output / "app.sqlite", CopyJournal(output / "journal.sqlite")
    backups = output / "branches"
    backups.mkdir()
    backup, fork, restored = (backups / name for name in ("archive.sqlite", "analysis.sqlite", "reopened.sqlite"))
    with closing(sqlite3.connect(main)) as db, db:
        db.execute("CREATE TABLE findings(subject TEXT PRIMARY KEY, detail TEXT)")
        db.executemany("INSERT INTO findings VALUES (?,?)", [("alice", "Synthetic quarantined device"),
                                                             ("bob", "Synthetic credential reset")])
    snapshot = datetime.now(UTC)
    with Turn("archive-run", "operator", "archive-agent").activate():
        _backup(main, backup)
        journal.record_branch("security-db", "archive", snapshot)
    with Turn("analysis-run", "analyst", "analysis-agent").activate():
        _backup(main, fork)
        journal.record_branch("security-db", "analysis-fork", snapshot)
    with closing(sqlite3.connect(main)) as db, db:
        db.execute("DELETE FROM findings WHERE subject='alice'")
    erased = datetime.now(UTC).isoformat()
    with Turn("restore-run", "analyst", "restore-agent").activate():
        _backup(backup, restored)
        journal.record_branch("archive", "restored-analysis", snapshot)
    inventory = output / "branch-inventory.toml"
    inventory.write_text('''[[scanners]]
id = "sqlite-snapshots"
kind = "sqlite"
path = "branches"

[scanners.aliases]
"archive.sqlite" = "archive"
"analysis.sqlite" = "analysis-fork"
"reopened.sqlite" = "restored-analysis"

[[restore_windows]]
id = "declared-pitr"
owner = "platform-db"
seconds = 86400
''', encoding="utf-8")
    print(f"Alice's finding after source erasure · source {'present' if _visible(main) else 'absent'} · "
          f"live fork {'present' if _visible(fork) else 'absent'} · "
          f"restored copy {'present' if _visible(restored) else 'absent'}")
    options = {"store": "security-db", "erased_at": erased, "inventory": inventory, "journal": journal.path}
    broken = check_branches(**options, output=output / "broken")
    print(summary(broken))
    for candidate in (backup, fork, restored):
        candidate.unlink()
    fixed = check_branches(**options, output=output / "fixed")
    print(summary(fixed))
    print("Replay the live-branch failure and the cleanup receipt.")
    for name in ("broken", "fixed"):
        print(join(["setrya", "replay", str(output / name)]))
    return 0 if [broken["technical_verdict"], fixed["technical_verdict"]] == ["FAIL", "PASS"] else 1
