# Check forks and restored copies after erasure

A source can stop serving a deleted record while a branch created before deletion still holds it. Use a branch receipt with your erasure drill to record the live descendants of one source and the restore windows your database operators disclose.

```sh
setrya demo branches --output branch-example
setrya replay branch-example/broken
setrya replay branch-example/fixed
setrya receipt summary branch-example/broken --audience reviewer
```

The demo uses SQLite's backup API to take a snapshot and fork a security investigation. It deletes Alice's synthetic finding from the source, restores the earlier snapshot into a new database, and checks that the fork and restored copy can still read the finding. The broken receipt replays to `FAIL` and lists the agent turns that made the copies. The fixed receipt replays to `PASS` after the local copies are removed. Its declared 24-hour restore window remains an open item.

## Record a copy once

Call `record_branch` when the application creates a fork, backup or restored store. Use one unique store identity per copy. `as_of` is when the copied state was current on the source, so it can precede the creation time of a restored store. Use timezone-aware timestamps and opaque IDs. An active Setrya `Turn` is recorded automatically.

```python
from datetime import UTC, datetime
from setrya.erasure import CopyJournal, Turn

journal = CopyJournal("journal.sqlite")
snapshot_time = datetime.now(UTC)  # capture when the source snapshot is taken

with Turn("fork-12", "analyst-7", "investigation-agent").activate():
    # After your adapter creates the snapshot, record its actual cut of source state.
    journal.record_branch("security-db", "analyst-fork-12", snapshot_time)
```

Keep the journal's store-branch chain head in the case system for independent verification. `setrya journal verify journal.sqlite --json` reports `branch_chain.head`. Use `journal verify --expected-branch-head` or `branches check --expect-journal` to check a saved head. The receipt binds the ordered branch observations to the head it verified.

Supply a branch inventory maintained by the service owner. Register every location expected to contain copies of this source. Store aliases map local file or checkout paths to opaque journal IDs. `setrya branches check` scans metadata and existence and stores the evidence without file paths, credentials or subject records.

```toml
[[scanners]]
id = "sqlite-backups"
kind = "sqlite"
path = "snapshots"
patterns = ["*.sqlite", "*.db"]

[scanners.aliases]
"fork.sqlite" = "analyst-fork-12"

[[restore_windows]]
id = "postgres-pitr"
owner = "platform-db"
seconds = 604800
# Optional read-only connection to observe PostgreSQL's effective archive_mode.
# postgres_dsn_env = "BRANCH_OBSERVER_DSN"
```

```sh
setrya branches check --inventory branch-inventory.toml --journal journal.sqlite \
  --store security-db --erased-at 2026-11-22T10:00:00Z --output branch-evidence
setrya replay branch-evidence
```

Use the erasure time from the operation you are verifying. The receipt covers the declared branch inventories and their ancestry. Use your application receipt for the original source erasure, caller behavior and any subject-level probes.

## Connect a branch inventory

| Scanner | What it observes |
| --- | --- |
| `sqlite` | Regular SQLite backups directly inside `path`. By default it considers `.sqlite`, `.sqlite3` and `.db`. Supply `patterns` for other names. A backup requiring WAL or rollback recovery stays unknown. |
| `git-clones` | Git checkouts and bare repositories directly inside `path`. Aliases use directory names. Supply separate entries for separate locations. |
| `git-worktrees` | Local worktrees registered with the Git checkout at `path`. Aliases use absolute worktree paths. |
| `neon` | Branch IDs, parents, source timestamps and active or recoverable status returned by the project's branch API. Use `project`, `source_branch` and `token_env` in place of `path` and `aliases`. `source_branch` is the provider ID for the store named by `--store`. Neon descendants use the ID form `neon:<project>:<branch>`. |

Set local paths relative to the inventory file or use absolute paths. List the external Git copies through your usual inventory. A configured remote becomes an open item because these scanners only read local metadata. Git configuration includes and worktree overrides also leave a remote follow-up when the scanner cannot establish that the checkout has no remote. Use the [Git object scanner](memory-files.md) for objects left in a repository after a history rewrite or worktree removal.

The Neon scanner sends `GET` requests to the fixed Management API host, follows pagination and asks for recoverable deleted branches. Give it a narrowly scoped credential via the named environment variable. A missing source timestamp, detached ancestry, in-place reset since the declared erasure, or unavailable inventory prevents a clean result for that evidence. The listing's current timestamp alone cannot prove which generation of a reset branch contains the old state. Record separate restored generations explicitly when an operation replaces a store in place. [Neon branch API](https://neon.com/docs/reference/api/branches/list-project-branches)

## Interpret the result

- `FAIL` means a scanned live branch descends from pre-erasure state. The verifier treats it as a residual until the operator removes the copy. The receipt identifies the ancestry and the observed agent turn where available.
- `NOT TESTED` means some necessary branch metadata was unavailable, unbound or ambiguous. File modification time and Neon branch creation time cannot establish a copy's source timestamp. A local clone, worktree, or SQLite file can be replaced under the same name. A local alias for a fork made after erasure stays unknown without evidence for the current generation.
- `PASS` means no pre-erasure live branch was found within the declared and successfully scanned boundaries. External copies and disclosed restore windows remain visible under open items.

Declare the restore window in seconds from the retention configuration for your base backups and WAL archive. With `postgres_dsn_env`, Setrya also reads the effective PostgreSQL `archive_mode` in a read-only transaction. Use the `setrya[erasure-postgres]` extra and a separate read-only connection. The receipt records only the setting value or an unavailable observation. Server archiving settings and `wal_keep_size` cannot establish which copies your backup service retains. A nonzero window gives the reviewer an expiry timestamp and owner. `setrya recheck` automatically closes the configuration item after that exact time using a linked receipt. It closes the declared interval without reading archives or proving physical destruction. [Postgres point-in-time recovery](https://www.postgresql.org/docs/current/continuous-archiving.html)

```sh
setrya recheck branch-evidence --output branch-follow-up
setrya replay branch-follow-up
```

An elapsed window leaves any previous `FAIL` intact. For pending windows, the follow-up exits 3. Use the [receipt signing commands](erasure.md#sign-and-verify) to authenticate the original evidence and keep the trusted key separate from the bundle.
