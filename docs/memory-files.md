# Verify deletion from agent memory files

An assistant saves Alice’s fictional incident note in `users/alice/memory_log.md`. A memory-consolidation worker reads it and updates `clients/acme/memory_current.md`. Deleting Alice’s file leaves two ways the note can survive. The worker may write the copy it already read, and the Git object store may keep the bytes even after a history rewrite.

Run the two examples on a system with Python and Git. Setrya creates and removes disposable repositories for both lanes.

```sh
setrya demo memory-files --output memory-review
setrya replay memory-review/broken
setrya replay memory-review/guarded
setrya receipt summary memory-review/guarded --audience reviewer
```

The broken replay exits 1. The working tree is clear immediately after deletion, and the synthetic Git commit no longer appears in refs or reflogs. Setrya still finds the unpruned blob in the local object store. When the held worker finishes, the shared memory file contains it again. The guarded replay exits 0. This lane rebuilds the shared file from the remaining note, prunes the expired objects in its disposable repository and fences the worker against changes to its input revisions. Both readers keep Acme’s deployment date. The recorded turn explains which agent read Alice’s file and which revision produced the shared memory. The receipt binds that observation to the journal head and leaves an open item for the plaintext previously sent to a model provider.

## Scan a boundary

Use a unique marker already observed in the disposable fixture. Call the scanners from your `scan(subject, store)` hook and list the relevant stores in `SharedCase.scan_stores`. Implement direct reads for the locations your scanner can return. Setrya checks the baseline before deletion and checks again after the held worker drains.

```python
from setrya.erasure.canary import (
    AgentFSCanaryScanner,
    FilesystemCanaryScanner,
    GitHistoryCanaryScanner,
)

marker = "Alder-417-needs-reimage"
files = FilesystemCanaryScanner("/path/to/test-workspace")
history = GitHistoryCanaryScanner("/path/to/test-workspace")

working_copies = files.find(scope=".", marker=marker)
historical_copies = history.find(scope=".", marker=marker)

agentfs = AgentFSCanaryScanner("/path/to/closed-test-snapshot.db")
memory_copies = agentfs.find(scope="clients/acme", marker=marker)
```

Scanners return native relative paths, `commit:path` locations, or a `blob:<oid>` key when a Git match lacks a reachable commit path. Encode those locations when passing them into a drill, so filenames with spaces or Unicode can appear in its evidence. Use the encoded keys for any declared artifacts or journal entries. Decode each key for the storage read and return the original encoded key in `Stored`.

```python
from setrya.erasure import Stored
from setrya.erasure.fs_canary import decode_scan_location

def scan(subject, store):
    return files.find(scope=".", marker=marker).encode_keys()

def inspect(subject, store, key):
    location = decode_scan_location(key)
    observed = read_scoped_file(location)
    return Stored(key, observed.exists, observed.target_present,
                  observed.control_present, observed.revision)
```

Here `read_scoped_file` is the fixture's direct read under the same root. For Git, inspect `commit:path` from the local history and `blob:<oid>` directly from the local object store. Return the set provided by the scanner or use `.encode_keys()` so the hook preserves the scan metadata. The encoding preserves ordinary identifier-safe keys such as `memory/log.md` and rejects any generated key that exceeds the receipt's 1,024-character limit.

- **Working files.** Scope `.` covers the root. A relative scope limits the scan to the named directory or file. Patterns default to `**/*.md` and `**/*.jsonl`. The scanner returns paths relative to the root and refuses symbolic links in the scanned scope. It skips the root `.git` metadata directory. The receipt records the include patterns. `setrya doctor` reports in-scope JSON, text, YAML and SQLite files outside those patterns. Pause writers while scanning. Setrya checks for changes during the reads and rechecks scoped files before returning.
- **Git history.** Use a complete local repository. The scanner reads all blobs from the local object database, including loose, packed and unreachable blobs. Matches reachable from an in-scope commit path, including one still available through `ORIG_HEAD` or another local pseudo-ref, keep a `commit:path` key. Tree-only pseudo-refs use the tree ID in the same key format. A match without any reachable commit path uses `blob:<oid>` and applies conservatively to every scope. A missing object, a shallow clone, an alternate object store or an in-scope submodule leaves the observation unverified. When the repo has a configured remote, the receipt leaves a remote inspection item open with `remote_owner` as the owner. Git never fetches during a scan. Other clones and remotes need separate checks.
- **AgentFS.** The scanner reads regular filesystem entries from a standalone, unencrypted AgentFS 0.4 schema, including markers split across data chunks. Give it a closed or quiescent source so it can copy the database and any WAL to a private read-only scan snapshot. Hard-linked paths are reported individually. Separate scopes need their own checks for overlay layers, the key-value store, tool calls, and provider copies. The `setrya[agentfs]` extra installs Turso’s SDK to create these fixtures. An existing snapshot can be scanned with the standard installation. [AgentFS 0.4 schema](https://github.com/tursodatabase/agentfs/blob/0a014ebd4918615baff589ed17486e557e7c6a23/SPEC.md)

All three scanners bound the size and number of observations. Pass `limits=ScanLimits(max_file_bytes=32 * 1024 * 1024, max_entries=50_000, max_commits=4_000, timeout_seconds=60)` to the filesystem or Git scanner for larger fixtures. The default file budget is 16 MiB and the total content budget is 128 MiB. Git counts entries once per unique tree and reads each blob once. An empty result covers exact marker bytes in the declared scope. To test whether an assistant can paraphrase the original fact, include an answer-path probe with reviewed variants or a model judge.
