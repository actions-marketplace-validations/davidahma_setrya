# Verify deletion from agent memory files

An assistant saves Alice’s fictional incident note in `users/alice/memory_log.md`. A memory-consolidation worker reads it and updates `clients/acme/memory_current.md`. Deleting Alice’s file leaves two ways the note can survive. The worker may write the copy it already read, and a Git commit may keep the original bytes.

Run the two examples on a system with Python and Git. Setrya creates and removes disposable repositories for both lanes.

```sh
setrya demo memory-files --output memory-review
setrya replay memory-review/broken
setrya replay memory-review/guarded
setrya receipt summary memory-review/guarded --audience reviewer
```

The broken replay exits 1. Immediately after deletion the working tree is clear, but Git history still contains the note. When the held worker finishes, the shared memory file contains it again. The guarded replay exits 0. This lane rebuilds the shared file from the remaining note, retires the old commit in its disposable repository and fences the worker against changes to its input revisions. Both readers keep Acme’s deployment date. The recorded turn explains which agent read Alice’s file and which revision produced the shared memory. The receipt binds that observation to the journal head and leaves an open item for the plaintext previously sent to a model provider.

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

- **Working files.** Scope `.` covers the root. A relative scope limits the scan to the named directory or file. Patterns default to `**/*.md` and `**/*.jsonl`. The scanner returns paths relative to the root and refuses symbolic links in the scanned scope. It skips the root `.git` metadata directory. Pause writers while scanning. Setrya checks for changes during the reads and rechecks scoped files before returning.
- **Git history.** Use a complete local repository. The scanner reads blobs from the commits reachable through local refs, HEADs and reflogs and returns `commit:path` keys. A missing object, a shallow clone, an alternate object store, an in-scope submodule, or a blob that has no commit path leaves the observation unverified. A clean read covers that reachable history. Remote repositories, other clones and unreachable objects require their own checks.
- **AgentFS.** The scanner reads regular filesystem entries from a standalone, unencrypted AgentFS 0.4 schema, including markers split across data chunks. Give it a closed or quiescent source so it can copy the database and any WAL to a private read-only scan snapshot. Hard-linked paths are reported individually. Separate scopes need their own checks for overlay layers, the key-value store, tool calls, and provider copies. The `setrya[agentfs]` extra installs Turso’s SDK to create these fixtures. An existing snapshot can be scanned with the standard installation. [AgentFS 0.4 schema](https://github.com/tursodatabase/agentfs/blob/0a014ebd4918615baff589ed17486e557e7c6a23/SPEC.md)

All three scanners bound the size and number of observations. Split large fixture scopes before rerunning. An empty result covers exact marker bytes in the declared scope. To test whether an assistant can paraphrase the original fact, include an answer-path probe with reviewed variants or a model judge.
