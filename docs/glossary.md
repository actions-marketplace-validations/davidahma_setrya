# Glossary

| Term | Meaning in Setrya |
| --- | --- |
| **Copy** | A stored, derived, or served representation of the data in scope. An answer, embedding, checkpoint, trace, and backup can each carry it. |
| **Copy site** | A source-code location where the app may make or send a copy. A scan identifies the location to inspect and test. |
| **Deferred writer** | A job or callback that can commit after the request or change that triggered it has completed. A retry, queue consumer, or cache fill can be a deferred writer. |
| **Stale write-back** | A writer commits a copy after deletion using inputs it captured before deletion. |
| **Residual** | Data observed after deletion that should have been erased. |
| **Retained control** | Known data or an answer that should stay visible throughout the test. It helps distinguish selective deletion from a broken read or an overly broad erase. |
| **Receipt** | The recorded verdict, scope, and evidence references for one drill or observation. Replay uses the companion evidence to recompute the verdict. |

Use `--mode write-back` for the held-writer drill. Setrya 1.x also accepts `late-write`, the value used by existing receipts. [CLI modes](erasure-cli.md) · [Receipt formats](receipt-format.md)
