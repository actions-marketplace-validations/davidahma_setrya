# Why deleted data comes back

A **stale write-back** happens when a writer captures customer data, the app deletes it, and the writer later commits a copy made from those old inputs. A read can be clean immediately after deletion and return the old fact as soon as the writer finishes.

Setrya holds a deferred writer after it captures its inputs. It runs the app's deletion operation, reads the declared stores and routes, releases the writer, and reads again. The retained control shows whether the app still serves information it should keep. The receipt records the checks and their scope. [Glossary](glossary.md) · [Required evidence](erasure-v3.md#required-evidence)

## Five ways the data can come back

| Cause | What to test | Existing evidence |
| --- | --- | --- |
| A held worker | Pause a summary or handoff job after it reads the source. Delete the source and release the job. Reopen the same handoff as the same callers. | [Workspace demo](../README.md#2-catch-a-write-back) · [Northline trial](northline.md) |
| A cache fill | Hold a fill after retrieval. Delete or revoke the source and evict its cached answer. Release the fill and read through the real endpoint. Check that a retained caller can still use the cache. | [Answer cache endpoint trial](answer-cache.md) · [Redis cache invalidation](redis-cache.md) |
| A retry or resume | Keep the original job inputs. Trigger a retry or resume the consumer after deletion. Check what that delivery commits before a fresh job can overwrite it. | [Celery retry and resume](endpoint-framework.md#test-retry-and-resume-after-deletion) · [Existing retry schedule](scenarios.md) |
| A restore | Restore a pre-deletion snapshot into an isolated store. Read the restored copy as well as live branches that forked before deletion. | [Branch and restore demo](branch-lineage.md) |
| Memory merging | Delete a source that contributed to a shared memory. Read the merged record after deletion and check that the other contribution survives. | [Graphiti comparison](graphiti-trial.md) · [Mem0 history result](vendor-conformance.md#results-matrix) |

A residual is evidence that data survived deletion. To identify a stale write-back, read the capture, the post-deletion observation, and the later write tied to the same writer or turn. A branch that already held the record and a history entry that remains readable are residuals with their own evidence. [Fix a write-back](fix-write-back.md)

To get the stale write-back label in your own receipt, checkpoint the worker after it captures its inputs. Use its attempt ID as the journal turn ID and record the exact revision it commits. The final direct read must find the deleted fact in that revision. Before release, Setrya must have seen a different revision or no copy. A canary scan can still expose a residual when it cannot identify which write produced it. [Required evidence](erasure-v3.md#required-evidence)
