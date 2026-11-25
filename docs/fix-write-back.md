# Fix a stale write-back

Start with the failing receipt. Find the first observation after deletion that contains the old data. Check the key and the writer or turn recorded for that copy. Compare the read while the writer was held with the read after it finished. If the earlier read already returned the data, trace that residual through the deletion path too. [Why deleted data comes back](write-back.md) · [Receipt guide](receipt-format.md)

| Change | What to verify |
| --- | --- |
| Check source revisions before publishing. | Capture every input revision when the job reads. Compare them at the write boundary, in the same transaction or conditional write where possible. Reject or rebuild an output when an input changed. The guarded workspace worker demonstrates this check. |
| Check the deletion marker at write time. | Keep the subject's deletion marker or generation where the writer can read it. Apply it to old queued inputs as well as current reads. Test marker expiry against the longest retry or restore window you allow. |
| Tie retry keys to source versions. | Attach the expected revision or generation to the original job and its idempotency key. Check it again on delivery. The same message can return after deletion, even when it has never successfully committed. |
| Cancel or drain jobs holding the subject. | Fence jobs that can still publish. Check pending, running, and redelivered work. Keep the write-time guard for a job that was already running when cancellation arrived. |

Rerun the same case with the same writer schedule after the change. Verify that the erased fact stays gone and that the retained control still survives in storage and at the endpoint.

```sh
setrya run --starter setrya-case/test_erasure.py --mode write-back --output after-fix
setrya replay after-fix
```

Use the PR check when the summarizer, cache, queue, or restore procedure changes. Save the complete evidence directory with the result. [Run the check in GitHub Actions](github-action.md#test-a-stale-write-back)
