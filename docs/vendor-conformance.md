# Vendor erasure conformance

A delete call can remove a record from retrieval while leaving its old text readable in history, a cached answer, or a live copy of the store. The vendor self-check seeds two synthetic records, deletes one, and tests that each measured read stops returning it while still returning the other. Setrya records the positive baseline, the first read after deletion, and the read after a retry. The signed bundle includes the fixture result, backend versions, and evidence for offline replay.

## Results matrix

These results apply to the stated configurations. The [Vendor conformance workflow](https://github.com/davidahma/setrya/actions/workflows/vendor-conformance.yml) runs the fixtures and publishes the signed `vendor-conformance-evidence` artifact with each run.

| Target and configuration | Direct record | Vector retrieval | History | Derived summaries, cache, branches, backups | Setrya Verified |
| --- | --- | --- | --- | --- | --- |
| pgvector 0.8.7, PostgreSQL 17, HNSW | PASS | PASS | Outside this fixture | Not tested | Unqualified |
| LangGraph 1.2.24, Python `InMemoryStore` with a scored vector index | PASS | PASS | Outside this fixture | Not tested | Unqualified |
| Mem0 OSS 2.2.1, local Qdrant and SQLite history | PASS | PASS | **FAIL**. The deleted record’s original text remained readable through `Memory.history`. | Not tested | Unqualified |

The pgvector case checks the query plan for the HNSW index. The LangGraph case exercises the in-process Store API. The Mem0 case uses public read and delete APIs, a direct read of SQLite history, and deterministic embeddings. It covers that OSS setup with `infer=False`. The retry calls the delete API again, even when Mem0 signals that the target ID is already missing. Hosted services, parallel worker races, and shared-record rewrites need separate fixtures.

The signed [Graphiti comparison](graphiti-trial.md) covers episode removal and shared-node summaries against Neo4j for two pinned OSS revisions. The [provider readback commands](provider-readback.md) cover Letta archival memory and hosted Mem0 as separate test-project surfaces. Hosted results remain unmeasured for this release.

## Run and replay

Install the matching Setrya release and Cosign 3. Use a signing key provisioned by the organization that will issue the result, or choose `--keyless` when an authorized OIDC identity is available.

```sh
python -m pip install 'setrya[erasure]'
setrya conformance run --target langgraph-store --key ./fixture.key --output ./langgraph-results
setrya verify --receipt ./langgraph-results/erasure-receipt.json \
  --bundle ./langgraph-results/conformance.sig --key ./fixture.pub
setrya replay ./langgraph-results
```

For pgvector, install `setrya[pgvector]` and set `SETRYA_PGVECTOR_DSN` to a loopback address for a **disposable PostgreSQL database** with the `vector` extension already installed. The fixture writes only its session’s temporary table and HNSW index. For Mem0, install `setrya[conformance-mem0]`. That fixture creates a new local Qdrant collection and SQLite history in a temporary directory and uses no provider credentials.

`PASS` (exit 0) describes the measured surfaces. `FAIL` (exit 1) identifies a residual or a lost control. `ERROR` (exit 2) signals a fixture or signing error. `NOT TESTED` (exit 3) means a required observation for the fixture was missing. A signed failure is still replayable. Reviewers should provision the trusted public key independently or pin the exact keyless signer identity, issuer, and trusted root. The ephemeral public key in the workflow artifact supports an integrity check of that run.

## GitHub Action self-check

Use the pinned revision from the [first-PR workflow](examples/first-pr/setrya.yml) and install its matching Setrya release with the selected target’s extra. In a job with only `contents: read` permission, install Cosign 3, provision the signing key, and set these inputs on the Setrya step.

```yaml
with:
  operation: conformance
  conformance-target: langgraph-store
  conformance-key: ${{ runner.temp }}/fixture.key
  output: setrya-conformance
```

Upload the output directory even when the self-check fails. For keyless signing in a trusted workflow, set `conformance-keyless: 'true'`, omit `conformance-key`, and grant `id-token: write` only in that job. A self-check uses synthetic data and writes to disposable resources. Keep reusable signing keys and production credentials out of jobs that execute untrusted pull requests.

## Setrya Verified criteria

Qualification applies to a named release and deployment model. It requires a reviewer to verify an authorized signature, independently replay the evidence, and reproduce the stated setup with synthetic subjects.

| Required coverage | Evidence |
| --- | --- |
| Store and index | The target and retained control are readable before deletion. Direct reads and the real search index show the target gone and the control still present after deletion, refresh, and a retry. |
| Derived summaries | Reopen the same shared object. The erased fact is absent from storage and the served answer. The other subject’s contribution survives. |
| Caches and workers | Hold a worker with old input across deletion, release it, then test both answer callers and the cache. |
| Branches and restore | Inspect live copies from before deletion and exercise an isolated restore at a point that could reintroduce the subject. |
| Backups | Disclose scope, owner, and restore window. Record evidence for the claimed policy and repeat verification when a retention item expires. |

Missing coverage, retained copies, or an unresolved review item keeps a deployment unqualified. The starter fixtures cover only the surfaces shown above. Their signatures authenticate the submitted evidence and signer under the reviewer’s trust policy.
