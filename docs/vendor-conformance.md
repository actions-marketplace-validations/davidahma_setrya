# Vendor erasure conformance

A delete call can remove a record from retrieval while leaving its old text readable in history, a cached answer, or a live copy of the store. The vendor self-check seeds two synthetic records, deletes one, and tests that each measured read stops returning it while still returning the other. Setrya records the positive baseline, the first read after deletion, and the read after a retry. The signed bundle includes the fixture result, backend versions, and evidence for offline replay.

## Results matrix

These results apply to the stated configurations. The [Vendor conformance workflow](https://github.com/davidahma/setrya/actions/workflows/vendor-conformance.yml) records `setrya-ci` as the operator and publishes a signed `vendor-conformance-evidence` artifact. The workflow creates a disposable signing key for each run and includes its public key in the artifact for checking integrity. Attribute these results to Setrya CI and use the workflow record to identify the run.

| Target and configuration | Test operator | Direct record | Vector retrieval | History | Derived summaries, cache, branches, backups | Setrya Verified |
| --- | --- | --- | --- | --- | --- | --- |
| pgvector 0.8.7, PostgreSQL 17, HNSW | Setrya CI | PASS | PASS | Outside this fixture | Not tested | Unqualified |
| LangGraph 1.2.24, Python `InMemoryStore` with a scored vector index | Setrya CI | PASS | PASS | Outside this fixture | Not tested | Unqualified |
| Mem0 OSS 2.2.1, local Qdrant and SQLite history | Setrya CI | PASS | PASS | **FAIL**. The deleted record’s original text remained readable through `Memory.history`. | Not tested | Unqualified |

The pgvector case checks the query plan for the HNSW index. The LangGraph case exercises the in-process Store API. The Mem0 case uses public read and delete APIs, a direct read of SQLite history, and deterministic embeddings. It covers that OSS setup with `infer=False`. The retry calls the delete API again, even when Mem0 signals that the target ID is already missing. Hosted services, stale write-backs, and shared-record rewrites need separate fixtures.

The signed [Graphiti comparison](graphiti-trial.md) covers episode removal and shared-node summaries against Neo4j for two pinned OSS revisions. The [provider readback commands](provider-readback.md) cover Letta archival memory and hosted Mem0 as separate test-project surfaces. Hosted results remain unmeasured for this release.

## Local agent memory fixtures

The fixtures below use public SDK delete and read methods with synthetic target and control records. Each reads both records at baseline, after deletion, and after a second delete request. The [Agent memory conformance workflow](https://github.com/davidahma/setrya/actions/workflows/agent-memory-conformance.yml) installs each fixture in a separate Python 3.11 environment and runs the signed checks without networking. Each target publishes its own replay bundle and disposable CI public key. The receipt records the installed versions and labels the operator `setrya-ci`.

| Target and signed v1.13.0 result | Install extra | Measured local reads | Additional coverage needed |
| --- | --- | --- | --- |
| `crewai-memory` [receipt](https://github.com/davidahma/setrya/releases/download/v1.13.0/agent-memory-conformance-crewai-memory.zip) | `conformance-crewai` | CrewAI `Memory.list_records` and shallow `Memory.recall` against a fresh reader over the same LanceDB directory. Deterministic embeddings make both records retrievable. | Background saves, deep recall, merged memories and old storage versions. |
| `cognee-dataset` [receipt](https://github.com/davidahma/setrya/releases/download/v1.13.0/agent-memory-conformance-cognee-dataset.zip) | `conformance-cognee` | Cognee `datasets.list_data` and direct reads of local text files created by `add`. The file scan also checks for text whose catalog entry has disappeared. | `cognify`, graph and vector retrieval, generated summaries and hosted Cognee. The fixture uses byte tokenization and disables real embeddings. |
| `google-adk-session` [receipt](https://github.com/davidahma/setrya/releases/download/v1.13.0/agent-memory-conformance-google-adk-session.zip) | `conformance-adk` | ADK `DatabaseSessionService.get_session` reads history from a reopened local SQLite service after `delete_session`. | Vertex AI services, state shared across sessions, memory banks and deferred writes. |
| `openai-agents-session` [receipt](https://github.com/davidahma/setrya/releases/download/v1.13.0/agent-memory-conformance-openai-agents-session.zip) | `agent-openai` | OpenAI Agents SDK `SQLiteSession.get_items` reads both known sessions in a reopened local database after `clear_session`. | Hosted Conversations and Responses, tracing, other session backends and deferred writes. |

Use a clean Python 3.11 environment for each extra. A local conversation or memory read covers the stated fixture only. Provider retention, caches, summaries, branches and backups require separate evidence.

## Run and replay

Install the matching Setrya release and Cosign 3. Use a signing key provisioned by the organization that will issue the result, or choose `--keyless` when an authorized OIDC identity is available.

```sh
python -m pip install 'setrya[erasure]'
setrya conformance run --target langgraph-store --operator vendor-qa \
  --key ./fixture.key --output ./langgraph-results
setrya conformance review ./langgraph-results --key ./trusted-vendor.pub \
  --expect-operator vendor-qa
setrya replay ./langgraph-results
```

For pgvector, install `setrya[pgvector]` and set `SETRYA_PGVECTOR_DSN` to a loopback address for a **disposable PostgreSQL database** with the `vector` extension already installed. The fixture writes only its session’s temporary table and HNSW index. For Mem0, install `setrya[conformance-mem0]`. That fixture creates a new local Qdrant collection and SQLite history in a temporary directory and uses no provider credentials.

For the local agent fixtures, use the matching target and extra above. For example, install `setrya[agent-openai]` and replace `--target langgraph-store` with `--target openai-agents-session`. These fixtures create their own storage in a temporary directory and run without API keys.

`PASS` (exit 0) describes the measured surfaces. `FAIL` (exit 1) identifies a residual or a lost control. `ERROR` (exit 2) signals a fixture, signing, or review error. `NOT TESTED` (exit 3) means a required observation for the fixture was missing. A signed failure is still replayable. Provision the trusted public key through your own trust channel. To review a keyless result, supply `--identity`, `--issuer`, and `--trusted-root` in place of `--key`.

## Review who ran the test

`setrya replay` and `setrya receipt summary` show the recorded operator and replay scope. Older bundles may leave the operator unrecorded. `setrya conformance review` also verifies the signature and reports the trusted key fingerprint or verified Sigstore identity. A vendor's self-check retains its execution label after an outside reviewer verifies it.

An independent operator can run the same fixture against the same backend versions with their own environment and Cosign key. Both results in a paired review use detached signatures. Send the operator the original bundle. Share the expected operator ID and trusted public keys through a separate channel.

For a LangGraph rerun, start a clean virtual environment. Set `SETRYA_VERSION`, `LANGGRAPH_VERSION`, and `LANGGRAPH_CHECKPOINT_VERSION` to the reviewed versions in the original receipt. Install those exact versions and use your own operator ID. Cosign prompts for a password when it creates the signing key.

```sh
python -m venv .venv-rerun
. .venv-rerun/bin/activate
python -m pip install "setrya[erasure]==${SETRYA_VERSION:?}" \
  "langgraph==${LANGGRAPH_VERSION:?}" \
  "langgraph-checkpoint==${LANGGRAPH_CHECKPOINT_VERSION:?}"
cosign generate-key-pair --output-key-prefix ./lab
setrya conformance run --target langgraph-store --operator reviewer-lab \
  --rerun-of ./langgraph-results --key ./lab.key --output ./lab-rerun
```

Setrya checks its own fixture version before running and signing the rerun. Share the new evidence directory and your public key with the reviewer. Keep the private key with the operator. A signed bundle remains reviewable when the fixture found a failure.

```sh
setrya conformance review ./lab-rerun --key ./trusted-lab.pub \
  --against ./langgraph-results --against-key ./trusted-vendor.pub \
  --expect-operator reviewer-lab
```

The paired review verifies both signatures, replays both bundles, checks their link, and requires separate runs, operators, and trusted keys. Both results must use the same target, Setrya version, and backend versions. The reviewer's trust policy establishes who controls those keys. [Receipt formats](receipt-format.md)

**Rerun matches original** means both verdicts, review statuses, and surface findings agree. The command returns the technical exit code. **Rerun differs from original** shows both verdicts and each changed surface finding, and returns 3. Use `--accept-rerun` to take the newer result's technical exit code after reviewing the differences. The command still shows the disagreement, and both signed receipts remain intact.

## GitHub Action self-check

Use the pinned revision from the [first-PR workflow](examples/first-pr/setrya.yml) and install its matching Setrya release with the selected target’s extra. In a job with only `contents: read` permission, install Cosign 3, provision the signing key, and set these inputs on the Setrya step.

```yaml
with:
  operation: conformance
  conformance-target: langgraph-store
  conformance-operator: vendor-qa
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
