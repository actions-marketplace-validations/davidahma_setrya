# Test deletion in a LangGraph application

A checkpoint can still hold a support note after the source row has gone. A new thread can look clean while reopening the original thread brings the note back. Start with a disposable thread containing one customer's test fact and one fact the team must keep.

## See the failure on a laptop

```sh
python -m pip install 'setrya[erasure]==1.4.0'
setrya demo analyst --output investigation
setrya replay investigation/broken
setrya replay investigation/guarded
```

The broken replay exits 1. The guarded replay exits 0. The demo reopens the same investigation for two analysts after a delayed writer finishes. The receipt records store and answer observations. A provider follow-up stays open even when the application checks pass. [Shared investigation](shared-investigation.md)

## Connect your application's Postgres memory

```sh
python -m pip install 'setrya[case-yaml,erasure-postgres]==1.4.0'
setrya init --stack langgraph-postgres --output graph-case
setrya doctor --case graph-case/case.yml
```

Doctor lists missing bindings. Set the test origin, reader and deletion credentials, subject reference and observer connection named in the file. Seed the declared memory namespace and keys in a disposable deployment. Replace the example questions, reviewed answers and HTTP paths with values your graph actually serves. Read an existing thread through its authenticated route. Have the application's deletion route update the appropriate state.

```sh
setrya doctor --case graph-case/case.yml
setrya run --case graph-case/case.yml --mode deletion --output graph-receipt
setrya replay graph-receipt
```

The starter reads three declared boundaries. The checkpoint observer inspects a full `PostgresSaver` thread, including orphan blobs and pending writes. The memory observer reads one exact `PostgresStore` namespace. The vector observer scans the declared raw text column within its scoped SQL rows. Point the YAML at disposable rows and a thread you can read with a PostgreSQL role that has visibility into all three. Keep the configured thread ID and checkpoint artifact key identical.

Use the generated Python file when you already have a test client and deletion hook. Add the hold and release hooks if you need to control a delayed writer. [HTTP case format](http-cases.md) · [Checkpoint and memory observers](harnesses.md) · [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)

## Approve a checkpoint snapshot

Doctor blocks deletion when a stored record might also contain the retained fact. Review the complete synthetic thread before approving it. This reads raw persisted records without deserializing application objects. Inspect the records in your local test environment before adding the digest to the case.

```python
import os
from hashlib import sha256

from langgraph.checkpoint.postgres import PostgresSaver
from setrya.erasure.adapters import LangGraphPostgresCheckpointAdapter
from setrya.erasure.case_stores import content_bytes

with PostgresSaver.from_conn_string(os.environ["SETRYA_TEST_POSTGRES_URL"]) as saver:
    adapter = LangGraphPostgresCheckpointAdapter(saver)
    snapshot = sorted(adapter.read_thread("ticket-204"), key=content_bytes)
    print(sha256(content_bytes(snapshot)).hexdigest())
```

Put the independently reviewed digest under `facts.control.stored.absent_sha256` for a target-only checkpoint. If your application must preserve part of a shared checkpoint, declare `rewrite` and approve the expected retained-only snapshot under `facts.target.stored.absent_sha256`. A digest binds that decision to the observed revision. Applications whose test fixtures generate new framework IDs each run can seed deterministic checkpoint data or supply their own content-aware Python observer.
