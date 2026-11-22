# Check a deleted fact in Langfuse traces

A trace can retain what an assistant saw even after the original source has been deleted. For a disposable Langfuse project, emit two observations in one fresh session. Put a unique synthetic marker in the first and a harmless control in the second. Record both trace/observation IDs.

Use `langfuse_observation` around the operation to record its pointer in a local Setrya copy journal. Flush the client, then give `LangfuseCanaryScanner` the project ID and the retained control's ID. The scanner checks stored input and output across every page of the declared session. A missing control, missing fields or an incomplete scan leaves that boundary unverified.

```python
from setrya.integrations.agent_harnesses import LangfuseCanaryScanner

def find_residuals(client, project_id, session_id, control_id, marker):
    scanner = LangfuseCanaryScanner(client, project_id=project_id, control=control_id)
    return scanner.find(scope=session_id, marker=marker)
```

First confirm that the scan returns the target ID. Delete the synthetic target through your application's normal operation, allow ingestion and deletion to settle, and repeat the read. An empty result with the control still visible means the marker is gone from the searched input and output. Other projects, backups and paraphrases fall outside that conclusion.

To reproduce the integration from the v1.3.0 source checkout, run the following with Docker available. The harness starts its own Langfuse server, writes synthetic traces, verifies the baseline, deletes the test trace and reads it back. It also checks that a marker in another session cannot satisfy this one.

```sh
python -m pip install '.[traces-langfuse,agent-openai,agent-claude,pytest]'
python scripts/verify-agent-harnesses.py
```

[Trace hooks and scanner contract](harnesses.md) · [Langfuse public API](https://langfuse.com/docs/api-and-data-platform/features/public-api)
