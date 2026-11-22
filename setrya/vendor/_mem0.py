"""Mem0's disposable local Qdrant and history run in an isolated child process."""

import json
import os
import sqlite3
import sys
from contextlib import closing
from importlib.metadata import version
from pathlib import Path


def observation(records, identities, text, marker, phase):
    """Require exact positive baselines, then detect the ID or any marker hit."""
    target = retained = False
    for key, body in records:
        if phase == "baseline":
            target |= key == identities["target"] and body == text["target"]
        else:
            target |= key == identities["target"] or isinstance(body, str) and marker in body
        retained |= key == identities["retained"] and body == text["retained"]
    return {"target": target, "retained": retained}


def observe(evidence, text, marker):
    import httpx
    from mem0 import Memory
    from openai import OpenAI

    def respond(request):
        # Route only embedding requests through a deterministic in-process
        # provider. Any unexpected generation/tool call fails the fixture.
        if request.url.path != "/v1/embeddings":
            return httpx.Response(400, json={"error": {"message": "unexpected model operation"}})
        inputs = json.loads(request.content)["input"]
        vectors = [[1.0, 0.0] if marker in value else [0.8, 0.6] for value in inputs]
        return httpx.Response(200, json={"data": [{"index": index, "embedding": vector}
                                                 for index, vector in enumerate(vectors)],
                                         "model": "setrya-synthetic", "object": "list",
                                         "usage": {"prompt_tokens": 1, "total_tokens": 1}})

    directory = Path(os.environ["MEM0_DIR"])
    local_provider = {"model": "setrya-synthetic", "api_key": "fixture",
                      "openai_base_url": "https://setrya-fixture.invalid/v1"}
    config = {
        "vector_store": {"provider": "qdrant", "config": {"path": str(directory / "qdrant"),
                         "collection_name": "setrya", "embedding_model_dims": 2, "on_disk": True}},
        "embedder": {"provider": "openai", "config": {**local_provider, "embedding_dims": 2}},
        "llm": {"provider": "openai", "config": local_provider},
        "history_db_path": str(directory / "history.db"),
    }
    user_id = "setrya-synthetic"
    evidence["versions"] = {name: version(name) for name in ("mem0ai", "qdrant-client")}
    with OpenAI(api_key="fixture", base_url=local_provider["openai_base_url"], max_retries=0,
                http_client=httpx.Client(transport=httpx.MockTransport(respond), trust_env=False)) as model:
        memory = Memory.from_config(config)
        memory.embedding_model.client.close()
        memory.embedding_model.client = model
        memory.llm.client.close()
        memory.llm.client = model
        ids = {key: memory.add(body, user_id=user_id, infer=False)["results"][0]["id"]
               for key, body in text.items()}
        for phase in ("baseline", "after_delete", "after_retry"):
            if phase != "baseline":
                try:
                    memory.delete(ids["target"])
                except ValueError as error:
                    if phase != "after_retry" or str(error) != f'Memory with id {ids["target"]} not found':
                        raise
            search = memory.search(text["target"], filters={"user_id": user_id}, top_k=10, threshold=0,
                                   rerank=False)
            indexed = [(row["id"], row["memory"]) for row in search["results"]]
            stored = [(key, result["memory"]) for key in ids.values() if (result := memory.get(key)) is not None]
            # Keep the public history API as a positive control and scan the
            # disposable database for copies moved to a different memory ID.
            history = [(key, row[field]) for key in ids.values() for row in memory.history(key)
                       for field in ("old_memory", "new_memory")]
            with closing(sqlite3.connect(Path(config["history_db_path"]).as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA trusted_schema=OFF")
                rows = db.execute("SELECT memory_id, old_memory, new_memory FROM history LIMIT 129").fetchall()
                if len(rows) > 128:
                    raise ValueError("fixture history observation exceeded its budget")
            disk = [(key, body) for key, old, new in rows for body in (old, new)]
            history_reading = observation(history, ids, text, marker, phase)
            disk_reading = observation(disk, ids, text, marker, phase)
            evidence["observations"][phase] = {
                "store": observation(stored, ids, text, marker, phase),
                "index": observation(indexed, ids, text, marker, phase),
                "history": {
                    "target": history_reading["target"] and disk_reading["target"] if phase == "baseline"
                    else history_reading["target"] or disk_reading["target"],
                    "retained": history_reading["retained"] and disk_reading["retained"],
                },
            }


if __name__ == "__main__":
    result = {"versions": {}, "observations": {}, "error": None}
    try:
        text, marker = json.load(sys.stdin)
        observe(result, text, marker)
    except Exception:  # noqa: BLE001 - Keep provider exception details out of evidence.
        result["error"] = "fixture-error"
    print(json.dumps(result))
