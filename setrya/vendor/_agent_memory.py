"""Exercise real local SDK stores in an isolated synthetic fixture process."""

import asyncio
import json
import sqlite3
import sys
from contextlib import closing, redirect_stdout
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import unquote, urlparse

from ._mem0 import observation
from .report import PHASES, SETUP


def crewai(evidence, directory, text, marker):
    from crewai import Memory
    from crewai.llms.base_llm import BaseLLM

    class OfflineModel(BaseLLM):
        def call(self, *args, **kwargs):
            raise RuntimeError("Unexpected model call in the memory fixture.")

    def embedding(input):
        return [[1.0, 0.0] if marker in value else [0.8, 0.6] for value in input]

    scope = "/setrya"
    config = {"storage": str(directory / "lance"), "llm": OfflineModel(model="fixture"), "embedder": embedding}
    writer = Memory(**config)
    ids = {key: writer.remember(body, scope=scope, categories=["fixture"], importance=0.5).id
           for key, body in text.items()}
    for phase in PHASES:
        if phase != "baseline":
            writer.forget(scope=scope, record_ids=[ids["target"]])
        reader = Memory(**config)
        stored = ((record.id, record.content) for record in reader.list_records(scope=scope))
        results = reader.recall(text["target"], scope=scope, depth="shallow")
        indexed = ((match.record.id, match.record.content) for match in results)
        evidence["observations"][phase] = {"store": observation(stored, ids, text, marker, phase),
                                           "index": observation(indexed, ids, text, marker, phase)}


async def openai_agents(evidence, directory, text, marker):
    from agents import SQLiteSession

    database = directory / "sessions.db"
    for key, body in text.items():
        with closing(SQLiteSession(key, database)) as session:
            await session.add_items([{"role": "user", "content": body}])
    for phase in PHASES:
        if phase != "baseline":
            with closing(SQLiteSession("target", database)) as session:
                await session.clear_session()
        rows = []
        for key in text:
            with closing(SQLiteSession(key, database)) as reader:
                rows.extend((key, item["content"]) for item in await reader.get_items())
        evidence["observations"][phase] = {
            "session-history": observation(rows, {key: key for key in text}, text, marker, phase),
        }


async def google_adk(evidence, directory, text, marker):
    from google.adk.events import Event
    from google.adk.sessions import DatabaseSessionService
    from google.genai.types import Content, Part

    url = f"sqlite+aiosqlite:///{directory / 'adk.db'}"
    scope = {"app_name": "setrya", "user_id": "fixture"}
    writer = DatabaseSessionService(url)
    try:
        for key, body in text.items():
            session = await writer.create_session(**scope, session_id=key)
            await writer.append_event(session, Event(author="user", content=Content(role="user", parts=[Part(text=body)])))
        for phase in PHASES:
            if phase != "baseline":
                await writer.delete_session(**scope, session_id="target")
            reader = DatabaseSessionService(url)
            try:
                rows = []
                sessions = await reader.list_sessions(**scope)
                session_ids = set(text).union(listed.id for listed in sessions.sessions)
                for key in session_ids:
                    found = await reader.get_session(**scope, session_id=key)
                    if found is not None:
                        rows.extend((found.id, part.text) for event in found.events if event.content
                                    for part in event.content.parts or ())
                evidence["observations"][phase] = {
                    "session-history": observation(rows, {key: key for key in text}, text, marker, phase),
                }
            finally:
                await reader.close()
    finally:
        await writer.close()


def local_file(uri, root):
    parsed = urlparse(uri)
    if parsed.scheme not in ("", "file") or parsed.netloc:
        raise ValueError("The fixture needs a local file inside its data directory.")
    path = Path(unquote(parsed.path)).resolve()
    path.relative_to(root)
    return path


def small_text(path):
    with path.open("rb") as source:
        body = source.read(8193)
    if len(body) > 8192:
        raise ValueError("The fixture exceeded its per-file read budget.")
    return body.decode("utf-8")


async def cognee(evidence, directory, text, marker):
    import tiktoken
    import tiktoken.model

    # The SDK initializes a tokenizer even for an uncognified dataset.
    # Substitute byte tokenization to keep these storage operations offline.
    tokenizer = tiktoken.Encoding(name="setrya-bytes", pat_str="(?s:.)",
                                 mergeable_ranks={bytes([value]): value for value in range(256)}, special_tokens={})
    tiktoken.get_encoding = tiktoken.model.get_encoding = lambda name: tokenizer

    import cognee as sdk
    from cognee.api.v1.datasets.datasets import datasets

    data = (directory / "data").resolve()
    initial = await sdk.add(text["target"], dataset_name="setrya_conformance")
    dataset = initial.dataset_id
    retained = await sdk.add(text["retained"], dataset_id=dataset)
    ids = {"target": initial.data_ids[0], "retained": retained.data_ids[0]}
    paths = {}
    for phase in PHASES:
        if phase != "baseline":
            await datasets.delete_data(dataset, ids["target"])
        catalog = []
        for entry in await datasets.list_data(dataset):
            path = local_file(entry.raw_data_location, data)
            if phase == "baseline":
                paths[entry.id] = path
            try:
                body = small_text(path)
            except FileNotFoundError:
                body = None
            catalog.append((entry.id, body))
        files = []
        path_ids = {path: key for key, path in paths.items()}
        for index, path in enumerate(data.rglob("*.txt")):
            if index == 64:
                raise ValueError("The fixture exceeded its local text file budget.")
            resolved = local_file(path.as_uri(), data)
            files.append((path_ids.get(resolved), small_text(resolved)))
        evidence["observations"][phase] = {"dataset-catalog": observation(catalog, ids, text, marker, phase),
                                           "ingested-text-files": observation(files, ids, text, marker, phase)}


FIXTURES = {"crewai-memory": crewai, "cognee-dataset": cognee, "google-adk-session": google_adk,
            "openai-agents-session": openai_agents}


def reject_network(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
                 "socket.gethostbyaddr", "socket.getnameinfo", "socket.sendto"}:
        raise RuntimeError("Network access is disabled in the local memory fixture.")


def main():
    target, text, marker = json.load(sys.stdin)
    evidence = {"versions": {}, "observations": {}, "error": None}
    # The child runs from a new empty directory with no provider credentials.
    sys.addaudithook(reject_network)
    try:
        with redirect_stdout(sys.stderr):
            evidence["versions"] = {name: sqlite3.sqlite_version if name == "sqlite" else version(name)
                                    for name in SETUP[target]}
            result = FIXTURES[target](evidence, Path.cwd(), text, marker)
            if asyncio.iscoroutine(result):
                asyncio.run(result)
    except PackageNotFoundError:
        evidence["error"] = "missing-extra" if not evidence["observations"] else "fixture-error"
    except Exception:  # noqa: BLE001 - SDK diagnostics are not included in receipts.
        evidence["error"] = "fixture-error"
    Path("observations.json").write_text(json.dumps(evidence), encoding="utf-8")


if __name__ == "__main__":
    main()
