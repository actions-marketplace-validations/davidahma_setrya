"""Observe copies at the calls that read, write or transmit subject-linked data."""

from __future__ import annotations

import inspect
import json
from itertools import islice
from collections.abc import Mapping
from typing import Any

from setrya.dependencies import ChunkDependency
from setrya.drill import InputError
from .journal import CopyJournal, identifier
from .lineage import VersionLineage, VersionRef
from .subject import Subject, _ACTIVE_TURN, keyed_digest


def _payload_bytes(value):
    # Keep bytes distinct from every JSON object, including an object whose
    # keys happen to resemble a binary encoding. SDK requests may carry images.
    def typed(item):
        if hasattr(item, "model_dump"):
            item = item.model_dump(mode="json")
        if isinstance(item, (bytes, bytearray)):
            return ["bytes", item.hex()]
        if isinstance(item, Mapping):
            return ["object", [[key, typed(item[key])] for key in sorted(item)]]
        if isinstance(item, (list, tuple)):
            return ["array", [typed(val) for val in item]]
        return ["scalar", item]
    return json.dumps(typed(value), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def _cache_hint(request, provider):
    """Inspect supported SDK cache control fields; a missing directive leaves account settings unknown."""
    def blocks(value):
        return (v for v in value if isinstance(v, Mapping)) if isinstance(value, (tuple, list)) else ()

    def directive(block):
        control = block.get("cache_control")
        point = block.get("cachePoint")
        return (isinstance(control, Mapping) and control.get("type") == "ephemeral"
                or isinstance(point, Mapping) and point.get("type") == "default")

    if provider == "openai":
        options = request.get("prompt_cache_options")
        if isinstance(options, Mapping) and options.get("mode") == "implicit":
            return True
        for item in blocks(request.get("input")):
            if any(isinstance(part.get("prompt_cache_breakpoint"), Mapping)
                   for part in blocks(item.get("content"))):
                return True
        if not options and request.get("prompt_cache_retention") in ("in_memory", "24h"):
            return True
        return None

    body = request.get("body", request)
    if isinstance(body, (str, bytes)):
        try:
            body = json.loads(body)
        except (ValueError, UnicodeError):
            return None
    if not isinstance(body, Mapping):
        return None
    candidates = [body, *blocks(body.get("system")), *blocks(body.get("tools"))]
    tool_config = body.get("toolConfig")
    if isinstance(tool_config, Mapping):
        candidates.extend(blocks(tool_config.get("tools")))
    for message in blocks(body.get("messages")):
        candidates.extend(blocks(message.get("content")))
    return True if any(directive(block) for block in candidates) else None


class CopyHooks:
    """One journal and subject per trusted request, job or graph invocation."""

    def __init__(self, journal: CopyJournal, subject: Subject, *, fingerprint_key: bytes | None = None,
                 infer_lineage: bool = False, lineage: VersionLineage | None = None):
        if not isinstance(subject, Subject):
            raise InputError("expected a Subject")
        if fingerprint_key is not None and (not isinstance(fingerprint_key, bytes) or len(fingerprint_key) < 32):
            raise InputError("use a private fingerprint key of at least 32 bytes")
        if type(infer_lineage) is not bool or (lineage is not None and (
                not infer_lineage or not isinstance(lineage, VersionLineage)
                or lineage.path.resolve() != journal.path.resolve())):
            raise InputError("lineage inference requires a VersionLineage in the same copy journal")
        self.journal = journal
        self.subject = subject
        self._fingerprint_key = fingerprint_key
        self._versions = (lineage or VersionLineage(journal, "turn-provenance")) if infer_lineage else None
        self._scope_key = ((self._versions.path.resolve(), self._versions.namespace, subject.ref)
                           if self._versions else None)

    def lineage(self, subject: Subject) -> dict:
        """Return the graph to use as the fixture's lineage hook."""
        if self._versions is None:
            raise InputError("enable infer_lineage on CopyHooks")
        if not isinstance(subject, Subject) or subject.ref != self.subject.ref:
            raise InputError("lineage hook belongs to a different subject")
        return self._versions.affected(subject)

    def record_copy(self, version: VersionRef, *, action: str, source: str | None = None, inputs=()):
        """Record a completed application operation with its exact physical revision."""
        if not isinstance(version, VersionRef):
            raise InputError("expected the exact VersionRef of the observed copy")
        return self._record(version.store, version.key, version.key if source is None else source, action,
                            version=version, inputs=inputs)

    def _infer(self, subject, action, version, inputs):
        scope = _ACTIVE_TURN.get()
        if self._versions is None or scope is None:
            return
        inputs = tuple(islice(inputs, 257))
        if len(inputs) > 256 or any(not isinstance(ref, VersionRef) for ref in inputs):
            raise InputError("use up to 256 exact VersionRef inputs for turn provenance")
        if action == "retrieved" and version is not None:
            inputs += (version,)
        # A provider operation can contribute its explicitly supplied input versions, but
        # the outbound request ID does not identify a source revision in application storage.
        for ref in set(inputs):
            self._versions.observe_source(ref, subject)
        parents = scope.add(self._scope_key, inputs)
        if action not in ("stored", "derived") or version is None:
            return
        if version in parents:
            # A same-version re-observation changes no immutable artifact or dependency.
            # If a new write absorbed other inputs, the caller needs a new revision.
            if len(parents) > 1:
                raise InputError("record a new revision for a write that used multiple input versions")
            return
        if parents:
            self._versions.record(version, inputs=parents)
        elif action == "stored":
            self._versions.observe_source(version, subject)

    def _record(self, store, key, source, action, *, version=None, inputs=(), **details):
        row = self.journal.record(self.subject, store=store, key=key, source=source, action=action, details=details)
        if action == "sent" or details.get("stage") != "attempted":
            self._infer(self.subject, action, version, inputs)
        return row

    def _fingerprint(self, value):
        if self._fingerprint_key is None:
            return {}
        return {"payload_hmac": keyed_digest(self._fingerprint_key, b"setrya.copy.payload.v1",
                                             self.subject.ref.encode() + b"\x00" + _payload_bytes(value))}

    def _attempt(self, store, key, source, action, **details):
        # A failed transport or process death may still leave a copy. Journal
        # before handing bytes to a different durability or trust boundary.
        self._record(store, key, source, action, stage="attempted", **details)

    def invoke_graph(self, graph, inputs, *, thread: str, store: str, source: str, config: Mapping | None = None,
                     copy_revision: str | None = None):
        config = self.subject.langgraph_config(thread, config)
        key = config["configurable"]["thread_id"]
        version = VersionRef(store, key, copy_revision) if copy_revision is not None else None
        self._attempt(store, key, source, "stored")
        with self.subject.activate():
            value = graph.invoke(inputs, config=config)
        self._record(store, key, source, "stored", version=version, stage="returned")
        return value

    def put_memory(self, memory, key: str, value: dict, *, store: str, source: str, copy_revision: str | None = None, **options):
        from .adapters import memory_namespace
        namespace = memory_namespace(self.subject)
        version = VersionRef(store, key, copy_revision) if copy_revision is not None else None
        details = {"boundary_kind": "namespace", "boundary": "/".join(namespace)}
        self._attempt(store, key, source, "stored", **details)
        value = memory.put(namespace, key, value, **options)
        self._record(store, key, source, "stored", version=version, stage="returned", **details)
        return value

    def add_documents(self, vector_store, documents, *, ids, store: str, **kwargs):
        """Write tagged LangChain documents to explicit adapter-visible physical IDs."""
        documents, ids = list(documents), list(ids)
        if len(documents) != len(ids) or len(set(ids)) != len(ids):
            raise InputError("supply one distinct vector store ID per document")
        tagged = []
        versions = []
        for doc, key in zip(documents, ids):
            identifier(key, "vector store ID")
            chunk = ChunkDependency.from_metadata(doc.metadata)
            tagged.append(doc.model_copy(update={"metadata": self.subject.headers(doc.metadata, include_turn=False)}))
            versions.append(chunk)
        for key, chunk in zip(ids, versions):
            self._attempt(store, key, chunk.setrya_marker, "stored")
        actual = list(vector_store.add_documents(tagged, ids=ids, **kwargs))
        if len(actual) != len(ids):
            raise InputError("vector store returned an unexpected number of written IDs")
        for key, chunk in zip(actual, versions):
            self._record(store, key, chunk.setrya_marker, "stored", stage="returned",
                         version=VersionRef(store, key, chunk.revision) if self._versions else None)
        if actual != ids:
            raise InputError("vector store replaced the supplied physical IDs; inspect the journal")
        return actual

    def retrieve(self, retriever, query, *, store: str, route: str, scope: str, key=None, config=None, **kwargs):
        """Observe only passages tagged with this data subject, independently of caller identity."""
        from setrya.integrations.langchain import retrieve_with_evidence
        documents, evidence = retrieve_with_evidence(retriever, query, route=route, scope=scope, config=config, **kwargs)
        for doc in documents:
            if doc.metadata.get("setrya_subject") != self.subject.ref:
                continue
            metadata_subject = Subject.from_metadata(doc.metadata)
            chunk = ChunkDependency.from_metadata(doc.metadata)
            physical = doc.id if key is None else key(doc)
            self.journal.record(metadata_subject, store=store, key=physical, action="retrieved",
                                source=chunk.setrya_marker)
            if self._versions:
                self._infer(metadata_subject, "retrieved", VersionRef(store, physical, chunk.revision), ())
        return documents, evidence

    def fill_cache(self, cache, cache_key, retrieve, generate, *, store: str, source: str, metadata=None, **kwargs):
        """Record a possible answer location before fill and its exact dependencies when available."""
        from .cache import answer_location
        key = answer_location(cache_key, self.subject)
        self._attempt(store, key, source, "derived")
        generated = False

        def checked_metadata(item):
            data = item if metadata is None else metadata(item)
            if Subject.from_metadata(data) != self.subject:
                raise InputError("a subject-exclusive answer cannot include a different subject or classification")
            return data
        def generate_new(items):
            nonlocal generated
            value = generate(items)
            generated = True
            return value

        answer = cache.fill(cache_key, retrieve, generate_new, metadata=checked_metadata, **kwargs)
        if answer is not None:
            version = (VersionRef(store, key, answer.dependencies.answer_id)
                       if generated and self._versions else None)
            self._record(store, key, source, "derived", stage="returned", version=version,
                         sources=answer.dependencies.markers)
        return answer

    def _provider(self, call, request, *, provider, model, region, store, key, source, invocation_logging,
                  prompt_caching, sources, operation, input_versions=()):
        if not isinstance(request, Mapping):
            raise InputError("provider request must be a mapping of SDK arguments")
        if inspect.iscoroutinefunction(call) or inspect.iscoroutinefunction(inspect.unwrap(call)):
            raise InputError("provider observation requires a synchronous SDK operation")
        requested_cache = _cache_hint(request, provider)
        if requested_cache is True and prompt_caching is False:
            raise InputError("request contains a cache directive but prompt_caching was declared off")
        details = dict(provider=provider, model=model, region=region, invocation_logging=invocation_logging,
                       prompt_caching=True if requested_cache else prompt_caching, evidence_level="configuration",
                       sources=list(sources), operation=operation,
                       components=sorted(name for name in ("input", "instructions", "messages", "system", "tools", "body", "toolConfig", "tool_choice")
                                         if name in request), **self._fingerprint(request))
        self._attempt(store, key, source, "sent", inputs=input_versions, **details)
        result = call(**request)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            raise InputError("provider operation returned an awaitable instead of an SDK response")
        self._record(store, key, source, "sent", stage="returned", **details)
        return result

    def bedrock(self, client, request: Mapping[str, Any], *, store: str, key: str, source: str,
                invocation_logging: bool | None = None, prompt_caching: bool | None = None,
                sources=(), operation: str = "converse", input_versions=()):
        """Call a boto3 Bedrock Runtime client. Resolve the destination region from the client."""
        if operation not in {"converse", "invoke_model", "converse_stream", "invoke_model_with_response_stream"}:
            raise InputError("unsupported Bedrock operation")
        model = identifier(request.get("modelId"), "modelId")
        region = getattr(getattr(client, "meta", None), "region_name", None)
        return self._provider(getattr(client, operation), request, provider="bedrock", model=model, region=region,
                              store=store, key=key, source=source, invocation_logging=invocation_logging,
                              prompt_caching=prompt_caching, sources=sources, operation=operation, input_versions=input_versions)

    def anthropic(self, client, request: Mapping[str, Any], *, store: str, key: str, source: str,
                  invocation_logging: bool | None = None, prompt_caching: bool | None = None, sources=(), input_versions=()):
        """Call the Anthropic Messages API with the supplied request and record its configured exposure."""
        model = identifier(request.get("model"), "model")
        return self._provider(client.messages.create, request, provider="anthropic", model=model, region=None,
                              store=store, key=key, source=source, invocation_logging=invocation_logging,
                              prompt_caching=prompt_caching, sources=sources, operation="messages.create", input_versions=input_versions)

    def langchain_callback(self, *, store: str, source: str, provider: str, model: str,
                           region: str | None = None, invocation_logging: bool | None = None,
                           prompt_caching: bool | None = None, sources=(), input_versions=()):
        """Attach at an application chat/LLM boundary when the framework owns the SDK call."""
        from langchain_core.callbacks import BaseCallbackHandler
        if provider not in {"anthropic", "bedrock"}:
            raise InputError("expected the Bedrock or Anthropic provider")
        details = dict(provider=provider, model=model, region=region, invocation_logging=invocation_logging,
                       prompt_caching=prompt_caching, evidence_level="configuration", sources=list(sources),
                       operation="langchain.start")
        hooks = self
        input_versions = tuple(islice(input_versions, 257))

        class ModelCopyCallback(BaseCallbackHandler):
            raise_error = True
            run_inline = True

            def on_chat_model_start(self, serialized, messages, *, run_id, **kwargs):
                payload = [[msg.model_dump(mode="json") for msg in group] for group in messages]
                hooks._attempt(store, str(run_id), source, "sent", inputs=input_versions, **details, components=["messages"],
                               **hooks._fingerprint(payload))

            def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
                hooks._attempt(store, str(run_id), source, "sent", inputs=input_versions, **details, components=["prompts"],
                               **hooks._fingerprint(prompts))

        return ModelCopyCallback()

    async def call_tool(self, client, name: str, arguments: dict, *, store: str, key: str, source: str,
                        input_versions=(), **kwargs):
        """Wrap one MCP ClientSession.call_tool, recording the input and returned result separately."""
        identifier(name, "tool name")
        self._attempt(store, key + "/input", source, "sent", inputs=input_versions, tool=name, direction="input",
                      **self._fingerprint(arguments))
        self._attempt(store, key + "/result", source, "derived", tool=name, direction="result")
        result = await client.call_tool(name, arguments, **kwargs)
        self._record(store, key + "/result", source, "derived", tool=name, direction="result", stage="returned",
                     **self._fingerprint(result))
        return result
