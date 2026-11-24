"""Find possible customer-data copy sites without importing application code."""

import ast
import json
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path

from setrya.core.inputs import (
    InvalidReport,
    keys_match,
    read_regular_bytes,
    require,
    unique_fields,
)
from setrya.core.provenance import verify_pins
from setrya.git_refs import git_bytes, resolve_commit
from setrya.receipt_format import MAX_BUNDLE_FILE_BYTES, RECEIPT
from setrya.route_coverage import _blob, _path

from .source_scan import (
    _MAX_FILE_BYTES,
    _MAX_FILES,
    _MAX_PATH,
    _MAX_TOTAL_BYTES,
    _SKIP_DIRECTORIES,
    MAX_SOURCE_CANDIDATE_BYTES,
    MAX_SOURCE_CANDIDATES,
    _argument,
    _expression,
    _parse_tree,
    _scan_python,
    _Scanner,
)

SCAN_FORMAT = "setrya.copy-scan.v1"
REVIEW_FORMAT = "setrya.copy-review.v1"
MAP_FORMAT = "setrya.copy-site-mapping.v1"
MAP_FILE = "setrya-copy-coverage.json"
KINDS = {
    "file": "file write", "object": "object storage", "vector": "vector store",
    "cache": "cache", "memory": "agent memory", "model-state": "stateful model", "trace": "trace export",
}
_STARTER_STORES = {
    "file": "file-archive", "object": "object-storage", "vector": "vector-index",
    "cache": "redis-answer-cache", "memory": "agent-memory", "model-state": "provider-conversation",
    "trace": "trace-store",
}
_IMPORTS = frozenset({
    "anthropic", "boto3", "chromadb", "elasticsearch", "google", "graphiti_core", "langfuse", "langgraph",
    "letta", "mem0", "openai", "opentelemetry", "pinecone", "qdrant_client", "redis", "zep_cloud",
})
_CLIENTS = {
    "anthropic.Anthropic": "$anthropic", "anthropic.AsyncAnthropic": "$anthropic",
    "boto3.Session": "boto3", "boto3.session.Session": "boto3",
    "chromadb.Client": "$chroma", "chromadb.PersistentClient": "$chroma", "chromadb.HttpClient": "$chroma",
    "elasticsearch.Elasticsearch": "$elasticsearch", "elasticsearch.AsyncElasticsearch": "$elasticsearch",
    "$elasticsearch.options": "$elasticsearch",
    "google.cloud.storage.Client": "$gcs", "$gcs.bucket": "$gcs-bucket", "$gcs-bucket.blob": "$gcs-blob",
    "graphiti_core.Graphiti": "$graphiti",
    "langfuse.get_client": "$langfuse", "langfuse.Langfuse": "$langfuse",
    "langgraph.store.memory.InMemoryStore": "$langgraph-store", "langgraph.store.postgres.PostgresStore": "$langgraph-store",
    "langgraph.store.postgres.AsyncPostgresStore": "$langgraph-store",
    "langgraph.store.postgres.PostgresStore.from_conn_string": "$langgraph-store",
    "langgraph.store.postgres.AsyncPostgresStore.from_conn_string": "$langgraph-store",
    "letta.Letta": "$letta", "letta.AsyncLetta": "$letta",
    "mem0.Memory": "$mem0", "mem0.Memory.from_config": "$mem0", "mem0.MemoryClient": "$mem0",
    "mem0.AsyncMemory": "$mem0", "mem0.AsyncMemory.from_config": "$mem0",
    "openai.OpenAI": "$openai", "openai.AsyncOpenAI": "$openai",
    "openai.AzureOpenAI": "$openai", "openai.AsyncAzureOpenAI": "$openai",
    "opentelemetry.sdk.trace.TracerProvider": "$tracing",
    "opentelemetry.trace.get_tracer": "$tracer", "$tracer.start_span": "$span",
    "opentelemetry.sdk.trace.export.ConsoleSpanExporter": "$span-exporter",
    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter.OTLPSpanExporter": "$span-exporter",
    "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter": "$span-exporter",
    "pinecone.Pinecone": "$pinecone", "$pinecone.Index": "$pinecone-index",
    "qdrant_client.QdrantClient": "$qdrant", "qdrant_client.AsyncQdrantClient": "$qdrant",
    "redis.Redis": "$redis", "redis.StrictRedis": "$redis", "redis.from_url": "$redis",
    "redis.Redis.from_url": "$redis", "redis.StrictRedis.from_url": "$redis",
    "redis.asyncio.Redis": "$redis", "redis.asyncio.Redis.from_url": "$redis",
    "redis.asyncio.from_url": "$redis", "$redis.pipeline": "$redis",
    "zep_cloud.Zep": "$zep", "zep_cloud.AsyncZep": "$zep",
}
_CLIENTS.update(dict.fromkeys((f"$chroma.{method}" for method in (
    "get_collection", "get_or_create_collection", "create_collection",
)), "$chroma-collection"))
_CLIENTS.update({"$s3.Bucket": "$s3", "$s3.Object": "$s3"})
_OPERATIONS = {
    "object": {"$s3": ("upload_file", "upload_fileobj", "put_object", "copy_object", "copy", "put"),
               "$gcs-blob": ("upload_from_filename", "upload_from_file", "upload_from_string", "open"),
               "$anthropic.beta.files": ("upload",), "$openai.files": ("create",)},
    "vector": {"$chroma-collection": ("add", "upsert", "update"),
               "$elasticsearch": ("index", "create", "update", "update_by_query", "bulk", "reindex"),
               "elasticsearch.helpers": ("bulk", "async_bulk", "streaming_bulk", "async_streaming_bulk",
                                         "parallel_bulk", "reindex"),
               "$pinecone-index": ("upsert", "upsert_records", "update"),
               "$qdrant": ("upsert", "upload_points", "upload_collection"),
               "$openai.vector_stores.files": ("create", "create_and_poll", "upload", "upload_and_poll"),
               "$openai.vector_stores.file_batches": ("create", "create_and_poll", "upload_and_poll")},
    "cache": {"$redis": ("set", "setex", "psetex", "mset", "msetnx", "hset", "hmset", "lpush",
                         "rpush", "sadd", "zadd", "xadd", "getset", "setnx")},
    "memory": {"$graphiti": ("add_episode", "add_episode_bulk"), "$zep.graph": ("add", "add_batch"),
               "$mem0": ("add", "update"), "$langgraph-store": ("put", "aput"),
               "$letta.agents.passages": ("create",), "$letta.agents.blocks": ("update",)},
    "model-state": {"$openai.conversations": ("create",), "$openai.conversations.items": ("create",),
                    "$openai.responses": ("create",), "$openai.chat.completions": ("create",),
                    "$bedrock-agent": ("invoke_agent", "create_session", "put_invocation_step")},
    "trace": {"$langfuse": ("start_span", "start_observation", "start_as_current_span",
                           "start_as_current_observation", "trace"),
              "$tracing": ("add_span_processor",), "$span-exporter": ("export",),
              "$span": ("set_attribute", "set_attributes", "add_event")},
}
_CALLS = {f"{receiver}.{name}": kind for kind, receivers in _OPERATIONS.items()
          for receiver, names in receivers.items() for name in names}
_CALLS.update({"opentelemetry.trace.set_tracer_provider": "trace"})
_SERVICE_FACTORIES = {"s3": "$s3", "bedrock-agent-runtime": "$bedrock-agent"}
_OID = re.compile(r"[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}")
_MAX_SQL_LITERAL = 8 * 1024
_SQL_WRITE = re.compile(r"\s*(?:INSERT\s+INTO|UPDATE)\s+", re.IGNORECASE)
_SQL_TEXT = re.compile(r"'(?:''|[^'])*'|--[^\r\n]*|/\*[\s\S]*?\*/")
_VECTOR_CAST = re.compile(r'::\s*(?:(?:[A-Za-z_][A-Za-z0-9_]*|"[A-Za-z_][A-Za-z0-9_]*")\s*\.\s*)?'
                          r'(?:vector|halfvec|sparsevec|"vector"|"halfvec"|"sparsevec")(?![A-Za-z0-9_"])', re.IGNORECASE)
_ELASTIC_ENDPOINT = re.compile(r"(?:https?://[^/?#\s]+)?(?:/[A-Za-z0-9_.~%+-]+)?/"
                               r"(?P<endpoint>_doc|_create|_update)(?P<record>/[A-Za-z0-9_.~%+-]+)?(?:\?[^#\s]*)?")


@dataclass(frozen=True)
class CopySite:
    id: str
    path: str
    line: int
    kind: str
    operation: str

    def wire(self):
        result = asdict(self)
        result["site_id"] = result.pop("id")
        result["starter"] = {"site_id": self.id, "store": _STARTER_STORES[self.kind],
                             "key": "replace-with-disposable-test-key", "test": "setrya-case/test_erasure.py"}
        return result


@dataclass(frozen=True)
class _Reference:
    name: str
    anchor: str = ""


def _digest(value):
    return sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


class _CopyScanner(_Scanner):
    def _bind(self, name, value):
        reference = self._reference(value) if isinstance(value, ast.AST) else None
        super()._bind(name, reference if reference is not None else value)

    def visit_Import(self, node):
        super().visit_Import(node)
        for item in node.names:
            root = item.name.split(".")[0]
            if root in _IMPORTS:
                self._bind(item.asname or root, _Reference(item.name if item.asname else root))

    def visit_ImportFrom(self, node):
        super().visit_ImportFrom(node)
        if node.level == 0 and node.module and node.module.split(".")[0] in _IMPORTS:
            for item in node.names:
                self._bind(item.asname or item.name, _Reference(node.module + "." + item.name))

    def _known_arguments(self, node):
        args = [*node.args, *(row.value for row in node.keywords)]
        return [self._value(arg).anchors for arg in args]

    def _reference(self, node):
        if isinstance(node, ast.Name):
            value = self.values.get(node.id)
            return value if isinstance(value, _Reference) else None
        if isinstance(node, ast.Attribute):
            base = self._reference(node.value)
            if base is not None:
                return _Reference(base.name + "." + node.attr, base.anchor)
        if isinstance(node, ast.Call):
            func = self._reference(node.func)
            if func is None:
                return None
            client = _CLIENTS.get(func.name)
            if func.name in {"boto3.client", "boto3.resource"}:
                client = _SERVICE_FACTORIES.get(self._value(_argument(node, 0, "service_name")).text)
            if client:
                return _Reference(client, _digest([func.anchor, _expression(node), self._known_arguments(node)]))
        return None

    def _provider_call(self, node, name):
        if name in {"$openai.responses.create", "$openai.chat.completions.create"}:
            args = {kw.arg: kw.value for kw in node.keywords}
            store = args.get("store")
            if name == "$openai.chat.completions.create" and store is None and None not in args:
                return False
            if isinstance(store, ast.Constant) and store.value is False and "conversation" not in args:
                return False
        if name == "$gcs-blob.open":
            return self._value(_argument(node, 0, "mode")).text in {"w", "wb", "wt"}
        return True

    def _query_text(self, node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value if len(node.value) <= _MAX_SQL_LITERAL else ""
        return self._value(node).text or ""

    def _endpoint_text(self, node):
        if isinstance(node, ast.JoinedStr):
            return "".join(part.value if isinstance(part, ast.Constant) else "record" for part in node.values)
        return self._value(node).text or ""

    def _vector_literal(self, node):
        # A static SQL vector cast or a document-write REST route makes these
        # specific calls review leads even when the receiver is an app wrapper.
        if not isinstance(node.func, ast.Attribute):
            return None
        method = node.func.attr
        if method in {"execute", "executemany"}:
            query = self._query_text(_argument(node, 0, "query"))
            masked = _SQL_TEXT.sub(" ", query)
            if _SQL_WRITE.match(masked) and _VECTOR_CAST.search(masked):
                return "pgvector." + method
        if method == "request":
            verb = self._value(_argument(node, 0, "method")).text
            if verb not in {"PUT", "POST"}:
                return None
            endpoint = self._endpoint_text(_argument(node, 1, "endpoint"))
            if not endpoint:
                endpoint = self._endpoint_text(_argument(node, 1, "url"))
            matched = _ELASTIC_ENDPOINT.fullmatch(endpoint) if len(endpoint) <= _MAX_PATH else None
            if matched:
                route = matched["endpoint"]
                if route == "_doc" and (matched["record"] or verb == "POST"):
                    return "elasticsearch-http.document"
                if matched["record"] and (route == "_create" or (route == "_update" and verb == "POST")):
                    return "elasticsearch-http." + route.removeprefix("_")
        return None

    def visit_Call(self, node):
        reference = self._reference(node.func)
        if reference and reference.name.startswith(("openai.responses.", "openai.conversations.",
                                                     "openai.chat.", "openai.files.", "openai.vector_stores.")):
            reference = _Reference("$" + reference.name, reference.anchor)
        kind = _CALLS.get(reference.name) if reference else None
        destination = self._destination(node)
        if destination:
            kind = "file"
            operation = destination[0]
            anchor = self._value(destination[1]).anchors
        elif kind and self._provider_call(node, reference.name):
            operation = reference.name.removeprefix("$")
            anchor = reference.anchor
        elif operation := self._vector_literal(node):
            kind = "vector"
            anchor = ""
        else:
            self.generic_visit(node)
            return
        stem = _digest([self.path, self.scope, kind, operation, _expression(node), anchor, self._known_arguments(node)])
        occurrence = self.occurrences[stem]
        self.occurrences[stem] += 1
        self.found.append(CopySite(_digest([stem, occurrence]), self.path, node.lineno, kind, operation))
        require(len(self.found) <= MAX_SOURCE_CANDIDATES, "Copy scan exceeded its candidate limit.")
        self.generic_visit(node)


def _inspect(raw, path):
    return _CopyScanner(path, _parse_tree(raw, path)).scan()


def scan(root):
    return {"format": SCAN_FORMAT, "sites": [site.wire() for site in _scan_python(root, _inspect)]}


def _mapping(raw):
    if raw is None:
        return {}
    require(len(raw) <= MAX_SOURCE_CANDIDATE_BYTES, "Copy mapping exceeds its byte limit.")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
    require(keys_match(data, {"format", "sites"}) and data["format"] == MAP_FORMAT
            and isinstance(data["sites"], list) and len(data["sites"]) <= MAX_SOURCE_CANDIDATES,
            "Invalid copy mapping format.")
    sites = {}
    for site in data["sites"]:
        require(keys_match(site, {"site_id", "store", "key", "test"}), "Invalid copy mapping entry.")
        identity = site["site_id"]
        require(isinstance(identity, str) and _OID.fullmatch(identity) and identity not in sites
                and all(isinstance(site[key], str) and _TOKEN.fullmatch(site[key]) for key in ("store", "key")),
                "Invalid or duplicate copy mapping.")
        _path(site["test"])
        require(len(site["test"]) <= _MAX_PATH, "Copy mapping test path exceeds its limit.")
        sites[identity] = site
    return sites


def _covered(receipts, candidate):
    from setrya.receipts import replay_bytes

    subjects, incomplete = {}, set()
    for bundle in receipts:
        bundle = Path(bundle)
        receipt = read_regular_bytes(bundle / RECEIPT, "copy-site receipt", MAX_BUNDLE_FILE_BYTES)
        result = replay_bytes(bundle, receipt)
        try:
            verify_pins(result, expected_app_commit=candidate)
        except InvalidReport:
            continue
        entrypoint = next(row["path"] for row in result["provenance"]["test_files"] if row["role"] == "entrypoint")
        digest = sha256(receipt).hexdigest()
        for artifact in result.get("case", {}).get("artifacts", []):
            if artifact["action"] in {"delete", "rewrite"}:
                identity = artifact["store"], artifact["key"], entrypoint
                if result.get("technical_verdict") == "PASS":
                    subjects.setdefault(identity, digest)
                else:
                    incomplete.add(identity)
    return {identity: digest for identity, digest in subjects.items() if identity not in incomplete}


def _new_sites(repo, ancestor, candidate):
    rows = git_bytes(repo, "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--name-only",
                     "-z", ancestor, candidate, "--")
    require(len(rows) <= _MAX_TOTAL_BYTES, "Changed source paths exceed the scan byte limit.")
    paths = [p.decode("utf-8") for p in rows.split(b"\0") if p.endswith(b".py")]
    require(len(paths) <= _MAX_FILES, "Changed Python files exceed the scan file limit.")
    total_bytes = report_bytes = 0
    found = []
    for path in paths:
        _path(path)
        require(len(path) <= _MAX_PATH, "Source path exceeds its scan limit.")
        if _SKIP_DIRECTORIES.intersection(path.split("/")[:-1]):
            continue
        before, after = (_blob(repo, ref, path) or b"" for ref in (ancestor, candidate))
        total_bytes += len(before) + len(after)
        require(max(len(before), len(after)) <= _MAX_FILE_BYTES and total_bytes <= _MAX_TOTAL_BYTES,
                "Changed Python source exceeds the scan byte limit.")
        previous = {site.id for site in _inspect(before, path)}
        added = [site.wire() for site in _inspect(after, path) if site.id not in previous]
        report_bytes += sum(len(json.dumps(site)) for site in added)
        found.extend(added)
        require(len(found) <= MAX_SOURCE_CANDIDATES and report_bytes <= MAX_SOURCE_CANDIDATE_BYTES,
                "Copy review exceeded its candidate limit.")
    return sorted(found, key=lambda row: (row["path"], row["line"], row["site_id"]))


def check(repo, base_ref, candidate_ref="HEAD", *, map_path=MAP_FILE, receipts=()):
    """Compare changed Git blobs and bind new sites to reviewed mappings and replayed evidence."""
    repo = Path(git_bytes(Path(repo), "rev-parse", "--show-toplevel").decode("utf-8").rstrip("\n"))
    base, candidate = (resolve_commit(repo, ref) for ref in (base_ref, candidate_ref))
    ancestor = resolve_commit(repo, git_bytes(repo, "merge-base", base, candidate).decode("ascii").strip())
    map_path = _path(map_path)
    approved = _mapping(_blob(repo, ancestor, map_path))
    declared = _mapping(_blob(repo, candidate, map_path))
    require(len(receipts) <= 32, "Supply up to 32 candidate receipts.")
    replayed = _covered(receipts, candidate) if receipts else {}
    sites = _new_sites(repo, ancestor, candidate)
    for site in sites:
        baseline = approved.get(site["site_id"])
        binding = declared.get(site["site_id"])
        digest = replayed.get((binding["store"], binding["key"], binding["test"])) if binding and binding == baseline else None
        site.update(status="evidence-replayed" if digest else "needs-review", binding=binding, receipt_sha256=digest)
    return {"format": REVIEW_FORMAT, "base_commit": base, "merge_base_commit": ancestor,
            "candidate_commit": candidate, "map_changed": approved != declared,
            "review_required": sum(row["status"] == "needs-review" for row in sites), "sites": sites}


def summarize(report):
    reviewed = report["format"] == REVIEW_FORMAT
    lines = ["Changed copy sites" if reviewed else "Possible copy sites"]
    if reviewed:
        lines.append(f"Candidate {report['candidate_commit']} · merge base {report['merge_base_commit']}")
        if report["map_changed"]:
            lines.append("The PR changes the copy mapping. Review the proposed bindings.")
    for site in report["sites"]:
        status = site.get("status", "detected").upper()
        name = ascii(site["path"])[1:-1]
        lines.append(f"{status}  {name}:{site['line']} · {KINDS[site['kind']]} · {site['operation']}")
        if site.get("status") != "evidence-replayed":
            lines.append("  Starter mapping " + json.dumps(site["starter"], separators=(",", ":")))
    if not report["sites"]:
        lines.append("No supported copy operations found in the scanned scope.")
    return "\n".join(lines)
