"""Read exact synthetic targets and retained controls through documented provider APIs."""

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from http.client import HTTPException
from secrets import token_hex
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from setrya.casework.profiles import decode, fields, require, sha, snapshot, stamp
from setrya.core.inputs import MAX_JSON_BYTES, publish_new, unique_fields

_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_NONCE = re.compile(r"[a-f0-9]{32}")
_LIMIT = 50
_PAGES = 10
_MAX_BODY = 2 * 1024 * 1024
_FORMAT = "setrya.provider-baseline.v1"


@dataclass(frozen=True)
class Surface:
    provider: str
    path: str
    name: str
    api: str
    listing: str | None = None
    needs_scope: bool = False


SURFACES = {
    "openai-conversations": Surface("openai", "/v1/conversations/{id}", "conversation", "v1"),
    "openai-conversation-items": Surface("openai", "/v1/conversations/{scope}/items",
                                         "conversation-items", "v1", "openai", True),
    "openai-responses": Surface("openai", "/v1/responses/{id}", "response", "v1"),
    "openai-vector-files": Surface("openai", "/v1/vector_stores/{scope}/files",
                                    "vector-attachment", "v1", "openai", True),
    "openai-files": Surface("openai", "/v1/files", "uploaded-file", "v1", "openai"),
    "anthropic-files": Surface("anthropic", "/v1/files", "file-metadata", "2026-10-21", "claude"),
    "anthropic-sessions": Surface("anthropic", "/v1/sessions", "managed-session",
                                  "managed-agents-2026-04-01", "claude"),
    "anthropic-session-events": Surface("anthropic", "/v1/sessions/{scope}/events", "managed-session-event",
                                        "managed-agents-2026-04-01", "claude", True),
    "bedrock-sessions": Surface("bedrock", "", "session-inventory", "2023-07-26", "bedrock-sessions", True),
    "bedrock-invocation-steps": Surface("bedrock", "", "invocation-step-inventory",
                                        "2023-07-26", "bedrock-steps", True),
    "letta-archival": Surface("letta", "/v1/agents/{scope}/archival-memory",
                              "archival-memory", "v1", "letta", True),
    "mem0-hosted": Surface("mem0", "/v1/memories/{id}/", "memory-object", "v1"),
    "mem0-hosted-history": Surface("mem0", "/v1/memories/{id}/history/", "memory-history-content", "v1"),
}

_HOSTS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "letta": "https://api.letta.com",
    "mem0": "https://api.mem0.ai",
}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _id(value):
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _fingerprint(*values):
    raw = json.dumps(values, separators=(",", ":")).encode("utf-8")
    return sha256(raw).hexdigest()


def _json_get(origin, headers, path, query):
    url = f"{origin}{path}" + (f"?{urlencode(query)}" if query else "")
    request = Request(url, headers={**headers, "Accept": "application/json"}, method="GET")
    try:
        with build_opener(_NoRedirect()).open(request, timeout=5) as response:
            raw = response.read(_MAX_BODY + 1)
            if response.status != 200 or len(raw) > _MAX_BODY:
                return None
        return json.loads(raw, object_pairs_hook=unique_fields)
    except (OSError, HTTPException, ValueError, RecursionError):
        # HTTP status, malformed data, denial, timeouts and redirects do not prove absence.
        return None


def _get(surface):
    provider = surface.provider
    env = f"SETRYA_{provider.upper()}_API_KEY"
    token = os.environ.get(env, "")
    require(0 < len(token) <= 4096 and all(33 <= ord(c) <= 126 for c in token),
            f"Set {env} to an authorized test-project key.")
    if provider == "anthropic":
        headers = {"x-api-key": token, "anthropic-version": "2026-10-21"}
        if surface.api.startswith("managed-agents-"):
            headers["anthropic-beta"] = surface.api
    else:
        scheme = "Token" if provider == "mem0" else "Bearer"
        headers = {"Authorization": f"{scheme} {token}"}
    return lambda path, query: _json_get(_HOSTS[provider], headers, path, query), token


def _extract_ids(rows, key="id"):
    if not isinstance(rows, list) or len(rows) > _LIMIT:
        return None
    if any(not isinstance(row, dict) or not _id(row.get(key)) for row in rows):
        return None
    ids = [row[key] for row in rows]
    return ids if len(ids) == len(set(ids)) else None


def _tracked(pair, get_page):
    """Return False only after all pages of the declared listing have been read."""
    found = set()
    seen = set()
    cursors = set()
    cursor = None
    missing = None
    for _ in range(_PAGES):
        ids, following = get_page(cursor)
        if ids is None or seen.intersection(ids):
            break
        seen.update(ids)
        found.update(seen.intersection(pair))
        if all(item in found for item in pair):
            break
        if following is None:
            missing = False
            break
        if not isinstance(following, str) or not following or len(following) > 2048 or following in cursors:
            break
        cursors.add(following)
        cursor = following
    return {role: True if identifier in found else missing
            for role, identifier in zip(("target", "retained"), pair, strict=True)}


def _http_page(get, surface, path, cursor):
    query = {"limit": _LIMIT}
    if cursor is not None:
        query["page" if surface.listing == "claude" else "after"] = cursor
    raw = get(path, query)
    if surface.listing == "letta":
        ids = _extract_ids(raw)
        return ids, ids[-1] if ids is not None and len(ids) == _LIMIT else None
    if not isinstance(raw, dict):
        return None, None
    ids = _extract_ids(raw.get("data"))
    if ids is not None and surface.listing == "claude":
        return (ids, raw["next_page"]) if "next_page" in raw else (None, None)
    if ids is None or type(raw.get("has_more")) is not bool:
        return None, None
    if raw["has_more"]:
        next_id = raw.get("last_id")
        return (ids, next_id) if ids and next_id == ids[-1] else (None, None)
    return ids, None


def _history_row(row, identifier):
    if not isinstance(row, dict) or row.get("memory_id") != identifier or not _id(row.get("id")):
        return None
    old = row.get("old_memory")
    new = row.get("new_memory")
    messages = row.get("input")
    if any(isinstance(text, str) and text for text in (old, new)):
        return True
    if not isinstance(messages, list) or any(
        not isinstance(message, dict) or message.get("role") not in ("user", "assistant")
        or not isinstance(message.get("content"), str) for message in messages
    ):
        return None
    if any(message["content"] for message in messages):
        return True
    return False if isinstance(new, str) and (old is None or isinstance(old, str)) else None


def _single(raw, surface, identifier):
    if surface.name == "memory-history-content":
        if not isinstance(raw, list) or len(raw) > 1000:
            return None
        checks = {_history_row(row, identifier) for row in raw}
        if True in checks:
            return True
        return None if None in checks else False
    if not isinstance(raw, dict) or raw.get("id") != identifier:
        return None
    if surface.provider == "openai":
        return True if raw.get("object") == surface.name else None
    return True if isinstance(raw.get("memory"), str) else None


def _bedrock(scope, surface):
    from boto3 import Session
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError

    region, _, session_id = scope.partition(":")
    config = Config(connect_timeout=5, read_timeout=5, retries={"total_max_attempts": 1},
                    ignore_configured_endpoint_urls=True)
    try:
        session = Session(region_name=region)
        identity = session.client("sts", config=config).get_caller_identity()
        principal = identity["Arn"]
        client = session.client("bedrock-agent-runtime", config=config)
    except (BotoCoreError, ClientError, KeyError):
        require(False, "An authorized Bedrock test identity is unavailable.")
    steps = surface.listing == "bedrock-steps"
    method = client.list_invocation_steps if steps else client.list_sessions
    field = "invocationStepSummaries" if steps else "sessionSummaries"
    key = "invocationStepId" if steps else "sessionId"

    def get_page(cursor):
        params = {"maxResults": _LIMIT}
        if steps:
            params["sessionIdentifier"] = session_id
        if cursor is not None:
            params["nextToken"] = cursor
        try:
            row = method(**params)
        except (BotoCoreError, ClientError):
            return None, None
        if not isinstance(row, dict):
            return None, None
        return _extract_ids(row.get(field), key), row.get("nextToken")

    return get_page, principal


def _observer(target, scope, pair):
    surface = SURFACES[target]
    if surface.provider == "bedrock":
        get_page, binding = _bedrock(scope, surface)
        return lambda: _tracked(pair, get_page), binding
    get, binding = _get(surface)
    if surface.listing:
        path = surface.path.format(scope=scope)
        return lambda: _tracked(pair, lambda cursor: _http_page(get, surface, path, cursor)), binding

    def read():
        return {role: _single(get(surface.path.format(id=identifier), {}), surface, identifier)
                for role, identifier in zip(("target", "retained"), pair, strict=True)}

    return read, binding


def _inputs(target, scope, record, retain):
    require(isinstance(target, str) and target in SURFACES, "Choose a supported provider surface.")
    surface = SURFACES[target]
    require(_id(record) and _id(retain) and record != retain, "Supply distinct opaque target and control identifiers.")
    if surface.provider == "bedrock":
        require(isinstance(scope, str) and len(scope) <= 100, "Use a Bedrock region as scope, with :SESSION_ID for steps.")
        region, colon, session = scope.partition(":")
        require(re.fullmatch(r"[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]", region)
                and ((colon and _id(session)) if surface.listing == "bedrock-steps" else not colon),
                "Use a Bedrock region as scope, with :SESSION_ID for steps.")
    else:
        require(_id(scope) if surface.needs_scope else scope is None,
                "Use --scope only for a surface with a required parent identifier.")


def capture(target, scope, record, retain, output):
    """Store a private continuity checkpoint after a first authorized GET or listing."""
    _inputs(target, scope, record, retain)
    observer, binding = _observer(target, scope, (record, retain))
    nonce = token_hex(16)
    counts = observer()
    packet = {
        "format": _FORMAT, "target": target, "nonce": nonce,
        "scope_sha256": _fingerprint(nonce, target, scope, record, retain),
        "principal_sha256": _fingerprint(nonce, binding),
        "observed_at": datetime.now(UTC).isoformat(), "observation": counts,
    }
    publish_new(packet, output)
    return counts


def follow(baseline, scope, record, retain):
    """Return publishable observations. Never include a credential, record ID or response body."""
    packet = decode(snapshot(baseline, MAX_JSON_BYTES))
    fields(packet, "format target nonce scope_sha256 principal_sha256 observed_at observation")
    require(packet["format"] == _FORMAT and isinstance(packet["nonce"], str) and _NONCE.fullmatch(packet["nonce"]),
            "Invalid provider baseline.")
    target, nonce = packet["target"], packet["nonce"]
    _inputs(target, scope, record, retain)
    sha(packet["principal_sha256"])
    require(sha(packet["scope_sha256"]) == _fingerprint(nonce, target, scope, record, retain),
            "The provider scope, target or retained control differs from the baseline.")
    require(stamp(packet["observed_at"]) <= datetime.now(UTC), "The provider baseline is dated in the future.")
    counts = packet["observation"]
    fields(counts, "target retained")
    require(all(type(value) is bool or value is None for value in counts.values()), "Invalid provider observation.")

    observer, binding = _observer(target, scope, (record, retain))
    require(packet["principal_sha256"] == _fingerprint(nonce, binding),
            "Use the same authorized provider identity as the baseline.")
    surface = SURFACES[target]
    later = observer()
    return {
        "target": target, "versions": {"api": surface.api}, "error": None,
        "observations": {"baseline": {surface.name: counts}, "after_delete": {surface.name: later}},
        "observed_at": datetime.now(UTC).isoformat(),
        "readback": {"baseline_at": packet["observed_at"], "scope_sha256": packet["scope_sha256"]},
    }
