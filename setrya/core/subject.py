"""Tenant-scoped pseudonyms and explicit propagation across trusted app boundaries."""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from threading import Lock

from .errors import InputError


_CURRENT: ContextVar[Subject | None] = ContextVar("setrya_subject", default=None)
_REF = "setrya_subject"
_LABEL = "setrya_classification"
_TURN_FIELDS = {"id": "turn", "initiator": "initiator", "agent": "agent",
                "on_behalf_of": "on_behalf_of", "parent": "parent_turn"}
_TURN_META = {name: "setrya_" + key for name, key in _TURN_FIELDS.items()}
_ACTIVE_TURN: ContextVar[_TurnScope | None] = ContextVar("setrya_turn", default=None)
_baggage_adapter = None


def _baggage():
    if _baggage_adapter is None:
        raise InputError("enable OpenTelemetry propagation through setrya.erasure")
    return _baggage_adapter()


def identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,1023}", value):
        raise InputError(f"{name} must be an opaque identifier of up to 1024 characters")
    return value


def _merge(values, fields, label):
    values = dict(values or {})
    if any(k in values and values[k] != v for k, v in fields.items()):
        raise InputError(f"conflicting {label} metadata")
    return {**values, **fields}


class _TurnScope:
    def __init__(self, turn):
        self.turn = turn
        self.reads = {}
        self.lock = Lock()
        self.open = True

    def add(self, key, versions):
        with self.lock:
            if not self.open:
                raise InputError("turn has already finished")
            if key not in self.reads and len(self.reads) >= 64:
                raise InputError("turn exceeds the provenance scope budget")
            inputs = set(versions) | self.reads.get(key, set())
            if len(inputs) > 256:
                raise InputError("turn exceeds the provenance input budget")
            self.reads[key] = inputs
            return tuple(sorted(inputs))


@dataclass(frozen=True, slots=True)
class Turn:
    """One application-observed invocation, with opaque actor and delegation references."""

    id: str
    initiator: str
    agent: str
    on_behalf_of: str | None = None
    parent: str | None = None

    def __post_init__(self):
        for name in ("id", "initiator", "agent", "on_behalf_of", "parent"):
            value = getattr(self, name)
            if name not in ("on_behalf_of", "parent") or value is not None:
                identifier(value, f"turn {name}")
        if self.parent == self.id:
            raise InputError("a turn cannot parent itself")

    def _fields(self, names):
        return {key: value for attr, key in names.items() if (value := getattr(self, attr)) is not None}

    def copy_fields(self) -> dict[str, str]:
        return self._fields(_TURN_FIELDS)

    def metadata(self) -> dict[str, str]:
        return self._fields(_TURN_META)

    @classmethod
    def _from(cls, values, names):
        if not isinstance(values, Mapping):
            raise InputError("expected a mapping for turn metadata")
        fields = {name: values[key] for name, key in names.items() if key in values and values[key] is not None}
        if not fields:
            return None
        if not {"id", "initiator", "agent"} <= fields.keys():
            raise InputError("incomplete Setrya turn metadata")
        return cls(**fields)

    @classmethod
    def from_metadata(cls, values: Mapping) -> Turn | None:
        """Restore an optional turn from trusted headers or graph configuration."""
        return cls._from(values, _TURN_META)

    @classmethod
    def from_copy_fields(cls, values: Mapping) -> Turn | None:
        return cls._from(values, _TURN_FIELDS)

    def headers(self, existing: Mapping | None = None) -> dict:
        prior = self.from_metadata(existing or {})
        if prior is not None and prior != self:
            raise InputError("conflicting turn metadata")
        return _merge(existing, self.metadata(), "turn")

    def otel_context(self, context=None):
        """Attach the turn to a trusted OpenTelemetry context when that API is installed."""
        baggage = _baggage()
        self.headers(baggage.get_all(context=context))
        for name, value in self.metadata().items():
            context = baggage.set_baggage(name, value, context=context)
        return context

    @classmethod
    def from_baggage(cls, context=None) -> Turn | None:
        baggage = _baggage()
        return cls.from_metadata(baggage.get_all(context=context))

    @contextmanager
    def activate(self):
        """Set invocation identity and start a fresh set of observed source versions."""
        scope = _TurnScope(self)
        token = _ACTIVE_TURN.set(scope)
        try:
            yield self
        finally:
            with scope.lock:
                scope.open = False
                scope.reads.clear()
            _ACTIVE_TURN.reset(token)

    @classmethod
    def current(cls) -> Turn | None:
        scope = _ACTIVE_TURN.get()
        if scope is not None and not scope.open:
            raise InputError("turn has already finished")
        return scope.turn if scope else None



def _text(value: object, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or not value.isprintable():
        raise InputError(f"{name} must be nonempty printable text of at most {limit} characters")
    return value


def keyed_digest(secret: bytes, domain: bytes, data: bytes) -> str:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise InputError("use a private key of at least 32 bytes")
    return hmac.digest(secret, domain + b"\x00" + data, "sha256").hex()


@dataclass(frozen=True, slots=True)
class Subject:
    ref: str
    classification: str

    def __post_init__(self):
        if not isinstance(self.ref, str) or not re.fullmatch("[0-9a-f]{64}", self.ref):
            raise InputError("expected a tenant-bound HMAC subject reference")
        _text(self.classification, "classification", 128)

    @classmethod
    def derive(cls, secret: bytes, tenant: str, subject_id: str, classification: str) -> Subject:
        identity = [_text(tenant, "tenant", 1024), _text(subject_id, "subject ID", 4096)]
        digest = keyed_digest(secret, b"setrya.subject.v1", json.dumps(identity, separators=(",", ":")).encode())
        return cls(digest, classification)

    def metadata(self) -> dict[str, str]:
        """Fields for passage metadata, trusted Celery headers and LangGraph metadata."""
        return {_REF: self.ref, _LABEL: self.classification}

    @classmethod
    def from_metadata(cls, values: Mapping) -> Subject:
        if not isinstance(values, Mapping) or not {_REF, _LABEL} <= values.keys():
            raise InputError("missing Setrya subject metadata")
        return cls(values[_REF], values[_LABEL])

    def headers(self, existing: Mapping | None = None, *, include_turn=True) -> dict:
        result = _merge(existing, self.metadata(), "subject")
        turn = Turn.current() if include_turn else None
        return turn.headers(result) if turn is not None else result

    def langgraph_config(self, thread: str, config: Mapping | None = None) -> dict:
        """Make a subject-exclusive thread and preserve other runnable options."""
        result = dict(config or {})
        values = dict(result.get("configurable", {}))
        thread_id = checkpoint_thread(self, thread)
        if "thread_id" in values and values["thread_id"] != thread_id:
            raise InputError("LangGraph config already selects a different thread")
        result["configurable"] = {**values, "thread_id": thread_id}
        result["metadata"] = self.headers(result.get("metadata"))
        return result

    def otel_context(self, context=None):
        """Return an OpenTelemetry context with this subject in baggage; attach explicitly."""
        baggage = _baggage()
        values = self.headers(baggage.get_all(context=context))
        names = self.metadata().keys() | _TURN_META.values()  # application baggage stays untouched
        for name in names & values.keys():
            context = baggage.set_baggage(name, values[name], context=context)
        return context

    @classmethod
    def from_baggage(cls, context=None) -> Subject:
        baggage = _baggage()
        return cls.from_metadata(baggage.get_all(context=context))

    @contextmanager
    def activate(self):
        """Bind this subject to the current request or task and restore the previous one."""
        token = _CURRENT.set(self)
        try:
            yield self
        finally:
            _CURRENT.reset(token)

    @classmethod
    def current(cls) -> Subject:
        current = _CURRENT.get()
        if current is None:
            raise InputError("no Setrya subject bound to this request")
        return current


def checkpoint_thread(subject: Subject, thread: str) -> str:
    if not isinstance(subject, Subject):
        raise InputError("expected a tenant-scoped Subject")
    return identifier(f"setrya:{subject.ref}:{identifier(thread, 'thread')}", "checkpoint thread")
