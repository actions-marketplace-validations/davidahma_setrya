"""Run a trusted YAML case against synthetic data in a disposable application."""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from ipaddress import ip_address
import json
import os
import re
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from setrya.drill import InputError
from setrya.offboarding.inputs import read_regular_bytes, unique_fields
from .case_stores import STORE_OPTIONS, open_observer
from .journal import identifier
from .judges import AnswerJudges, Marker, ReviewedAnswers, TextAnswer
from .model import route_id
from .subject import Subject
from .v3 import Artifact, SharedCase


FORMAT = "setrya.http-case.v1"


def fields(obj, required, optional=()):
    if not isinstance(obj, dict) or not set(required) <= obj.keys() or obj.keys() - (set(required) | set(optional)):
        raise InputError("invalid case fields; expected " + ", ".join(sorted(required)))


def strings(values, label, minimum=1, maximum=32):
    if (not isinstance(values, list) or not minimum <= len(values) <= maximum
            or any(not isinstance(value, str) or not 0 < len(value) <= 4096 for value in values)):
        raise InputError("invalid " + label)
    return tuple(values)


def envname(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", value):
        raise InputError("supply an environment variable name, without a credential or URL")
    return value


def yaml_document(path):
    try:
        import yaml
    except ImportError:
        raise InputError("install setrya[case-yaml] to read YAML cases") from None
    raw = read_regular_bytes(path, "YAML case", 64 * 1024)
    try:
        depth = count = 0
        for event in yaml.parse(raw, Loader=yaml.SafeLoader):
            count += 1
            if isinstance(event, yaml.events.CollectionStartEvent):
                depth += 1
            if isinstance(event, yaml.events.CollectionEndEvent):
                depth -= 1
            if count > 4096 or depth > 16 or getattr(event, "anchor", None) or getattr(event, "tag", None):
                raise InputError("expected a bounded case with no tags, anchors or aliases")
        class CaseLoader(yaml.SafeLoader):
            def construct_mapping(self, node, deep=False):
                value = super().construct_mapping(node, deep=deep)
                if len(value) != len(node.value) or any(not isinstance(k, str) for k in value):
                    raise InputError("case keys must be unique strings")
                return value
        return yaml.load(raw, Loader=CaseLoader)
    except (yaml.YAMLError, UnicodeError, ValueError) as error:
        if isinstance(error, InputError):
            raise
        raise InputError("invalid YAML case; check indentation, quoting and unique fields") from None


def path_route(value):
    route = route_id(value)
    if not route.startswith("/") or {"..", "."}.intersection(route.split("/")):
        raise InputError("expected a same-origin route beginning with /")
    return route


def origin(value):
    parts = urlsplit(value)
    loopback = parts.hostname == "localhost"
    try:
        loopback |= ip_address(parts.hostname or "").is_loopback
    except ValueError:
        pass
    if (not parts.hostname or parts.username is not None or parts.password is not None or parts.path not in ("", "/")
            or parts.query or parts.fragment or (parts.scheme != "https" and not (parts.scheme == "http" and loopback))):
        raise InputError("use an HTTPS test origin, or HTTP on loopback, with no credentials or path")
    return f"{parts.scheme}://{parts.netloc}"


@dataclass
class HttpCase:
    case: SharedCase
    stores: dict
    markers: tuple
    settings: dict
    bindings: list

    def missing(self, *, stores_only=False):
        return [f"{hook} ({name})" for hook, name in self.bindings if not os.environ.get(name)
                and (not stores_only or hook == "subject" or hook.startswith("inspect/scan "))]

    @contextmanager
    def open_stores(self):
        """Provide direct inspect/scan hooks for an application-owned Python fixture."""
        if missing := self.missing(stores_only=True):
            raise InputError("missing fixture bindings: " + ", ".join(missing))
        subject = Subject(os.environ[self.settings["subject_ref_env"]], "synthetic-test")
        with ExitStack() as stack:
            observers = {name: open_observer(stack, cfg, os.environ[cfg["connection_env"]])
                         for name, cfg in self.stores.items()}
            yield subject, StoreApplication(self, observers), ()

    @contextmanager
    def open_fixture(self):
        if missing := self.missing():
            raise InputError("missing fixture bindings: " + ", ".join(missing))
        with self.open_stores() as (subject, app, items):
            yield subject, HttpApplication(self, app.observers, subject), items


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class StoreApplication:
    def __init__(self, spec, observers):
        self.spec, self.observers = spec, observers

    def inspect(self, subject, store, key):
        return self.observers[store].inspect(key, *self.spec.markers)

    def scan(self, subject, store):
        return self.observers[store].scan(self.spec.markers[0])

class HttpApplication(StoreApplication):
    def __init__(self, spec, observers, subject):
        super().__init__(spec, observers)
        self.subject = subject
        self.base = origin(os.environ[spec.settings["origin_env"]])
        self.http = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method, route, token_env, payload):
        token = os.environ[token_env]
        if len(token) > 8192 or not token.isascii() or not token.isprintable() or any(ch.isspace() for ch in token):
            raise InputError("expected a bearer token in the configured environment variable")
        request = Request(self.base + route, method=method, data=json.dumps(payload).encode(), headers={
            "Authorization": "Bearer " + token, "Content-Type": "application/json",
            "Accept": "application/json",
        })
        return self.http.open(request, timeout=10)

    def read(self, subject, caller, conversation, question):
        with self.request("POST", self.spec.case.route, self.spec.settings["caller_tokens"][caller],
                          {"conversation": conversation, "question": question}) as reply:
            body = reply.read(131073)
            if (reply.status != 200 or reply.headers.get_content_type() != "application/json"
                    or len(body) > 131072):
                raise InputError("answer route must return a bounded JSON response with status 200")
            data = json.loads(body, object_pairs_hook=unique_fields)
        fields(data, ("caller", "conversation", "route", "question", "text"))
        return TextAnswer(**data)

    def erase(self, subject):
        if subject != self.subject:
            raise InputError("unexpected erase subject")
        with self.request("DELETE", self.spec.settings["erase_route"], self.spec.settings["erase_token_env"],
                          {"subject_ref": subject.ref, "conversation": self.spec.case.conversation}) as reply:
            if reply.status != 204:
                raise InputError("expected 204 after the disposable app applied erasure")


def load_case(path):
    settings = yaml_document(path)
    fields(settings, ("format", "conversation", "subject_ref_env", "origin_env", "read_route", "erase_route",
                      "caller_tokens", "erase_token_env", "facts", "stores"), ("samples",))
    if settings["format"] != FORMAT:
        raise InputError("unknown HTTP case format")
    bindings = [(hook, envname(settings[name])) for hook, name in (
        ("subject", "subject_ref_env"), ("read/erase origin", "origin_env"), ("erase authorization", "erase_token_env"))]
    callers = settings["caller_tokens"]
    if not isinstance(callers, dict) or not 1 <= len(callers) <= 16:
        raise InputError("declare 1–16 caller token bindings")
    for caller, token in callers.items():
        bindings.append(("read as " + identifier(caller, "caller"), envname(token)))
    settings["erase_route"] = path_route(settings["erase_route"])
    facts = settings["facts"]
    fields(facts, ("target", "control"))
    questions, markers, judges_by_role = {}, {}, {}
    for role, fact in facts.items():
        fields(fact, ("marker", "questions", "answers"))
        marker = fact["marker"]
        if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_.:@/+ -]{8,128}", marker):
            raise InputError("use unique synthetic ASCII markers of 8–128 characters")
        markers[role] = marker
        questions[role] = strings(fact["questions"], "questions")
        fields(fact["answers"], ("present", "absent"))
        judges_by_role[role] = (Marker(marker), ReviewedAnswers(
            present=strings(fact["answers"]["present"], "reviewed positive answers"),
            absent=strings(fact["answers"]["absent"], "reviewed negative answers")))
    if markers["control"] == markers["target"]:
        raise InputError("use distinct synthetic target and control markers")
    judges = AnswerJudges(**judges_by_role)
    stores, artifacts = settings["stores"], []
    if not isinstance(stores, dict) or not 1 <= len(stores) <= 32:
        raise InputError("declare 1–32 scoped stores")
    for name, cfg in stores.items():
        identifier(name, "store")
        if not isinstance(cfg, dict) or not isinstance(cfg.get("kind"), str) or cfg["kind"] not in STORE_OPTIONS:
            raise InputError("unknown case store kind")
        fields(cfg, {"kind", "connection_env", "scope", "artifacts"} | STORE_OPTIONS[cfg["kind"]])
        identifier(cfg["scope"], "store scope")
        bindings.append(("inspect/scan " + name, envname(cfg["connection_env"])))
        if not isinstance(cfg["artifacts"], dict) or not cfg["artifacts"]:
            raise InputError("declare the keys and expected actions for each store")
        artifacts.extend(Artifact(name, key, action) for key, action in cfg["artifacts"].items())
    case = SharedCase(conversation=settings["conversation"], route=path_route(settings["read_route"]),
                      callers=tuple(callers), target_question=questions["target"][0], control_question=questions["control"][0],
                      artifacts=tuple(artifacts), scan_stores=tuple(stores), judges=judges,
                      samples=settings.get("samples", 3), target_variants=questions["target"][1:],
                      control_variants=questions["control"][1:])
    case.spec()
    return HttpCase(case, stores, (markers["target"], markers["control"]), settings, bindings)
