"""Run a trusted YAML case against synthetic data in a disposable application."""
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from ipaddress import ip_address
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import re
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from setrya.core.deployment import validate_record
from setrya.core.receipt_v3 import check_external
from setrya.drill import InputError
from setrya.offboarding.inputs import read_regular_bytes, unique_fields
from .case_stores import STORE_OPTIONS, StoredFact, content_bytes, open_observer
from .https_case import DeploymentHTTP
from .journal import CopyJournal, identifier
from .judges import AnswerJudges, Marker, ReviewedAnswers, TextAnswer
from .model import route_id
from .subject import Subject
from .v3 import Artifact, ExternalItem, SharedCase


FORMAT = "setrya.http-case.v1"
BEHAVIOR_FORMAT = "setrya.http-behavior.v1"
DEPLOYMENT_FORMAT = "setrya.http-deployment.v1"
_YAML_LIMIT = 64 * 1024
_BINDINGS = ("conversation", "subject_ref_env", "read_route", "erase_route", "caller_tokens", "erase_token_env", "stores")


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


def yaml_document(raw, locations=None):
    try:
        import yaml
    except ImportError:
        raise InputError("install setrya[case-yaml] to read YAML cases") from None
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
        value = yaml.load(raw, Loader=CaseLoader)
        if locations is not None:
            def walk(node, path):
                if isinstance(node, yaml.MappingNode):
                    for key, child in node.value:
                        child_path = (*path, key.value)
                        locations[child_path] = key.start_mark.line + 1
                        walk(child, child_path)
            walk(yaml.compose(raw, Loader=yaml.SafeLoader), ())
        return value
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
    store_facts: tuple
    settings: dict
    bindings: list
    locations: dict
    path: Path
    deployment: dict | None = None
    deployment_path: Path | None = None
    deployment_locations: dict | None = None
    exceptions: tuple = ()

    def position(self, keys):
        """Locate a behavior rule or deployment binding in its own source."""
        path, locations = self.path, self.locations
        if self.deployment_path is not None and keys and keys[0] not in ("facts", "artifacts", "samples", "controls"):
            path, locations = self.deployment_path, self.deployment_locations
        while keys and keys not in locations:
            keys = keys[:-1]
        return f"{path}:{locations.get(keys, 1)}"

    def source_digests(self):
        if self.deployment is None:
            return {}
        return {self.path: self.deployment["behavior_sha256"],
                self.deployment_path: self.deployment["deployment_sha256"]}

    def missing_bindings(self, *, stores_only=False):
        return [(f"{hook} ({name})", path) for hook, name, path in self.bindings if not os.environ.get(name)
                and (not stores_only or hook == "subject" or hook.startswith("inspect/scan "))]

    def missing(self, *, stores_only=False):
        return [message for message, _ in self.missing_bindings(stores_only=stores_only)]

    @contextmanager
    def open_stores(self, *, on_unavailable=None):
        """Provide direct inspect/scan hooks for an application-owned Python fixture."""
        if missing := self.missing(stores_only=True):
            raise InputError("missing fixture bindings: " + ", ".join(missing))
        subject = Subject(os.environ[self.settings["subject_ref_env"]], "synthetic-test")
        with ExitStack() as stack:
            observers = {}
            for name, cfg in self.stores.items():
                try:
                    observers[name] = open_observer(stack, cfg, os.environ[cfg["connection_env"]])
                except Exception as error:
                    if on_unavailable is None:
                        raise
                    on_unavailable(name, type(error).__name__)
            location = os.environ.get("SETRYA_COPY_JOURNAL")
            if location:
                journal_path = Path(location).resolve()
                for cfg in self.stores.values():
                    if cfg["kind"] in ("sqlite", "openai-agents"):
                        store_path = Path(os.environ[cfg["connection_env"]]).resolve()
                        if (store_path == journal_path or (store_path.exists() and journal_path.exists()
                                                          and store_path.samefile(journal_path))):
                            raise InputError("Use a separate local file for the copy journal and application store.")
            else:
                directory = stack.enter_context(TemporaryDirectory(prefix="setrya-recipe-journal-"))
                location = Path(directory) / "copies.sqlite"
            items = tuple(replace(item, subject_ref=subject.ref) for item in self.exceptions)
            yield subject, StoreApplication(self, observers, CopyJournal(location)), items

    @contextmanager
    def open_fixture(self, *, on_unavailable=None):
        if missing := self.missing():
            raise InputError("missing fixture bindings: " + ", ".join(missing))
        with self.open_stores(on_unavailable=on_unavailable) as (subject, app, items):
            yield subject, HttpApplication(self, app.observers, subject, app.journal), items


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class StoreApplication:
    def __init__(self, spec, observers, journal):
        self.spec, self.observers, self.journal = spec, observers, journal

    def _record(self, subject, store, key, operation):
        scope = self.observers[store].scope
        self.journal.record(subject, store=store, key=key, source=scope, action="retrieved",
                            details={"operation": operation, "boundary_kind": "namespace", "boundary": scope})

    def inspect(self, subject, store, key):
        row = self.observers[store].inspect(key, *self.spec.store_facts)
        self.journal.record_boundary(subject, store=store, kind="namespace", name=self.observers[store].scope)
        if row.exists and row.target_present is True:
            self._record(subject, store, key, "fixture.inspect")
        return row

    def scan(self, subject, store):
        keys = self.observers[store].scan(self.spec.markers[0])
        self.journal.record_boundary(subject, store=store, kind="namespace", name=self.observers[store].scope)
        for key in sorted(keys):
            self._record(subject, store, key, "fixture.scan")
        return keys


class HttpApplication(StoreApplication):
    def __init__(self, spec, observers, subject, journal):
        super().__init__(spec, observers, journal)
        self.subject = subject
        self.deployment = DeploymentHTTP(spec.deployment) if spec.deployment is not None else None
        if self.deployment is None:
            self.base = origin(os.environ[spec.settings["origin_env"]])
            self.http = build_opener(ProxyHandler({}), NoRedirect())

    @staticmethod
    def headers(token_env):
        token = os.environ[token_env]
        if len(token) > 8192 or not token.isascii() or not token.isprintable() or any(ch.isspace() for ch in token):
            raise InputError("expected a bearer token in the configured environment variable")
        return {"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json"}

    def request(self, method, route, token_env, payload):
        request = Request(self.base + route, method=method, data=json.dumps(payload).encode(),
                          headers=self.headers(token_env))
        return self.http.open(request, timeout=10)

    def read(self, subject, caller, conversation, question):
        token = self.spec.settings["caller_tokens"][caller]
        payload = {"conversation": conversation, "question": question}
        if self.deployment is not None:
            request = self.deployment.request("POST", self.spec.case.route, payload, lambda: self.headers(token))
            with request as (reply, _):
                return self.answer(reply) if reply is not None else None
        with self.request("POST", self.spec.case.route, token, payload) as reply:
            return self.answer(reply)

    @staticmethod
    def answer(reply):
        body = reply.read(131073)
        if reply.status != 200 or reply.headers.get_content_type() != "application/json" or len(body) > 131072:
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

    def erase_bound(self, subject):
        if subject != self.subject:
            raise InputError("unexpected erase subject")
        payload = {"subject_ref": subject.ref, "conversation": self.spec.case.conversation}
        request = self.deployment.request("DELETE", self.spec.settings["erase_route"], payload,
                                          lambda: self.headers(self.spec.settings["erase_token_env"]))
        with request as (reply, sent):
            if not sent or reply is not None and reply.status == 412:
                return False
            if reply is None or reply.status != 204:
                raise InputError("The deployment did not acknowledge a verified erasure.")
            return True


def stored_fact(marker, reviewed, settings):
    fields(settings, (), ("present", "absent", "absent_sha256"))
    phrases = strings(settings.get("present", []), "stored positive phrases", minimum=0)
    present = tuple(dict.fromkeys((marker, *reviewed.present, *phrases)))
    absent = settings.get("absent", [])
    reviewed_digests = settings.get("absent_sha256", [])
    if (not isinstance(absent, list) or not isinstance(reviewed_digests, list)
            or len(absent) + len(reviewed_digests) > 32):
        raise InputError("supply at most 32 reviewed whole-payload absences per fact")
    if any(not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value) for value in reviewed_digests):
        raise InputError("reviewed whole-payload SHA-256 values must be 64 lowercase hexadecimal characters")
    try:
        digests = frozenset(sha256(content_bytes(value)).hexdigest() for value in (*reviewed.absent, *absent))
    except (TypeError, ValueError, UnicodeError):
        raise InputError("each reviewed stored absence must be a complete JSON-compatible value") from None
    return StoredFact(present, digests.union(reviewed_digests))


def split_settings(behavior, config):
    fields(behavior, ("format", "facts", "artifacts"), ("samples", "controls"))
    fields(config, ("format", "record", *_BINDINGS), ("retention_exceptions",))
    if behavior["format"] != BEHAVIOR_FORMAT or config["format"] != DEPLOYMENT_FORMAT:
        raise InputError("Expected matching HTTP behavior and deployment file formats.")
    artifacts, stores = behavior["artifacts"], config["stores"]
    if not isinstance(artifacts, dict) or not isinstance(stores, dict) or stores.keys() != artifacts.keys():
        raise InputError("Deployment stores must bind every logical store from the behavior file.")
    bound = {}
    for store, keys in artifacts.items():
        entry = stores[store]
        if (not isinstance(keys, dict) or not keys or not isinstance(entry, dict)
                or not isinstance(entry.get("kind"), str) or entry["kind"] not in STORE_OPTIONS):
            raise InputError("Expected artifact actions and a supported adapter for every behavior store.")
        fields(entry, {"kind", "connection_env", "scope"} | STORE_OPTIONS[entry["kind"]], ("keys",))
        mapping = entry.get("keys", {key: key for key in keys})
        if not isinstance(mapping, dict) or mapping.keys() != keys.keys():
            raise InputError("Deployment key mappings must bind every logical artifact in their store.")
        physical = {identifier(mapping[key], "deployment artifact key"): action for key, action in keys.items()}
        if len(physical) != len(keys):
            raise InputError("Deployment artifact keys must remain distinct within each store.")
        bound[store] = {key: value for key, value in entry.items() if key != "keys"} | {"artifacts": physical}
    exceptions = config.get("retention_exceptions", [])
    if not isinstance(exceptions, list) or len(exceptions) > 128:
        raise InputError("Expected a bounded list of retention exceptions.")
    items = []
    for item in exceptions:
        fields(item, ("store", "key", "owner", "evidence", "expires_on"))
        items.append(ExternalItem(item["store"], item["key"], item["owner"], "retained",
                                  item["evidence"], follow_up=item["expires_on"]))
    settings = {key: config[key] for key in _BINDINGS} | {
        key: behavior[key] for key in ("facts", "samples", "controls") if key in behavior
    }
    return {**settings, "stores": bound}, tuple(items)


def load_case(path, *, deployment_path=None, locate=False):
    locations = {}
    source = Path(path).resolve()
    raw = read_regular_bytes(source, "YAML case", _YAML_LIMIT)
    settings = yaml_document(raw, locations if locate else None)
    deployment, deployment_locations, exceptions = None, {}, ()
    environment = ("subject", "subject_ref_env"), ("erase authorization", "erase_token_env")
    if deployment_path is None:
        fields(settings, ("format", "origin_env", "facts", *_BINDINGS), ("samples", "controls"))
        if settings["format"] != FORMAT:
            raise InputError("Use --deployment with a split HTTP behavior file.")
        environment += (("read/erase origin", "origin_env"),)
    else:
        deployment_path = Path(deployment_path).resolve()
        if deployment_path == source or deployment_path.suffix.lower() not in (".yml", ".yaml"):
            raise InputError("Supply a separate YAML deployment file.")
        contents = read_regular_bytes(deployment_path, "YAML deployment", _YAML_LIMIT)
        binding = yaml_document(contents, deployment_locations if locate else None)
        settings, exceptions = split_settings(settings, binding)
        deployment = {"record": validate_record(binding["record"]), "behavior_sha256": sha256(raw).hexdigest(),
                      "deployment_sha256": sha256(contents).hexdigest()}
    if "controls" in settings:
        from setrya.control_references import validate_controls
        validate_controls(settings["controls"])
    bindings = [(hook, envname(settings[name]), (name,)) for hook, name in environment]
    callers = settings["caller_tokens"]
    if not isinstance(callers, dict) or not 1 <= len(callers) <= 16:
        raise InputError("declare 1–16 caller token bindings")
    for caller, token in callers.items():
        bindings.append(("read as " + identifier(caller, "caller"), envname(token), ("caller_tokens", caller)))
    settings["erase_route"] = path_route(settings["erase_route"])
    facts = settings["facts"]
    fields(facts, ("target", "control"))
    questions, markers, judges_by_role, store_facts = {}, {}, {}, {}
    for role, fact in facts.items():
        fields(fact, ("marker", "questions", "answers"), ("stored",))
        marker = fact["marker"]
        if not isinstance(marker, str) or not re.fullmatch(r"[A-Za-z0-9_.:@/+ -]{8,128}", marker):
            raise InputError("use unique synthetic ASCII markers of 8–128 characters")
        markers[role] = marker
        questions[role] = strings(fact["questions"], "questions")
        fields(fact["answers"], ("present", "absent"))
        reviewed = ReviewedAnswers(
            present=strings(fact["answers"]["present"], "reviewed positive answers"),
            absent=strings(fact["answers"]["absent"], "reviewed negative answers"))
        judges_by_role[role] = (Marker(marker), reviewed)
        store_facts[role] = stored_fact(marker, reviewed, fact.get("stored", {}))
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
        bindings.append(("inspect/scan " + name, envname(cfg["connection_env"]), ("stores", name, "connection_env")))
        if not isinstance(cfg["artifacts"], dict) or not cfg["artifacts"]:
            raise InputError("declare the keys and expected actions for each store")
        if cfg["kind"] == "langgraph-checkpoint" and set(cfg["artifacts"]) != {cfg["scope"]}:
            raise InputError("the checkpoint artifact key must equal the declared thread ID in scope")
        artifacts.extend(Artifact(name, key, action) for key, action in cfg["artifacts"].items())
    case = SharedCase(conversation=settings["conversation"], route=path_route(settings["read_route"]),
                      callers=tuple(callers), target_question=questions["target"][0], control_question=questions["control"][0],
                      artifacts=tuple(artifacts), scan_stores=tuple(stores), judges=judges,
                      samples=settings.get("samples", 3), target_variants=questions["target"][1:],
                      control_variants=questions["control"][1:], controls=tuple(settings.get("controls", ())))
    check_external([asdict(item) for item in exceptions], case.spec(), None)
    return HttpCase(case, stores, (markers["target"], markers["control"]),
                    (store_facts["target"], store_facts["control"]), settings, bindings, locations, source,
                    deployment, deployment_path, deployment_locations, exceptions)
