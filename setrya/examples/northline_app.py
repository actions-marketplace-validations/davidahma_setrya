"""Local Northline investigation with a saved chart and a physical PDF export."""

import json
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from secrets import token_urlsafe
from tempfile import NamedTemporaryFile, TemporaryDirectory
from threading import RLock, Thread

from setrya.erasure.journal import CopyJournal
from setrya.erasure.lineage import VersionLineage, VersionRef
from setrya.erasure.subject import Subject, Turn
from setrya.erasure.v3 import Answer, Artifact, SharedCase, Stored
from setrya.erasure.worker_fixture import WorkerFixture

from .northline_pdf import MAX_PDF_BYTES, read_pdf_labels, render_pdf

ENVIRONMENT = "northline-fixture"
CASE_ID = "N-204"
CONVERSATION = "case-F42"
ROUTE = f"/investigations/{CONVERSATION}/ask"
CALLERS = ("analyst-east", "analyst-west")
SOURCE_STORE, SOURCE_KEY, SOURCE_REVISION = "findings", "F-42", "finding-v1"
DETECTION_STORE, DETECTION_KEY = "detections", "event-f42"
CHART_STORE, CHART_KEY = "dashboard", "saved-chart-f42"
PDF_STORE, PDF_KEY = "pdf-exports", "dashboard-f42.pdf"
CHAT_STORE, CHAT_KEY = "saved-investigations", CONVERSATION
PROVIDER_ID, PROVIDER_STORE = "model-invocation", "model-provider"
PROVIDER_KEY, PROVIDER_OWNER = "synthetic-invocation", "provider-owner"
TARGET_NAME = "Alice North"
TARGET_REFERENCE = "OWNER-ALICE-17"
TARGET_FACT = f"{TARGET_NAME} ({TARGET_REFERENCE})"
CONTROL_FACT = "17 external sessions exceeded the approval threshold."
TARGET_QUESTION = "Who owned the dataset in finding F-42?"
CONTROL_QUESTION = "What exposure finding triggered this investigation?"
_NO_OWNER = "No dataset owner is recorded for this finding."
_PDF_TITLE = f"{SOURCE_KEY} Northline security investigation"
_ERASED_REVISION = "finding-v2"

ARTIFACTS = (
    Artifact(SOURCE_STORE, SOURCE_KEY, "rewrite"),
    Artifact(DETECTION_STORE, DETECTION_KEY, "preserve"),
    Artifact(CHART_STORE, CHART_KEY, "rewrite"),
    Artifact(CHAT_STORE, CHAT_KEY, "rewrite"),
    Artifact(PDF_STORE, PDF_KEY, "rewrite"),
)


def subject():
    return Subject.derive(bytes(range(32)), ENVIRONMENT, "person-alice", "restricted")


def case_spec():
    return SharedCase(CONVERSATION, ROUTE, CALLERS, TARGET_QUESTION, CONTROL_QUESTION,
                      ARTIFACTS, require_lineage=True)


def _target_in(text):
    return TARGET_NAME in text or TARGET_REFERENCE in text


def _json(fields):
    return json.dumps(fields, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


@dataclass(frozen=True)
class Finding:
    revision: str
    owner: str | None
    exposure: str


@dataclass(frozen=True)
class Publication:
    chart: bytes
    pdf: bytes
    chat: bytes


def _visible(raw, *, in_chat=False):
    state = json.loads(raw)
    fields = {"finding", "owner", "exposure"} | ({"conversation"} if in_chat else set())
    if (not isinstance(state, dict) or state.keys() != fields or state["finding"] != SOURCE_KEY
            or type(state["owner"]) not in (str, type(None)) or not isinstance(state["exposure"], str)):
        raise ValueError("The stored investigation is unreadable.")
    return state


def _render(finding):
    chart = _json({"finding": SOURCE_KEY, "owner": finding.owner, "exposure": finding.exposure})
    visible = _visible(chart)
    pdf = render_pdf((_PDF_TITLE, visible["exposure"], "Dataset owner: " + (visible["owner"] or "redacted")))
    chat = _json({"conversation": CONVERSATION, **visible})
    return Publication(chart, pdf, chat)


class _Endpoint(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        app = self.server.app
        caller = app.tokens.get(self.headers.get("Authorization"))
        if caller is None or self.path != ROUTE:
            self.send_error(403)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1024:
                raise ValueError("Expected a bounded question.")
            question = json.loads(self.rfile.read(size))["question"]
            if question not in (TARGET_QUESTION, CONTROL_QUESTION):
                raise ValueError("Unknown fixture question.")
        except (TypeError, ValueError, KeyError):
            self.send_error(400)
            return
        try:
            conversation, answer = app.answer(question)
        except (TypeError, ValueError, KeyError, sqlite3.Error):
            self.send_error(500)
            return
        payload = _json({"caller": caller, "conversation": conversation, "route": self.path,
                         "question": question, "answer": answer})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _LoopbackServer(HTTPServer):
    def get_request(self):
        sock, peer = super().get_request()
        sock.settimeout(3)
        return sock, peer


class Northline:
    WORKER_ATTEMPT = "northline-refresh"

    def __init__(self, folder, target, journal, *, guarded):
        self.target = target
        self.journal = journal
        self.versions = VersionLineage(journal, ENVIRONMENT)
        self.guarded = guarded
        self.pdf_path = folder / PDF_KEY
        self.lock = RLock()
        self.tokens = {"Bearer " + token_urlsafe(32): caller for caller in CALLERS}
        self.db = sqlite3.connect(folder / "northline.sqlite", check_same_thread=False)
        self.db.executescript("""
            CREATE TABLE detections (id TEXT PRIMARY KEY, revision TEXT NOT NULL, exposure TEXT NOT NULL);
            CREATE TABLE findings (
                id TEXT PRIMARY KEY, revision TEXT NOT NULL, owner TEXT, detection TEXT NOT NULL
            );
            CREATE TABLE saved (store TEXT PRIMARY KEY, payload BLOB NOT NULL);
        """)
        self.worker = WorkerFixture(self._refresh, self.read, attempt=self.WORKER_ATTEMPT)

    def _finding(self):
        row = self.db.execute("""SELECT f.revision, f.owner, d.exposure
            FROM findings AS f JOIN detections AS d ON f.detection=d.id WHERE f.id=?""", (SOURCE_KEY,)).fetchone()
        return Finding(*row) if row is not None else None

    def _saved(self, store):
        row = self.db.execute("SELECT payload FROM saved WHERE store=?", (store,)).fetchone()
        return row[0] if row is not None else None

    def _publish(self, publication):
        self.db.executemany("INSERT OR REPLACE INTO saved VALUES (?, ?)",
                            ((CHART_STORE, publication.chart), (CHAT_STORE, publication.chat)))
        with NamedTemporaryFile(dir=self.pdf_path.parent, prefix=".northline-pdf-", delete=False) as stream:
            staged = Path(stream.name)
            try:
                stream.write(publication.pdf)
                stream.close()
                staged.replace(self.pdf_path)
            finally:
                staged.unlink(missing_ok=True)

    def _record_versions(self, finding, publication):
        detection = VersionRef(DETECTION_STORE, DETECTION_KEY, "1")
        source = VersionRef(SOURCE_STORE, SOURCE_KEY, finding.revision)
        self.versions.record(source, inputs=[detection], subjects=[self.target] if finding.owner else [])
        chart = VersionRef(CHART_STORE, CHART_KEY, sha256(publication.chart).hexdigest())
        chat = VersionRef(CHAT_STORE, CHAT_KEY, sha256(publication.chat).hexdigest())
        self.versions.record(chart, inputs=[source])
        self.versions.record(chat, inputs=[chart])
        pdf = VersionRef(PDF_STORE, PDF_KEY, sha256(publication.pdf).hexdigest())
        self.versions.record(pdf, inputs=[chart])
        if finding.owner:
            for ref in (chart, chat, pdf):
                self.journal.record(self.target, store=ref.store, key=ref.key, source=SOURCE_KEY, action="derived",
                                    details={"revision": ref.revision, "stage": "committed"})

    def seed(self):
        with self.lock, self.db:
            self.db.execute("INSERT INTO detections VALUES (?, '1', ?)", (DETECTION_KEY, CONTROL_FACT))
            self.db.execute("INSERT INTO findings VALUES (?, ?, ?, ?)",
                            (SOURCE_KEY, SOURCE_REVISION, TARGET_FACT, DETECTION_KEY))
            finding = self._finding()
            rendered = _render(finding)
            self._publish(rendered)
        self.versions.record(VersionRef(DETECTION_STORE, DETECTION_KEY, "1"),
                             subjects=[Subject.derive(bytes(range(32)), ENVIRONMENT, "retained-control", "restricted")])
        self.journal.record(self.target, store=SOURCE_STORE, key=SOURCE_KEY, source=SOURCE_KEY, action="stored",
                            details={"revision": SOURCE_REVISION})
        self._record_versions(finding, rendered)

    def _check_subject(self, selected):
        if selected != self.target:
            raise ValueError("The fixture only accepts its synthetic subject.")

    def erase_approved(self, selected, source, actions):
        self._check_subject(selected)
        expected_source = {"store": SOURCE_STORE, "key": SOURCE_KEY, "revision": SOURCE_REVISION, "action": "rewrite"}
        if source != expected_source or actions != tuple(asdict(artifact) for artifact in ARTIFACTS):
            return False
        with self.lock:
            before = self._finding()
            if before is None or before.revision != SOURCE_REVISION or before.owner != TARGET_FACT:
                return False
            after = replace(before, owner=None, revision=_ERASED_REVISION)
            publication = _render(after)
            with self.db:
                self.db.execute("UPDATE findings SET revision=?, owner=NULL WHERE id=?",
                                (after.revision, SOURCE_KEY))
                self._publish(publication)
            self._record_versions(after, publication)
        return True

    def _refresh(self, selected, before_write):
        self._check_subject(selected)
        with self.lock:
            captured = self._finding()
            publication = _render(captured)
        before_write()
        with self.lock, Turn(self.WORKER_ATTEMPT, "analyst-east", "dashboard-worker").activate():
            if self.guarded and self._finding() != captured:
                return
            with self.db:
                self._publish(publication)
            self._record_versions(captured, publication)

    def hold(self, selected):
        return self.worker.hold(selected)

    def checkpoint(self, selected):
        return self.worker.checkpoint(selected)

    def release_and_drain(self, selected, attempt):
        return self.worker.release_and_drain(selected, attempt)

    def cancel_and_drain(self, selected, attempt):
        return self.worker.cancel_and_drain(selected, attempt)

    def lineage(self, selected):
        self._check_subject(selected)
        return self.versions.affected(selected)

    def inspect(self, selected, store, key):
        self._check_subject(selected)
        if not any((store, key) == (artifact.store, artifact.key) for artifact in ARTIFACTS):
            raise ValueError("No direct reader for that fixture location.")
        with self.lock:
            missing = Stored(key, False, False, False, None)
            if store == SOURCE_STORE:
                found = self._finding()
                if found is None:
                    return missing
                text = f"{found.owner or ''}\n{found.exposure}"
                revision = found.revision
            elif store == DETECTION_STORE:
                observed = self.db.execute("SELECT revision, exposure FROM detections WHERE id=?",
                                           (key,)).fetchone()
                if observed is None:
                    return missing
                revision, text = observed
            elif store == PDF_STORE:
                try:
                    with self.pdf_path.open("rb") as stream:
                        raw = stream.read(MAX_PDF_BYTES + 1)
                except FileNotFoundError:
                    return missing
                title, *labels = read_pdf_labels(raw)
                if title != _PDF_TITLE:
                    raise ValueError("The stored PDF belongs to a different finding.")
                text = "\n".join(labels)
                revision = sha256(raw).hexdigest()
            else:
                raw = self._saved(store)
                if raw is None:
                    return missing
                visible = _visible(raw, in_chat=store == CHAT_STORE)
                if store == CHAT_STORE and visible["conversation"] != CONVERSATION:
                    raise ValueError("The stored checkpoint belongs to a different investigation.")
                text = f"{visible['owner'] or ''}\n{visible['exposure']}"
                revision = sha256(raw).hexdigest()
        return Stored(key, True, _target_in(text), CONTROL_FACT in text, revision)

    def answer(self, question):
        with self.lock:
            state = _visible(self._saved(CHAT_STORE), in_chat=True)
        response = (state["owner"] or _NO_OWNER) if question == TARGET_QUESTION else state["exposure"]
        return state["conversation"], response

    def read(self, selected, caller, conversation, question):
        self._check_subject(selected)
        auth = next(token for token, principal in self.tokens.items() if principal == caller)
        with closing(HTTPConnection(*self.server.server_address, timeout=3)) as client:
            client.request("POST", f"/investigations/{conversation}/ask", _json({"question": question}),
                           {"Authorization": auth})
            response = client.getresponse()
            if response.status != 200:
                raise ValueError("The investigation endpoint rejected the authenticated read.")
            body = response.read(4097)
            if len(body) > 4096:
                raise ValueError("The investigation answer exceeded its read budget.")
            row = json.loads(body)
        return Answer(row["caller"], row["conversation"], row["route"], row["question"],
                      _target_in(row["answer"]), CONTROL_FACT in row["answer"])


@contextmanager
def open_fixture(binding=None, *, revision, guarded=True):
    """Yield discovery runner inputs from a disposable fixture with its own identity."""
    target = subject()
    with TemporaryDirectory(prefix="setrya-northline-") as directory:
        folder = Path(directory)
        journal = CopyJournal(folder / "journal.sqlite")
        app = Northline(folder, target, journal, guarded=guarded)
        with closing(app.db), app.worker, _LoopbackServer(("127.0.0.1", 0), _Endpoint) as server:
            app.seed()
            server.app = app
            app.server = server
            thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            try:
                yield {"subject": target, "case": case_spec(), "application": app, "environment": ENVIRONMENT,
                       "revision": revision, "journal": journal}
            finally:
                server.shutdown()
                thread.join()
