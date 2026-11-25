"""Exercise deletion against a disposable HTTP service and native Celery deliveries."""

import json
import sys
from contextlib import closing
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from secrets import token_bytes, token_hex
from socketserver import TCPServer
from threading import Thread
from time import monotonic, sleep
from uuid import uuid4

from celery_endpoint_app import QUEUE, URL, worker
from langchain_core.documents import Document
from redis import Redis

from setrya.adapter import Receipt
from setrya.erasure import (
    Answer,
    Artifact,
    CopyJournal,
    Drain,
    Hold,
    SharedCase,
    Stored,
    Subject,
    Turn,
    run_shared,
)
from setrya.integrations.celery_langchain import RedisCeleryCheckpoint
from setrya.integrations.langchain import tag_documents

_CALLERS = ("reviewer", "operator")
_TARGET = "The source record belongs to case 42."
_CONTROL = "The retained source belongs to case 73."
_TARGET_QUESTION = "Which case ID should be erased?"
_CONTROL_QUESTION = "Which case ID must remain?"
_ROUTE = "/handoff"
_CONVERSATION = "shared-handoff"
_CASE = SharedCase(_CONVERSATION, _ROUTE, _CALLERS, _TARGET_QUESTION, _CONTROL_QUESTION, (
    Artifact("records", "target", "delete"), Artifact("records", "control", "preserve"),
    Artifact("records", "handoff", "rewrite"),
))


def _key(run_id):
    return f"setrya-tests:write-back:{run_id}"


def _capture(snapshot):
    text = "\n".join((snapshot["target"], snapshot["control"]))
    docs = tag_documents([Document(page_content=text)], document="handoff", revision=snapshot["revision"])
    return {"document": "handoff", "revision": snapshot["revision"], "name": "before-write",
            "caller": _CALLERS[0], "question": _TARGET_QUESTION, "answer": text, "documents": docs}


@worker.task(bind=True, name="setrya.tests.writeback.handoff", shared=False, max_retries=1)
def write_handoff(task, snapshot):
    with Redis.from_url(URL, decode_responses=True) as db:
        gate = RedisCeleryCheckpoint.for_task(db, task)
        if gate is None:
            raise RuntimeError("missing native handoff checkpoint")
        key = _key(gate.run_id)
        if gate.writer_type == "retry" and task.request.retries == 0:
            try:
                gate.hold(**_capture(snapshot))
            except TimeoutError:
                db.hset(key, "retired", gate.task_id)
                return
            # Celery requeues the original task ID, arguments, and run header.
            gate.retry(task)

        revision = snapshot["revision"]
        committed = db.eval("""
            if redis.call('HGET', KEYS[1], 'guarded') == 'yes' and
               redis.call('HGET', KEYS[1], 'source_revision') ~= ARGV[1] then return 0 end
            redis.call('HSET', KEYS[1], 'handoff', ARGV[2], 'handoff_revision', ARGV[3])
            return redis.call('HINCRBY', KEYS[1], 'position', 1)
        """, 1, key, revision, json.dumps([snapshot["target"], snapshot["control"]]), gate.task_id)
        if committed:
            subject = Subject.from_metadata(task.request.headers)
            with Turn(task.request.id, "deletion-fixture", f"celery-{gate.writer_type}").activate():
                journal = CopyJournal(db.hget(key, "journal"))
                journal.record(subject, store="records", key="handoff", source="records/target", action="derived",
                               details={"revision": gate.task_id, "stage": "committed"})
        gate.finish(Receipt(gate.run_id, gate.task_id, "handoff", revision, "committed" if committed else "rejected",
                            gate.run_id if committed else None, committed or None))


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        app = self.server.app
        caller = app.sessions.get(self.headers.get("Authorization"))
        if caller is None or self.path != _ROUTE:
            self.send_error(403)
            return
        query = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if query["conversation"] != _CONVERSATION:
            self.send_error(404)
            return
        _target, found = json.loads(app.db.hget(app.key, "handoff"))
        fields = {"caller": caller, **query, "route": self.path, "target_present": _target == _TARGET,
                  "control_present": found == _CONTROL}
        body = json.dumps(fields).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _wait(observe):
    deadline = monotonic() + 10
    while (observation := observe()) is None:
        if monotonic() >= deadline:
            raise TimeoutError("timed out waiting for a native Celery observation")
        sleep(0.02)
    return observation


class _ErasureApplication:
    def __init__(self, db, run_id, writer_type, subject, journal, *, guarded):
        self.db = db
        self.key = _key(run_id)
        self.queue = f"{QUEUE}-{run_id}" if writer_type == "resume" else QUEUE
        self.subject = subject
        self.sessions = {"Bearer " + token_hex(16): caller for caller in _CALLERS}
        db.hset(self.key, mapping={"target": _TARGET, "control": _CONTROL, "handoff": json.dumps([_TARGET, _CONTROL]),
                                  "guarded": "yes" if guarded else "no", "source_revision": "initial", "position": 1,
                                  "handoff_revision": "original", "journal": str(journal.path)})
        db.expire(self.key, 180)
        self.gate = RedisCeleryCheckpoint.create(db, run_id, uuid4().hex, writer_type=writer_type)

    def __enter__(self):
        self.http = TCPServer(("127.0.0.1", 0), _Handler)
        self.http.app = self
        self.thread = Thread(target=self.http.serve_forever, kwargs={"poll_interval": 0.02})
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.gate.close()
        self.http.shutdown()
        self.thread.join()
        self.http.server_close()
        try:
            if self.gate.writer_type == "resume":
                self._consume(False)
        finally:
            if self.gate.writer_type == "resume":
                self.db.delete(self.queue)
            self.db.delete(self.key)

    def _consume(self, active):
        destination = [QUEUE + "@setrya"]
        change = worker.control.add_consumer if active else worker.control.cancel_consumer
        reply = change(self.queue, destination=destination, reply=True, timeout=2)
        if not reply or "ok" not in reply[0].get(destination[0], {}):
            raise RuntimeError("the native Celery worker did not acknowledge the consumer change")

        def observed():
            queues = worker.control.inspect(destination=destination, timeout=1).active_queues()
            if queues and destination[0] in queues and any(row["name"] == self.queue for row in queues[destination[0]]) == active:
                return True

        _wait(observed)

    def hold(self, subject):
        target, control, revision = self.db.hmget(self.key, "target", "control", "source_revision")
        snapshot = {"target": target, "control": control, "revision": revision}
        signature = write_handoff.s(snapshot).set(queue=self.queue, headers=subject.headers())
        if self.gate.writer_type == "resume":
            self._consume(True)
            self._consume(False)
            attempt = self.gate.park(signature, **_capture(snapshot))
        else:
            attempt = self.gate.dispatch(signature)
        if attempt != _wait(lambda: self.checkpoint(subject)).attempt:
            raise RuntimeError("the observed hold did not bind the dispatched job")
        return Hold(attempt)

    def checkpoint(self, subject):
        held = self.gate.checkpoint()
        if subject != self.subject or held is None:
            return None
        if self.gate.writer_type == "resume" and self.db.llen(self.queue) != 1:
            return None
        return Hold(held.attempt)

    def release_and_drain(self, subject, attempt):
        if self.checkpoint(subject) != Hold(attempt):
            raise RuntimeError("the selected job is not held")
        self.gate.release()
        if self.gate.writer_type == "resume":
            self._consume(True)
        receipt = _wait(self.gate.receipt)
        if (receipt.attempt, receipt.revision) != (attempt, "initial"):
            raise RuntimeError("drain did not identify the captured delivery")
        return Drain(attempt, True)

    def cancel_and_drain(self, subject, attempt):
        if subject != self.subject or attempt != self.gate.task_id:
            raise RuntimeError("the selected job is not held")
        self.gate.close()
        if self.gate.writer_type == "resume":
            if self.db.delete(self.queue) != 1:
                raise RuntimeError("the paused job could not be retired")
        elif _wait(lambda: self.db.hget(self.key, "retired")) != attempt:
            raise RuntimeError("the held job could not be retired")
        return Drain(attempt, True)

    def erase(self, subject):
        if subject != self.subject:
            raise RuntimeError("the requested subject does not identify this fixture")
        with self.db.pipeline() as transaction:
            transaction.hdel(self.key, "target")
            transaction.hset(self.key, mapping={"handoff": json.dumps([None, _CONTROL]),
                                                "handoff_revision": "erased", "source_revision": "erased"})
            transaction.execute()

    def inspect(self, subject, store, key):
        if subject != self.subject or store != "records":
            raise RuntimeError("unexpected fixture record")
        value = self.db.hget(self.key, key)
        if value is None:
            return Stored(key, False, None, None, None)
        revision = self.db.hget(self.key, "handoff_revision") if key == "handoff" else "preserved"
        return Stored(key, True, _TARGET in value, _CONTROL in value, revision)

    def read(self, subject, caller, conversation, question):
        if subject != self.subject:
            raise RuntimeError("unexpected subject")
        token = next(key for key, identity in self.sessions.items() if identity == caller)
        with closing(HTTPConnection(*self.http.server_address, timeout=3)) as connection:
            connection.request("POST", _ROUTE, json.dumps({"conversation": conversation, "question": question}),
                               {"Authorization": token, "Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError("the authenticated endpoint did not return an answer")
            return Answer(**json.load(response))


def _run(writer_type, mode, output):
    subject = Subject.derive(token_bytes(32), "test-tenant", "case-42", "synthetic")
    run_id = uuid4().hex
    journal = CopyJournal(Path(output).with_suffix(".sqlite"))
    with (Redis.from_url(URL, decode_responses=True) as db,
          _ErasureApplication(db, run_id, writer_type, subject, journal, guarded=mode == "guarded") as app):
        result = run_shared(subject, case=_CASE, application=app, output=output, journal=journal, run_id=run_id)
        if app.inspect(subject, "records", "target").exists:
            raise RuntimeError("the primary source survived deletion")
        terminal = app.gate.receipt()
        if terminal is None or terminal.outcome != ("rejected" if mode == "guarded" else "committed"):
            raise RuntimeError("the actual Celery delivery did not report the expected write outcome")
        print(result["technical_verdict"])


if __name__ == "__main__":
    _run(*sys.argv[1:])
