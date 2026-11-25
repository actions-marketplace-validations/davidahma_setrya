"""Two-user tests with a separate Celery worker and a disposable Redis service."""

import json
import math
from contextlib import AbstractContextManager
from dataclasses import asdict
from hashlib import sha256
from time import sleep
from uuid import uuid4

from setrya.adapter import Checkpoint, Receipt
from setrya.drill import InputError, label
from setrya.endpoint import MissingHook

from .langchain import observe_documents

# All state transitions and expirations use the same Redis instance. Neither
# participant sends a timestamp to the other. Never initialize a missing gate
# from the worker: the driver must have reserved this exact delivery first.
_TRANSITION = """
if redis.call('HGET', KEYS[1], 'state') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'state', ARGV[2])
if ARGV[4] ~= '' then redis.call('HSET', KEYS[1], ARGV[4], ARGV[5]) end
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
"""
_CREATE = """
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'state', 'pending', 'writer_type', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return 1
"""
_TTL_MS = 120_000
_RUN_HEADER = "setrya_test_run"
_WRITER_TYPES = ("held", "retry", "resume")


def _hash(text):
    return sha256(text.encode("utf-8")).hexdigest()


def _state(value):
    return value.decode("ascii") if isinstance(value, bytes) else value


def _payload(args, kwargs):
    try:
        raw = json.dumps([args, kwargs], sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise InputError("retry and resume need stable JSON task arguments") from None
    return _hash(raw)


class RedisCeleryCheckpoint:
    """One reserved task, its held input, and its application write receipt."""

    def __init__(self, client, run_id, task_id, writer_type="held"):
        self.client = client
        self.run_id = label(run_id, "run ID")
        self.task_id = label(task_id, "task ID")
        if writer_type not in _WRITER_TYPES:
            raise InputError("use a held, retry or resume Celery writer")
        self.writer_type = writer_type
        self.key = f"setrya:celery:{self.run_id}:{self.task_id}"
        self._worker = False
        self._resumed = False
        self._payload_sha256 = None
        self._completion = None

    @classmethod
    def create(cls, client, run_id, task_id, *, writer_type="held"):
        gate = cls(client, run_id, task_id, writer_type)
        if not client.eval(_CREATE, 1, gate.key, _TTL_MS, writer_type):
            raise InputError("the selected Celery checkpoint already exists")
        return gate

    @classmethod
    def for_task(cls, client, task):
        """Return the checkpoint for a scheduled drill delivery, or None for an ordinary task."""
        request = task.request
        run_id = (request.headers or {}).get(_RUN_HEADER)
        if run_id is None:
            return None
        if request.is_eager or request.called_directly or (request.delivery_info or {}).get("redelivered"):
            raise InputError("the checkpoint requires a live Celery delivery without broker redelivery")
        gate = cls(client, run_id, request.id)
        state, writer_type, capture = client.hmget(gate.key, "state", "writer_type", "capture")
        state = _state(state)
        gate.writer_type = _state(writer_type) or "held"
        gate._worker = True
        if gate.writer_type != "held":
            gate._payload_sha256 = _payload(request.args, request.kwargs)
        if request.retries == 0 and gate.writer_type in ("held", "retry") and state == "pending":
            return gate
        previous = {("retry", 1): "retrying", ("resume", 0): "released"}.get((gate.writer_type, request.retries))
        if (previous is None or state != previous or capture is None
                or json.loads(capture).get("payload_sha256") != gate._payload_sha256
                or not gate._change(previous, "writing")):
            raise InputError("the task has no reserved Celery delivery matching its original arguments")
        gate._resumed = True
        gate._completion = "writing"
        return gate

    def _change(self, previous, state, *, ttl=_TTL_MS, field="", data=None):
        return self.client.eval(_TRANSITION, 1, self.key, previous, state, ttl, field,
                                json.dumps(data, separators=(",", ":")) if field else "")

    def _capture(self, document, revision, name, caller, question, answer, documents):
        checkpoint = Checkpoint(self.run_id, self.task_id, label(document, "document"),
                                label(revision, "revision"), label(name, "checkpoint"))
        sources = observe_documents(documents, route="capture", scope=caller).passages
        return {"checkpoint": asdict(checkpoint), "caller": caller, "question_sha256": _hash(question),
                "answer_sha256": _hash(answer), "sources": sources}

    @staticmethod
    def _lease(timeout):
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 120):
            raise InputError("use a checkpoint timeout greater than zero and at most 120 seconds")
        return math.ceil(timeout * 1000)

    def dispatch(self, signature):
        """Dispatch the reserved task with the run header on its usual queue."""
        if self._worker or self.writer_type == "resume":
            raise InputError("park a resumed delivery on its paused queue")
        return self._dispatch(signature)

    def _dispatch(self, signature):
        headers = dict(signature.options.get("headers") or {})
        headers[_RUN_HEADER] = self.run_id
        return signature.apply_async(task_id=self.task_id, headers=headers).id

    def park(self, signature, *, document, revision, name, caller, question, answer, documents, timeout=30):
        """Enqueue a captured payload on a disposable queue whose consumer is paused."""
        if self._worker or self.writer_type != "resume":
            raise InputError("only a reserved resume writer can park a delivery")
        lease = self._lease(timeout)
        capture = self._capture(document, revision, name, caller, question, answer, documents)
        capture["payload_sha256"] = _payload(signature.args, signature.kwargs)
        if not self._change("pending", "enqueuing"):
            raise InputError("no unused checkpoint for this task and run")
        if (self._dispatch(signature) != self.task_id
                or not self._change("enqueuing", "held", ttl=lease, field="capture", data=capture)):
            raise InputError("the original Celery delivery could not be parked")
        return self.task_id

    def hold(self, *, document, revision, name, caller, question, answer, documents, timeout=30):
        """Call after generating from these LangChain documents and before writing the cache."""
        if not self._worker or self._resumed:
            raise InputError("only the original Celery task can acknowledge a live capture")
        lease = self._lease(timeout)
        capture = self._capture(document, revision, name, caller, question, answer, documents)
        if self.writer_type == "retry":
            capture["payload_sha256"] = self._payload_sha256
        if not self._change("pending", "held", ttl=lease, field="capture", data=capture):
            raise InputError("no unused checkpoint for this task and run")
        while True:
            state = _state(self.client.hget(self.key, "state"))
            if state == "released":
                self._resumed = True
                if self.writer_type == "held":
                    self._completion = "released"
                return
            if state != "held":
                raise TimeoutError("Celery checkpoint expired or closed before release")
            sleep(0.02)

    def retry(self, task):
        """Request one native Celery retry without replacing the original arguments."""
        request = task.request
        if (not self._resumed or self._completion is not None or self.writer_type != "retry"
                or (request.id, request.retries) != (self.task_id, 0)
                or _payload(request.args, request.kwargs) != self._payload_sha256
                or not self._change("released", "retrying")):
            raise InputError("only the released original task can retry its captured arguments")
        raise task.retry(countdown=0)

    def checkpoint(self):
        state, data = self.client.hmget(self.key, "state", "capture")
        if _state(state) == "held" and data is not None:
            return Checkpoint(**json.loads(data)["checkpoint"])
        return None

    def captured(self, case):
        data = self.client.hget(self.key, "capture")
        if data is None:
            return None
        capture = json.loads(data)
        held = capture["checkpoint"]
        # The controller already knows the synthetic test inputs. It can
        # identify an exact match without storing raw questions or answers in Redis.
        answer = next((text for text in (case.private_answer, case.public_answer)
                       if _hash(text) == capture["answer_sha256"]), None)
        question = case.question if _hash(case.question) == capture["question_sha256"] else None
        return {"run_id": held["run_id"], "attempt": held["attempt"], "caller": capture["caller"],
                "revision": held["revision"], "question": question,
                "answer": answer, "sources": capture["sources"]}

    def release(self):
        if not self._change("held", "released"):
            raise InputError("no live Celery checkpoint is available for release")

    def finish(self, receipt: Receipt):
        """Publish the application's terminal write receipt after its write decision."""
        if self._completion is None:
            raise InputError("only the task that resumed from this hold can complete its write receipt")
        if (not isinstance(receipt, Receipt) or (receipt.run_id, receipt.attempt) != (self.run_id, self.task_id)
                or receipt.outcome not in ("committed", "rejected")):
            raise InputError("supply the terminal receipt for this Celery delivery")
        if not self._change(self._completion, "finished", field="receipt", data=asdict(receipt)):
            raise InputError("no released Celery checkpoint is waiting for a write receipt")

    def receipt(self):
        data = self.client.hget(self.key, "receipt")
        return Receipt(**json.loads(data)) if data is not None else None

    def close(self):
        self.client.delete(self.key)


# A test client reserves a fresh request ID before calling HTTP. Duplicate
# completions invalidate the observation; a delayed response cannot recreate it.
_OBSERVE = """
local old = redis.call('GET', KEYS[1])
if not old then return 0 end
if old ~= 'waiting' then
  redis.call('SET', KEYS[1], 'ambiguous', 'KEEPTTL')
  return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')
return 1
"""


def record_served(client, request_id, *, route, caller, question, answer, sources, cache_hit,
                  cache_writer, generation=None, commit=None):
    """Record test-only serving metadata without changing the public HTTP response."""
    key = "setrya:served:" + label(request_id, "test request ID")
    row = {"route": label(route, "served route"), "caller": label(caller, "authenticated caller"),
           "query_sha256": _hash(question), "body_sha256": _hash(answer),
           "sources": list(sources), "cache_hit": cache_hit, "cache_writer": cache_writer,
           "generation": generation, "commit": commit}
    return bool(client.eval(_OBSERVE, 1, key, json.dumps(row, separators=(",", ":"))))


def _read_served(client, send, caller, question):
    request_id = uuid4().hex
    key = "setrya:served:" + request_id
    if not client.set(key, "waiting", nx=True, px=_TTL_MS):
        raise InputError("could not reserve a fresh endpoint request")
    try:
        status, text = send(caller, question, request_id)
        recorded = client.getdel(key)
    finally:
        client.delete(key)
    observed = {"http_status": status, "answer": text}
    if recorded is not None and _state(recorded) not in ("waiting", "ambiguous"):
        row = json.loads(recorded)
        if isinstance(text, str) and row.pop("body_sha256") == _hash(text):
            observed.update(row)
    return observed


class CeleryLangChainEndpoint(AbstractContextManager):
    """Adapt a native task signature and three application callbacks to check_endpoint.

    send(caller, question, request_id) returns the actual HTTP status and answer
    text. The serving code records its native metadata using record_served().
    revoke() returns the app's Publication. seed() prepares both warm entries.
    """

    def __init__(self, client, run_id, case, *, task, seed, revoke, send):
        self.client = client
        self.case = case
        self.task = task
        self.seed = seed
        self.revoke = revoke
        self.send = send
        self.gate = RedisCeleryCheckpoint.create(client, run_id, uuid4().hex)

    def __exit__(self, *exc):
        self.gate.close()

    @classmethod
    def from_application(cls, app, run_id, case):
        """Adapt a fixture incrementally. Only dispatch needs a task signature and worker gate."""
        return _ApplicationEndpoint(app, run_id, case)

    def answer(self, caller, question):
        return _read_served(self.client, self.send, caller, question)

    def start_old(self):
        return self.gate.dispatch(self.task)

    def checkpoint(self):
        return self.gate.checkpoint()

    def captured(self):
        return self.gate.captured(self.case)

    def release(self):
        self.gate.release()

    def receipt(self):
        return self.gate.receipt()


class _ApplicationEndpoint(CeleryLangChainEndpoint):
    """Resolve each optional native hook only when the runner reaches it."""

    def __init__(self, app, run_id, case):
        self.app = app
        self.run_id = run_id
        self.case = case
        self.gate = None

    def __exit__(self, *exc):
        if self.gate is not None:
            self.gate.close()

    def _hook(self, name):
        hook = getattr(self.app, name, None)
        if not callable(hook):
            raise MissingHook(name)
        return hook

    def seed(self):
        return self._hook("seed")()

    def revoke(self):
        return self._hook("revoke")()

    def answer(self, caller, question):
        # A serving observation from the real HTTP response works before Redis
        # or task controls have been connected, and can also drive the full race.
        observe = getattr(self.app, "answer", None)
        if callable(observe):
            return observe(caller, question)
        send = getattr(self.app, "send_answer", None)
        if not callable(send) or getattr(self.app, "test_redis", None) is None:
            raise MissingHook("answer")
        return _read_served(self.app.test_redis, send, caller, question)

    def start_old(self):
        task = getattr(self.app, "fill_answer", None)
        client = getattr(self.app, "test_redis", None)
        if task is None or client is None:
            raise MissingHook("start_old")
        self.task = task.s(self.case.revoked, self.case.question)
        self.gate = RedisCeleryCheckpoint.create(client, self.run_id, uuid4().hex)
        return super().start_old()
