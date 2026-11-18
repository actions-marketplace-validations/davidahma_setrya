"""Drive a trusted adapter and record observations in runner clock order."""

from dataclasses import asdict, dataclass
from importlib import import_module
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic_ns, sleep
from uuid import uuid4

from .adapter import Adapter, RunContext
from .checker import NS_PER_MS, Status, Verdict, evaluate
from .drill import Drill, InputError, Probe, label
from .evidence import Report


@dataclass(frozen=True)
class RunResult:
    verdict: Verdict
    report: Report


def run(drill: Drill | str | Path) -> RunResult:
    """Run a drill against a reviewed adapter and return its verdict and evidence."""
    if not isinstance(drill, Drill):
        drill = Drill.load(drill)
    module, factory_name = drill.factory.split(":")
    try:
        factory = getattr(import_module(module), factory_name)
    except (ImportError, AttributeError):
        raise InputError("could not import adapter factory from the checkout or Python path") from None

    run_id = uuid4().hex
    with TemporaryDirectory(prefix="setrya-") as directory:
        adapter = factory(RunContext(run_id, Path(directory), drill))
        try:
            execution = _Execution(drill, adapter, run_id)
            return execution.run()
        finally:
            adapter.close()


class _Execution:
    def __init__(self, drill: Drill, adapter: Adapter, run_id: str):
        self.drill = drill
        self.adapter = adapter
        self.run_id = run_id
        self.rules = drill.rules
        self.started = monotonic_ns()
        self.events = []

    def time(self) -> int:
        return monotonic_ns() - self.started

    def add(self, kind: str, **fields) -> int:
        now = self.time()
        self.events.append({"kind": kind, "seq": len(self.events) + 1, "ns": now, **fields})
        return now

    def result(self) -> RunResult:
        report = Report(self.run_id, self.rules, tuple(self.events))
        return RunResult(evaluate(report), report)

    def probe(self, probe: Probe, stage: str) -> tuple[str | None, ...]:
        started = self.time()
        observed = self.adapter.search(probe)
        origins = (None,) * len(observed.passages) if observed.origins is None else observed.origins
        self.add("probe", probe_id=probe.rules.id, stage=stage, started_ns=started,
                 passages=observed.passages, origins=origins,
                 view=asdict(observed.view) if observed.view else None)
        return observed.passages

    def wait_until(self, timestamp: int) -> None:
        sleep(max(0, (timestamp - self.time()) / 1_000_000_000))

    def run(self) -> RunResult:
        self.adapter.seed()
        self.add("seeded")
        for probe in self.drill.probes:
            if probe.rules.before:
                self.probe(probe, "baseline")

        attempt = label(self.adapter.start_old(), "attempt")
        start = self.add("started", attempt=attempt)
        deadline = start + self.rules.checkpoint_ms * NS_PER_MS
        interval = self.rules.sample_ms * NS_PER_MS
        while self.time() <= deadline:
            held = self.adapter.checkpoint()
            received = self.time()
            if held is not None and received <= deadline:
                self.add("held", **asdict(held))
                break
            if received >= deadline:
                return self.result()
            self.wait_until(min(received + interval, deadline))
        else:
            return self.result()
        expected_hold = (self.run_id, attempt, self.rules.document, self.rules.old_revision, self.rules.checkpoint)
        if (held.run_id, held.attempt, held.document, held.revision, held.name) != expected_hold:
            return self.result()

        self.adapter.publish()
        publication = self.add("published")
        freshness = next(probe for probe in self.drill.probes if probe.rules.id == self.rules.freshness_probe)
        cutoff = publication + self.rules.freshness_ms * NS_PER_MS
        while True:
            probe_started = self.time()
            passages = self.probe(freshness, "freshness")
            if set(freshness.rules.require) <= set(passages):
                break
            if probe_started >= cutoff:
                return self.result()
            self.wait_until(min(probe_started + interval, cutoff))

        # A second probe of the live path can expose a stale read before resume.
        for probe in self.drill.probes:
            self.probe(probe, "freshness")
        self.adapter.release()
        release = self.add("released", attempt=attempt)
        final_cutoff = release + self.rules.settle_ms * NS_PER_MS
        receipt = None
        while self.time() <= final_cutoff:
            sample_started = self.time()
            if receipt is None:
                receipt = self.adapter.receipt()
                if receipt is not None:
                    self.add("receipt", **asdict(receipt))
            for probe in self.drill.probes:
                self.probe(probe, "final")
            if receipt is not None:
                result = self.result()
                if result.verdict.status in {Status.PASS, Status.FAIL}:
                    return result
            if self.time() >= final_cutoff:
                break
            self.wait_until(min(sample_started + interval, final_cutoff))
        return self.result()
