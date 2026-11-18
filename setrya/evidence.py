"""Portable, versioned evidence for the offline checker."""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import tempfile

from .drill import InputError, Rules, integer, label, mapping

SCHEMA = 1
CHECKER = 1
MAX_REPORT_BYTES = 16 * 1024 * 1024
_MAX_TIME = 2**63 - 1
_IDENTITY = {"run_id", "attempt", "document", "revision"}
_EVENT_FIELDS = {
    "seeded": set(), "started": {"attempt"}, "held": _IDENTITY | {"name"},
    "published": set(), "released": {"attempt"},
    "receipt": _IDENTITY | {"outcome", "generation", "commit"},
    "probe": {"probe_id", "stage", "started_ns", "passages", "origins", "view"},
}


@dataclass(frozen=True)
class Report:
    run_id: str
    rules: Rules
    events: tuple[dict, ...]

    def save(self, path: str | Path) -> None:
        target = Path(path)
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=target.parent, prefix=".setrya-", delete=False
            ) as stream:
                temporary = Path(stream.name)
                try:
                    json.dump({
                        "schema": SCHEMA, "checker": CHECKER, "run_id": self.run_id,
                        "rules": asdict(self.rules), "events": self.events,
                    }, stream, indent=2)
                    stream.write("\n")
                    if stream.tell() > MAX_REPORT_BYTES:
                        raise InputError("report exceeds size limit")
                    stream.close()
                    os.replace(temporary, target)
                finally:
                    temporary.unlink(missing_ok=True)
        except OSError:
            raise InputError("could not write report; check the destination directory") from None

    @classmethod
    def load(cls, path: str | Path) -> "Report":
        try:
            with Path(path).open("rb") as stream:
                data = stream.read(MAX_REPORT_BYTES + 1)
            if len(data) > MAX_REPORT_BYTES:
                raise InputError("report exceeds size limit")
            obj = json.loads(data)
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
            raise InputError("could not read report as JSON") from None
        fields = mapping(obj, "report", {"schema", "checker", "run_id", "rules", "events"})
        if type(fields["schema"]) is not int or fields["schema"] != SCHEMA:
            raise InputError("unsupported report schema")
        if type(fields["checker"]) is not int or fields["checker"] != CHECKER:
            raise InputError("unsupported checker version")
        if not isinstance(fields["events"], list):
            raise InputError("report events must be a list")
        report = cls(label(fields["run_id"], "run ID"), Rules.parse(fields["rules"]), tuple(fields["events"]))
        report.validate()
        return report

    def validate(self) -> None:
        """Validate the same event fields for live and replayed reports."""
        probes = {probe.id: probe for probe in self.rules.probes}
        previous_ns = 0
        stage = None
        singletons = set()
        transitions = {
            "seeded": None, "started": "seeded", "held": "started",
            "published": "held", "released": "published",
        }
        for index, raw in enumerate(self.events, 1):
            if not isinstance(raw, dict) or not isinstance(raw.get("kind"), str):
                raise InputError("each evidence event needs a kind")
            kind = raw["kind"]
            if kind not in _EVENT_FIELDS:
                raise InputError("unknown evidence event kind")
            event = mapping(raw, "event", {"kind", "seq", "ns"} | _EVENT_FIELDS[kind])
            integer(event["seq"], "event sequence", index, index)
            ns = integer(event["ns"], "event time", previous_ns, _MAX_TIME)
            if kind in transitions:
                if stage != transitions[kind] or kind in singletons:
                    raise InputError("invalid lifecycle event order")
                stage = kind
                singletons.add(kind)
            if kind in {"held", "receipt"}:
                for field in _IDENTITY:
                    label(event[field], field)
            if kind in {"started", "released"}:
                label(event["attempt"], "attempt")
            if kind == "held":
                label(event["name"], "checkpoint name")
            if kind == "receipt":
                if stage != "released" or kind in singletons:
                    raise InputError("unexpected terminal write receipt")
                _validate_receipt(event)
                singletons.add(kind)
            if kind == "probe":
                _validate_probe(event, probes, stage, previous_ns)
            previous_ns = ns


def _validate_receipt(event: dict) -> None:
    if event["outcome"] == "committed":
        label(event["generation"], "index generation")
        integer(event["commit"], "write commit", 0, _MAX_TIME)
    elif event["outcome"] != "rejected" or event["generation"] is not None or event["commit"] is not None:
        raise InputError("invalid terminal write receipt")


def _validate_probe(event: dict, probes: dict, stage: str, previous_ns: int) -> None:
    probe_id = label(event["probe_id"], "probe ID")
    stages = {"seeded": "baseline", "published": "freshness", "released": "final"}
    if probe_id not in probes or stage not in stages or event["stage"] != stages[stage]:
        raise InputError("invalid probe evidence")
    integer(event["started_ns"], "probe start time", previous_ns, event["ns"])
    passages, origins = event["passages"], event["origins"]
    if not isinstance(passages, (list, tuple)) or len(passages) > probes[probe_id].top_k:
        raise InputError("probe evidence exceeds the declared result depth")
    if not isinstance(origins, (list, tuple)) or len(origins) != len(passages):
        raise InputError("probe origins must align with passages")
    for marker in (*passages, *origins):
        if marker is not None:
            label(marker, "passage or write marker")
    if event["view"] is not None:
        view = mapping(event["view"], "search view", {"generation", "commit", "route", "scope"})
        for field in ("generation", "route", "scope"):
            label(view[field], field)
        integer(view["commit"], "search commit", 0, _MAX_TIME)
