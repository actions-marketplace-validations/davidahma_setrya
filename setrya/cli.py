"""Command-line entry point for check, replay, demo and qualification."""

import argparse
from contextlib import closing
from dataclasses import replace
from pathlib import Path
import re
import shlex
import sqlite3
import sys

from . import __version__
from .checker import Status, Verdict, evaluate
from .drill import Drill, InputError
from .evidence import Report
from .runner import RunResult, run

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "support-search"
DEMO_CASES = {
    "broken": (Status.FAIL, "The refund policy returned to 30 days after the old job resumed."),
    "fixed": (Status.PASS, "The index rejected the old write. Search returned 14 days and still found the delivery policy."),
    "opaque": (Status.NOT_TESTED, "Search returned 14 days. The tested search view supplied no proof it had seen the old write."),
}


def preflight() -> None:
    try:
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute("CREATE VIRTUAL TABLE preflight USING fts5(body)")
    except sqlite3.Error:
        raise InputError("SQLite FTS5 is unavailable; use a Python build with FTS5 enabled") from None


def format_verdict(verdict: Verdict, report: Report, rerun: str | None = None) -> str:
    lines = [f"{verdict.status.label}  {verdict.detail}"]
    if verdict.probe:
        rule = next(probe for probe in report.rules.probes if probe.id == verdict.probe)
        lines.append(f"  Probe {rule.id} · route {rule.route} · scope {rule.scope} · top {rule.top_k}")
    if verdict.event:
        event = report.events[verdict.event - 1]
        lines.append(f"  Event {verdict.event} at {event['ns'] / 1_000_000:.1f} ms")
    if verdict.status is Status.NOT_TESTED:
        latest = {event["probe_id"]: event for event in report.events if event["kind"] == "probe"}
        for event in latest.values():
            markers = ", ".join(marker or "?" for marker in event["passages"]) or "(empty)"
            lines.append(f"  Last {event['stage']} {event['probe_id']} → {markers}")
    if verdict.attribution:
        lines.append(f"  {verdict.attribution}")
    lines.append(f"  Run {report.run_id}")
    if rerun:
        lines.append(f"  Rerun  {rerun}")
    return "\n".join(lines)


def history(report: Report) -> str:
    lines = ["  History"]
    for event in report.events:
        if event["kind"] == "probe":
            markers = ", ".join(marker if marker is not None else "?" for marker in event["passages"])
            lines.append(f"    {event['seq']:>3}  {event['stage']} {event['probe_id']} → {markers or '(empty)'}")
        elif event["kind"] == "receipt":
            lines.append(f"    {event['seq']:>3}  old write {event['outcome']}")
        else:
            lines.append(f"    {event['seq']:>3}  {event['kind']}")
    return "\n".join(lines)


def demo_case(mode: str) -> RunResult:
    drill = Drill.load(EXAMPLE / "python.toml")
    return run(replace(drill, options={"mode": mode}))


def demo(selected: str | None) -> int:
    ok = True
    for mode in (selected,) if selected else DEMO_CASES:
        result = demo_case(mode)
        expected, description = DEMO_CASES[mode]
        outcome = result.verdict.status
        ok &= outcome is expected
        print(f"{outcome.label:<11} {description if outcome is expected else result.verdict.detail}")
        events = result.report.events
        probes = [event for event in events if event["kind"] == "probe" and event["probe_id"] == "refund-window"]
        observed = []
        for probe in probes:
            markers = ", ".join(marker or "?" for marker in probe["passages"]) or "(empty)"
            if not observed or observed[-1] != markers:
                observed.append(markers)
        receipt = next((event["outcome"] for event in events if event["kind"] == "receipt"), "unobserved")
        print(f"            {' → '.join(observed)} · held and resumed · old write {receipt}")
        print(f"            Rerun  python3 -m setrya demo --case {mode}")
    return 0 if ok else 1


def rerun_command(path: str) -> str:
    # Reports and summaries avoid embedding private absolute paths or file names.
    if re.fullmatch(r"examples/support-search/(drill|python|retired)\.toml", path):
        return "python3 -m setrya check " + shlex.quote(path)
    return 'python3 -m setrya check "$DRILL" --report run.json'


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="setrya", description="Test whether search stays current after document updates.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    demo_parser = commands.add_parser("demo", help="run three synthetic outcomes")
    demo_parser.add_argument("--case", choices=DEMO_CASES)
    check = commands.add_parser("check", help="run a drill")
    check.add_argument("drill")
    check.add_argument("--report", help="write a portable JSON report")
    check.add_argument("--summary", help="write a Markdown summary")
    replay = commands.add_parser("replay", help="recompute a verdict from saved observations")
    replay.add_argument("report")
    qualify = commands.add_parser("qualify", help="run the shipped qualification cases")
    qualify.add_argument("--case")
    qualify.add_argument("--quick", action="store_true", help="skip the 90-run repeatability case")
    args = parser.parse_args(argv)

    try:
        if args.command == "replay":
            report = Report.load(args.report)
            verdict = evaluate(report)
            print(format_verdict(verdict, report))
            print(history(report))
            return verdict.status.exit_code
        if args.command == "check":
            paths = [Path(path).resolve() for path in (args.drill, args.report, args.summary) if path is not None]
            if len(set(paths)) != len(paths):
                raise InputError("drill, report and summary must use distinct files")
            drill = Drill.load(args.drill)
            preflight()
            result = run(drill)
            if args.report:
                result.report.save(args.report)
            summary = format_verdict(result.verdict, result.report, rerun_command(args.drill))
            print(summary)
            if args.summary:
                Path(args.summary).write_text(f"### Setrya · {result.report.rules.id}\n\n```text\n{summary}\n```\n",
                                              encoding="utf-8")
            return result.verdict.status.exit_code
        preflight()
        if args.command == "demo":
            return demo(args.case)
        from .qualification import qualify as run_qualification

        return run_qualification(args.case, args.quick)
    except InputError as error:
        print(f"ERROR  {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ERROR  interrupted; fixture teardown requested", file=sys.stderr)
        return 2
    except Exception as error:
        # Third-party errors may contain queries, snippets and local URLs.
        print(f"ERROR  {type(error).__name__} during {args.command}; check adapter health and local permissions",
              file=sys.stderr)
        return 2
