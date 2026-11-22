"""Verify SDK candidates and propose bounds after the native tests have passed."""

import argparse
from importlib.metadata import version
import json
from pathlib import Path
import re
import tomllib
from urllib.request import urlopen

CAPS = {"openai-agents": "agent-openai", "claude-agent-sdk": "agent-claude", "langfuse": "traces-langfuse"}
PACKAGES = (*CAPS, "langgraph")


def latest_versions():
    checked = {}
    for name in PACKAGES:
        with urlopen(f"https://pypi.org/pypi/{name}/json", timeout=20) as response:
            latest = json.load(response)["info"]["version"]
        installed = version(name)
        print(f"{name}: installed {installed}, latest {latest}")
        if installed != latest:
            raise SystemExit("Latest SDK not installed in this compatibility job.")
        checked[name] = installed
    return checked


def proposals(checked, extras):
    """Suggest a new upper cap only when a tested release reaches the old cap."""
    changes = {}
    for package, extra in CAPS.items():
        requirement, = extras[extra]
        current = re.fullmatch(rf"({re.escape(package)}>=[0-9]+(?:\.[0-9]+)*),<([0-9]+)\.([0-9]+)", requirement)
        stable = re.fullmatch(r"([0-9]+)\.([0-9]+)\.[0-9]+(?:\.post[0-9]+)?", checked[package])
        if current is None or stable is None:
            raise ValueError(f"Expected a stable SDK version and an explicit minor cap for {package}.")
        eligible = tuple(map(int, stable.groups()))
        if eligible >= (int(current[2]), int(current[3])):
            changes[extra] = {
                "package": package,
                "qualified_version": checked[package],
                "current": requirement,
                "suggested": f"{current[1]},<{eligible[0]}.{eligible[1] + 1}",
            }
    return {"qualified": checked, "cap_proposals": changes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, help="save the exact latest SDK versions selected for qualification")
    parser.add_argument("--qualified", type=Path, help="use the earlier version snapshot after native tests have passed")
    parser.add_argument("--output", type=Path, help="write the cap proposal report")
    options = parser.parse_args()
    if options.qualified:
        if options.record or not options.output:
            parser.error("--qualified needs --output")
        checked = json.loads(options.qualified.read_text())
        if checked != {name: version(name) for name in PACKAGES}:
            raise SystemExit("SDK versions changed during qualification.")
        root = Path(__file__).resolve().parents[1]
        extras = tomllib.loads((root / "pyproject.toml").read_text())["project"]["optional-dependencies"]
        report = proposals(checked, extras)
        options.output.write_text(json.dumps(report, indent=2) + "\n")
        for change in report["cap_proposals"].values():
            print(f"Review a cap update after successful qualification: {change['suggested']}")
    else:
        if options.output:
            parser.error("--output needs --qualified")
        checked = latest_versions()
        if options.record:
            options.record.write_text(json.dumps(checked, indent=2) + "\n")


if __name__ == "__main__":
    main()
