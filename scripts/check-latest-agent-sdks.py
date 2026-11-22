"""Fail when pip selected an older compatible SDK instead of the latest release."""
from importlib.metadata import version
import json
from urllib.request import urlopen

for name in ("openai-agents", "claude-agent-sdk", "langfuse", "langgraph"):
    with urlopen(f"https://pypi.org/pypi/{name}/json", timeout=20) as response:
        latest = json.load(response)["info"]["version"]
    installed = version(name)
    print(f"{name}: installed {installed}, latest {latest}")
    if installed != latest:
        raise SystemExit("Latest SDK not installed in this compatibility job.")
