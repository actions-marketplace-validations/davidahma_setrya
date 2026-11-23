"""Exercise the public CLI from an empty directory with only the installed distribution."""
import json
import subprocess
import sys
from importlib.metadata import metadata
from importlib.resources import files
from importlib.util import find_spec
from pathlib import Path
from tempfile import TemporaryDirectory


def call(cwd, *args, code=0):
    result = subprocess.run([sys.executable, "-I", "-m", "setrya", *args], check=False, cwd=cwd, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    if result.returncode != code:
        raise RuntimeError(f"{args} exited {result.returncode}\n{result.stdout}")
    return result.stdout


with TemporaryDirectory() as tmp:
    path = Path(tmp)
    for module in ("demo", "runner", "starter_template"):
        if find_spec("setrya.erasure." + module) is not None:
            raise RuntimeError("Distribution contains a retired v2 writer: " + module)
    help_text = call(path, "--help")
    if metadata("setrya")["Summary"] not in help_text:
        raise RuntimeError("Installed package summary and CLI help differ.")
    if "scan Python PDF writes" not in help_text:
        raise RuntimeError("The public help omits the discovery command.")
    call(path, "demo")
    call(path, "replay", "workspace/broken", code=1)
    call(path, "replay", "workspace/guarded")
    call(path, "replay", "workspace/guarded", "--case-review", code=3)
    call(path, "recheck", "workspace/guarded", "--output", "follow-up", code=3)
    call(path, "replay", "follow-up", "--case-review", code=3)
    for audience in ("engineer", "reviewer", "customer"):
        call(path, "receipt", "summary", "follow-up", "--audience", audience, "--format", "markdown")
    call(path, "demo", "memory-files")
    call(path, "replay", "memory-files/broken", code=1)
    call(path, "replay", "memory-files/guarded")
    call(path, "receipt", "summary", "memory-files/guarded", "--format", "md")
    call(path, "demo", "branches")
    call(path, "replay", "branches/broken", code=1)
    call(path, "replay", "branches/fixed")
    call(path, "recheck", "branches/fixed", "--output", "branch-follow-up", code=3)
    call(path, "receipt", "summary", "branch-follow-up", "--audience", "customer")
    call(path, "demo", "northline")
    call(path, "discovery", "init", "--example", "northline", "--output", "northline-inputs")
    call(path, "discovery", "import", "--finding", "northline-inputs/finding.json", "--output", "finding.json")
    approval = ("--finding", "finding.json", "--mapping", "northline-inputs/mapping.json")
    call(path, "discovery", "replay", "northline/broken", *approval, code=1)
    call(path, "discovery", "replay", "northline/guarded", *approval)
    call(path, "replay", "northline/guarded", "--case-review", code=3)
    call(path, "discovery", "export", "northline/guarded", *approval, "--output", "N-204.json")
    call(path, "demo", "northline-source")
    call(path, "discovery", "init", "--example", "northline-source", "--output", "exports")
    call(path, "discovery", "source-scan", "exports/source")
    common = ("--finding", "exports/finding.json")
    unmapped = (*common, "--mapping", "exports/unmapped.json")
    call(path, "discovery", "source-check", "exports/base", *unmapped, "--output", "baseline.json")
    call(path, "discovery", "source-check", "exports/source", *unmapped, "--baseline", "baseline.json", code=3)
    approved = (*common, "--mapping", "exports/mapping.json", "--approvals", "exports/source-approvals.json")
    for lane, verdict, code in (("broken", "FAIL", 1), ("guarded", "PASS", 0)):
        case_directory = f"northline-source/{lane}"
        source_review = call(path, "discovery", "source-check", "exports/source", *approved,
                             "--receipt", case_directory)
        if f"runtime baseline CONFIRMED · deletion check {verdict}" not in source_review:
            raise RuntimeError("The installed source review did not link the archive observations.")
        call(path, "replay", case_directory, code=code)
    call(path, "replay", "northline-source/guarded", "--case-review", code=3)
    schema = files("setrya.erasure").joinpath("copy-event.v1.schema.json")
    skill = files("setrya").joinpath("resources/skills/setrya-erasure/SKILL.md")
    if json.loads(schema.read_text(encoding="utf-8"))["$id"] != "urn:setrya:copy-event:v1" or not skill.is_file():
        raise RuntimeError("The installed copy-event schema or erasure skill is missing.")
    call(path, "init")
    # A consumer's fixture commonly lives in tests/ or setrya-case/ and imports
    # an application package in the root of a checkout that is not pip-installed.
    starter = path / "setrya-case" / "test_erasure.py"
    (path / "application_fixture.py").write_text(
        "from setrya.examples.workspace import SIMPLE as CASE, open_fixture\n", encoding="utf-8")
    starter.write_text(starter.read_text().replace("from setrya.examples.workspace import SIMPLE as CASE",
                                                   "from application_fixture import CASE").replace(
        "from setrya.examples.workspace import open_fixture", "from application_fixture import open_fixture"))
    fixture = ("--starter", "setrya-case/test_erasure.py")
    for mode in ("deletion", "late-write"):
        call(path, "doctor", *fixture, "--mode", mode)
        call(path, "run", *fixture, "--mode", mode, "--output", mode)
        call(path, "replay", mode)
        receipt = json.loads((path / mode / "erasure-receipt.json").read_bytes())
        if len(receipt["case"]["callers"]) != 1 or receipt["case"]["artifacts"][0]["action"] != "delete":
            raise RuntimeError("The starter must exercise a single-caller delete-only case.")
print("Installed workspace, branch, Northline and source coverage demos, case review, starter, doctor, deletion, late writer and replay passed.")
