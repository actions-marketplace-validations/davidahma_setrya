"""Run the Northline investigation against an independently approved Macie finding."""
from hashlib import sha1
from importlib.resources import files
from pathlib import Path
from shlex import join

from setrya.casework.profiles import new_bundle
from setrya.drill import InputError
from setrya.examples import northline_app
from setrya.offboarding.inputs import publish_new
from setrya.receipts import summary

from .case import exit_code, replay, run_case
from .macie import load_finding
from .mapping import bind_finding, load_mapping


def _git_id(kind, data):
    return sha1(f"{kind} {len(data)}\0".encode("ascii") + data, usedforsecurity=False)


def fixture_revision(*, source_export=False):
    """Identify a reproducible Git commit of the packaged synthetic application."""
    folder = files("setrya.examples")
    entries = []
    names = ["northline_app.py", "northline_pdf.py"]
    if source_export:
        names.append("northline_export_app.py")
    for name in sorted(names):
        blob = _git_id("blob", folder.joinpath(name).read_bytes()).digest()
        entries.append(b"100644 " + name.encode("ascii") + b"\0" + blob)
    tree = _git_id("tree", b"".join(entries)).hexdigest()
    identity = "Setrya <fixture@example.invalid> 946684800 +0000"
    message = f"tree {tree}\nauthor {identity}\ncommitter {identity}\n\nNorthline fixture\n"
    return _git_id("commit", message.encode("ascii")).hexdigest()


def open_fixture(binding, **options):
    """Supply the fixture's actual packaged revision independently of the approval."""
    return northline_app.open_fixture(binding, revision=fixture_revision(), **options)


def init_example(output):
    """Write the fictional input finding, approved mapping, and guarded fixture."""
    target = Path(output)
    resources = files(__package__)
    with new_bundle(target) as staged:
        for name in ("finding.json", "mapping.json"):
            (staged / name).write_bytes(resources.joinpath(f"northline-{name}").read_bytes())
        (staged / "fixture.py").write_text(
            '"""A disposable Northline investigation. The fixture runs on loopback."""\n'
            'from setrya.discovery.northline import open_fixture\n',
            encoding="utf-8",
        )


def demo(output):
    """Exercise the broken and guarded applications and keep only portable evidence."""
    output = Path(output)
    lines = [
        "Northline case N-204 · Two analysts reopen the same investigation after the owner field is erased.",
        "Setrya checks the original finding, saved chart, exported PDF and answering route after a delayed refresh.",
    ]
    with new_bundle(output) as staged:
        inputs = staged / "example"
        init_example(inputs)
        normalized = inputs / "normalized.json"
        publish_new(load_finding(inputs / "finding.json"), normalized)
        binding = bind_finding(load_finding(normalized), load_mapping(inputs / "mapping.json"))
        for lane, expected in (("broken", 1), ("guarded", 0)):
            bundle = staged / lane
            with open_fixture(binding, guarded=lane == "guarded") as settings:
                reported = run_case(binding, **settings, mode="late-write", output=bundle)
            checked = replay(bundle, expected_binding=binding)
            if reported != checked or exit_code(checked) != expected:
                raise InputError(f"The {lane} Northline fixture produced an unexpected verdict.")
            lines.extend(("", lane, summary(checked, bundle=bundle), join(["setrya", "replay", str(output / lane)])))
    print("\n".join(lines))
    return 0
