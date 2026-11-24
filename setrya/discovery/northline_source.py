"""Find and verify a second PDF export in a disposable investigation."""
from importlib.resources import files
from pathlib import Path
from shlex import join

from setrya.casework.profiles import new_bundle
from setrya.examples import northline_export_app
from setrya.offboarding.inputs import publish_new, require

from .case import exit_code, replay, run_case
from .macie import load_finding
from .mapping import bind_finding, load_mapping
from .northline import fixture_revision
from .source_coverage import assess, load_document, summarize


def open_fixture(binding, **options):
    revision = fixture_revision(source_export=True)
    return northline_export_app.open_fixture(binding, revision=revision, **options)


def init_example(output):
    """Export source snapshots and the reviewed example approvals."""
    catalog = files(__package__)
    package = files("setrya.examples")
    with new_bundle(output) as staged:
        for local, packaged in (
            ("finding.json", "northline-finding.json"),
            ("unmapped.json", "northline-source-unmapped.json"),
            ("mapping.json", "northline-source-mapping.json"),
            ("source-approvals.json", "northline-source-approvals.json"),
        ):
            (staged / local).write_bytes(catalog.joinpath(packaged).read_bytes())
        for label, names in (
            ("base", ("northline_app.py", "northline_pdf.py")),
            ("source", ("northline_app.py", "northline_pdf.py", "northline_export_app.py")),
        ):
            folder = staged / label
            folder.mkdir()
            for name in names:
                (folder / name).write_bytes(package.joinpath(name).read_bytes())
        (staged / "fixture.py").write_text(
            '"""Run the disposable Northline archive investigation."""\n'
            'from setrya.discovery.northline_source import open_fixture\n',
            encoding="utf-8",
        )


def demo(output):
    output = Path(output)
    lines = []
    with new_bundle(output) as staged:
        inputs = staged / "example"
        init_example(inputs)
        finding = load_finding(inputs / "finding.json")
        unmapped = bind_finding(finding, load_mapping(inputs / "unmapped.json"))
        baseline = assess(inputs / "base", unmapped)
        publish_new(baseline, staged / "baseline.json")
        gap = assess(inputs / "source", unmapped, baseline=baseline)
        publish_new(gap, staged / "unmapped.json")
        require(gap["review_required"] == 1, "Expected one new source destination without a reviewed mapping.")
        lines.extend(("Northline found one newly referenced PDF export before running the application.",
                      summarize(gap)))

        binding = bind_finding(finding, load_mapping(inputs / "mapping.json"))
        approvals = load_document(inputs / "source-approvals.json", "source approvals")
        for lane, expected in (("broken", 1), ("guarded", 0)):
            folder = staged / lane
            with open_fixture(binding, guarded=lane == "guarded") as settings:
                run_case(binding, **settings, output=folder, mode="late-write")
            checked = replay(folder, expected_binding=binding)
            report = assess(inputs / "source", binding, approvals=approvals, baseline=baseline, bundle=folder)
            archive = next((row for row in report["sites"] if row["approval"] and
                            row["approval"]["store"] == northline_export_app.ARCHIVE_STORE), None)
            require(archive and archive["runtime"] and report["review_required"] == 0
                    and archive["runtime"]["baseline"] == "CONFIRMED"
                    and archive["deletion"]["status"] == ("FAIL" if expected else "PASS")
                    and exit_code(checked) == expected and checked["review_status"] ==
                    ("RESIDUAL_FOUND" if expected else "OPEN_ITEMS"),
                    f"The {lane} Northline export produced an unexpected review.")
            publish_new(report, staged / f"{lane}-source.json")
            lines.extend(("", f"{lane} · {checked['technical_verdict']} · {checked['review_status']}",
                          summarize(report), join(["setrya", "replay", str(output / lane)])))
    print("\n".join(lines))
    return 0
