"""Run or review an erasure drill scoped to one person or a tenant."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from tempfile import TemporaryDirectory

from setrya import provenance
from setrya.core.deployment import read_pin as read_deployment_pin
from setrya.core.provenance import read_pin, verify_pins
from setrya.drill import InputError
from setrya.offboarding import signature
from setrya.offboarding.inputs import InvalidReport, read_regular_bytes, require
from .receipt import RECEIPT
from .v3 import _RUN_CONFIRMATION, _RUN_OUTPUT
from setrya.receipts import check_scope, exit_code as receipt_exit, replay as load_directory, report, signature_command


def replay_directory(directory, *, case_review=False, expected_scope=None,
                     expected_provenance=None, expected_app_commit=None, expected_deployment=None):
    receipt = load_directory(directory, expected_provenance=expected_provenance,
                             expected_app_commit=expected_app_commit, expected_deployment=expected_deployment)
    check_scope(receipt, expected_scope)
    return report(receipt, case_review=case_review)


def _run_starter(starter, mode, output, producer):
    with TemporaryDirectory(prefix="setrya-live-") as tmp:
        confirmation = Path(tmp) / "evidence-sha256"
        child_env = {**os.environ, _RUN_OUTPUT: str(output.resolve()), _RUN_CONFIRMATION: str(confirmation),
                     provenance.RUN_PROVENANCE: json.dumps(producer, separators=(",", ":"))}
        # Installed starters can import their own siblings and the caller's application.
        paths = [str(Path.cwd()), child_env.get("PYTHONPATH", "")]
        child_env["PYTHONPATH"] = os.pathsep.join(filter(None, paths))
        code = subprocess.run([sys.executable, str(starter.resolve()), "--mode", mode,
                               "--output", str(output.resolve())], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env=child_env, check=False).returncode
        digest = read_regular_bytes(confirmation, "live run confirmation", 64) if confirmation.exists() else None
    return code, digest


def run_person_starter(starter, mode, output, *, test_files=(), deployed_commit=None, fixture_source=None,
                       deployment_path=None):
    """Publish only replayable evidence bound to this invocation and its unchanged test inputs."""
    from setrya.casework.profiles import new_bundle

    if output is None or starter is None:
        raise InputError("Supply --starter and a new --output directory.")
    if not starter.is_file() or os.path.lexists(output):
        raise InputError("Choose a trusted starter file and a fresh output directory.")
    if mode not in ("deletion", "late-write"):
        raise InputError("Choose deletion or late-write for the drill mode.")
    test_files = tuple(test_files)
    canonical = fixture_source or starter
    snapshot = starter if fixture_source is not None else None
    capture_options = {"deployed_commit": deployed_commit, "executed_copy": snapshot}
    parsed = None
    if deployment_path is not None:
        if starter.suffix.lower() not in (".yml", ".yaml") or mode != "deletion" or fixture_source is not None:
            raise InputError("A deployment file requires a YAML behavior case in deletion mode.")
        from .casefile import load_case

        parsed = load_case(starter, deployment_path=deployment_path)
        test_files += (deployment_path,)
        capture_options["expected_hashes"] = parsed.source_digests()
    producer = provenance.capture(canonical, test_files, **capture_options)
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="setrya-provenance-", dir=output.parent) as temp:
        # Preserve the caller's chosen name inside the private staging area.
        candidate = Path(temp) / output.name
        code, receipt = _run_person(starter, mode, candidate, producer, parsed=parsed)
        if receipt is None:
            return code, None
        verify_pins(receipt, expected_provenance=producer)
        require(producer == provenance.capture(canonical, test_files, **capture_options),
                "The application checkout or declared test files changed during the drill.")
        require(candidate.is_dir() and not candidate.is_symlink(), "The fixture must write a regular receipt directory.")
        with new_bundle(output) as published:
            candidate.replace(published)
        return code, receipt


def _run_person(starter, mode, output, producer, *, parsed=None):
    if starter.suffix.lower() in (".yml", ".yaml"):
        from .casefile import load_case
        from .v3 import run_shared
        spec = parsed or load_case(starter)
        if spec.missing():
            print("NOT TESTED  Missing fixture bindings: " + ", ".join(spec.missing()), file=sys.stderr)
            return 3, None
        with spec.open_fixture() as (subject, application, items):
            bound = application.deployment
            live = run_shared(subject, case=spec.case, application=application, mode=mode, output=output,
                              external_items=items, journal=application.journal, provenance=producer,
                              erase_action=application.erase_bound if bound is not None else None,
                              deployment_evidence=bound.evidence if bound is not None else None)
        replayed = load_directory(output)
        if live != replayed:
            raise InputError("Replayed evidence differs from the live HTTP case.")
        return receipt_exit(replayed), replayed
    code, issued_digest = _run_starter(starter, mode, output, producer)
    if not (output / RECEIPT).is_file():
        label = "NOT TESTED" if code == 3 else "ERROR"
        print(f"{label}  The starter exited {code} before writing a receipt. "
              "Run the trusted starter directly to see its diagnostics.", file=sys.stderr)
        return (3 if code == 3 else 2), None
    receipt = load_directory(output)
    if receipt["version"] != 3:
        raise InputError("Update the starter to issue v3 receipts. Use replay for historical v2 evidence.")
    if (receipt.get("scope") != "person" or "profile" in receipt
            or code != receipt_exit(receipt) or receipt.get("mode") != mode):
        raise InputError("Starter exit or recorded mode differs from the requested drill.")
    if issued_digest != receipt["evidence"]["sha256"].encode("ascii"):
        raise InputError("Receipt does not match evidence issued by this live run.")
    return code, receipt


def main(argv, *, prog="setrya erasure"):
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    demo = commands.add_parser("demo", help="exercise the shared investigation or tenant example")
    demo.add_argument("--scope", choices=("person", "tenant"), default="person")
    demo.add_argument("--output", type=Path, default=Path("investigation"))
    demo.add_argument("--example", choices=("shared", "investigation"))
    demo.add_argument("--mode", choices=("deletion", "late-write"))
    init = commands.add_parser("init", help="create an application starter or tenant observation policy")
    init.add_argument("--scope", choices=("person", "tenant"), default="person")
    init.add_argument("--output", type=Path, default=Path("setrya-erasure"))
    init.add_argument("--example", choices=("shared", "investigation"))
    run = commands.add_parser("run", help="execute a trusted local starter or evaluate a tenant gate")
    run.add_argument("--scope", choices=("person", "tenant"), default="person")
    run.add_argument("case_path", nargs="?", type=Path, help="declarative YAML case (default output: setrya-receipt)")
    case_arg = run.add_mutually_exclusive_group()
    case_arg.add_argument("--starter", type=Path, help="trusted generated test file")
    case_arg.add_argument("--case", type=Path, help="trusted declarative YAML file")
    run.add_argument("--mode", choices=("deletion", "late-write"))
    run.add_argument("--output", type=Path)
    run.add_argument("--test-file", type=Path, action="append", default=[],
                     help="additional trusted test file whose exact bytes should be bound (repeatable)")
    run.add_argument("--deployed-commit", help="issuer-declared remote deployment Git commit")
    run.add_argument("--deployment", type=Path, help="client deployment bindings for a split YAML case")
    run.add_argument("--fixture-source", type=Path, help=argparse.SUPPRESS)
    replay = commands.add_parser("replay", help="recompute engineering or case-review outcomes")
    replay.add_argument("--scope", choices=("person", "tenant"), help="require the selected receipt scope")
    replay.add_argument("directory", nargs="?", type=Path)
    replay.add_argument("--case-review", action="store_true")
    replay.add_argument("--expect-provenance", type=Path, help="independent provenance JSON record")
    replay.add_argument("--expect-app-commit", help="expected clean local application checkout Git commit")
    replay.add_argument("--expect-deployment", type=Path, help="independent expected HTTPS deployment record")
    signature.add_commands(commands, local_keys=True, aliases=True)
    verify = commands.choices["verify"]
    verify.add_argument("--expect-provenance", type=Path, help="independent provenance JSON record")
    verify.add_argument("--expect-app-commit", help="expected clean local application checkout Git commit")
    verify.add_argument("--expect-deployment", type=Path, help="independent expected HTTPS deployment record")

    # Tenant commands retain the native request, policy and exhibits as inputs.
    # Delegate their argument parsing so the frozen v1 contract stays authoritative.
    if argv[:1] in (["replay"], ["run"]):
        scope_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
        scope_parser.add_argument("--scope", choices=("person", "tenant"))
        scope, rest = scope_parser.parse_known_args(argv[1:])
        if scope.scope == "tenant":
            prog = f"{prog} {argv[0]} --scope tenant"
            if argv[0] == "replay" and "--request" in rest:
                from setrya.offboarding.cli import main as tenant_main
                return tenant_main(["verify-receipt", *rest], command_prog=prog)
            try:
                if argv[0] == "run":
                    from setrya.offboarding.tenant_v3 import command
                    return command(rest, prog=prog)
                tenant = argparse.ArgumentParser(prog=prog, description="Replay a request-bound tenant receipt.")
                tenant.add_argument("directory", type=Path)
                tenant.add_argument("--expect-request")
                tenant.add_argument("--expect-job")
                tenant.add_argument("--case-review", action="store_true")
                opts = tenant.parse_args(rest)
                receipt = load_directory(opts.directory, expected_request=opts.expect_request, expected_job=opts.expect_job)
                check_scope(receipt, "tenant")
                return report(receipt, case_review=opts.case_review)
            except (ValueError, OSError, RecursionError) as error:
                detail = str(error) if isinstance(error, (InputError, InvalidReport)) else type(error).__name__
                print(f"ERROR  {detail}", file=sys.stderr)
                return 2
    args = parser.parse_args(argv)
    try:
        if args.action in ("sign-receipt", "sign", "verify-signature", "verify"):
            args.offboarding_action = "sign-receipt" if args.action in ("sign", "sign-receipt") else "verify-signature"
            return signature_command(args)
        if args.action == "replay":
            if args.directory is None:
                raise InputError("Supply the directory containing the receipt and its evidence.")
            return replay_directory(args.directory, case_review=args.case_review, expected_scope=args.scope,
                                    expected_provenance=read_pin(args.expect_provenance),
                                    expected_app_commit=args.expect_app_commit,
                                    expected_deployment=read_deployment_pin(args.expect_deployment))
        if args.action == "run":
            if args.case_path:
                if args.case or args.starter:
                    raise InputError("Choose one positional case, --case or --starter.")
                args.case = args.case_path
                args.output = args.output or Path("setrya-receipt")
            if args.case and args.case.suffix.lower() not in (".yaml", ".yml"):
                raise InputError("Use a .yaml or .yml file with --case.")
            if args.deployment is not None:
                args.output = args.output or Path("setrya-receipt")
            code, receipt = run_person_starter(args.case or args.starter, args.mode or "deletion", args.output,
                                               test_files=args.test_file, deployed_commit=args.deployed_commit,
                                               fixture_source=args.fixture_source, deployment_path=args.deployment)
            return report(receipt) if receipt is not None else code
        if args.scope == "tenant" and (args.example or getattr(args, "mode", None)):
            raise InputError("Use person scope to select a shared investigation mode.")
        if args.action == "demo":
            if args.scope == "tenant":
                from setrya.offboarding.cli import main as tenant_main

                return tenant_main(["demo", "--output", str(args.output)])
            from .investigation import run_demo

            return run_demo(args.output, mode=args.mode or "late-write")
        if args.scope == "tenant":
            from importlib.resources import files

            args.output.mkdir(parents=True, exist_ok=False)
            policy = args.output / "policy.json"
            policy.write_bytes(files("setrya.examples.offboarding.sqlite").joinpath("policy.json").read_bytes())
            print(f"Created {policy}. Connect your tenant observer, then run erasure run --scope tenant --help.")
        else:
            from .starter import init_erasure

            init_erasure(args.output)
            print(f"Created {args.output}. Connect the disposable application fixture, then run")
            print(shlex.join(["python", "-m", "pytest", "-q", "-s", "--", str(args.output / "test_erasure.py")]))
        return 0
    except (ValueError, OSError, RecursionError) as exc:
        detail = str(exc) if isinstance(exc, (InputError, InvalidReport)) else type(exc).__name__
        print(f"ERROR  {detail}", file=sys.stderr)
        return 2
