"""Report actionable pre-erasure observations without exercising destructive hooks."""
import argparse
import ast
from functools import partial
import inspect
from pathlib import Path
import runpy
import sys
import traceback

from setrya.drill import InputError
from .v3 import SharedCase, observe_baseline


class Locations:
    def __init__(self, path, *, case=None):
        self.path, self.case = path, case
        self.hooks = {}
        if case is None:
            source = path.read_bytes()
            for node in ast.walk(ast.parse(source, filename=str(path))):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.hooks.setdefault(node.name, node.lineno)
                elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Store):
                    self.hooks.setdefault(node.id if isinstance(node, ast.Name) else node.attr, node.lineno)
                elif isinstance(node, ast.ImportFrom):
                    for name in node.names:
                        self.hooks.setdefault(name.asname or name.name, node.lineno)
            # The generated fixture shows the exact assignment to uncomment.
            for n, line in enumerate(source.splitlines(), 1):
                if line.strip().startswith(b"# application."):
                    name = line.split(b"application.", 1)[1].split()[0].decode("ascii")
                    self.hooks.setdefault(name, n)

    def yaml(self, keys):
        while keys and keys not in self.case.locations:
            keys = keys[:-1]
        return f"{self.path}:{self.case.locations.get(keys, 1)}"

    def hook(self, name, subject=None, detail=None, app=None):
        if self.case is not None:
            if name == "inspect" and detail:
                return self.yaml(("stores", subject, "artifacts", detail))
            if name in ("scan", "inspect"):
                return self.yaml(("stores", subject, "scope"))
            if name == "read" and detail:
                return self.yaml(("facts", detail, "questions"))
            return self.yaml(({"erase": "erase_route", "read": "read_route"}.get(name, "format"),))
        fn = getattr(app, name, None)
        if inspect.ismethod(fn) or inspect.isfunction(fn):
            fn = inspect.unwrap(fn)
            file = Path(fn.__code__.co_filename).resolve()
            if file.is_relative_to(self.path.parent) and file.is_file():
                return f"{file}:{fn.__code__.co_firstlineno}"
        return f"{self.path}:{self.hooks.get(name, self.hooks.get('open_fixture', self.hooks.get('CASE', 1)))}"


def run(argv):
    parser = argparse.ArgumentParser(prog="setrya doctor", description="Read a trusted fixture's baseline before erasure.")
    source_arg = parser.add_mutually_exclusive_group(required=True)
    source_arg.add_argument("--starter", type=Path, help="trusted Python starter or YAML case")
    source_arg.add_argument("--case", type=Path, help="trusted declarative YAML case")
    parser.add_argument("--mode", choices=("deletion", "late-write"), default="deletion")
    args = parser.parse_args(argv)
    if args.case and args.case.suffix.lower() not in (".yaml", ".yml"):
        raise InputError("Use a .yaml or .yml file with --case.")
    source = (args.case or args.starter).resolve()
    if not source.is_file():
        raise InputError("Supply a trusted application case or starter file.")
    original = sys.path
    try:
        sys.path = [str(source.parent), str(Path.cwd()), *original]
        from .casefile import HttpCase, load_case
        gaps = set()
        store_location = None
        def unavailable(name, error):
            gaps.add(f"{store_location.yaml(('stores', name, 'connection_env'))}  {name}: observer could not open ({error}).")

        if args.case or source.suffix.lower() in (".yml", ".yaml"):
            parsed = load_case(source, locate=True)
            location = store_location = Locations(source, case=parsed)
            missing = [(msg, location.yaml(keys)) for msg, keys in parsed.missing_bindings()]
            if args.mode == "late-write":
                missing += [(f"{hook} (wire in the Python starter for late-write)", location.hook(hook))
                            for hook in ("hold", "checkpoint", "release_and_drain")]
            if missing:
                print("NOT TESTED  Missing fixture hooks or bindings:")
                for msg, position in missing:
                    print(f"  {position}  {msg}")
                return 3
            case, open_fixture = parsed.case, partial(parsed.open_fixture, on_unavailable=unavailable)
        else:
            location = Locations(source)
            hooks = runpy.run_path(str(source))
            case, open_fixture = hooks.get("CASE"), hooks.get("open_fixture")
            profile = hooks.get("PROFILE")
            if isinstance(profile, HttpCase):
                parsed = load_case(profile.path, locate=True)
                store_location = Locations(parsed.path, case=parsed)
                if missing := parsed.missing_bindings(stores_only=True):
                    print("NOT TESTED  Missing native store bindings:")
                    for message, keys in missing:
                        print(f"  {store_location.yaml(keys)}  {message}")
                    return 3
                if callable(open_fixture) and "on_unavailable" in inspect.signature(open_fixture).parameters:
                    open_fixture = partial(open_fixture, on_unavailable=unavailable)
        if not isinstance(case, SharedCase) or not callable(open_fixture):
            raise InputError("The trusted starter must define a SharedCase named CASE and open_fixture().")
        case.spec()
        with open_fixture() as (subject, app, items):
            required = ["inspect", "read", "erase"]
            if case.scan_stores:
                required.append("scan")
            if case.require_lineage:
                required.append("lineage")
            if args.mode == "late-write":
                required += ["hold", "checkpoint", "release_and_drain"]
            missing = [name for name in required if not callable(getattr(app, name, None))]
            if missing:
                print("NOT TESTED  Missing fixture methods: " + ", ".join(missing))
                gaps.update(f"{location.hook(name, app=app)}  Connect {name}." for name in missing)
            def baseline_gap(hook, store, key, message):
                fixture_location = store_location if store_location and hook in ("inspect", "scan") else location
                gaps.add(f"{fixture_location.hook(hook, store, key, app)}  {hook}: {message}")
            observe_baseline(subject, case, app, external_items=items, on_gap=baseline_gap)
            if gaps:
                print("NOT TESTED  Check these fixture locations:")
                for message in sorted(gaps):
                    print("  " + message)
                return 3
            print(f"READY  Read {len(case.artifacts)} declared keys and all declared questions for {len(case.callers)} caller(s).")
            print("Erasure and worker hooks will be exercised by setrya run.")
            return 0
    except NotImplementedError as exc:
        frames = traceback.extract_tb(exc.__traceback__)
        frame = next((f for f in reversed(frames) if Path(f.filename).resolve().is_relative_to(source.parent)), None)
        hint = f"{frame.filename}:{frame.lineno}  {frame.name}" if frame else str(source)
        print(f"NOT TESTED  {hint}: connect the fixture to your disposable application.")
        return 3
    except SystemExit:
        raise InputError("The starter exited before its baseline could be checked.") from None
    finally:
        sys.path = original
