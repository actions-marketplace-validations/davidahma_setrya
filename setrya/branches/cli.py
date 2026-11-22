"""Issue replayable branch observations from a trusted local inventory."""
import argparse
import re
import tomllib
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path

from setrya.casework.profiles import fields, issue, new_bundle, stamp
from setrya.core.branch_journal import read_branch_snapshot
from setrya.core.inputs import read_regular_bytes, require
from setrya.core.subject import identifier

from .receipt import FORMAT, KIND, MAX_SCANNERS, MAX_WINDOW_SECONDS, PROFILE
from .scanners import observe, postgres_archiving


def _inventory(path):
    path = Path(path).absolute()
    require(not path.is_symlink(), "Choose a local branch inventory file.")
    inventory = tomllib.loads(read_regular_bytes(path, "branch inventory").decode("utf-8"))
    fields(inventory, "scanners", ("restore_windows",))
    scanners, windows = inventory["scanners"], inventory.get("restore_windows", [])
    require(isinstance(scanners, list) and 1 <= len(scanners) <= MAX_SCANNERS
            and isinstance(windows, list) and len(windows) <= MAX_SCANNERS,
            "Use a bounded branch inventory with at least one scanner.")
    identifiers, aliases = set(), set()
    for spec in scanners:
        fields(spec, "id kind", ("path", "aliases", "patterns", "project", "source_branch", "token_env"))
        name = identifier(spec["id"], "scanner ID")
        kind = spec["kind"]
        require(name not in identifiers and kind in KIND, "Repeated or unknown branch scanner.")
        identifiers.add(name)
        if kind == "neon":
            fields(spec, "id kind project source_branch token_env")
            require(isinstance(spec["token_env"], str) and re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", spec["token_env"]),
                    "The Neon credential must be named by an environment variable.")
            continue
        fields(spec, "id kind path", ("aliases", "patterns") if kind == "sqlite" else ("aliases",))
        require(isinstance(spec["path"], str) and spec["path"], "Local branch scanner needs a path.")
        spec["path"] = path.parent / spec["path"]
        spec["aliases"] = spec.get("aliases", {})
        require(isinstance(spec["aliases"], dict), "Branch aliases must map paths to opaque store IDs.")
        for file, child in spec["aliases"].items():
            identifier(child, "branch alias")
            require(child not in aliases and (Path(file).is_absolute() if kind == "git-worktrees"
                                              else Path(file).name == file and file not in ("", ".", "..")),
                    "Repeated alias or unsupported branch alias path.")
            aliases.add(child)
        if kind == "sqlite":
            spec["patterns"] = spec.get("patterns", ["*.sqlite", "*.sqlite3", "*.db"])
            require(isinstance(spec["patterns"], list) and 1 <= len(spec["patterns"]) <= 64
                    and all(isinstance(p, str) and p and len(p) <= 256 and "/" not in p for p in spec["patterns"]),
                    "SQLite backup patterns must be simple filename globs.")
            require(all(any(fnmatchcase(name, p) for p in spec["patterns"]) for name in spec["aliases"]),
                    "A SQLite branch alias does not match the scanner's patterns.")
    for spec in windows:
        fields(spec, "id owner seconds", ("postgres_dsn_env",))
        identifier(spec["id"], "restore window ID")
        identifier(spec["owner"], "restore window owner")
        if "postgres_dsn_env" in spec:
            name = spec["postgres_dsn_env"]
            require(isinstance(name, str) and re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", name),
                    "The PostgreSQL read-only DSN must be named by an environment variable.")
        require(type(spec["seconds"]) is int and 0 <= spec["seconds"] <= MAX_WINDOW_SECONDS,
                "Restore windows must be given in seconds, up to ten years.")
    return scanners, windows


def check_branches(*, store, erased_at, inventory, journal, output, expect_journal=None):
    """Inspect declared branch boundaries and issue a scoped v3 receipt."""
    root = identifier(store, "original store")
    erased = stamp(erased_at).astimezone(UTC)
    require(erased <= datetime.now(UTC), "Erasure time cannot be in the future.")
    scanners, windows = _inventory(inventory)
    with new_bundle(output) as bundle:
        rows, _ = read_branch_snapshot(journal)
        known = {row["child"] for row in rows}
        scans = [observe(spec, root, known, erased) for spec in scanners]
        restore_settings = []
        for window in windows:
            name = window.pop("postgres_dsn_env", None)
            restore_settings.append({"store": root, **window,
                                     **({"postgres_archiving": postgres_archiving(name)} if name else {})})
        # A copy created while the scan ran must be surfaced as unknown unless
        # a declared scanner has decisively observed it.
        latest, checkpoint = read_branch_snapshot(journal)
        require(latest[:len(rows)] == rows, "Branch ancestry changed during the scan.")
        require(expect_journal in (None, checkpoint["head"]), "Branch journal differs from the independently saved head.")
        evidence = {"format": FORMAT, "store": root, "erased_at": erased.isoformat(),
                    "observed_at": datetime.now(UTC).isoformat(), "journal": latest,
                    "journal_head": checkpoint["head"], "scanners": scans,
                    "windows": restore_settings}
        return issue(PROFILE, evidence, bundle)


def command(argv):
    from setrya.receipts import report

    parser = argparse.ArgumentParser(prog="setrya branches", description=__doc__)
    commands = parser.add_subparsers(required=True)
    check = commands.add_parser("check", help="inspect branch descendants of one erased source")
    check.add_argument("--inventory", required=True, type=Path)
    check.add_argument("--journal", required=True, type=Path)
    check.add_argument("--store", required=True)
    check.add_argument("--erased-at", required=True, help="original erasure time with a timezone")
    check.add_argument("--expect-journal", help="independently saved branch journal head")
    check.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    receipt = check_branches(store=args.store, erased_at=args.erased_at, inventory=args.inventory,
                             journal=args.journal, output=args.output, expect_journal=args.expect_journal)
    print(f"Saved branch evidence to {args.output}")
    return report(receipt)
