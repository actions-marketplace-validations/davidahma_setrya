"""Capture the local runtime and trusted CLI inputs for a receipt."""

import json
import os
from hashlib import new as git_hash
from hashlib import sha256
from pathlib import Path

from . import __version__
from .core.inputs import read_regular_bytes, require, unique_fields
from .core.provenance import _COMMIT, _MAX_TEST_FILES, _ci_is_valid, _matches, validate
from .drill import InputError
from .git_refs import git_bytes, resolve_commit

RUN_PROVENANCE = "SETRYA_LIVE_RUN_PROVENANCE"
_MAX_TEST_BYTES = 16 * 1024 * 1024


def producer_only():
    """Record runtime and CI context when no application checkout was observed."""
    ci = None
    if os.environ.get("GITHUB_ACTIONS") == "true":
        candidate = {field: os.environ.get(f"GITHUB_{field.upper()}", "")
                     for field in ("workflow_ref", "workflow_sha", "run_id", "run_attempt")}
        if _ci_is_valid(candidate):
            ci = candidate
    return {"setrya_version": __version__,
            "application": {"checkout_commit": None, "checkout_state": "unavailable",
                            "asserted_deploy_commit": None, "execution": "unavailable"},
            "test_files": [], "ci": ci}


def _checkout(directory):
    try:
        root = Path(os.fsdecode(git_bytes(directory, "rev-parse", "--show-toplevel").rstrip(b"\r\n")))
        commit = resolve_commit(root, "HEAD")
        dirty = git_bytes(root, "-c", "core.fsmonitor=false", "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=none")
    except InputError:
        return directory, None, "unavailable"
    return root.resolve(), commit, "dirty" if dirty else "clean"


def _matches_commit(root, commit, path, raw):
    try:
        blob = git_bytes(root, "rev-parse", "--verify", "--end-of-options", f"{commit}:{path}").strip()
    except InputError:
        return False
    # Compare exact bytes to the Git blob name. The portable checksum below remains SHA-256.
    algo = "sha1" if len(commit) == 40 else "sha256"
    recorded = git_hash(algo, usedforsecurity=False)
    recorded.update(f"blob {len(raw)}\0".encode("ascii"))
    recorded.update(raw)
    return blob == recorded.hexdigest().encode("ascii")


def capture(starter, test_files=(), *, deployed_commit=None, executed_copy=None, expected_hashes=None,
            expected_entrypoint_sha256=None):
    """Fingerprint the executing entrypoint and explicitly declared local test code."""
    files = [starter, *test_files]
    require(len(files) <= _MAX_TEST_FILES, "Declare at most 32 test files including the entrypoint.")
    require(deployed_commit is None or _matches(_COMMIT, deployed_commit), "Invalid issuer-declared deployment commit.")
    root, commit, state = _checkout(Path.cwd())
    result = producer_only()
    execution = "http-case" if Path(starter).suffix.lower() in (".yaml", ".yml") else "local-starter"
    result["application"].update(checkout_commit=commit, checkout_state=state, asserted_deploy_commit=deployed_commit,
                                 execution=execution)
    parsed_sources = set(expected_hashes or ())
    for index, file in enumerate(files):
        source = Path(file).resolve()
        inside = commit is not None and source.is_relative_to(root)
        label = source.relative_to(root).as_posix() if inside else source.name
        raw = read_regular_bytes(source, "test provenance file", _MAX_TEST_BYTES)
        digest = sha256(raw).hexdigest()
        if index == 0 and expected_entrypoint_sha256 is not None:
            require(digest == expected_entrypoint_sha256, "The parsed HTTP entrypoint changed before this run.")
        if expected_hashes is not None and source in expected_hashes:
            require(digest == expected_hashes[source], "The parsed HTTP test inputs changed before this run.")
            parsed_sources.discard(source)
        result["test_files"].append({
            "path": label, "location": "checkout" if inside else "external",
            "role": "test" if index else "entrypoint", "sha256": digest,
            "commit_bound": inside and _matches_commit(root, commit, label, raw),
        })
    require(not parsed_sources, "The parsed HTTP test inputs changed before this run.")
    if executed_copy is not None:
        original, copy = Path(starter).resolve(), Path(executed_copy).resolve()
        require(original.parent == copy.parent and original.suffix == copy.suffix,
                "An approved fixture snapshot must use the original directory and file type.")
        entrypoint = result["test_files"][0]
        require(entrypoint["sha256"] == sha256(read_regular_bytes(copy, "fixture snapshot", _MAX_TEST_BYTES)).hexdigest(),
                "Fixture snapshot differs from the approved entrypoint.")
    result["test_files"].sort(key=lambda row: (row["location"], row["path"]))
    return validate(result)


def live_provenance(value=None):
    """Validate the exact provenance the current runner will put into evidence."""
    observed = producer_only()
    result = validate(observed if value is None else value)
    require(result["setrya_version"] == observed["setrya_version"] and result["ci"] == observed["ci"],
            "Producer provenance differs from this Setrya runtime or CI context.")
    return result


def from_environment():
    encoded = os.environ.get(RUN_PROVENANCE)
    return None if encoded is None else json.loads(encoded, object_pairs_hook=unique_fields)
