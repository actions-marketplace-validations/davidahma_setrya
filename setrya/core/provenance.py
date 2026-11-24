"""Validate and review portable producer provenance without running the application."""

import re

from .inputs import keys_match, read_json, require

_MAX_TEST_FILES = 32
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[0-9][A-Za-z0-9_.+-]{0,63}")
_NUMBER = re.compile(r"[1-9][0-9]{0,23}")
_WORKFLOW_REF = re.compile(
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@"
    r"(?:refs/[^\s]+|[0-9a-f]{40}|[0-9a-f]{64})"
)


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _relative_label(value):
    return (isinstance(value, str) and 0 < len(value) <= 512 and value.isprintable()
            and "\\" not in value and all(part not in ("", ".", "..") for part in value.split("/")))


def _ci_is_valid(ci):
    return (keys_match(ci, ("workflow_ref", "workflow_sha", "run_id", "run_attempt"))
            and _matches(_WORKFLOW_REF, ci["workflow_ref"]) and len(ci["workflow_ref"]) <= 512
            and ci["workflow_ref"].isprintable() and _matches(_COMMIT, ci["workflow_sha"])
            and _matches(_NUMBER, ci["run_id"]) and _matches(_NUMBER, ci["run_attempt"]))


def validate(value):
    """Reject invalid or ambiguous provenance without consulting live Git or CI."""
    require(keys_match(value, ("setrya_version", "application", "test_files", "ci"))
            and _matches(_VERSION, value["setrya_version"]), "Invalid Setrya producer version.")
    app = value["application"]
    require(keys_match(app, ("checkout_commit", "checkout_state", "asserted_deploy_commit", "execution")),
            "Invalid application provenance fields.")
    checkout = app["checkout_commit"]
    state = app["checkout_state"]
    deployment = app["asserted_deploy_commit"]
    execution = app["execution"]
    require(execution in ("local-starter", "http-case", "unavailable"), "Invalid application execution context.")
    require((state == "unavailable" and checkout is None)
            or (state in ("clean", "dirty") and _matches(_COMMIT, checkout)),
            "Invalid application checkout provenance.")
    require(deployment is None or _matches(_COMMIT, deployment), "Invalid issuer-declared deployment commit.")
    require(execution != "unavailable" or checkout is None and deployment is None,
            "An unobserved application cannot claim a checkout or deployment.")
    tests = value["test_files"]
    require(isinstance(tests, list) and len(tests) <= _MAX_TEST_FILES
            and bool(tests) == (execution != "unavailable"), "Invalid test provenance file count.")
    slots = []
    for row in tests:
        require(keys_match(row, ("location", "path", "role", "sha256", "commit_bound"))
                and row["location"] in ("checkout", "external") and _relative_label(row["path"])
                and (row["location"] == "checkout" or "/" not in row["path"])
                and row["role"] in ("entrypoint", "test") and _matches(_DIGEST, row["sha256"])
                and type(row["commit_bound"]) is bool
                and (not row["commit_bound"] or (checkout is not None and row["location"] == "checkout")),
                "Invalid test-file provenance.")
        slots.append((row["location"], row["path"]))
    require(slots == sorted(set(slots)) and sum(row["role"] == "entrypoint" for row in tests) == int(bool(tests)),
            "Expected one entrypoint and sorted unique test files.")
    require(value["ci"] is None or _ci_is_valid(value["ci"]), "Invalid GitHub Actions producer metadata.")
    return value


def verify_pins(receipt, *, expected_provenance=None, expected_app_commit=None):
    """Compare replayed metadata with custody information supplied by the reviewer."""
    if expected_provenance is not None:
        validate(expected_provenance)
        require(receipt.get("provenance") == expected_provenance,
                "Receipt provenance differs from the independently supplied record.")
    if expected_app_commit is not None:
        require(_matches(_COMMIT, expected_app_commit), "Expected a full Git application commit ID.")
        provenance = receipt.get("provenance", {})
        app = provenance.get("application", {})
        tests = provenance.get("test_files", ())
        require(app.get("checkout_commit") == expected_app_commit and app.get("checkout_state") == "clean"
                and app.get("execution") == "local-starter" and app.get("asserted_deploy_commit") is None
                and tests and all(row["commit_bound"] for row in tests),
                "Receipt does not bind the expected clean application checkout and committed test files.")
    return receipt


def read_pin(path):
    if path is None:
        return None
    value, _ = read_json(path, "expected provenance")
    return validate(value)


def describe(producer):
    app = producer["application"]
    lines = [f"Producer Setrya {producer['setrya_version']}"]
    if app["checkout_commit"]:
        lines.append(f"Recorded checkout {app['checkout_commit']} · {app['checkout_state']} tracked state")
    if app["asserted_deploy_commit"]:
        lines.append(f"Issuer-declared deployed commit {app['asserted_deploy_commit']}")
    if tests := producer["test_files"]:
        bound = sum(row["commit_bound"] for row in tests)
        lines.append(f"Test files fingerprinted {len(tests)} · matching checkout commit {bound}")
    if ci := producer["ci"]:
        lines.append(f"CI {ci['workflow_ref']} · run {ci['run_id']} · attempt {ci['run_attempt']}")
    return lines
