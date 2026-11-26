"""Authenticate vendor evidence and check separately issued fixture reruns."""

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from setrya import __version__
from setrya.casework import profiles
from setrya.core import signing
from setrya.core.inputs import InvalidReport, MAX_JSON_BYTES, read_regular_bytes, require
from setrya.receipt_format import RECEIPT

from .report import SETUP, execution_lines, operator_label

DETACHED_SIGNATURE = "conformance.sig"
KEYLESS_SIGNATURE = "sigstore.json"


def _read_bundle(folder):
    require(folder.is_dir() and not folder.is_symlink(), "Supply a vendor conformance bundle directory.")
    raw = profiles.snapshot(folder / RECEIPT)
    try:
        document = profiles.decode(raw)
    except (ValueError, RecursionError):
        raise InvalidReport("Invalid conformance receipt JSON.") from None
    require(isinstance(document, dict) and document.get("profile") == profiles.VENDOR,
            "Expected a vendor conformance receipt.")
    return raw, profiles.replay_bytes(folder, raw)


def _original_execution(receipt):
    execution = receipt.get("execution")
    require(execution and execution["operator"] and "rerun_of" not in execution,
            "An original self-check needs a recorded operator and its own execution ID.")
    return execution


def rerun_digest(original, target, operator, *, setrya_version=__version__):
    """Link a new live fixture run to the bytes of an existing self-check."""
    operator_label(operator)
    folder = Path(original)
    raw, receipt = _read_bundle(folder)
    execution = _original_execution(receipt)
    require(receipt["target"] == target, "Run the same target as the original self-check.")
    require(operator != execution["operator"], "Use a different operator for the rerun.")
    require(execution["setrya_version"] == setrya_version,
            f"Use the same Setrya fixture version as the original ({execution['setrya_version']}).")
    signature = folder / DETACHED_SIGNATURE
    require(signature.is_file(), "A linked rerun needs an original with a detached Cosign signature.")
    profiles.snapshot(signature, MAX_JSON_BYTES)
    return sha256(raw).hexdigest()


@dataclass(frozen=True)
class _Verified:
    receipt: dict
    digest: str
    signer: str


def _verify(folder, *, key=None, identity=None, issuer=None, trusted_root=None):
    require((key and not any((identity, issuer, trusted_root))) or (not key and identity and issuer and trusted_root),
            "Supply an independently trusted key or exact Sigstore identity, issuer and root.")
    folder = Path(folder)
    raw, receipt = _read_bundle(folder)
    if key:
        signature = profiles.snapshot(folder / DETACHED_SIGNATURE, MAX_JSON_BYTES)
        with signing.trusted_public_key(key) as (pinned_key, fingerprint):
            signing.verify_bytes(raw, signature, key=pinned_key)
        signer = "Cosign public key SHA-256 " + fingerprint
    else:
        signature = profiles.snapshot(folder / KEYLESS_SIGNATURE, signing.MAX_SIGSTORE_BYTES)
        root = read_regular_bytes(trusted_root, "trusted root", signing.MAX_SIGSTORE_BYTES)
        signing.verify_bytes(raw, signature, identity=identity, issuer=issuer, trusted_root=root)
        signer = f"Sigstore identity {json.dumps(identity)} · issuer {json.dumps(issuer)}"
    return _Verified(receipt, sha256(raw).hexdigest(), signer)


@dataclass(frozen=True)
class ReviewResult:
    receipt: dict
    details: tuple[str, ...]
    agrees: bool | None = None

    @property
    def headline(self):
        if self.agrees is None:
            return None
        return "Rerun matches original" if self.agrees else "Rerun differs from original"


def _changed_checks(original, current):
    before = {row["surface"]: row for row in original["checks"]}
    after = {row["surface"]: row for row in current["checks"]}
    changes = []
    for surface in sorted(before.keys() | after.keys()):
        prior, rerun = before.get(surface, {}), after.get(surface, {})
        old_status, new_status = prior.get("status", "not recorded"), rerun.get("status", "not recorded")
        if old_status != new_status:
            changes.append(f"Surface {surface}: {old_status} → {new_status}")
        elif prior != rerun:
            changes.append(f"Surface {surface}: {old_status} in both runs, finding changed")
            changes.append(f"  Original: {prior['reason']}")
            changes.append(f"  Rerun: {rerun['reason']}")
    return changes


def assess_review(directory, *, key=None, identity=None, issuer=None, trusted_root=None, expect_operator=None,
                  against=None, against_key=None):
    """Authenticate the result and compare the findings in a linked pair."""
    require((against is None and against_key is None) or (against and key and against_key and expect_operator),
            "A paired review needs both detached public keys and the expected rerun operator.")
    if expect_operator is not None:
        operator_label(expect_operator)
    current = _verify(directory, key=key, identity=identity, issuer=issuer, trusted_root=trusted_root)
    execution = current.receipt.get("execution") or {}
    require(expect_operator is None or execution.get("operator") == expect_operator,
            "The result differs from the expected test operator.")
    current_digest = f"Signed receipt SHA-256 {current.digest}"
    if against is None:
        lines = execution_lines(current.receipt, signer=current.signer, review_scope="authenticated signer and evidence replay")
        return ReviewResult(current.receipt, (*lines, current_digest))

    original = _verify(against, key=against_key)
    prior_execution = _original_execution(original.receipt)
    require(execution.get("rerun_of") == original.digest, "The rerun does not link to this original signed receipt.")
    require(current.signer != original.signer, "The rerun and original need distinct trusted signing keys.")
    require(execution["operator"] != prior_execution["operator"] and execution["run_id"] != prior_execution["run_id"],
            "The rerun and original need distinct recorded operators and executions.")
    require(current.receipt["evidence"]["sha256"] != original.receipt["evidence"]["sha256"],
            "The rerun needs its own recorded evidence.")
    require(execution["setrya_version"] == prior_execution["setrya_version"],
            "The rerun and original need the same Setrya fixture version.")
    target = original.receipt["target"]
    versions = original.receipt["versions"]
    require(target == current.receipt["target"] and versions == current.receipt["versions"]
            and set(versions) == set(SETUP[target]), "The rerun and original need the same target and recorded backend versions.")
    lines = execution_lines(current.receipt, signer=current.signer,
                            review_scope="authenticated signatures and evidence replay for two linked executions")
    changes = _changed_checks(original.receipt, current.receipt)
    agrees = not changes and all(original.receipt[field] == current.receipt[field]
                                 for field in ("technical_verdict", "review_status"))
    details = (
        *lines, current_digest, f"Original recorded operator {prior_execution['operator']}",
        f"Original execution ID {prior_execution['run_id']}", f"Original signer verified {original.signer}",
        f"Original technical verdict {original.receipt['technical_verdict']} · Review status {original.receipt['review_status']}",
        f"Rerun technical verdict {current.receipt['technical_verdict']} · Review status {current.receipt['review_status']}",
        *changes,
    )
    return ReviewResult(current.receipt, details, agrees)


def review(directory, *, key=None, identity=None, issuer=None, trusted_root=None, expect_operator=None,
           against=None, against_key=None):
    """Return the replayed receipt and reviewer-authenticated execution details."""
    result = assess_review(directory, key=key, identity=identity, issuer=issuer, trusted_root=trusted_root,
                           expect_operator=expect_operator, against=against, against_key=against_key)
    details = [result.headline] if result.headline is not None else []
    return result.receipt, [*details, *result.details]
