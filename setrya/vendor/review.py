"""Authenticate vendor evidence and check separately issued fixture reruns."""

from base64 import b64decode
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory

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


def rerun_digest(original, target, operator):
    """Link a new live fixture run to the bytes of an existing self-check."""
    operator_label(operator)
    raw, receipt = _read_bundle(Path(original))
    execution = _original_execution(receipt)
    require(receipt["target"] == target, "Run the same target as the original self-check.")
    require(operator != execution["operator"], "Use a different operator for the rerun.")
    return sha256(raw).hexdigest()


def _key_fingerprint(pem):
    match = re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\r\n\t ]+)-----END PUBLIC KEY-----", pem.strip())
    require(match is not None, "Use a trusted public key in Cosign's PUBLIC KEY PEM format.")
    try:
        der = b64decode(b"".join(match[1].split()), validate=True)
    except ValueError:
        raise InvalidReport("Invalid Cosign public key encoding.") from None
    return sha256(der).hexdigest()


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
        public_key = read_regular_bytes(key, "trusted conformance public key")
        fingerprint = _key_fingerprint(public_key)
        with TemporaryDirectory() as directory:
            pinned_key = Path(directory) / "signer.pub"
            pinned_key.write_bytes(public_key)
            signing.verify_bytes(raw, signature, key=pinned_key)
        signer = "Cosign public key SHA-256 " + fingerprint
    else:
        signature = profiles.snapshot(folder / KEYLESS_SIGNATURE, signing.MAX_SIGSTORE_BYTES)
        root = read_regular_bytes(trusted_root, "trusted root", signing.MAX_SIGSTORE_BYTES)
        signing.verify_bytes(raw, signature, identity=identity, issuer=issuer, trusted_root=root)
        signer = f"Sigstore identity {json.dumps(identity)} · issuer {json.dumps(issuer)}"
    return _Verified(receipt, sha256(raw).hexdigest(), signer)


def review(directory, *, key=None, identity=None, issuer=None, trusted_root=None, expect_operator=None,
           against=None, against_key=None):
    """Return the replayed verdict and reviewer-authenticated execution details."""
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
        return current.receipt, [*lines, current_digest]

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
    lines[0] = "Execution Independent rerun verified"
    return current.receipt, [*lines, current_digest, f"Original recorded operator {prior_execution['operator']}",
                             f"Original execution ID {prior_execution['run_id']}", f"Original signer verified {original.signer}",
                             f"Original technical verdict {original.receipt['technical_verdict']} · Review status {original.receipt['review_status']}",
                             f"Rerun technical verdict {current.receipt['technical_verdict']} · Review status {current.receipt['review_status']}"]
