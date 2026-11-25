"""Sign exact receipt bytes and check the signer against a caller-supplied policy."""

from base64 import b64decode
from contextlib import contextmanager
from hashlib import sha256
import os
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from .inputs import MAX_JSON_BYTES, InvalidReport, read_regular_bytes, require
from .receipt_format import MAX_BUNDLE_FILE_BYTES

MAX_SIGSTORE_BYTES = 32 * 1024 * 1024


@contextmanager
def trusted_public_key(path):
    """Snapshot a trusted Cosign key and identify it by the SHA-256 of its DER bytes."""
    pem = read_regular_bytes(path, "trusted verification key")
    match = re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\r\n\t ]+)-----END PUBLIC KEY-----", pem.strip())
    require(match is not None, "Use a trusted public key in Cosign's PUBLIC KEY PEM format.")
    try:
        der = b64decode(b"".join(match[1].split()), validate=True)
    except ValueError:
        raise InvalidReport("Invalid Cosign public key encoding.") from None
    with TemporaryDirectory() as folder:
        snapshot = Path(folder, "trusted.pub")
        snapshot.write_bytes(pem)
        yield snapshot, sha256(der).hexdigest()


def add_commands(commands, *, local_keys=False, aliases=False, scope=True):
    for name, help_text in (
        ("sign-receipt", "create a keyless Sigstore bundle for a deletion receipt"),
        ("verify-signature", "verify the exact receipt bytes and signer offline"),
    ):
        command = commands.add_parser(name, help=help_text, aliases=[name.split("-")[0]] if aliases else [])
        if aliases and scope:
            command.add_argument("--scope", choices=("person", "tenant"), help="require the selected receipt scope")
        command.add_argument("--receipt", required=True, type=Path)
        command.add_argument("--bundle", required=True, type=Path)
        if local_keys:
            command.add_argument("--key", type=Path, help="local signing or trusted verification key for detached signatures")
        if name == "verify-signature":
            command.add_argument("--identity", required=not local_keys, help="exact authorized certificate identity")
            command.add_argument("--issuer", required=not local_keys, help="exact trusted OIDC issuer")
            command.add_argument("--trusted-root", required=not local_keys, type=Path, help="independently provisioned Sigstore root JSON")


def _cosign(command):
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        raise InvalidReport("Install Cosign 3 to sign or verify receipt signatures.") from None
    except subprocess.CalledProcessError:
        raise InvalidReport("Check the receipt, bundle, trust root and Cosign result.") from None


def sign_bytes(raw, output, *, key=None):
    """Publish a signature for a caller-owned snapshot of the exact signed bytes."""
    require(not os.path.lexists(output), "Choose a new output path for the signature bundle.")
    if key is not None:
        require(key.is_file(), "Expected a local Cosign key file.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output.parent) as folder:
        snapshot = Path(folder, "receipt.json").resolve()
        snapshot.write_bytes(raw)
        bundle = snapshot.with_name("sigstore.json")
        if key is not None:
            # Cosign 3 uses a detached signature for the existing --key contract.
            _cosign(["cosign", "sign-blob", "--yes", "--key", str(key.resolve()), "--tlog-upload=false",
                     "--use-signing-config=false", "--new-bundle-format=false",
                     "--output-signature", str(bundle), str(snapshot)])
        else:
            _cosign(["cosign", "sign-blob", "--yes", "--bundle", str(bundle), str(snapshot)])
        os.link(bundle, output)


def verify_bytes(raw, signature, *, key=None, identity=None, issuer=None, trusted_root=None):
    """Verify exact snapshots with independently supplied signer trust."""
    require(not key or not any((identity, issuer, trusted_root)), "Choose one signer policy.")
    require(key or (identity and issuer and trusted_root), "Both an exact signer identity and issuer are required.")
    with TemporaryDirectory() as folder:
        snapshot = Path(folder, "receipt.json")
        snapshot.write_bytes(raw)
        bundle = snapshot.with_name("sigstore.json")
        bundle.write_bytes(signature)
        if key:
            public_key = snapshot.with_name("public.key")
            public_key.write_bytes(read_regular_bytes(key, "trusted verification key"))
            command = ["cosign", "verify-blob", "--key", str(public_key), "--insecure-ignore-tlog",
                       "--signature", str(bundle), str(snapshot)]
        else:
            root = snapshot.with_name("trusted-root.json")
            root.write_bytes(trusted_root)
            command = ["cosign", "verify-blob", "--bundle", str(bundle), "--trusted-root", str(root),
                       "--certificate-identity", identity, "--certificate-oidc-issuer", issuer, str(snapshot)]
        _cosign(command)


def run(args, *, validate, receipt_limit=MAX_BUNDLE_FILE_BYTES, signature_limit=MAX_SIGSTORE_BYTES):
    signing = args.offboarding_action == "sign-receipt"
    try:
        raw = read_regular_bytes(args.receipt, "receipt", receipt_limit)
        validate(raw)
        key = getattr(args, "key", None)
        if signing:
            sign_bytes(raw, args.bundle, key=key)
        else:
            require(not key or not any((args.identity, args.issuer, args.trusted_root)), "Choose one signer policy.")
            require(key or (args.identity and args.issuer and args.trusted_root),
                    "Both an exact signer identity and issuer are required.")
            signature = read_regular_bytes(args.bundle, "signature bundle", signature_limit if not key else MAX_JSON_BYTES)
            root = read_regular_bytes(args.trusted_root, "trusted root", signature_limit) if args.trusted_root else None
            verify_bytes(raw, signature, key=key, identity=args.identity, issuer=args.issuer, trusted_root=root)
        print("Receipt signature bundle saved." if signing else "Receipt signature and signer verified.")
        return 0
    except (ValueError, OSError, RecursionError) as error:
        message = str(error) if isinstance(error, InvalidReport) else "Check the receipt, bundle, trust root and Cosign result."
        print(f"Signature operation failed. {message}", file=sys.stderr)
        return 2
