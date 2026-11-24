"""Validate the offboarding bundle before signing through the shared core."""
import json

from setrya.core.signing import MAX_SIGSTORE_BYTES, add_commands, run as _run, subprocess
from setrya.receipt_format import MAX_BUNDLE_FILE_BYTES
from .receipt_schema import validate_receipt
from .inputs import MAX_JSON_BYTES, InvalidReport, unique_fields


def run(args, *, validate=None, receipt_limit=MAX_BUNDLE_FILE_BYTES):
    def validate_tenant(raw):
        header = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
        if isinstance(header, dict) and header.get("scope") == "tenant" and header.get("version") == 3:
            from . import tenant_v3
            from setrya.evidence import bundle_manifest
            if args.receipt.name != tenant_v3.RECEIPT or bundle_manifest(args.receipt.parent) != tenant_v3.RECEIPT:
                raise InvalidReport("Choose the manifest from the original tenant evidence bundle.")
            tenant_v3.replay_bytes(args.receipt.parent, raw)
        else:
            if len(raw) > MAX_JSON_BYTES:
                raise InvalidReport("The v1 receipt exceeds the 1 MiB limit.")
            validate_receipt(header)

    return _run(args, validate=validate if validate is not None else validate_tenant,
                receipt_limit=receipt_limit, signature_limit=MAX_SIGSTORE_BYTES)
