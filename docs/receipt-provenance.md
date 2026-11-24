# Identify the code behind a deletion receipt

A person drill run by the CLI records the Setrya version that executed it, the Git checkout visible to the runner, the exact bytes of its fixture entrypoint, and any additional test files you declare. The fixture's observations still decide the verdict. An independent reviewer can compare the recorded producer data to a checkout and workflow they trust.

```sh
setrya run --starter setrya-case/test_erasure.py \
  --test-file tests/helpdesk_fixture.py --output receipt/
```

Pass each supporting test file with its own `--test-file`. The run checks the fixture and declared file fingerprints before execution and before publishing the receipt. A tracked checkout state or commit change during the run also prevents publication. The tool reads ordinary files up to 16 MiB per file and records no contents or absolute paths. A Python fixture receives a private staging path with the requested output basename. The CLI publishes that directory at the requested destination after checking the inputs and replaying the evidence.

## Read the producer metadata

Person drills use the v3 receipt family with `evidence_format: "setrya.erasure.evidence.v3.2"`. The receipt's `provenance` object mirrors the evidence protected by its SHA-256 digest.

| Field | Meaning |
| --- | --- |
| `setrya_version` | Version loaded by the Setrya runtime that recorded the evidence. |
| `application.checkout_commit` and `checkout_state` | Git HEAD as seen from the runner's working directory and the state of tracked files. The checkout can be `clean`, `dirty`, or `unavailable`. A clean result excludes untracked files. |
| `application.execution` | A CLI-driven Python fixture is a `local-starter`. A declarative HTTP case is an `http-case`. A run without recorded application inputs uses `unavailable`. |
| `application.asserted_deploy_commit` | An optional issuer declaration recorded with `--deployed-commit`. A checkout is separate from the code serving a remote endpoint. |
| `test_files` | The declared entrypoint and supporting files with exact SHA-256 digests. Labels are checkout-relative or external basenames. `commit_bound` confirms the file's exact bytes match its Git blob at the recorded commit. |
| `ci` | GitHub Actions workflow path and ref, workflow commit, run ID and attempt when the runner supplies all four values. |

The direct read-only observer records the Setrya and CI producer in new observed-deletion evidence v1.1. Its checkout and test files are unavailable. SDK drills without CLI provenance also record the producer without inferring an application revision. Supported older receipts replay under their original formats.

## Verify against independent inputs

For a CLI person drill using a local fixture, obtain the expected application Git commit from the change or release under review. Pin it when replaying the receipt.

```sh
setrya replay receipt/ --expect-app-commit "$EXPECTED_APPLICATION_COMMIT"
```

The pin requires a matching clean local checkout and committed bytes for all recorded test files. A dirty checkout, an uncommitted fixture, an HTTP case, or a receipt without producer data fails the pin. Use `--expect-provenance trusted-producer.json` to compare the whole object against an independently prepared record, including expected test-file hashes and GitHub Actions run identity. The same pins can be used with `setrya verify` for signed original receipts or `setrya receipt verify-exchange` for the signed exchange.

Replaying recomputes the verdict and producer projection from evidence. Signatures authenticate those bytes under the reviewer's separately provisioned key or identity policy. Review the assertions in the pinned fixture, establish that the workflow is trusted, and confirm the deployment revision independently when a check uses an external endpoint. [Receipt verification](receipt-format.md) · [Signed exchange](receipt-exchange.md)

In GitHub Actions, the erasure Action accepts `test-files` as one trusted file path per line. The approved MCP run records the canonical fixture path only after its bytes match the executed snapshot.
