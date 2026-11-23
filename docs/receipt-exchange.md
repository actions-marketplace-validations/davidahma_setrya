# Deletion Receipt v1 exchange draft

Use this exchange to send one deletion result to a reviewer who has no access to the application, database or journal. The format binds a small signed manifest to the original v3 receipt and evidence. Setrya replays the original evidence using the existing verdict rules. [JSON Schema](../setrya/casework/receipt-exchange-v1.schema.json) · [Try a completed PostgreSQL ticket](receipt-handoff.md)

The exchange format, `setrya.deletion-receipt-exchange.v1`, is a draft. Preserve the Setrya version used to issue it. Historical tenant v1 receipts and the underlying v3 receipt format retain their existing identifiers and verification rules. The draft will be frozen after an outside issuer and a separate reviewer complete the handoff independently. [Supported receipt formats](receipt-format.md)

## What the issuer sends

The exchange directory contains four regular files.

| File | Purpose |
| --- | --- |
| `exchange.json` | Versioned manifest. It records the system and version supplied by the issuer, the declared stores and route, the observation timing, the replayed verdict and open items, and SHA-256 digests of the two v3 files. |
| `exchange.sig` | Cosign detached signature or Sigstore bundle for the exact manifest bytes. The `signature_type` selects the representation. |
| `erasure-receipt.json` | The exact original v3 receipt. |
| `observation-evidence.json` or `erasure-evidence.json` | The exact original companion, chosen by the evidence kind. |

A **read-only observation** binds an opaque completed ticket ID and the SHA-256 of the exact completed-request export. Its two timestamps are the completion times of the recorded reads. The second journal snapshot must follow the first completed observation when that snapshot is available. It checks known, journalled keys with a retained visibility control. A **synthetic drill** uses an isolated fixture, carries no completed-ticket binding, and records the drill's end time and duration. A **vendor attestation** can appear as an external open item, with its owner and follow-up date when recorded. Its status remains an attestation in the original evidence.

The system label, version and declared surfaces describe the issuer's scope. The original evidence shows which reads occurred. The signature authenticates the receipt issuer against the verifier's own trust policy. The observer still determines what could be seen. Use the original bundle only with reviewers authorized to see potentially linkable subject, ticket and store identifiers. Synthetic evidence can also contain configured answer excerpts. Public examples use fictional data.

## How an independent reviewer verifies it

Provision the expected issuer's public key separately. For keyless signing, use the exact issuer and certificate identity from your trust policy and a locally provisioned Sigstore root. The certificate identifies the keyless signer. For a detached signature, your trust record identifies the owner of the pinned public key. Trust learned from files inside the exchange cannot authenticate the issuer.

```sh
setrya receipt verify-exchange received/ --key independently-trusted.pub \
  --expect-ticket "$TICKET_ID" --expect-frame "$COMPLETED_FRAME_SHA256"
```

Get the expected ticket ID and frame digest from the originating ticket system. These checks bind the exchange to the case under review. No database, app fixture or network is needed after trust and tools have been provisioned. For keyless verification, substitute `--identity`, `--issuer` and `--trusted-root` for `--key`. For the GitHub release examples, the trusted identity is `https://github.com/davidahma/setrya/.github/workflows/erasure.yml@refs/heads/main` and the issuer is `https://token.actions.githubusercontent.com`. Provision the Sigstore root as described in the [receipt verification guide](northline.md).

An independent implementation verifies the signature over the exact bytes of `exchange.json`, validates the schema, and checks the SHA-256 of the exact companion bytes. Replay the original v3 files and compare the resulting state, surfaces, timing, ticket binding, and open items to the manifest. Schema validation or signature verification alone covers only one part of the check. JSON Pointer fragments in open items address fields in the original receipt.

| Example directory | Replayed result | Exit |
| --- | --- | --- |
| `passed` | `PASS · READY_FOR_REVIEW` | 0 |
| `residual` | `FAIL · RESIDUAL_FOUND` | 1 |
| `unavailable` | `NOT TESTED · OPEN_ITEMS` | 3 |
| `open-items` | `PASS · OPEN_ITEMS` | 0, or 3 with `--case-review` |

[Download the four signed examples](https://github.com/davidahma/setrya/releases/download/v1.8.0/deletion-receipt-exchange.zip). The first three capture native PostgreSQL observations of synthetic completed tickets. The fourth opens the synthetic workspace issue with its provider follow-up unchanged. A malformed bundle, unverifiable signature or case pin mismatch exits 2. A valid signature can accompany any engineering verdict.
