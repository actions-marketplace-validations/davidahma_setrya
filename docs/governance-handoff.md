# Attach deletion evidence to a governance ticket

A support team uses `ERASURE-07` to track its deletion check and `GOV-204` to track review of one release. The fictional workspace drill checks whether a background writer can restore a deleted note and whether both teammates can still read their launch date. The guarded run produces `PASS · OPEN_ITEMS`. The application checks passed and the platform team still owns a provider follow-up.

## Issue the evidence

Run these commands from the Setrya repository root with Bash, Python 3.11 or later and Cosign 3. The example uses the installed Setrya package, a disposable local application fixture and a temporary signing key.

```sh
example="$PWD/docs/examples/governance-handoff/handoff.py"
scratch=$(mktemp -d)
python3 -m venv "$scratch/env"
python="$scratch/env/bin/python"
setrya="$scratch/env/bin/setrya"
"$python" -m pip install setrya
mkdir "$scratch/issuer" "$scratch/reviewer"

(
  cd "$scratch/issuer" || exit 1
  COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix issuer
  COSIGN_PASSWORD="" "$python" -I "$example" issue exchange --key issuer.key
)
```

The [example](examples/governance-handoff/handoff.py) supplies the existing `controls` field with `Support governance / ERASURE-07`. Replay checks the reference against the original evidence. The signature binds the exact receipt and evidence digests. Use a trusted signing key and share the exchange through your approved channel for a real review. [Control references](customer-casework.md#attach-a-contract-or-control-reference)

## Verify and attach to the ticket

Give the reviewer the four-file exchange and provision the trusted issuer public key separately. The copy commands simulate both deliveries for this local exercise. A reviewer can verify the saved exchange with the public key after the application stops.

```sh
cp -R "$scratch/issuer/exchange" "$scratch/reviewer/exchange"
cp "$scratch/issuer/issuer.pub" "$scratch/reviewer/trusted-issuer.pub"

(
  cd "$scratch/reviewer" || exit 1
  "$python" -I "$example" review exchange --key trusted-issuer.pub > ticket.json || exit 1
  "$setrya" receipt summary exchange --audience reviewer --format md > approval.md || exit 1
  cat ticket.json
)
```

Attach `exchange/`, `ticket.json`, and `approval.md` to the governance ticket. `ticket.json` names `GOV-204`, the control reference, the exchange attachment, and the SHA-256 of the exact `erasure-receipt.json` bytes. It records the technical and review states and keeps the provider item with its owner, follow-up date, and JSON Pointer into the signed receipt. The index is for the ticket system. Use the signed exchange to recreate it when reviewing a case.

The reviewer authenticates the signer against the supplied key and replays the recorded evidence. The run remains the issuer's execution. `GOV-204` is the governance review location. For a completed deletion request, an originating ticket and request-export digest can also be checked using independent `--expect-ticket` and `--expect-frame` pins. [Completed-ticket handoff](receipt-handoff.md)

Treat a successfully generated attachment as evidence ready to review. Use the stricter case-review exit code when a workflow must wait for every item to close. Expect exit 3 for this example because the provider item remains open.

```sh
"$setrya" receipt verify-exchange "$scratch/reviewer/exchange" \
  --key "$scratch/reviewer/trusted-issuer.pub" --case-review
```

Keep the control or ticket reference separate from your governance decision. Decide whether the observed stores, answers, and writer satisfy the external control, and route the remaining item to its recorded owner. [Receipt exchange](receipt-exchange.md)
