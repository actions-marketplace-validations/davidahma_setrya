# Verify selective erasure in a saved investigation

Northline's analysts share investigation F-42. A customer's identifying detail is part of the finding and appears in a chart and its PDF export. The security finding must survive. Two authorized analysts reopen the same conversation after erasure while a refresh worker is still holding the original version.

## Run the fixture

Install or upgrade Setrya in a Python 3.11+ virtual environment and run the two disposable application versions. The demo uses SQLite, a real local PDF and an authenticated loopback HTTP endpoint. It needs no cloud, model or database account.

```sh
python -m pip install setrya==1.6.0
setrya demo northline --output northline
setrya replay northline/broken
setrya replay northline/guarded
```

The demo verifies both bundles before publishing its output directory. Its own exit code is 0 when both expected outcomes are reproduced. Replaying the broken case exits 1. Replaying the guarded case exits 0, or 3 with `--case-review` because the model-provider owner still has an open item.

| Observation | Broken | Guarded |
| --- | --- | --- |
| Immediately after erasure | The identifying detail is absent and the security finding survives. | Same baseline and immediate result. |
| After the same paused refresh finishes | The saved chart, PDF, conversation and answer route expose the old detail again. | The worker checks the source revision and retires its stale write. The original finding remains readable without the identifying detail. |
| Technical verdict and review status | `FAIL · RESIDUAL_FOUND` | `PASS · OPEN_ITEMS` |

Read the saved case with `setrya receipt summary northline/guarded --audience reviewer`. The provider boundary is declared with an owner. It shows an unobserved invocation and no retention evidence. The application observations and the provider item have separate statuses. The demo's raw SQLite and PDF files belong to the disposable fixture. The portable bundle keeps the observations and evidence references.

## Bring the finding through discovery

The sample input is an offline Macie export with a concrete S3 object version. The reviewed mapping pins its digest, customer handling label, application revision, exact source revision and approved actions. The fixture independently identifies the installed application revision and reads the persisted source, chart, PDF and conversation. The approved application owns the rewrite. The catalog finding alone supplies a pointer for review.

```sh
setrya discovery init --example northline --output approved
setrya discovery import --finding approved/finding.json --output normalized.json
setrya discovery run --finding normalized.json --mapping approved/mapping.json \
  --fixture approved/fixture.py --mode late-write --output guarded
setrya discovery replay guarded --finding normalized.json --mapping approved/mapping.json
setrya discovery export guarded --finding normalized.json --mapping approved/mapping.json \
  --output N-204.json
```

The customer and label are synthetic. For your own application, keep the original finding private and review the mapping before providing it to a trusted disposable fixture. Mark required application artifacts separately from external obligations. If a required PDF or route is unreadable, a clean result remains unverified. [Mapping fields and approval](discovery-mapping.md)

## Verify the published receipts

Download [northline-case-review.zip](https://github.com/davidahma/setrya/releases/download/v1.6.0/northline-case-review.zip) and unpack it into a fresh directory. It contains only the two replayable evidence bundles and their signatures. Use the separately generated `approved` finding and mapping above to bind the download to the expected case. Run the existing discovery signature verification with Cosign 3 and a separately trusted Sigstore root. [Prepare a trusted root](receipt-format.md#verify-offline)

```sh
setrya discovery verify --receipt downloaded/guarded/case-result.json \
  --bundle downloaded/guarded/receipt.sigstore.json \
  --identity 'https://github.com/davidahma/setrya/.github/workflows/erasure.yml@refs/heads/main' \
  --issuer 'https://token.actions.githubusercontent.com' --trusted-root trusted_root.json
setrya discovery replay downloaded/guarded \
  --finding approved/finding.json --mapping approved/mapping.json
```
