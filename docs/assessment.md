# Sign a deletion assessment

Use `setrya assess` to combine results from several repositories. The report records the supplied commit for each repository, the digest and gap count of each coverage check, and the verdict and evidence digest of each replayed receipt. It creates a signed JSON report and a short Markdown summary.

## Build the report

Generate scan and coverage reports with the [copy-site check](copy-coverage.md), `route-coverage --json` or `coverage-drift --json`. Use an empty list where an input is unavailable. List paths relative to the plan or use absolute paths. Use full Git commit IDs.

```json
{
  "format": "setrya.assessment-input.v1",
  "repositories": [
    {
      "name": "support",
      "commit": "2222222222222222222222222222222222222222",
      "checks": ["support-copy-review.json", "support-journal-coverage.json"],
      "receipts": ["support-receipt"]
    },
    {
      "name": "billing",
      "commit": "3333333333333333333333333333333333333333",
      "checks": ["billing-routes.json"],
      "receipts": []
    }
  ]
}
```

```sh
setrya assess build --plan assessment-plan.json --output assessment --key issuer.key
setrya assess verify assessment --key trusted-issuer.pub
```

Cosign 3 signs the exact `assessment.json` bytes. The report binds `summary.md` to those bytes by digest. For keyless signing, omit `--key` on build. The CLI verifier takes the already trusted `--identity`, `--issuer`, and `--trusted-root`. Keep the inputs separately if a reviewer needs to reproduce the assessment. Share them only with people authorized to see the underlying evidence.

Copy scans and coverage exports describe what their input files report. A map entry identifies work to test. The builder replays receipt contents without contacting the application. A clean recorded checkout or commit-bearing coverage export that differs from the plan blocks the build. Older receipts, dirty checkouts, and unpinned checks carry no checkout binding. The signature authenticates the report's issuer. The issuer's controls establish which inputs and runner it trusted.

## Verify without installing tools

Download the [offline verifier](https://github.com/davidahma/setrya/releases/download/v1.9.0/setrya-verify-offline.html) independently of the report sender and open it in a browser. Select all files from a single assessment or draft receipt exchange. Select the trusted Cosign P-256 PEM public key you received through your organization's approved channel. Confirm the displayed key fingerprint against your trust record.

The page checks the signature and all companion file digests locally. It displays the signed executive summary or the issuer's receipt result. Full evidence replay and keyless Sigstore verification are available through the CLI. [Receipt exchange](receipt-exchange.md)
