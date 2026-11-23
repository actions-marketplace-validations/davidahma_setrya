# Find PDF exports missing from an erasure test

A pull request adds a PDF archive. The existing deletion drill stays green because it only reads the primary PDF. Run a source coverage check to give the export owner a concrete file and line to investigate.

Setrya parses Python locally with the standard library. A source candidate identifies a write site. A reviewer approves the corresponding store and exact key using the case mapping. If you supply a matching discovery receipt, Setrya replays it and links the baseline and deletion evidence for that service. The report names the mapped fixture revision. To use those observations for a PR, bind the mapping and the fixture to the tested head revision and generate a fresh receipt.

## Try the Northline archive

```sh
python -m pip install setrya==1.7.0
setrya demo northline-source --output northline-source
setrya replay northline-source/broken           # 1, FAIL / RESIDUAL_FOUND
setrya replay northline-source/guarded          # 0, PASS / OPEN_ITEMS
setrya replay northline-source/guarded --case-review  # 3, provider follow-up
```

The source comparison finds an archive PDF write with a dynamic directory and the literal name `archive-f42.pdf`. Before approval, the report has a source location and a mapping gap. After approval, both runs directly read that archive before and after selective erasure. The late worker restores the old archive in the broken run. The guarded run leaves it redacted. The security finding and both analysts' access survive in both runs. The provider's configuration-only evidence stays open in the guarded case.

[Download the release cases](https://github.com/davidahma/setrya/releases/download/v1.7.0/northline-source-review.zip) and replay the `broken` and `guarded` directories offline. Each `receipt.sigstore.json` authenticates the corresponding `case-result.json`. The source review JSON is an advisory report. Replay checks the evidence bound to the signed case result. [Signature verification](northline.md)

## Try the PR gate

```sh
setrya discovery init --example northline-source --output source-case

setrya discovery source-check source-case/base \
  --finding source-case/finding.json --mapping source-case/unmapped.json \
  --output base-review.json

setrya discovery source-check source-case/source \
  --finding source-case/finding.json --mapping source-case/unmapped.json \
  --baseline base-review.json --output head-review.json
```

The second check exits 3 and names the archive candidate. Inspect the write path and approve which service and exact key your case should read. An approved relationship can connect a relative filesystem path to a different key in an application store. The scanner does not infer that relationship. Use `head-review.json` for the candidate's `source.id`. After approving a service in the mapping, run `source-check` with that mapping to get its `binding_sha256`. Store the candidate-to-service approval in a reviewed JSON file. The example's `source-approvals.json` shows the exact fields.

```sh
setrya discovery source-check source-case/source \
  --finding source-case/finding.json --mapping source-case/mapping.json \
  --approvals source-case/source-approvals.json --baseline base-review.json \
  --receipt northline-source/broken --output mapped-review.json
```

This command exits 0 because the new site has an approved mapping. Its deletion column reports `FAIL`. Run `setrya replay` or `setrya discovery replay` as a separate CI step to gate on deletion. Use `--case-review` when an unresolved obligation should also block the job.

For your own CI, run the same pinned Setrya version on base and head. Generate the baseline from the protected base revision with that revision's reviewed mappings and approvals. Keep the baseline outside the PR checkout. Generating the baseline writes the report even when the command exits 3 for a known gap. Stop on exit 2. Run the head check with the reviewed mapping and approval files. If you allow changes to those files in the same PR, require review by their owners. Keep the case ID, subject reference, finding asset and environment consistent across the comparison. A new candidate or a formerly approved candidate without approval exits 3. Previously unapproved sites remain visible as existing gaps. Omit `--baseline` to require approval for every detected site.

To inspect code before you have a discovery case, run `setrya discovery source-scan path/to/python --output pdf-writes.json`. It reports possible PDF writes without a finding, mapping or fixture.

## Scan boundary

Point the scanner at a checked-out Python source directory. It recognizes supported filesystem write calls with a PDF filename, and common PDF-producing calls assigned to a supported write. It cannot resolve arbitrary runtime paths, external rendering services, indirect wrappers, code in other languages or arbitrary data flow. A dynamic path remains unresolved even if a filename is known. Use a local Linux or macOS checkout. The scan allows up to 1,024 Python files, 512 KiB per file, and 16 MiB of Python source in total. Input errors, symbolic links in the scanned scope, or exceeded limits exit 2. Keep the scanned root focused on application source.

A source site is a lead for mapping review. The runtime baseline establishes whether the fixture could observe the expected data in the declared store and key. The deletion status comes from the matching replay. Unmapped sites and approvals without a supplied receipt have no runtime or deletion result.
