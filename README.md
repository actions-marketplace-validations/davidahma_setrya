# Setrya

**Find where your app copies customer data. Test whether deletion reaches those copies.**

A deleted support note can survive in an answer cache, a vector index, or a background job. Setrya spots supported Python copy sites in source and tests a deletion against the stores and callers you declare.

## 1. Scan your code

```sh
python -m pip install setrya
setrya discovery copy-scan .
```

Get file and line numbers with starter mappings. Add the GitHub Action to flag new copy sites that need a test. [Scan and PR setup](https://github.com/davidahma/setrya/blob/v1.10.0/docs/copy-coverage.md)

## 2. Run your first drill

```sh
setrya demo --output workspace
setrya replay workspace/guarded
```

The sample compares a worker that restores a deleted note with one that checks its source revisions first. Use a reusable HTTP case to test the same behavior across deployments. [Connect your app](https://github.com/davidahma/setrya/blob/v1.10.0/docs/github-action.md#switch-from-the-sample-to-your-app) · [HTTP deployment cases](https://github.com/davidahma/setrya/blob/v1.10.0/docs/http-cases.md)

## 3. Review the receipt

Review a signed exchange offline or compare a candidate assessment with the last approved release. A receipt covers the recorded observations and keeps open provider items visible. [Receipt guide](https://github.com/davidahma/setrya/blob/v1.10.0/docs/receipt-format.md) · [Offline verification](https://github.com/davidahma/setrya/blob/v1.10.0/docs/assessment.md#verify-without-installing-tools) · [Assessment](https://github.com/davidahma/setrya/blob/v1.10.0/docs/assessment.md)

[Examples and legacy workflows](https://github.com/davidahma/setrya/blob/v1.10.0/docs/examples-archive.md) · [Release schedule](https://github.com/davidahma/setrya/blob/v1.10.0/docs/releases.md) · [Contributing](https://github.com/davidahma/setrya/blob/v1.10.0/CONTRIBUTING.md) · [License](https://github.com/davidahma/setrya/blob/v1.10.0/LICENSE)
