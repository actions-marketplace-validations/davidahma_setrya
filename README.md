# Setrya

**Deleted customer data shouldn't come back. Setrya proves it doesn't.**

Your app and its agents copy customer data into caches, vector indexes, memory, and traces. Deleting the source can leave those copies behind. A job that read the data before deletion can write it back afterward. Setrya finds supported copy sites in your code and runs your app's deletion operation against the stores, callers, and writers you test. [Why deleted data comes back](https://github.com/davidahma/setrya/blob/v1.11.0/docs/write-back.md)

## 1. Scan your code

```sh
python -m pip install setrya
setrya discovery copy-scan .
```

Get file and line numbers with starter mappings. The GitHub Action flags new copy sites and highlights writes that can run in the background. [Scan and PR setup](https://github.com/davidahma/setrya/blob/v1.11.0/docs/copy-coverage.md) · [GitHub Marketplace](https://github.com/marketplace/actions/setrya-erasure-drill)

## 2. Catch a write-back

```sh
setrya demo --output workspace
setrya replay workspace/guarded
```

In the broken workspace, a job puts a deleted support note back into a handoff. The guarded job checks its source revisions before it writes. Both cases check that the teammates can still read the launch date. [Connect your app](https://github.com/davidahma/setrya/blob/v1.11.0/docs/github-action.md#switch-from-the-sample-to-your-app) · [Fix a write-back](https://github.com/davidahma/setrya/blob/v1.11.0/docs/fix-write-back.md)

## 3. Review the receipt

Review a signed exchange offline or compare a candidate assessment with the last approved release. A receipt covers the recorded observations and keeps open provider items visible. [Receipt guide](https://github.com/davidahma/setrya/blob/v1.11.0/docs/receipt-format.md) · [Offline verification](https://github.com/davidahma/setrya/blob/v1.11.0/docs/assessment.md#verify-without-installing-tools) · [Assessment](https://github.com/davidahma/setrya/blob/v1.11.0/docs/assessment.md)

[Glossary](https://github.com/davidahma/setrya/blob/v1.11.0/docs/glossary.md) · [Examples and legacy workflows](https://github.com/davidahma/setrya/blob/v1.11.0/docs/examples-archive.md) · [Release schedule](https://github.com/davidahma/setrya/blob/v1.11.0/docs/releases.md) · [Contributing](https://github.com/davidahma/setrya/blob/v1.11.0/CONTRIBUTING.md) · [License](https://github.com/davidahma/setrya/blob/v1.11.0/LICENSE)
