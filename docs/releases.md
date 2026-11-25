# Release schedule

Setrya targets one scheduled release every two weeks. Fixes that need to reach users sooner can ship separately. Each release runs the repository's checks, exercises an install from PyPI, and records evidence that a reviewer can replay. [Release notes](../CHANGELOG.md)

Setrya 2.0 is targeted for February 2, 2027. It is the planned removal point for deprecated 1.x CLI commands and their top-level discoverability. The list is maintained with their migration paths. Teams that still run those commands can pin a 1.x release during migration. Open a [compatibility issue](https://github.com/davidahma/setrya/issues) for a workflow without an equivalent. [Legacy migration guide](other-drills.md) · [API stability](api-stability.md)

Setrya 1.x accepts `--mode write-back` and `--mode late-write` for the same drill. The CLI rename to `write-back` is planned for 2.0. Archived receipts retain their recorded mode and replay rules. [CLI modes](erasure-cli.md)
