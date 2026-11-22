# Setrya 1.x compatibility

The supported developer entry points are `setrya init`, `run`, `replay`, `demo` and `verify`. Use `setrya doctor` to check a trusted fixture before its first run. The package supports Python 3.11 and newer. The core install and offline replay require only the standard library.

## Writing a fixture

New Python fixtures import from `setrya.erasure`, independent of the receipt version. Use that namespace for the person-erasure fixture types, `observe_baseline`, `run_shared`, text judges and decisions. The `setrya.erasure.v3` and `setrya.erasure.judges` import paths continue to expose their original classes. A fixture implements the documented store, caller and worker methods. Keyword names, required fields and the meanings of actions and exit codes are public contracts. New optional capabilities can arrive in a minor release. A change requiring an existing 1.x fixture to be rewritten requires a major version. [Fixture contract](erasure-v3.md)

`setrya.core` is the standard-library boundary for subject and turn identity, journals, lineage, v3 replay and signing transport. Existing erasure imports forward to the same Python classes. Optional carrier integrations are wired by `setrya.erasure`.

## Reviewing a receipt

New person, tenant and discovery receipts use `setrya.erasure.receipt.v3`. Their scopes or profiles identify the evidence required. The shipped JSON Schema describes the wire representation. Always replay the accompanying evidence to recompute the verdict. Validate the signature against an independently selected identity or public key to authenticate the issuer. The standard engineering exits are 0 PASS, 1 FAIL, 2 ERROR and 3 NOT TESTED. A case-review gate can also exit 3 for outstanding obligations. [Published schema](../setrya/erasure/receipt-v3.schema.json) · [Receipt profiles](receipt-format.md)

Setrya 1.x reads supported historical receipts under the rules that issued them. The v3.1 evidence groups samples per caller and question and includes journal chain and turn data when available. Both the original single-read v3 and the flat sampled v3 evidence remain replayable. Archived tenant v1 bundles need the original request digest and exhibits. Historical person v2 runs remain replayable. Create new tests with the v3 starter. Schema-incompatible evidence changes require a new format identifier or version and compatibility fixtures. A correctness fix that changes interpretation must be called out in the changelog. Preserve the original release and signer information with any long-lived receipt.

The Macie importer and classification mapping are experimental. SDK integrations follow the dependency bounds and capabilities in the integration guide. Application callbacks, CLI prose, sample record IDs and third-party service APIs can change. Use exit codes and the documented receipt fields for automation. [Integration coverage](harnesses.md) · [Changelog](../CHANGELOG.md)
