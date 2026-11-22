# Verify AWS KMS key destruction

An application can erase its ability to decrypt a subject's data while encrypted bytes remain in a store. Setrya distinguishes a row that is still there under a destroyed key (`crypto-erased`) from an expected row that the observer could no longer find (`absent`). The verifier reads AWS and the declared stores. Key lifecycle changes stay in your existing authorized process.

## Capture the scope before deletion

Use a customer-managed, single-Region symmetric AWS KMS key with AWS-generated key material. Supply the immutable key ARN and a separate enabled control key in the same commercial AWS account and Region. Each ciphertext must come from the AWS Encryption SDK version 2 message format and contain exactly one encrypted data key, wrapped under the expected KMS key. The application owner must establish that the target key is the only usable recovery path for these records, including how the application handles plaintext data keys, caches, alternate wrapping keys, exports and backups. If your recovery design does not satisfy that condition, use direct deletion observations.

The first adapter reads a rollback-mode SQLite database in a read-only snapshot. Map the application-owned table with `copy_ref TEXT PRIMARY KEY`, `subject_ref TEXT NOT NULL` and `ciphertext BLOB NOT NULL`. `copy_ref` is a 64-character lowercase hex opaque reference that stays fixed for that store key. `subject_ref` is the same tenant-scoped HMAC used in the app's journal. Give each database one unrelated, retained row under its own subject reference and KMS key. Keep the retained row unchanged so it proves the verifier read the same store. An index on `subject_ref` helps SQLite find the copies in larger tables.

Put the following in `crypto-inventory.json`. Replace the example references, ARNs and store mapping with trusted values from your application. Relative database paths are resolved from this file when the capture is made. Keep the same resolved database locations for verification.

```json
{
  "format": "setrya.crypto-inventory.v1",
  "subject_ref": "1111111111111111111111111111111111111111111111111111111111111111",
  "retained_ref": "2222222222222222222222222222222222222222222222222222222222222222",
  "key_arn": "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-111111111111",
  "retained_key_arn": "arn:aws:kms:us-east-1:111122223333:key/22222222-2222-2222-2222-222222222222",
  "owner": "platform",
  "recovery_scope": "exclusive-kms-key",
  "stores": { "snapshots": { "database": "snapshots.db", "table": "encrypted_copies" } }
}
```

Use a dedicated AWS reader role in the key's account, with `kms:DescribeKey` on the two named ARNs and `cloudtrail:LookupEvents` in the Region. The verifier also calls `sts:GetCallerIdentity` to confirm the observer's account. The role needs neither decryption nor key mutation privileges. Use authoritative SQLite files that the observer can only read. [KMS `DescribeKey`](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html) · [CloudTrail `LookupEvents`](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)

```sh
python -m pip install 'setrya[crypto-aws]'
setrya crypto-erasure capture --inventory crypto-inventory.json --output crypto-capture.json
```

Record the SHA-256 printed by `capture` in the approved request or hand it directly to the reviewer before the key is destroyed. Verification uses the independently retained value to pin the capture. The capture binds the exact key lifecycle, inventory, pseudonymous copy keys, wrapping key references and ciphertext digests. It reads up to 16 declared stores and 512 target copies, with per-store resource limits.

## Verify completed destruction

Run verification when AWS has finished deleting the key. Scheduling deletion starts a waiting period. A pending or disabled key, an access error, or an uncorroborated `NotFound` leaves the proof open. Verification requires a CloudTrail `DeleteKey` service event for the exact key ARN after capture, an exact KMS lookup returning `NotFound`, the captured retained key still enabled, and a fresh read of the mapped stores. CloudTrail event history covers 90 days and the verifier bounds the number of pages it reads. Verify while the event is available. [AWS key deletion lifecycle](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html) · [CloudTrail `DeleteKey` event](https://docs.aws.amazon.com/kms/latest/developerguide/ct-delete-key.html)

```sh
setrya crypto-erasure verify --inventory crypto-inventory.json \
  --manifest crypto-capture.json --expect-manifest "$CAPTURE_SHA256" --output crypto-receipt
setrya replay crypto-receipt
setrya receipt summary crypto-receipt --audience reviewer
```

| Result | Interpretation |
| --- | --- |
| `PASS` | AWS evidence establishes the captured key's destruction. Each captured copy was absent from its mapped table or its same ciphertext remained under the destroyed key. All retained controls survived. |
| `FAIL` | The captured target key was still enabled. Matching ciphertext rows are reported as `recoverable`. |
| `NOT TESTED` | Evidence is incomplete, including an unconfirmed key lifecycle, a lost control, a changed ciphertext or new copies outside the captured scope. Review the open items with the inventory owner. |

The evidence bundle includes ciphertext hashes, pseudonymous copy references, the AWS key ARNs and the selected service event ID. It excludes ciphertext and plaintext, raw CloudTrail records, AWS credentials, source paths and the original subject HMAC. Share it according to your organization's metadata policy. To sign with a trusted local Cosign key, use the same receipt commands as the other profiles.

```sh
setrya erasure sign --receipt crypto-receipt/erasure-receipt.json \
  --bundle crypto-receipt.sig --key reviewer.key
setrya verify --receipt crypto-receipt/erasure-receipt.json \
  --bundle crypto-receipt.sig --key reviewer.pub
```

The signature authenticates the observer's receipt and binds the evidence digest. Offline replay checks the saved evidence against the verdict. A live run reads the encrypted data key reference from the AWS Encryption SDK message header and compares the full ciphertext digest against the capture. It relies on storage and encryption performed by the trusted application. Scope covers the declared copies and the observed key lifecycle. Assess other stores, plaintext, exported key material and backups separately. [AWS Encryption SDK message format](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html)
