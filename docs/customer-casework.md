# A customer summary and a read-only request check

A support lead answering a deletion ticket has two different kinds of evidence. A replayed drill shows how the application behaved in a test. A direct key check shows which recorded copies a reader could still find for an actual completed request.

## Summarize the recorded verdict

```sh
setrya demo --output workspace
setrya receipt summary workspace/broken --audience engineer
setrya receipt summary workspace/guarded --audience reviewer --format markdown
setrya receipt summary workspace/guarded --audience customer --case-id N-204
```

The command replays the receipt and verifies its evidence before rendering. An engineer gets the decisive reads and evidence locations. A reviewer sees the technical verdict, the worker scope, which tested records or answers still contained the deleted fact, and what to follow up. A customer sees counts and plain language. Each audience gets the recorded owner and follow-up date, or an explicit indication that either is missing. Use owner names approved for the customer copy. Questions, answers, subject references and internal store keys stay out of that view.

Person drills, observed-deletion receipts, linked follow-ups, tenant receipts and discovery cases all have summaries. On historical v3 drills, the summary preserves the limits of the evidence those versions collected. `receipt render` is also available.

### Attach a contract or control reference

A team can attach its own control identifiers and DPA clauses when issuing a receipt. Add this optional field to a declarative case.

```yaml
controls:
  - framework: SOC 2
    reference: C1.2
  - framework: DPA
    reference: clause 4.2
```

For a Python fixture, supply the same dictionaries as a tuple in `SharedCase(controls=(...), ...)`. The runner binds these references to the original evidence. Editing only the issued receipt causes replay to fail. References carry forward into linked follow-ups. They help the reviewer locate the relevant agreement or control. The technical verdict covers the recorded observations only. Older receipts that omitted references retain their original verdict and replay rules.

For a tenant receipt, save the references as a JSON array, for example `[{"framework":"DPA","reference":"clause 4.2"}]`. Add `--controls controls.json` to `setrya run --scope tenant` alongside the original ticket digest, policy and evidence. Python callers pass the same list to `setrya.offboarding.tenant_v3.issue(controls=..., ...)`. The tenant input manifest binds those references to the request and exhibits. All three receipt summaries show them.

A tenant or discovery receipt has its own request or case ID. Supplying a different ID is an error. On a synthetic drill the optional case number is identified as a label supplied at rendering time. The rendering command exits 0 when it produces the summary, including for a correctly recorded failure. Use `setrya replay` for the engineering gate and `setrya verify` for signer authentication.

## Observe one completed request

Export completed requests from the deletion system. Give each one its opaque ticket ID, the tenant-bound HMAC reference used when journalling copies, completion time and expected stores from the ticket's scope. Here is one row of a `completed.json` file.

```json
{
  "format": "setrya.completed-requests.v1",
  "requests": [
    {
      "id": "N-204",
      "subject_ref": "ba0b9039a66500f5499cae65f3e3575b548ff514781b054428bfc4d295fcf7c6",
      "completed_at": "2025-05-14T16:35:00Z",
      "stores": ["support_notes"]
    }
  ]
}
```

Configure the mapping outside the request. Each store points to a real table with a single primary key and **exclusively owned keys**. The journal's copy key must be that primary key. Choose a permanent control row that the observer must always be able to see. Shared rows and provider sends cannot prove subject absence with an existence check.

```toml
[stores.support_notes]
kind = "postgres"
dsn_env = "SUPPORT_READONLY_DSN"
schema = "support"
table = "notes"
key_column = "id"
control_key = "observer-visibility-control"
```

Use `python -m pip install 'setrya[pgvector]'` for the PostgreSQL driver. Point the DSN to the authoritative primary using your normal secret manager and certificate validation. Grant the observer login `CONNECT` on the database, `USAGE` on the selected schema and `SELECT (id)` on the mapped table. The login only needs the key column. Keep administrative roles, write grants and membership in the table's owning role away from this login.

The PostgreSQL reader opens a read-only, repeatable-read transaction, verifies the control and looks up the keys with bound parameters. It declines replicas, views, inherited and partitioned tables, tables with row-level security, and roles with elevated attributes or write privileges on the mapped table. Configure any other production systems the role can access according to your own least-privilege policy. [PostgreSQL transaction modes](https://www.postgresql.org/docs/current/sql-set-transaction.html)

For SQLite, map a single `TEXT PRIMARY KEY` using binary collation and text keys throughout. A mixed text and binary key representation cannot establish absence. Use `kind = "sqlite"` and `path = "support.db"` in place of the DSN and schema. Paths are relative to the mapping file. Both the journal and SQLite store must be existing rollback-mode database files. Setrya opens them read-only, checks base tables, and never creates or initializes a journal. A WAL-mode file yields an unknown result. If you must use an exported database, record its snapshot time separately and interpret absence as applying to that snapshot. Supply a fresh, authoritative copy journal with all expected producers. [SQLite WAL and read-only access](https://www.sqlite.org/wal.html#read_only_databases)

```sh
setrya observe request --id N-204 --population completed.json \
  --inventory observer.toml --journal copies.db --output N-204-observation.json
```

The observer uses no application fixture, synthetic reader, deletion command or worker hook. The report contains the ticket ID, observation time, mapped store alias, journal event or lineage version numbers and presence results. Setrya follows recorded lineage from each subject source through downstream versions. Other subjects’ revisions of a key and their direct journal events make that key shared. Each request records when its journal was read. The journal transaction closes before the first store lookup, so waiting for a remote database leaves the journal available to writers. It includes no source contents, connection strings or subject references. Existing output files are protected. Omit `--output` to print JSON.

| Request status | Interpretation | Exit |
| --- | --- | --- |
| `ABSENT` | Every journalled key in the declared scope was absent under a successful control read. | 0 |
| `PRESENT` | At least one exclusive key still existed, including when another key could not be checked. | 1 |
| `UNKNOWN` | A required store, journal entry, control, permission or unambiguous key check was unavailable. | 3 |

Invalid configuration or a malformed request frame exits 2. Seeing a key still present says nothing about its content. An absent key can later be recreated. The observation neither discovers unjournalled copies nor exercises a user's answer route. Reads of different stores can occur at different instants.

## Sample a completed week

Freeze a complete export of the week's deletion tickets before the draw. Select a Monday in UTC and a sample size between 1 and the lesser of 256 and the number of eligible subjects. The week must have ended. Request IDs must be unique. Each eligible request must refer to a distinct subject for the subject-level estimate.

```sh
setrya observe week --week 2025-05-12 --sample 25 --population completed.json \
  --inventory observer.toml --journal copies.db --output week-observations.json
```

The command above assumes the export contains at least 25 eligible subjects. The observer selects requests uniformly without replacement using a fresh random seed. Keep the seed, completed-request export and reported frame digest with the case. Pass the recorded hex seed with `--seed` to repeat the selection against the same frame. Later observations can change as stores change. For an externally audited draw, freeze the population and commit the seed before inspecting outcomes to prevent choosing a favorable sample.

The JSON includes the eligible and sampled counts, present, absent and unknown totals, and a 95% equal-tailed finite-population interval for the proportion of eligible requests with a residual exclusive key. An exact hypergeometric calculation accounts for sampling without replacement. A full census produces the observed count. When even one sampled request is unknown, the point estimate is null. The lower limit treats every unknown as absent and the upper treats every unknown as present. With no observed residuals a small sample can still have a wide upper bound.

The interval describes only the supplied week's frame and mapped keys. Omitted tickets, uninstrumented stores, changed key ownership and stale snapshots can bias the result independently of the interval.

## Issue and replay a read-only deletion receipt

Use `--receipt` on a single completed request to record two independent observations of the journalled keys. Each observation opens the journal, follows known derived copies, checks each mapped store’s retained control and reads the keys. Setrya records a subject-bound key digest and the journal event or lineage pointer. The receipt omits raw keys, stored content and connection strings.

```sh
setrya observe request --id N-204 --population completed.json \
  --inventory observer.toml --journal copies.sqlite --receipt N-204-observed
setrya replay N-204-observed
```

The v3 profile is `observed-deletion`. Either reading a residual fails the check. PASS requires two absences for each expected exclusive key and consistent journal coverage. A shared key, missing control, unavailable reader or changed journal scope leaves a gap. Production observation uses the journal and read-only SQLite or PostgreSQL readers. Endpoint answers, unjournalled data, provider copies and worker races need separate evidence.

For a distributed app, pass the combined `CollectedJournal` SQLite file to `--journal`. List the expected producers in the observer inventory and import a sealed packet for the selected subject from each one. A worker that saw no copies still exports an empty packet.

```toml
[journal]
run_id = "deletion-check-42"
expected_producers = ["api", "summarizer"]
```

The observer checks the sealed roster and reads imported events, local copy events and lineage from the same SQLite snapshot. Its `collector_sha256` identifies the subject, run and sealed packet digests. Missing packets, a trace without its producer's seal, or a standalone worker journal leave the result `NOT TESTED`. The same inventory and producer requirements apply to follow-ups. A single-process `CopyJournal` needs only the store mappings.

Use the same public API inside an existing case workflow.

```python
from setrya.casework import observe_deletion

receipt = observe_deletion(
    frame="completed.json", request="N-204", journal="copies.sqlite",
    inventory_file="observer.toml", output="N-204-observed",
    controls=[{"framework": "DPA", "reference": "clause 4.2"}],
)
print(receipt["technical_verdict"])
```

`JournalObserver(journal=..., inventory_file=...)` also exposes `find(request)` and `verify_absent(request)` for one validated request row from the frame above. Each operation takes a new read-only snapshot. The operator controls the local store mapping. SQLite uses a read-only URI and query-only transactions. PostgreSQL requires a dedicated role with read privileges on the mapped table, rejects roles with write privileges there, and uses a read-only transaction on the primary. The API accepts the built-in read-only mappings and never invokes an application’s seeding, deletion, worker or synthetic-caller hooks.

## Recheck a due obligation

`setrya recheck` reads the original v3 receipt and verifies its evidence. For an elapsed UTC follow-up date, it looks up the exact store and key in the subject’s current journal. For directly inspectable retained or attested copies, it reads the physical key and scans the mapped subject-reference column for any remaining row. An unrelated retained row anchors the scan. Configure that row, its actual tenant-bound reference, and optional ownership fields inside the relevant store section of `observer.toml`.

```toml
subject_column = "subject_ref"
control_subject_ref = "a9b4cd22b9be40f5076d8fabce26c23a05b8ff3ba5d0d68a573ab3531e04ade"
owner = "customer-platform"
follow_up = "2026-05-14"
```

The PostgreSQL reader needs SELECT on the primary-key and subject-reference columns. A currently retained control already present in the application supplies the reference. The journal must identify the target’s exclusive key. A missing control, shared key, provider send, future or undated obligation, or missing store mapping stays open. A scan covers exactly the configured subject column in that store. An obligation with only provider configuration has no direct observation. Tenant and discovery items without a directly bound subject and copy key retain their original obligations.

```sh
setrya recheck N-204-observed --journal copies.sqlite --inventory observer.toml --output N-204-followup
setrya replay N-204-followup --case-review
```

Each linked receipt includes the original evidence needed to replay it offline. Follow-ups carry the case or request number from that evidence, including across repeated rechecks. Keep the original signed receipt separately and pass its expected SHA-256 to `recheck --expect-parent` when an independent ticket or reviewer supplies it. The output marks each original open item `verified` or `still open`. Both direct and scanned absence are needed to close an item. The original technical verdict remains visible. New residuals fail the follow-up, and a follow-up can never turn the original failed drill into a PASS. The command exits 0 for a clear case, 1 for residuals, 2 for invalid inputs, or 3 when evidence or follow-up remains outstanding.
