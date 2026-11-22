# A customer summary and a read-only request check

A support lead answering a deletion ticket has two different kinds of evidence. A replayed drill shows how the application behaved in a test. A direct key check shows which recorded copies a reader could still find for an actual completed request.

## Give a customer the result of a drill

```sh
setrya demo --output workspace
setrya receipt render workspace/guarded --audience customer --case-id N-204
```

The renderer replays the v3 receipt with its companion evidence before producing plain text. It covers person drills, tenant receipts and discovery cases. The customer sees what was checked, whether a delayed writer ran, and how many provider, retention or other follow-ups remain. A review date appears when the evidence contains one. For discovery cases, the observation date comes from the drill. A deferred case gives the catalog date and states that no deletion drill ran. Questions, answers, internal store keys and subject references stay in the original bundle.

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
