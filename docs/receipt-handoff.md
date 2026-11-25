# Hand off a completed deletion ticket

A support app has erased a customer's note. Its customer success team needs evidence that the note and its derived summary are absent. The issuer checks the mapped PostgreSQL keys. A separate reviewer verifies the signed receipt without connecting to PostgreSQL.

For an example of attaching signed evidence to a governance ticket with a control reference and follow-up owner, use the [governance handoff](governance-handoff.md).

## Run the synthetic PostgreSQL handoff

Use Bash, Python 3.11 or later, Docker, OpenSSL and Cosign 3. Use a clean directory and install Setrya with the PostgreSQL extra. The example uses a new loopback-only database and removes it once the original observations have been saved.

```bash
scratch=$(mktemp -d)
cd "$scratch"
python3 -m venv issuer-env
issuer="$scratch/issuer-env/bin"
"$issuer/python" -m pip install 'setrya[pgvector]==1.8.0'

(
  export POSTGRES_PASSWORD
  POSTGRES_PASSWORD=$(openssl rand -hex 18)
  pg=$(docker run -d --rm -p 127.0.0.1::5432 -e POSTGRES_PASSWORD \
    pgvector/pgvector:0.8.7-pg17-bookworm@sha256:b513c48566e4777cd3370451400000c78eda6a08131d68f4c31d4a76f27bd8fd)
  trap 'docker rm -f "$pg" >/dev/null' EXIT
  for _ in $(seq 1 30); do
    docker exec "$pg" pg_isready -h 127.0.0.1 -q && break
    sleep 1
  done
  docker exec "$pg" pg_isready -h 127.0.0.1 -q || exit 1
  SETRYA_PGVECTOR_DSN="postgresql://postgres:$POSTGRES_PASSWORD@$(docker port "$pg" 5432/tcp)/postgres" \
    "$issuer/python" -I -m setrya.examples.receipt_postgres --output originals
)
```

The synthetic fixture commits the source note deletion before it records each ticket as completed. Its separately granted observer can read the primary-key column only. It checks a retained note for another customer, then checks the journalled keys under two independently opened read-only PostgreSQL snapshots. The original receipt and evidence land in one directory per case. The application journal, raw keys, mapping and connection settings stay inside the fixture.

| Ticket | Result | What the observer saw |
| --- | --- | --- |
| `HD-101` | `PASS · READY_FOR_REVIEW` | The source note and summary were absent in both observations. |
| `HD-102` | `FAIL · RESIDUAL_FOUND` | The source note was absent, but the summary still had its original key. |
| `HD-103` | `NOT TESTED · OPEN_ITEMS` | The mapped visibility control was missing, so the reads could establish no absence. |

## Issue and verify the exchange

The issuer signs the draft v1 exchange over the saved v3 evidence. Use a temporary key for this exercise.

```sh
COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix issuer
COSIGN_PASSWORD="" "$issuer/setrya" receipt pack originals/passed --output issued \
  --system synthetic-support --system-version 1 --key issuer.key
```

Give the reviewer the `issued/` directory. Provision the expected issuer public key independently. The original ticket system should supply the expected ticket ID and completed-frame digest. This sample writes both values to `originals/ticket-pins.json` as a separate fixture output.

```sh
ticket=HD-101
frame=$("$issuer/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["passed"]["frame_sha256"])' \
  originals/ticket-pins.json)
review=$(mktemp -d)
cp -R issued "$review/exchange"
cp issuer.pub "$review/trusted-issuer.pub"
python3 -m venv "$review/env"
"$review/env/bin/python" -m pip install setrya==1.8.0

(
  cd "$review"
  env -u SETRYA_PGVECTOR_DSN -u SETRYA_RECEIPT_OBSERVER_DSN \
    env/bin/setrya receipt verify-exchange exchange --key trusted-issuer.pub \
    --expect-ticket "$ticket" --expect-frame "$frame"
)
```

Repeat with `residual` or `unavailable` and their respective ticket pins. After a successful signature and replay check, the command exits 0 for `PASS`, 1 for `FAIL`, or 3 for `NOT TESTED`. Invalid evidence, a mismatched ticket, or an untrusted signature exits 2. Share a customer-safe receipt summary where the recipient needs only the outcome and follow-up. Generate it with `setrya receipt summary originals/passed --audience customer --format md`. Restrict the original and exchange files to reviewers authorized to see their linkable ticket, pseudonymous subject and store metadata. [Existing observer configuration](customer-casework.md#observe-one-completed-request)

## Connect a staging ticket

Use the application's completed-ticket export for the request ID, tenant-bound subject reference, completion timestamp and expected store aliases. The operator supplies the journal, PostgreSQL connection and approved table mapping. Keep their contents inside the application's environment.

```sh
setrya observe request --id HD-101 --population completed.json \
  --inventory observer.toml --journal copies.sqlite --receipt original
setrya receipt pack original --output issued \
  --system support-app --system-version 1 --key issuer.key
```

Use a completed request in a staging case you can identify independently. Provision the issuer key according to your deployment and change the ticket and system labels to match the case. Issuer-supplied system labels describe the run. The receipt records direct observations of mapped keys at the stated times. Use separate evidence for an answer route, another store or a backup.

## Try the same handoff with a second person

Give the issuer the app fixture or an authorized disposable staging case. Give the reviewer the exchange, signer trust, and ticket pins separately. Run each role without live coaching and record the setup time, requests for help, and any misread verdict. The reviewer should be able to name which stores were measured, whether any residual was found, and who owns a remaining item. Repeat with one changed case to see whether the issuer can maintain the mapping. A scripted run qualifies the technical handoff. An outside issuer and reviewer exercising it independently qualify the draft for freezing.
