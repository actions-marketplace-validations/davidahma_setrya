# Test your application's HTTP endpoint with a YAML case

Use a YAML case when your application serves answers over HTTP and its test data is directly readable in a store. The application can run on Node.js, Python or another runtime. Setrya calls the authenticated answer and deletion routes and reads the declared store keys itself.

Start with a disposable, seeded application. The fixture needs one synthetic fact to delete and a second fact its reader should keep. Install the YAML extra on the machine running Setrya and choose the store holding the derived copy.

```sh
python -m pip install 'setrya[case-yaml]'
setrya init --stack openai-agents --output setrya-case
setrya doctor --case setrya-case/case.yml
```

Doctor names the environment bindings that still need values. It checks the caller and baseline reads once those bindings are available. It leaves the deletion route untouched. Edit the generated questions, expected answers, store scope and artifact keys to match the fixture you seeded.

| Stack | Direct reads and scans in the generated case | Connection variable |
| --- | --- | --- |
| `openai-agents` | Message rows in one native Agents SQLiteSession. Use its session ID as the scope and its message row IDs as keys. | `SETRYA_TEST_AGENTS_DB`, path to the SQLite file |
| `claude-agent` | JSONL records in one project transcript. Use a canonical session UUID as both scope and key. The example expects the shared transcript to be rewritten in place. | `SETRYA_TEST_TRANSCRIPTS`, project transcript directory |
| `langgraph-postgres` | Values in one exact LangGraph PostgresStore long-term memory namespace. Set the dot-separated namespace as the scope and the memory item IDs as keys. Checkpoints and vector tables require separate fixture coverage. | `SETRYA_TEST_POSTGRES_URL`, PostgreSQL URL. Install `setrya[case-yaml,erasure-postgres]`. |
| `redis-cache` | Strings at `prefix:scope:key` in a dedicated standalone Redis primary. The scanner supports up to 4,096 keys in the fixture database. | `SETRYA_TEST_REDIS_URL`, Redis URL. Install `setrya[case-yaml,redis]`. |

For ordinary SQL, use store kind `sqlite` or `postgres`. Declare `table`, `key_column`, `content_column` and `scope_column` with the names of the application's key, text and scope fields. SQLite uses a path in the named environment variable. PostgreSQL uses a connection URL. The observer opens SQLite read-only, runs PostgreSQL reads in read-only transactions and reads Redis without mutating keys. Use a database account with read permissions for these observations. Both SQL readers require a physical base table on each inspection and scan. A filtered view can hide a row that a soft delete left behind. The PostgreSQL reader also declines replicas, row-level security, and partitioned or inherited layouts. Scope identifiers match their exact text representation, so `001` and `1` are distinct.

## Use existing Python test hooks

Each stack starter also writes `test_erasure.py`. Its `open_fixture()` provides the same direct `inspect` and `scan` implementations as the YAML case. Configure the store and subject bindings, then run `setrya doctor --starter setrya-case/test_erasure.py`. It names the missing `read` and `erase` methods. Bind these to your application’s authenticated test client and erasure operation inside `open_fixture()`. A native Python fixture can bind worker hooks here too. The YAML path below uses HTTP to call the application instead.

## Connect an authenticated app

`origin_env` names the variable containing the test origin. Use HTTPS for remote fixtures. Local HTTP works on loopback. The case names environment variables for a reader token per caller and a separate erasure token. Keep the token values and connection credentials outside the case and repository. Use scoped test credentials and a trusted fixture in CI.

| Request | Response the case requires |
| --- | --- |
| `POST` to `read_route` with the reader's bearer token and JSON fields `conversation` and `question` | HTTP 200 with `caller`, `conversation`, `route`, `question` and `text` from the serving response. Resolve `caller` from the authenticated session. |
| `DELETE` to `erase_route` with the erasure token and JSON fields `subject_ref` and `conversation` | HTTP 204 after the disposable app has applied the request. Set `subject_ref_env` to the synthetic subject's preseeded 64-character lowercase HMAC reference. |

Declare the expected action for each known key as `delete`, `preserve` or `rewrite`. The scanner also looks for the target marker within the store scope. Each scan needs a positive baseline. The case checks actual answer text against the synthetic marker and the whole replies that a human classified as containing or excluding each fact. Include paraphrases you expect to encounter. A reply outside those judgments can leave the verdict **NOT TESTED**. The receipt records hashes of questions and answer observations.

For each known key, a direct read looks for the marker and the fact’s reviewed positive replies anywhere in an individual text field or field name. A missing key establishes absence. An existing copy establishes absence only when its complete value matches a reviewed negative. The negative replies in `answers.absent` cover exact string values. Use `stored.absent` for a reviewed JSON object, array or differently worded summary. If a rewrite adds unreviewed text, the direct read stays uncertain even when the endpoint returns a clean answer. Unlisted keys are discovered by the synthetic marker.

This example under `facts.target` gives the alternate depot name and the complete support record allowed after erasure.

```yaml
stored:
  present: ["Dock 17"]
  absent:
    - {summary: "Dispatch is still on Thursday."}
```

```sh
setrya doctor --case setrya-case/case.yml
setrya run --case setrya-case/case.yml --output receipt
setrya replay receipt
```

In the Action's `starter` input, use the path to the YAML file and install the same extras in the drill job. A YAML case covers deletion. Use the Python fixture when the application can expose a worker hold, checkpoint and release for a late-write test.

## Try a Node.js application

The [SQLite case](examples/http-case/case.yml) runs against a [small Node.js help desk](examples/http-case/fixture.mjs). It deletes the customer note and checks whether the authenticated reader still gets the team dispatch day. From a checkout with Node.js 22.13+ and the YAML extra installed, run this in a POSIX shell.

```sh
fixture_dir=$(mktemp -d)
export SETRYA_TEST_DB="$fixture_dir/notes.sqlite"
export SETRYA_SUBJECT_REF=$(openssl rand -hex 32)
export SETRYA_READER_TOKEN=$(openssl rand -hex 24)
export SETRYA_ERASER_TOKEN=$(openssl rand -hex 24)
node docs/examples/http-case/fixture.mjs > "$fixture_dir/origin" &
fixture_pid=$!
trap 'kill "$fixture_pid" 2>/dev/null || true' EXIT
while [ ! -s "$fixture_dir/origin" ] && kill -0 "$fixture_pid" 2>/dev/null; do sleep 0.1; done
export SETRYA_TEST_ORIGIN=$(cat "$fixture_dir/origin")
setrya doctor --case docs/examples/http-case/case.yml
setrya run --case docs/examples/http-case/case.yml --output "$fixture_dir/receipt"
setrya replay "$fixture_dir/receipt"
kill "$fixture_pid"
trap - EXIT
```

The Node process seeds a fresh SQLite file and chooses a free loopback port. A clean run returns **PASS**. To try your own service, keep the case and connect the two HTTP routes and store mapping to your application's fixture.
