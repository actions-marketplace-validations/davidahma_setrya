# Storage and route coverage

## Find observed stores without a mapping

Run the application fixture with a Setrya copy journal. In CI, compare the resulting observations with the owners, adapters and scanners declared in the application's inventory.

```sh
setrya coverage-drift --journal copies.sqlite --inventory inventory.toml
```

Each journal is read in a single read-only transaction. A broken copy chain or imported packet seal stops the coverage check. Older unchained records and trace-only events remain readable. Repeat `--journal` to include multiple producers, or point it at the combined SQLite journal after importing worker packets and trace events. Stack fixtures record the namespace of each successful inspection or scan, including a scan with zero matches. These coverage records carry no copy keys. Supply the original fixture journals to include those reads alongside imported copy packets. Existing rollback-mode SQLite journals are supported. Use `--json` for a list of observed boundaries with their owners and matching bindings.

This inventory maps a trace store and one named Langfuse sink. Add one entry for each distinct trace sink or storage namespace seen in your fixture. Set the optional `sink=` argument on `langfuse_observation` when several projects share a logical store name. Its default is the journalled store name.

```toml
version = 1

[[systems]]
name = "traces"
owner = "observability"
role = "trace"
approved_labels = ["synthetic"]
retention_days = 7
adapter = "trace-deletion"

[[coverage]]
store = "traces"
kind = "trace"
name = "support-sandbox"
scanner = "langfuse-observations"
```

A system's deletion adapter covers the store-level entry. To map a store with a scanner alone, declare `adapter = "none"` on the system and add a coverage entry with `kind = "store"` and its name in both `store` and `name`. Namespaces and sinks require their own exact mapping. For a namespace, use `kind = "namespace"` and the complete recorded name. Custom copy hooks can record `details={"boundary_kind": "namespace", "boundary": "support/investigations"}`. For the built-in LangGraph memory hook, `name = "setrya/{subject}"` matches the namespace only when its suffix equals the subject reference on that event. A fresh test subject can reuse the mapping. A version-lineage journal contributes the physical stores named in its graph.

Exit 0 means every observed boundary has a named adapter or scanner. An unmapped boundary or an empty journal exits 3. The command names the owner when the store appears in the inventory. Invalid inputs exit 2. A mapping establishes coverage of the observed names. Run the deletion drill to test the adapter itself. Writes outside the supplied journals remain outside this comparison.

## Find changed routes without matching tests

The `route-coverage` command inspects a Git diff. Its earlier `coverage` spelling remains available.

A team adds an agent-summary endpoint to the module that already serves support search. The existing refund regression passes on both commits. The new endpoint has a different caller, and nobody has tested it. Use a coverage map to put its name and owner in the PR.

Commit `setrya-coverage.toml` in the application repository. This example discovers Python route registrations and maps a background job by filename.

```toml
version = 1

[[component]]
name = "support-retrieval"
root = "app/routes"
owner = "@search-platform"
decorators = ["router.get"]

[[component.binding]]
file = "app/routes/search.py"
surface = "router.get /support/search"
drill = "tests/refund.toml"
probe = "refund-window"

[[component]]
name = "index-jobs"
root = "app/jobs"
owner = "@indexing"

[[component.binding]]
file = "app/jobs/refund.py"
drill = "tests/refund.toml"
probe = "refund-window"
test_id = "refund-update"
```

For a recorder binding, use the exact test ID supplied to the recorder. For an adapter-driven check, omit `test_id`; the drill identifies the adapter. To require a worker schedule, replace `test_id` with `scenario = "revoke"` and `schedule = "reverse"`, and point `drill` to the same configured scenario TOML used to collect the evidence. Use `schedule = "all"` to require the entire suite.

Run this after collecting candidate evidence. Both Git refs must be available locally, with sufficient history to find their common ancestor. Give the command each search report or scenario directory with a separate `--evidence`.

```sh
setrya route-coverage --repo . --base origin/main --candidate HEAD \
  --evidence refund-review/candidate.json --summary coverage.md
```

The command reads the map, drills, and source at the candidate commit. It checks the diff from the merge base. A report must replay and match the commit, drill rules, query fingerprints, and adapter or recorder identity. The mapped probe supplies the caller and route in the summary. The search report format omits adapter options. For an options-sensitive test, retain the `run-pr` handoff, which records the selected drill digest and checks the full live drill in each lane. A scenario also has to match the configured application and requested schedule. A matching failure takes precedence over a passing report. Keep both the native test and coverage exit codes as CI gates. A successful coverage check cannot clear a failed test.

| Exit | Meaning |
| --- | --- |
| 0 | Every affected mapped surface passed, or the diff touched no declared surfaces. The summary distinguishes these cases. |
| 1 | A matching report shows a failure. |
| 2 | The map, source, or evidence could not be evaluated. |
| 3 | A changed surface lacks a binding or matching evidence, was removed, or the matching evidence is NOT TESTED. |

Decorator mode recognizes the configured Python decorator names with literal paths or job names. It ignores formatting and comments, checks a changed handler, and rechecks registrations in the same module when shared code changes. Changes to registration order can affect later handlers. Use a file-level component for dynamic registration and remove that decorator from the overlapping decorator component. File-level components can also cover shared helpers in other modules, non-Python code, or other files whose changes need review. In file-level mode every changed file under the root needs a binding or an owner decision. Removing a route or narrowing its component in the same PR still brings the changed surface to its previous owner's attention.

This is an inventory the team maintains. Owners choose the relationship between a file or registration and a drill. The command does not trace calls across modules or discover undeclared components. Review map changes alongside the code.

## Replay the example

Unpack the [coverage review bundle](https://github.com/davidahma/setrya/releases/download/v0.12.1/route-coverage-review.zip). The bundle contains a two-commit synthetic application, the ordinary test handoff and the coverage summary.

```sh
git clone -b main application.bundle fixture
setrya route-coverage --repo fixture --base base --candidate candidate \
  --evidence handoff/candidate.json --summary reproduced.md
```

Both native test runs pass. Coverage exits 3 and names `router.get /agent/summary` and `@search-platform`. An independent coding-agent reviewer also spotted the omission from the diff and ordinary test handoff, without seeing the map or coverage result. The check makes that finding repeatable and assigns an owner. This trial did not show a reviewer-time advantage. No human reviewer participated.

Use `setrya coverage-drift` to compare observed storage boundaries with the inventory. The 1.x `setrya coverage` alias accepts the existing route-mapping arguments.
