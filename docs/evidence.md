# Verdict and evidence contract

Setrya uses a single runner-relative monotonic clock. Reports record the order and timing of lifecycle events, plus the start and end of each query. The runner issues serial probes so a query that started before the first verified new result cannot be mistaken for a subsequent read.

1. The adapter seeds the original revision and an unaffected control. The runner records declared baseline probes.
2. The old attempt reads A and acknowledges that it is waiting at the checkpoint. An independent path publishes B. The runner timestamps the acknowledgment and begins freshness sampling.
3. The designated freshness probe first observes B. A result containing B and a forbidden passage violates the assertion on that same probe. After this point, any verified forbidden passage in an applicable observation is a failure, including while the worker is still held.
4. The runner releases the old attempt. For each final probe it needs either a matching terminal rejection observed before the query or a response from the declared route and caller scope with a watermark at or beyond the matching commit in the same index generation. Each final probe must find its required passages, be fully identifiable, and finish within the settle window.

A freshness deadline failure requires a completed, identified pre-deadline sample and an applicable boundary observation within `max_gap_ms`. The boundary observation must show absence in a query started at or after the cutoff, or first return the required revision after the cutoff. An unevaluable deadline yields NOT TESTED. The settle window bounds the wait for final evidence. Within that window, a fully identified final result that lacks a required passage after write resolution earns FAIL. Missing proof earns NOT TESTED. The checker keeps the first observed applicable violation.

The report attributes a stale passage to the old write only when its recorded origin matches the attempt and its response correlates to the relevant commit and search view. If the stale read preceded release, the report records that ordering. Other stale reads can establish FAIL with unknown write origin.

## Replay and sharing

A JSON report saves schema and checker versions, an opaque run ID, text-free effective rules, ordered event times, passage markers, and optional receipt or read evidence. Replay uses those saved rules and events. It never invokes the adapter. The current schema rejects unsupported fields and versions. A corrupt or unsupported bundle exits with code 2.

Keep report artifacts with the exact commit and CI run. Share only synthetic or approved identifiers in public GitHub issues. Default output has no query or passage strings. The bundled fixtures use synthetic data and their independent search endpoint returns the full synthetic snippets to its local caller.
