# Import copy observations from OpenTelemetry

A copy event tells Setrya where a synthetic subject’s data was retrieved, stored, derived or sent. A producer can emit the event without linking the Setrya SDK. Use the [copy-event v1 schema](../setrya/erasure/copy-event.v1.schema.json) for the normalized event shape.

Export a trusted trace as an [OTLP/JSON trace request](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding). Setrya reads named span events under `resourceSpans[].scopeSpans[].spans[].events[]`. Give each event the name `setrya.copy.v1`. This command imports a single run and producer into a local collector journal.

```sh
setrya journal import --otlp worker-traces.json --journal collector.sqlite \
  --run-id erasure-trial --producer summarizer
setrya journal verify collector.sqlite
```

The import deduplicates exact repeats. A reused identity with different observations rejects the batch. The file can be up to 8 MiB with up to 8,192 matching events. Exporters with binary OTLP should convert the trace request to OTLP/JSON first.

## Draft span attributes

Use OTLP `stringValue` for each field except `setrya_sequence`, which is an `intValue` such as `"17"`.

| Span attribute | Normalized field | Purpose |
| --- | --- | --- |
| `setrya_run`, `setrya_producer`, `setrya_sequence` | `run_id`, `producer`, `sequence` | Stable event identity within the producer. Reuse the same sequence in the durable journal and trace. |
| `setrya_subject`, `setrya_classification` | `subject_ref`, `classification` | Tenant-scoped HMAC and the case’s classification label. Use the same pseudonym as the app’s other observers. |
| `store`, `copy_key`, `source` | `store`, `key`, `source` | Opaque identifiers for the observed copy and its source. |
| `action`, `observed_at` | `action`, `observed_at` | Copy operation and its timestamp with an offset. |
| `details_json` | `details` | JSON object with the approved metadata fields. Use `{}` for an empty object. |
| `setrya_turn`, `setrya_initiator`, `setrya_agent` | `turn`, `initiator`, `agent` | Supply all three when attributing a copy to a turn. |
| `setrya_on_behalf_of`, `setrya_parent_turn` | `on_behalf_of`, `parent_turn` | Optional turn context. |

Keep request bodies, raw subject IDs, prompts, answer text and credentials out of these attributes. The importer ignores unrelated trace payloads. Authenticate the export and bind it to the named producer before import. Sampling and exporter loss can hide copies. Only a verified, sealed worker journal can satisfy completeness for an expected producer. [Journal hooks](erasure-hooks.md)
