# Test deletion in a LangGraph application

A checkpoint can still hold a support note after the source row has gone. A new thread can look clean while reopening the original thread brings the note back. Start with a disposable thread containing one customer's test fact and one fact the team must keep.

## See the failure on a laptop

```sh
python -m pip install 'setrya[erasure]==1.1.0'
setrya demo analyst --output investigation
setrya replay investigation/broken
setrya replay investigation/guarded
```

The broken replay exits 1. The guarded replay exits 0. The demo reopens the same investigation for two analysts after a delayed writer finishes. The receipt records store and answer observations. A provider follow-up stays open even when the application checks pass. [Shared investigation](shared-investigation.md)

## Connect your application's Postgres memory

```sh
python -m pip install 'setrya[case-yaml,erasure-postgres]==1.1.0'
setrya init --stack langgraph-postgres --output graph-case
setrya doctor --case graph-case/case.yml
```

Doctor lists missing bindings. Set the test origin, reader and deletion credentials, subject reference and observer connection named in the file. Seed the declared memory namespace and keys in a disposable deployment. Replace the example questions, reviewed answers and HTTP paths with values your graph actually serves. Read an existing thread through its authenticated route. Have the application's deletion route update the appropriate state.

```sh
setrya doctor --case graph-case/case.yml
setrya run --case graph-case/case.yml --mode deletion --output graph-receipt
setrya replay graph-receipt
```

The Postgres starter inspects and scans the declared **long-term memory** namespace. For thread checkpoints or a delayed checkpoint writer, use the Python fixture, the checkpoint scanner and your application's hold/release hooks. Declare each additional store you expect the receipt to cover. [HTTP case format](http-cases.md) · [Checkpoint and memory observers](harnesses.md) · [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
