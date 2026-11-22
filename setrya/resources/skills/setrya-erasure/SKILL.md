---
name: setrya-erasure
description: Use Setrya to test deletion across an application's stores, read routes, and delayed workers. Use when changing an agent's memory, summaries, cache, or indexing.
---

Run all drills with synthetic subjects and a disposable application fixture. Get the fixture and credentials approved by the repository owner before starting `setrya mcp --fixture`.

1. Find the repo's existing `SharedCase` or YAML case and its inventory. If you added a store or route, find a direct read and the observer that can search for a synthetic canary there.
2. Add a retained control and establish that the synthetic fact is readable before erasure. For delayed workers, capture the affected write before erasure and recheck after the same attempt drains.
3. Use `doctor` on the approved fixture and `run` to save a new bundle. The CLI equivalents are `setrya doctor --starter path` and `setrya run --starter path --output evidence`.
4. Replay the bundle and prepare a reviewer summary. Name the observation that drove the verdict and any open items. Preserve an uncertain or unavailable read as a gap.
5. Publish only the synthetic evidence that the repository permits. Keep application credentials, real prompts, production identifiers, and private evidence out of the pull request.
