# Use Setrya from a coding agent

The local stdio server gives a coding agent the same replay and summary that a reviewer can run in a shell.

```sh
python -m pip install 'setrya[mcp]'
setrya mcp --root /path/to/your/worktree
```

Point the client at the installed `setrya` executable with arguments `mcp --root /path/to/your/worktree`. Evidence paths are relative to that worktree. The default server can replay evidence and render it for an engineer, reviewer or customer. `doctor` reports the enabled capabilities.

| Tool | When it is available |
| --- | --- |
| `replay(bundle)` | Default. Recompute the technical verdict from an existing bundle. |
| `receipt_summary(bundle, audience)` | Default. Explain the recorded evidence. |
| `init(folder)` | Start with `--allow-init` to create a new starter directory. |
| `doctor()` | Start with `--fixture PATH` to run diagnoses against one approved fixture. |
| `run(folder, mode)` | Start with `--fixture PATH` to run that fixture and write a fresh evidence directory. |

Approve only a fixture you would run yourself. The opt-in check can execute Python and call the app’s deletion endpoint. Start it in a disposable environment with synthetic data and least-privilege fixture credentials. The fixture and its imported code use the server user's permissions. A change to the approved entry file requires review and a server restart.

Use the [Setrya erasure skill](../setrya/resources/skills/setrya-erasure/SKILL.md) in clients that accept agent skills. Copy the skill directory into the client's configured skills location and point the agent at the repo's fixture and inventory. For pull requests, use the [GitHub Action](github-action.md) to publish the authoritative CI result.
