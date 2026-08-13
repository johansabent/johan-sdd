# AGENTS.md — johan-sdd

`johan-sdd` is a public, portable integration product for spec-driven delivery. Read
`CONTEXT.md` for canonical language and `STATE.md` for the current gate before non-trivial work.

## Delivery contract

- Use `uv` with Python 3.11. Run locked environments and repository tests through `uv`.
- Treat the integration charter and versioned schemas as contracts. The root coordinator alone
  accepts contract changes and integrates workstreams.
- Give each implementation worker an isolated worktree plus an explicit path and resource
  allowlist. Workers do not create subagents or alter another owner's surface.
- Keep the product core host-neutral. It emits desired state, previews, transactions, and evidence;
  it never writes directly to an agent home such as `.agents`.
- Separate generation from promotion and select one session authority mode. Never dual-write a
  session to legacy JSON and Buzz.
- Preserve upstream output. Custom behavior belongs in adapters, presets, overlays, or wrappers,
  with its source revision and local delta recorded.

## Authority gates

- Inspect Git, worktrees, claims, and unrelated changes before writing.
- A valid session claim is required before a mutable feature workstream. Micro work is limited by
  the repository's classifier and cannot pause dirty in the primary checkout.
- Commits, pushes, remote creation, releases, publication, global agent-home changes, tracker
  writes, and Work/global promotion require their own current authorization.
- Keep secrets, host-specific paths, account tokens, and transcripts out of committed artifacts.

## Verification

- Start with the narrow test for the changed contract, then run the relevant unit, contract,
  concurrency, cross-agent, and rollback suites.
- A handoff is acceptable only with reproducible commands, exit codes, hashes or receipts, risks,
  and one exact next action. Conversation summaries are not verification evidence.
