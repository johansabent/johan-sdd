# State — johan-sdd

Last verified: 2026-08-13

## Current phase

Public product published and globally installed. Host-owner adoption of the
shared router, engineering-flow hub, and Codex compatibility alias is applied.

## Active work

None in this repository. Remaining JOH-70 work (scheduler/shared trigger and
dashboard atualizar button) lives in `johan-dashboard`, not here.

## Locked decisions

- Public downstream product, not a fork of Spec Kit or Matt skills.
- Python 3.11 with `uv`; Codex and Claude are the first supported agents.
- Spec Kit owns the feature delivery spine: spec, plan, tasks, and orchestration.
- `using-johan-skills` is the sole automatic phase router; it selects `micro`,
  `small`, or `feature`, then `lean` or `full`.
- `ask-matt` is an engineering-flow module hub, not a second artifact spine.
- `disciplined-delivery` is a compatibility alias only.
- `token-saver` bounds bulk reads and peer-review packets only.
- Exactly one lifecycle authority and one artifact sink exist per event.
- The public product emits desired state and never writes `.agents` or `.codex`.
- The private host owner applies exact desired state with approval, scoped
  pre-state, lock, readback, and rollback.

## Human gates

- Work/global promotion and destructive cleanup.
- Any later batch that changes global agent-home files outside the adopted allowlist.

## Current evidence

- Public repository: `https://github.com/johansabent/johan-sdd`.
- Verified base: `main` / `origin/main` at
  `2ced86ff5070d744f611ce9e43a01688178596b6`.
- Local functional fix: `cedf2e2872158c973a1ea7df627e82edee89e53e`
  requires `python -m johan_sdd.sessions open` to receive a live explicit
  agent process; the Python API retains its in-process default.
- `uv run --locked pytest -q`: 210 passed after the fix.
- Global install: `johan-sdd 0.1.0`.
- Spec Kit: `specify 0.16.3`, tag `v0.16.3`, commit `b85aaeda4a7aec37a6620bba9d77ab37c6589141`.
- Host-owner apply receipts are versioned in the private operations repository.
- Shared home adoption commit: `4d898cbdf7479062482ad044d192bbd4cae2631c`
  (taxonomy registration `8aec35d3c4a3f03a921998fbc1ea42ce88771331`).
- Codex home alias commit: `567ebd2089c8c23db7ff530aa66bd08df879726c`.
- Token-saver explicitly declares no authority in the shared `.agents` commit
  `12be7dd`.
- Live `johan-sdd route` returns `micro`, `small`, and `feature` for measured
  fixtures; `architecture-change` selects `full`; invalid input exits `2` and a
  lean-vs-security policy block exits `3`.
- Dashboard PR #109 merged at `57775ae22435a4431ea0aa076757d971257f1618`.

## Blockers

None for publication or the authorized global skill adoption.

## Next safe action

Shape the remaining JOH-70 scheduler/shared trigger and dashboard atualizar
button from Linear `Triage`. Do not redesign `johan-sdd`.
