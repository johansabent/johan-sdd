# State — johan-sdd

Last verified: 2026-08-13

## Current phase

Onda 1: local runtime integrated; pilot and external adoption remain gated.

## Active work

The local runtime and its reconstructable closeout evidence are complete. The Codex+Claude pilot
is waiting at the dashboard repository's mandatory live Linear preflight.

## Locked decisions

- Public downstream product, not a fork of Spec Kit or Matt skills.
- Python 3.11 with `uv`; Codex and Claude are the first supported agents.
- Spec Kit owns the medium/large delivery spine; local adapters own the delivery envelope.
- Session ownership is per worktree plus explicit shared-resource claims.
- The product emits host desired state and never writes directly to `.agents`.
- Each session selects legacy JSON or Buzz as its authority; dual-write is forbidden.

## Human gates

- Remote creation, push, and public GitHub repository.
- Any batch that applies desired state to a global agent home.
- Work/global promotion and destructive cleanup.

## Current evidence

- Local Git repository has a verified commit history on `main`, with no remote.
- Upstream pins and local seams were independently inventoried in the active goal.
- Onboarding taxonomy classification is `personal-project` under `personal-dev-root`.
- The locked suite passes 197 tests, and `evidence/packets/local-runtime-closeout.json` binds the
  implementation commit, verification log, charter, CLI hash, risks, and next consumer.
- All four implementation worktrees and their local task branches were removed after patch-equivalence
  and clean-worktree readback; the session registry records four closed claims at revision 3.

## Blockers

The current Codex runtime exposes no Linear connector. The `johan-dashboard` hard gate requires a
live read proving workspace `johan-pc`, team `Johan PC`, key `JOH` before non-trivial pilot work.
Publication and global-host adoption also remain intentionally gated.

## Next safe action

Restore a Linear connector that proves live read access to `JOH`, then run the Codex+Claude pilot
in an isolated dashboard worktree. Do not bypass the dashboard's tracker gate.
