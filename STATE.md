# State — johan-sdd

Last verified: 2026-08-13

## Current phase

Onda 0: taxonomy, onboarding, upstream pins, and integration contracts.

## Active work

The root coordinator is establishing the public repository scaffold and freezing the first
implementation contracts before dispatching isolated workstreams.

## Locked decisions

- Public downstream product, not a fork of Spec Kit or Matt skills.
- Python 3.11 with `uv`; Codex and Claude are the first supported agents.
- Spec Kit owns the medium/large delivery spine; local adapters own the delivery envelope.
- Session ownership is per worktree plus explicit shared-resource claims.
- The product emits host desired state and never writes directly to `.agents`.
- Each session selects legacy JSON or Buzz as its authority; dual-write is forbidden.

## Human gates

- First commit, remote creation, push, and public GitHub repository.
- Any batch that applies desired state to a global agent home.
- Dashboard pilot readiness, Work/global promotion, and destructive cleanup.

## Current evidence

- Local Git repository exists on unborn `main`, with no remote or commits.
- Upstream pins and local seams were independently inventoried in the active goal.
- Onboarding taxonomy classification is `personal-project` under `personal-dev-root`.

## Blockers

No implementation blocker. Publication and global-host adoption remain intentionally gated.

## Next safe action

Validate this onboarding batch, create the product scaffold and integration charter, then dispatch
the Core, Router/Profile, and Lifecycle workstreams into isolated worktrees.
