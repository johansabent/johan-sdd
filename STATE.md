# State — johan-sdd

Last verified: 2026-08-13

## Current phase

Onda 1 complete locally; publication and external adoption remain gated.

## Active work

The portable runtime and its reconstructable closeout evidence are complete. A real
`johan-dashboard` PR was classified independently by Codex and Grok, then exercised through
capture generation, promotion, and idempotent replay. Claude was not invoked because Johan
reported no available Claude quota; compatibility remains contract-tested without a live claim.

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
- The locked suite passes 198 tests, and `evidence/packets/local-runtime-closeout.json` binds the
  implementation commit, verification log, charter, CLI hash, risks, and next consumer.
- All four implementation worktrees and their local task branches were removed after patch-equivalence
  and clean-worktree readback; the session registry records four closed claims at revision 3.
- `evidence/packets/dashboard-pr109-pilot.json` binds Linear/PR readiness, independent
  Codex+Grok `feature/full` decisions, Grok risk readback, and idempotent promotion proof.
- `.gitattributes` fixes LF as the repository text policy, and evidence tests hash canonical LF so
  receipts remain reproducible in worktrees created under Windows `core.autocrlf=true`.
- The pilot is integrated on `main` at `49301ee`; a fresh detached checkout passed 198 tests,
  compileall, lock validation, wheel/sdist build, evidence hashes, and clean-worktree readback.

## Blockers

No local implementation blocker. Publication and global-host adoption remain intentionally gated.
The installed Grok review wrapper also needs a separate owner update for Grok 1.0.3's lowercase
`end_turn`; the completed pilot report was recovered without retrying or changing global tooling.

## Next safe action

Johan may separately authorize remote creation/push and public publication. Any application of
desired state to a global agent home remains a different explicit gate.
