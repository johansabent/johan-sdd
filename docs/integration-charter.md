# Integration charter v1

This document explains the normative machine-readable contract in
`manifests/integration-charter.v1.json`. If prose and JSON disagree, the versioned JSON contract
wins. Changes to that contract require the root coordinator to accept them explicitly.

Every executable contract is registered with its exact repository-relative schema path in the
machine-readable charter's `contract_registry`. Implementations must not infer an unregistered
contract from prose or accept a similarly named schema from another source.

## Product seam

`johan-sdd` is a downstream integration product, not a fork. It pins a delivery-spine upstream and
an engineering-flow upstream independently and preserves their output. The portable core exposes
`phase-router/v1` and `engineering-flow-hub/v1`; `spec-driven-delivery/v1` joins them behind one
small interface. A host may bind those interfaces through an optional adapter. The bundled
`johan-host-adapter/v1` binds `using-johan-skills` and `ask-matt`, but the core contract remains
valid when that adapter is absent.

Exactly one lane is selected:

| Lane | Admission | Spine | Checkout |
| --- | --- | --- | --- |
| `micro` | At most 3 files/50 lines, docs or non-operational config only | None | Clean primary |
| `small` | Bounded engineering work without durable feature artifacts | Engineering-flow modules | Primary for read-only; isolated for mutation |
| `feature` | Medium/large work or any elevated-risk surface | Delivery spine with engineering-flow auxiliaries | Isolated worktree |

Ambiguity escalates rather than silently using `micro`. Tracker fields own business intent, owner,
and status; Git artifacts own engineering specs, plans, tasks, and evidence. No actor writes the
same spec/task to both authorities.

## Profiles

`lean` is the default. It produces spec, plan, tasks, implementation slices, verification, and
review. `full` adds constitution references, checklists, analysis, and convergence when the change
touches public contracts, architecture, security, identity, migrations, multiple systems,
destructive/external effects, or has high uncertainty/blast radius. Automatic selection explains
itself in one line. Natural language may always escalate. A downgrade is valid only when no hard
trigger applies and an explicit human decision receipt records the exception.

A constitution records only project-specific principles and links to authoritative instructions;
it does not copy `AGENTS.md` or design documentation.

## Desired state and host application

The product never writes directly into an agent home. Desired state names an abstract `target_id`,
the trust-root and allowlist hashes, and normalized repository-relative POSIX paths. Create and
replace operations reference content as `sha256:<digest>`; desired state carries neither a raw
target path nor raw content.

A strict `preview/v1` binds the desired-state hash, target ID, measured pre-state, trust root,
allowlist, exact operations, and expiry. A separately authorized host owner applies an unexpired
preview and emits an `apply-receipt/v1` binding its actor policy, exact operations, readback, and
rollback outcome. A changed pre-state or expired preview invalidates the transaction. Authority,
target, runner, hook, installer, permission, trust-root, or allowlist changes return to a human
gate.

## Session and resource ownership

`agent-work-session/v1` claims live beside, and do not replace, the existing worktree orientation
registry in the Git common directory. A revision compare-and-swap plus exclusive file lock and
atomic replacement serializes writers. Each claim binds feature or micro mode, agent/model,
host/PID/process start, hashed lease token, generation, heartbeat/expiry/TTL, a canonical worktree
object, and typed shared resources.

Worktrees isolate files, not those shared resources. Conflicting resource claims block the mutable
operation. An unreadable registry or ambiguous double owner also fails closed for mutations while
remaining inspectable. The 90-minute lease uses opportunistic heartbeats; expiry alone is not
proof of abandonment. Process identity includes PID and process start time, and unreachable remote
hosts are recorded as such. Feature mutation requires a linked worktree. Micro work requires the
clean primary checkout and closes or escalates instead of pausing. A clean paused feature records
`dirty=false`; a dirty paused feature must carry `pause-recovery/v1`.

Authority is derived from the durable cutover marker, session start, Buzz readiness, and transition
health; callers cannot override it. The four decision results are
`pre_cutover_json_authority`, `blocked_authority_transition`,
`post_cutover_buzz_authority`, and `post_cutover_fallback_evidence`. Each lifecycle event has
exactly one sink. Pre-cutover JSON writes only `SessionArtifactV1`; healthy post-cutover events
write only Buzz. A blocked transition writes neither. Post-cutover fallback is evidence in a
non-canonical ledger and must never recreate or update `SessionArtifactV1`. Dual-write is forbidden.

### Dirty-pause recovery

A dirty feature may pause only in a dedicated worktree. Before creating recovery state, scan both
path names and content for secret-shaped material and stop on suspicion. Record the original HEAD,
SHA-256 of porcelain-v2 status, and every non-ignored untracked path.

Build a synthetic commit from the complete non-ignored worktree using a temporary
`GIT_INDEX_FILE`: `read-tree HEAD`, `add -A`, `write-tree`, `commit-tree`, then `update-ref` to
`refs/agent-sessions/<session-id>`. This must not touch the real index, worktree, branch, or HEAD.
The protected ref keeps tracked modifications, deletions, and untracked files reachable until an
explicit verified cleanup. Pointing a ref at HEAD or relying on an incomplete `stash create` does
not satisfy the contract. Handoff to a different owner requires an authorized local checkpoint
commit.

## Capture authority

The session owner generates and validates `capture-packet/v2`; v1 is not silently extended. The
packet binds a deterministic capture ID, RFC 8785 packet digest, lifecycle cursor, generator
identity, constrained lifecycle payload, and durable authority-decision reference. It does not let
the generator select authority mode or sink.

A distinct promoter creates `promotion-request/v1` after acquiring a durable cross-process lock.
The request binds packet hash, authority decision and revision, promoter policy, fencing token,
target preimage, and planned next digest. `promotion-receipt/v1` records `prepared`, `committed`,
`failed`, or `needs_recovery`; a committed receipt proves the planned digest by readback, while a
recovery receipt binds rollback evidence. A dashboard outage leaves the lease and pending capture
recoverable. `/wrap` remains agent-learning work and is never treated as capture.

## Upgrades and rollback

The updater accepts only immutable tag objects and peeled commits already anchored in the trust
root. It tests manifest/schema validation, both profiles, Codex and Claude adapters, host preview,
and exact rollback in a disposable worktree. Unknown or dirty targets are skipped and reported.
It cannot edit its trust root, allowlist, permissions, runners, hooks, installer, target roots, or
agent homes. Rollback restores the old manifest, content, and pins and proves them by hash readback.

## Evidence

Every slice, pause, handoff, close, update, and rollback produces an evidence packet binding its
event type, agent/model, base/final Git SHAs, worktree and claim refs, non-empty contracts, changes,
verification, hashed artifacts/logs, decisions, risks, and an exact next consumer/action. Each
event carries its reconstructing artifact: slice manifest, session capture, handoff manifest,
closeout receipt, update manifest, or rollback receipt. A transcript or compacted conversation is
not evidence; missing evidence returns the workstream to `needs-reconstruction`.
