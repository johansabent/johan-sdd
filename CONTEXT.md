# Johan Spec-Driven Delivery

This context names the delivery and session concepts shared by the product, its agent adapters,
and its host integrations.

## Language

**Delivery spine**:
The ordered engineering artifacts that carry a feature from specification through verified slices.
_Avoid_: Framework, process replacement

**Delivery envelope**:
The ownership, identity, readiness, verification, publication, and closeout rules surrounding the delivery spine.
_Avoid_: Spine, Spec Kit flow

**Profile**:
A named depth of delivery work. `lean` is the default depth; `full` adds evidence for higher-risk work without changing the meaning of the flow.
_Avoid_: Mode, policy level

**Lane**:
A class of work with a stable admission and delivery contract, such as `micro` or `feature`.
_Avoid_: Profile, task size

**Session claim**:
A time-bounded declaration that one session owns a worktree and named shared resources.
_Avoid_: Worktree registration, permanent lock

**Authority mode**:
The single canonical writer selected for a session's durable lifecycle state.
_Avoid_: Capture format, storage preference

**Capture**:
A validated, non-canonical account of session state and evidence produced for a downstream authority.
_Avoid_: Wrap, promotion, transcript

**Promotion**:
The separately authorized act that incorporates a capture into the current canonical session authority.
_Avoid_: Capture, generation

**Cutover marker**:
Durable evidence after which new sessions use Buzz events rather than legacy JSON as their authority.
_Avoid_: Installation complete, feature flag

**Desired state**:
A portable declaration of intended integration behavior that does not itself mutate a host.
_Avoid_: Installation, applied state

**Preview**:
A content-addressed proposal calculated from desired state and measured pre-state.
_Avoid_: Dry-run log, approval

**Evidence packet**:
A compact, reproducible handoff that binds contracts, commits, commands, results, risks, and the next consumer.
_Avoid_: Chat summary, transcript
