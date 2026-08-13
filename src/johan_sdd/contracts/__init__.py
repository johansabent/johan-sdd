"""Public semantic validation seam for versioned Johan SDD contracts.

JSON Schema owns document shape and formats.  This module deliberately uses only
the standard library and validates invariants that span fields or documents.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
import re
from typing import Any


Contract = Mapping[str, Any]
ContractError = dict[str, object]
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[/\\]")


def _error(code: str, path: str, message: str) -> ContractError:
    return {"code": code, "path": path, "message": message}


def _portable_path_error(value: object, path: str) -> ContractError | None:
    if not isinstance(value, str):
        return None
    if "\\" in value:
        return _error("path.not-posix", path, "paths must use POSIX separators")
    if value.startswith("/") or _WINDOWS_ABSOLUTE.match(value):
        return _error("path.absolute", path, "paths must be repository-relative")
    segments = value.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return _error("path.dot-segment", path, "paths must not contain dot segments")
    if any(segment == "" for segment in segments):
        return _error("path.not-normalized", path, "paths must be normalized")
    return None


def _operation_errors(document: Contract) -> list[ContractError]:
    errors: list[ContractError] = []
    operations = document.get("operations")
    if not isinstance(operations, Sequence) or isinstance(operations, (str, bytes)):
        return errors
    seen: set[str] = set()
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            continue
        prefix = f"/operations/{index}"
        path = operation.get("path")
        path_error = _portable_path_error(path, f"{prefix}/path")
        if path_error:
            errors.append(path_error)
        if isinstance(path, str):
            if path in seen:
                errors.append(
                    _error(
                        "operation.duplicate-path",
                        f"{prefix}/path",
                        "each target path may appear only once",
                    )
                )
            seen.add(path)
        if operation.get("action") == "remove" and "content_ref" in operation:
            errors.append(
                _error(
                    "operation.remove-has-content",
                    f"{prefix}/content_ref",
                    "remove operations must omit content_ref",
                )
            )
    return errors


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _validate_desired_state(document: Contract) -> list[ContractError]:
    return _operation_errors(document)


def _validate_preview(document: Contract) -> list[ContractError]:
    errors = _operation_errors(document)
    created = _parse_time(document.get("created_at"))
    expires = _parse_time(document.get("expires_at"))
    if created is not None and expires is not None and expires <= created:
        errors.append(
            _error("preview.invalid-expiry", "/expires_at", "preview must expire after creation")
        )
    return errors


def _validate_apply_receipt(document: Contract) -> list[ContractError]:
    errors = _operation_errors(document)
    applied = _parse_time(document.get("applied_at"))
    expires = _parse_time(document.get("preview_expires_at"))
    if applied is not None and expires is not None and applied > expires:
        errors.append(
            _error("apply.preview-expired", "/applied_at", "application occurred after preview expiry")
        )

    planned = document.get("operations")
    readback = document.get("readback")
    if isinstance(planned, Sequence) and isinstance(readback, Mapping):
        observed = readback.get("operations")
        if isinstance(observed, Sequence):
            planned_paths = [item.get("path") for item in planned if isinstance(item, Mapping)]
            observed_paths = [item.get("path") for item in observed if isinstance(item, Mapping)]
            if planned_paths != observed_paths:
                errors.append(
                    _error(
                        "apply.operation-mismatch",
                        "/readback/operations",
                        "readback operations must exactly match the preview operation order",
                    )
                )
            else:
                result_by_action = {
                    "create": "created",
                    "replace": "replaced",
                    "remove": "removed",
                }
                for index, (operation, result) in enumerate(zip(planned, observed, strict=True)):
                    if not isinstance(operation, Mapping) or not isinstance(result, Mapping):
                        continue
                    action = operation.get("action")
                    expected_result = result_by_action.get(action)
                    if expected_result is not None and result.get("result") != expected_result:
                        errors.append(
                            _error(
                                "apply.result-mismatch",
                                f"/readback/operations/{index}/result",
                                f"{action} operations require a {expected_result} readback result",
                            )
                        )
                    content_ref = operation.get("content_ref")
                    if isinstance(content_ref, str) and content_ref.startswith("sha256:"):
                        if result.get("content_sha256") != content_ref.removeprefix("sha256:"):
                            errors.append(
                                _error(
                                    "apply.content-mismatch",
                                    f"/readback/operations/{index}/content_sha256",
                                    "readback content must match the planned content reference",
                                )
                            )
    return errors


def _claim_is_active(claim: Mapping[str, Any]) -> bool:
    return claim.get("state") not in {"closed", "abandoned"}


def _resource_key(resource: Mapping[str, Any]) -> tuple[object, object]:
    return resource.get("resource_type"), resource.get("resource_id")


def _validate_session_registry(document: Contract) -> list[ContractError]:
    errors: list[ContractError] = []
    claims = document.get("claims")
    if not isinstance(claims, Sequence) or isinstance(claims, (str, bytes)):
        return errors

    seen_sessions: dict[object, int] = {}
    active_worktrees: dict[str, int] = {}
    active_resources: dict[tuple[object, object], tuple[int, object]] = {}

    for index, claim in enumerate(claims):
        if not isinstance(claim, Mapping):
            continue
        prefix = f"/claims/{index}"
        session_id = claim.get("session_id")
        if session_id in seen_sessions:
            errors.append(
                _error("session.duplicate-id", f"{prefix}/session_id", "session IDs must be unique")
            )
        else:
            seen_sessions[session_id] = index

        mode = claim.get("mode")
        state = claim.get("state")
        dirty = claim.get("dirty")
        worktree = claim.get("worktree")
        kind = worktree.get("kind") if isinstance(worktree, Mapping) else None
        if mode == "feature" and kind != "linked":
            errors.append(
                _error(
                    "worktree.feature-requires-linked",
                    f"{prefix}/worktree/kind",
                    "feature sessions require an isolated linked worktree",
                )
            )
        if mode == "micro":
            if kind != "primary":
                errors.append(
                    _error(
                        "worktree.micro-requires-primary",
                        f"{prefix}/worktree/kind",
                        "micro sessions run only in the clean primary checkout",
                    )
                )
            if state == "paused":
                errors.append(
                    _error(
                        "session.micro-cannot-pause",
                        f"{prefix}/state",
                        "micro sessions must close or escalate instead of pausing",
                    )
                )
            if dirty is not False:
                errors.append(
                    _error(
                        "session.micro-must-be-clean",
                        f"{prefix}/dirty",
                        "micro sessions must keep the primary checkout clean",
                    )
                )

        if isinstance(worktree, Mapping):
            worktree_path = worktree.get("path")
            if isinstance(worktree_path, str) and not (
                worktree_path.startswith("/") or _WINDOWS_ABSOLUTE.match(worktree_path)
            ):
                errors.append(
                    _error(
                        "worktree.path-not-absolute",
                        f"{prefix}/worktree/path",
                        "canonical worktree paths must be absolute host paths",
                    )
                )
            if isinstance(worktree_path, str) and (
                "\\" in worktree_path
                or worktree_path.endswith("/")
                or "//" in worktree_path
                or "/./" in worktree_path
                or "/../" in worktree_path
            ):
                errors.append(
                    _error(
                        "worktree.path-not-canonical",
                        f"{prefix}/worktree/path",
                        "worktree paths must use canonical forward-slash form without dot or trailing segments",
                    )
                )

        recovery = claim.get("recovery")
        if dirty is True and state == "paused" and not isinstance(recovery, Mapping):
            errors.append(
                _error(
                    "session.dirty-pause-missing-recovery",
                    f"{prefix}/recovery",
                    "dirty paused sessions require a recovery snapshot",
                )
            )
        if isinstance(recovery, Mapping):
            expected_ref = f"refs/agent-sessions/{session_id}"
            if recovery.get("protected_ref") != expected_ref:
                errors.append(
                    _error(
                        "recovery.ref-session-mismatch",
                        f"{prefix}/recovery/protected_ref",
                        "protected recovery ref must be bound to the session ID",
                    )
                )
            untracked = recovery.get("untracked_paths")
            if isinstance(untracked, Sequence) and not isinstance(untracked, (str, bytes)):
                for path_index, path_value in enumerate(untracked):
                    path_error = _portable_path_error(
                        path_value,
                        f"{prefix}/recovery/untracked_paths/{path_index}",
                    )
                    if path_error:
                        errors.append(path_error)

        lease = claim.get("lease")
        if isinstance(lease, Mapping):
            acquired = _parse_time(lease.get("acquired_at"))
            heartbeat = _parse_time(lease.get("heartbeat_at"))
            expires = _parse_time(lease.get("expires_at"))
            ttl = lease.get("ttl_seconds")
            process = claim.get("process")
            process_started = _parse_time(process.get("started_at")) if isinstance(process, Mapping) else None
            if process_started is not None and acquired is not None and process_started > acquired:
                errors.append(
                    _error(
                        "process.started-after-lease",
                        f"{prefix}/process/started_at",
                        "process start time cannot follow lease acquisition",
                    )
                )
            if acquired is not None and heartbeat is not None and heartbeat < acquired:
                errors.append(
                    _error(
                        "lease.heartbeat-before-acquisition",
                        f"{prefix}/lease/heartbeat_at",
                        "lease heartbeat cannot precede acquisition",
                    )
                )
            if heartbeat is not None and expires is not None and isinstance(ttl, int):
                if int((expires - heartbeat).total_seconds()) != ttl:
                    errors.append(
                        _error(
                            "lease.ttl-mismatch",
                            f"{prefix}/lease/expires_at",
                            "lease expiry must equal heartbeat plus TTL",
                        )
                    )

        resources = claim.get("resources")
        local_resources: set[tuple[object, object]] = set()
        if isinstance(resources, Sequence) and not isinstance(resources, (str, bytes)):
            for resource_index, resource in enumerate(resources):
                if not isinstance(resource, Mapping):
                    continue
                key = _resource_key(resource)
                if key in local_resources:
                    errors.append(
                        _error(
                            "resource.duplicate",
                            f"{prefix}/resources/{resource_index}",
                            "a claim may name each resource only once",
                        )
                    )
                local_resources.add(key)

        if not _claim_is_active(claim):
            continue
        if isinstance(worktree, Mapping) and isinstance(worktree.get("path"), str):
            canonical_path = worktree["path"].replace("\\", "/").rstrip("/").casefold()
            if canonical_path in active_worktrees:
                errors.append(
                    _error(
                        "worktree.conflict",
                        f"{prefix}/worktree/path",
                        "active claims cannot own the same canonical worktree",
                    )
                )
            else:
                active_worktrees[canonical_path] = index
        if isinstance(resources, Sequence) and not isinstance(resources, (str, bytes)):
            for resource_index, resource in enumerate(resources):
                if not isinstance(resource, Mapping):
                    continue
                key = _resource_key(resource)
                access = resource.get("access")
                prior = active_resources.get(key)
                if prior is not None and (access == "exclusive" or prior[1] == "exclusive"):
                    errors.append(
                        _error(
                            "resource.conflict",
                            f"{prefix}/resources/{resource_index}",
                            "active resource claims conflict when either access is exclusive",
                        )
                    )
                else:
                    active_resources[key] = (index, access)
    return errors


def _validate_recovery(document: Contract) -> list[ContractError]:
    errors: list[ContractError] = []
    untracked = document.get("untracked_paths")
    if isinstance(untracked, Sequence) and not isinstance(untracked, (str, bytes)):
        for index, path_value in enumerate(untracked):
            path_error = _portable_path_error(path_value, f"/untracked_paths/{index}")
            if path_error:
                errors.append(path_error)
    return errors


def _no_semantic_errors(document: Contract) -> list[ContractError]:
    del document
    return []


def _validate_human_decision(document: Contract) -> list[ContractError]:
    recorded_at = _parse_time(document.get("recorded_at"))
    human = document.get("human")
    confirmed_at = _parse_time(human.get("confirmed_at")) if isinstance(human, Mapping) else None
    if recorded_at is not None and confirmed_at is not None and confirmed_at > recorded_at:
        return [
            _error(
                "decision.confirmed-after-recorded",
                "/human/confirmed_at",
                "human confirmation cannot occur after the receipt is recorded",
            )
        ]
    return []


def _validate_content_bundle(document: Contract) -> list[ContractError]:
    errors: list[ContractError] = []
    entries = document.get("entries")
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        return errors
    seen_paths: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        prefix = f"/entries/{index}"
        logical_path = entry.get("logical_path")
        if isinstance(logical_path, str):
            if logical_path in seen_paths:
                errors.append(
                    _error(
                        "content.duplicate-logical-path",
                        f"{prefix}/logical_path",
                        "each logical path must resolve exactly once",
                    )
                )
            seen_paths.add(logical_path)
        content_sha256 = entry.get("content_sha256")
        resolved_ref = entry.get("resolved_ref")
        if isinstance(content_sha256, str) and resolved_ref != f"sha256:{content_sha256}":
            errors.append(
                _error(
                    "content.digest-mismatch",
                    f"{prefix}/resolved_ref",
                    "resolved content reference must match the verified content digest",
                )
            )
    return errors


def _validate_micro_assessment(document: Contract) -> list[ContractError]:
    changes = document.get("changes")
    if not isinstance(changes, Mapping):
        return []
    additions = changes.get("additions")
    deletions = changes.get("deletions")
    changed_lines = changes.get("changed_lines")
    if (
        isinstance(additions, int)
        and not isinstance(additions, bool)
        and isinstance(deletions, int)
        and not isinstance(deletions, bool)
        and isinstance(changed_lines, int)
        and not isinstance(changed_lines, bool)
        and changed_lines != additions + deletions
    ):
        return [
            _error(
                "micro.changed-lines-mismatch",
                "/changes/changed_lines",
                "changed_lines must equal additions plus deletions",
            )
        ]
    return []


def _validate_cutover_marker(document: Contract) -> list[ContractError]:
    revision = document.get("revision")
    cas = document.get("cas")
    expected_revision = cas.get("expected_revision") if isinstance(cas, Mapping) else None
    if (
        isinstance(revision, int)
        and not isinstance(revision, bool)
        and isinstance(expected_revision, int)
        and not isinstance(expected_revision, bool)
        and revision != expected_revision + 1
    ):
        return [
            _error(
                "cutover.invalid-revision-advance",
                "/revision",
                "marker revision must equal expected_revision plus one",
            )
        ]
    return []


def _validate_update_manifest(document: Contract) -> list[ContractError]:
    current = document.get("current")
    bindings = document.get("bindings")
    prestate = bindings.get("prestate") if isinstance(bindings, Mapping) else None
    if not isinstance(current, Mapping) or not isinstance(prestate, Mapping):
        return []
    for field in ("manifest_sha256", "pins_sha256"):
        current_value = current.get(field)
        prestate_value = prestate.get(field)
        if current_value is not None and prestate_value is not None and current_value != prestate_value:
            return [
                _error(
                    "update.prestate-mismatch",
                    f"/bindings/prestate/{field}",
                    "measured prestate must match the current update manifest and pins",
                )
            ]
    return []


def _validate_rollback_receipt(document: Contract) -> list[ContractError]:
    if document.get("terminal_status") != "rolled_back":
        return []
    snapshots = document.get("snapshots")
    readback = document.get("readback")
    if not isinstance(snapshots, Mapping) or not isinstance(readback, Mapping):
        return []
    pre_update = snapshots.get("pre_update")
    post_rollback = snapshots.get("post_rollback")
    components = readback.get("components")
    if not isinstance(pre_update, Mapping) or not isinstance(post_rollback, Mapping):
        return []
    errors: list[ContractError] = []
    for component in ("content", "pins", "manifest"):
        field = f"{component}_sha256"
        expected = pre_update.get(field)
        observed = post_rollback.get(field)
        if expected != observed:
            errors.append(
                _error(
                    "rollback.snapshot-mismatch",
                    f"/snapshots/post_rollback/{field}",
                    "post-rollback snapshot must exactly restore pre-update hashes",
                )
            )
        component_readback = components.get(component) if isinstance(components, Mapping) else None
        if isinstance(component_readback, Mapping):
            readback_matches = (
                component_readback.get("expected_preupdate_sha256") == expected
                and component_readback.get("observed_postrollback_sha256") == observed
                and component_readback.get("status") == "matched"
                and expected == observed
            )
            if not readback_matches:
                errors.append(
                    _error(
                        "rollback.readback-mismatch",
                        f"/readback/components/{component}",
                        "successful rollback readback must bind equal pre-update and post-rollback hashes",
                    )
                )
    return errors


_AUTHORITY_SINKS = {
    "pre_cutover_json_authority": "session_artifact_v1",
    "blocked_authority_transition": "none",
    "post_cutover_buzz_authority": "buzz_event",
    "post_cutover_fallback_evidence": "noncanonical_fallback_ledger",
}


def _validate_capture_packet(document: Contract) -> list[ContractError]:
    return []


def _validate_promotion(document: Contract) -> list[ContractError]:
    errors: list[ContractError] = []
    generator_actor = document.get("generator_actor_id")
    promoter = document.get("promoter")
    if isinstance(promoter, Mapping) and promoter.get("actor_id") == generator_actor:
        errors.append(
            _error(
                "promotion.actor-not-distinct",
                "/promoter/actor_id",
                "capture generator and promoter must be distinct actors",
            )
        )
    authority = document.get("authority")
    if isinstance(authority, Mapping):
        expected_sink = _AUTHORITY_SINKS.get(authority.get("mode"))
        if expected_sink is not None and authority.get("sink") != expected_sink:
            errors.append(
                _error(
                    "promotion.sink-mismatch",
                    "/authority/sink",
                    "promotion sink must match the external authority decision",
                )
            )
        if authority.get("mode") == "blocked_authority_transition":
            target = document.get("target")
            if isinstance(target, Mapping) and target.get("next_digest") != target.get("preimage_digest"):
                errors.append(
                    _error(
                        "promotion.blocked-changes-target",
                        "/target/next_digest",
                        "blocked authority must preserve the target preimage",
                    )
                )
    if document.get("phase") == "committed":
        target = document.get("target")
        if isinstance(target, Mapping) and document.get("readback_digest") != target.get("next_digest"):
            errors.append(
                _error(
                    "promotion.readback-mismatch",
                    "/readback_digest",
                    "committed readback must equal the planned next digest",
                )
            )
    return errors


_EVENT_ARTIFACTS = {
    "slice": "slice-manifest",
    "pause": "session-capture",
    "handoff": "handoff-manifest",
    "close": "closeout-receipt",
    "update": "update-manifest",
    "rollback": "rollback-receipt",
}


def _validate_evidence(document: Contract) -> list[ContractError]:
    errors: list[ContractError] = []
    event_type = document.get("event_type")
    required_kind = _EVENT_ARTIFACTS.get(event_type)
    artifacts = document.get("artifacts")
    artifact_kinds: set[object] = set()
    if isinstance(artifacts, Sequence) and not isinstance(artifacts, (str, bytes)):
        artifact_kinds = {
            artifact.get("kind") for artifact in artifacts if isinstance(artifact, Mapping)
        }
    if required_kind is not None and required_kind not in artifact_kinds:
        errors.append(
            _error(
                "evidence.missing-event-artifact",
                "/artifacts",
                f"{event_type} evidence requires a {required_kind} artifact",
            )
        )

    changes = document.get("changes")
    if isinstance(changes, Sequence) and not isinstance(changes, (str, bytes)):
        for index, change in enumerate(changes):
            if not isinstance(change, Mapping):
                continue
            path_error = _portable_path_error(change.get("path"), f"/changes/{index}/path")
            if path_error:
                errors.append(path_error)

    git = document.get("git")
    if event_type != "pause" and isinstance(git, Mapping):
        if git.get("base_sha") == git.get("final_sha"):
            errors.append(
                _error(
                    "evidence.unchanged-final-sha",
                    "/git/final_sha",
                    f"{event_type} evidence must identify a resulting Git revision",
                )
            )
    return errors


_UPDATER_PROHIBITIONS = {
    "hooks",
    "installer",
    "host-policy",
    "trust-root",
    "allowlist",
    "agent-home",
    "permissions",
    "runner",
    "target-root",
}


def _validate_charter(document: Contract) -> list[ContractError]:
    updater = document.get("updater")
    if not isinstance(updater, Mapping):
        return []
    prohibitions = updater.get("never_automatic")
    present = set(prohibitions) if isinstance(prohibitions, Sequence) and not isinstance(prohibitions, (str, bytes)) else set()
    missing = sorted(_UPDATER_PROHIBITIONS - present)
    if missing:
        return [
            _error(
                "updater.missing-prohibition",
                "/updater/never_automatic",
                f"updater must prohibit automatic changes to: {', '.join(missing)}",
            )
        ]
    return []


_VALIDATORS: dict[str, Callable[[Contract], list[ContractError]]] = {
    "johan-sdd/desired-state/v1": _validate_desired_state,
    "johan-sdd/preview/v1": _validate_preview,
    "johan-sdd/apply-receipt/v1": _validate_apply_receipt,
    "agent-work-session/v1": _validate_session_registry,
    "johan-sdd/pause-recovery/v1": _validate_recovery,
    "johan-sdd/cli-invocation/v1": _no_semantic_errors,
    "johan-sdd/human-decision-receipt/v1": _validate_human_decision,
    "johan-sdd/content-bundle/v1": _validate_content_bundle,
    "johan-sdd/evidence-artifact/v1": _no_semantic_errors,
    "johan-sdd/micro-assessment/v1": _validate_micro_assessment,
    "johan-sdd/secret-scan-receipt/v1": _no_semantic_errors,
    "johan-sdd/authority-decision/v1": _no_semantic_errors,
    "johan-sdd/cutover-marker/v1": _validate_cutover_marker,
    "johan-sdd/update-manifest/v1": _validate_update_manifest,
    "johan-sdd/rollback-receipt/v1": _validate_rollback_receipt,
    "johan-sdd/capture-packet/v2": _validate_capture_packet,
    "johan-sdd/promotion-request/v1": _validate_promotion,
    "johan-sdd/promotion-receipt/v1": _validate_promotion,
    "johan-sdd/evidence-packet/v1": _validate_evidence,
    "johan-sdd/integration-charter/v1": _validate_charter,
}


def validate_semantics(document: Contract) -> list[ContractError]:
    """Return stable, JSON-friendly semantic errors for a shaped contract.

    Unknown schema versions return one explicit error rather than silently
    passing. Callers should run the matching JSON Schema validator first.
    """

    schema_version = document.get("schema_version")
    validator = _VALIDATORS.get(schema_version) if isinstance(schema_version, str) else None
    if validator is None:
        return [
            _error(
                "contract.unsupported-version",
                "/schema_version",
                "no semantic validator is registered for this schema version",
            )
        ]
    return validator(document)


__all__ = ["ContractError", "validate_semantics"]
