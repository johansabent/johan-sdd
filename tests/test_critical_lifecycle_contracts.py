from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest


SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
GIT_A = "1" * 40
GIT_B = "2" * 40
GIT_C = "3" * 40
GIT_D = "4" * 40


def assert_schema_valid(schema_name: str, instance: dict[str, object]) -> None:
    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(instance)


def authority_decision() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/authority-decision/v1",
        "decision_id": f"authority_{SHA_A}",
        "revision": 7,
        "session": {
            "session_id": "session-01",
            "started_at": "2026-08-13T11:50:00Z",
            "decision_stage": "continuation",
            "relation_to_cutover": "started_before_cutover",
            "original_decision_ref": f"authority:{SHA_B}",
            "original_mode": "pre_cutover_json_authority",
            "original_sink": "session_artifact_v1",
        },
        "marker_observation": {
            "state": "present",
            "marker_id": f"cutover_{SHA_B}",
            "marker_revision": 3,
            "marker_sha256": SHA_C,
            "cutover_at": "2026-08-13T12:00:00Z",
        },
        "readiness": {
            "buzz": "ready",
            "transition_health": "healthy",
        },
        "derivation": {
            "derived_at": "2026-08-13T12:01:00Z",
            "inputs_sha256": SHA_B,
            "caller_override": False,
            "reason": "enrolled_authority_continuity",
        },
        "decision": {
            "mode": "pre_cutover_json_authority",
            "sink": "session_artifact_v1",
        },
        "immutability": "immutable_append_only_receipt",
    }


def test_authority_decision_preserves_existing_session_continuity() -> None:
    assert_schema_valid("authority-decision.schema.json", authority_decision())


def test_authority_decision_rejects_caller_override_and_mode_sink_mismatch() -> None:
    overridden = authority_decision()
    overridden["derivation"]["caller_override"] = True  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("authority-decision.schema.json", overridden)

    mismatched = authority_decision()
    mismatched["decision"]["sink"] = "buzz_event"  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("authority-decision.schema.json", mismatched)


@pytest.mark.parametrize(
    ("reason", "buzz", "health", "mode", "sink"),
    [
        (
            "transition_blocked",
            "ready",
            "blocked",
            "blocked_authority_transition",
            "none",
        ),
        (
            "buzz_ready",
            "ready",
            "healthy",
            "post_cutover_buzz_authority",
            "buzz_event",
        ),
        (
            "buzz_unavailable",
            "unavailable",
            "healthy",
            "post_cutover_fallback_evidence",
            "noncanonical_fallback_ledger",
        ),
    ],
)
def test_new_session_authority_is_one_exact_derived_mode_and_sink(
    reason: str,
    buzz: str,
    health: str,
    mode: str,
    sink: str,
) -> None:
    decision = authority_decision()
    decision["session"]["decision_stage"] = "initial_enrollment"  # type: ignore[index]
    decision["session"]["relation_to_cutover"] = "started_at_or_after_cutover"  # type: ignore[index]
    decision["session"].pop("original_decision_ref")  # type: ignore[union-attr]
    decision["session"].pop("original_mode")  # type: ignore[union-attr]
    decision["session"].pop("original_sink")  # type: ignore[union-attr]
    decision["readiness"] = {"buzz": buzz, "transition_health": health}
    decision["derivation"]["reason"] = reason  # type: ignore[index]
    decision["decision"] = {"mode": mode, "sink": sink}
    assert_schema_valid("authority-decision.schema.json", decision)


def test_buzz_authority_continuation_cannot_switch_to_fallback_on_outage() -> None:
    continuation = authority_decision()
    continuation["session"].update(  # type: ignore[union-attr]
        {
            "decision_stage": "continuation",
            "relation_to_cutover": "started_at_or_after_cutover",
            "original_mode": "post_cutover_buzz_authority",
            "original_sink": "buzz_event",
        }
    )
    continuation["readiness"] = {
        "buzz": "unavailable",
        "transition_health": "healthy",
    }
    continuation["derivation"]["reason"] = "enrolled_authority_continuity"  # type: ignore[index]
    continuation["decision"] = {
        "mode": "post_cutover_buzz_authority",
        "sink": "buzz_event",
    }
    assert_schema_valid("authority-decision.schema.json", continuation)

    switched = copy.deepcopy(continuation)
    switched["derivation"]["reason"] = "buzz_unavailable"  # type: ignore[index]
    switched["decision"] = {
        "mode": "post_cutover_fallback_evidence",
        "sink": "noncanonical_fallback_ledger",
    }
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("authority-decision.schema.json", switched)


@pytest.mark.parametrize(
    "field",
    ["original_decision_ref", "original_mode", "original_sink"],
)
def test_every_continuation_binds_its_original_enrollment(field: str) -> None:
    continuation = authority_decision()
    continuation["session"].pop(field)  # type: ignore[union-attr]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("authority-decision.schema.json", continuation)


def cutover_marker() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/cutover-marker/v1",
        "marker_id": f"cutover_{SHA_A}",
        "revision": 3,
        "marker_sha256": SHA_B,
        "cutover_at": "2026-08-13T12:00:00Z",
        "state": "cutover_active",
        "transition": {
            "from": "legacy_session_artifact_v1",
            "to": "buzz_event_authority",
        },
        "cas": {
            "operation": "compare_and_swap_append",
            "expected_revision": 2,
            "expected_marker_sha256": SHA_C,
            "advance_by": 1,
        },
        "evidence": {
            "decision_ref": f"decision:{SHA_A}",
            "prestate_sha256": SHA_B,
            "verification_refs": [
                {"ref": "evidence/cutover-canary.json", "sha256": SHA_C}
            ],
        },
        "mutation_policy": "append_evidence_only_no_cutover_rollback",
    }


def test_cutover_marker_carries_monotonic_cas_identity_and_evidence() -> None:
    assert_schema_valid("cutover-marker.schema.json", cutover_marker())


def test_cutover_marker_rejects_revision_or_state_rollback() -> None:
    revision_rollback = cutover_marker()
    revision_rollback["revision"] = 0
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("cutover-marker.schema.json", revision_rollback)

    state_rollback = cutover_marker()
    state_rollback["state"] = "legacy_active"
    state_rollback["transition"] = {
        "from": "buzz_event_authority",
        "to": "legacy_session_artifact_v1",
    }
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("cutover-marker.schema.json", state_rollback)

    reverse_cas = cutover_marker()
    reverse_cas["cas"]["advance_by"] = -1  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("cutover-marker.schema.json", reverse_cas)


def upstream_pin(
    upstream_id: str,
    version: str,
    tag_object: str,
    peeled_commit: str,
) -> dict[str, object]:
    return {
        "id": upstream_id,
        "source": f"https://github.com/example/{upstream_id}",
        "version": version,
        "reference_type": "annotated_tag",
        "tag_object": tag_object,
        "peeled_commit": peeled_commit,
        "anchored_in_trust_root": True,
        "trust_root_entry_sha256": SHA_A,
        "immutability": "immutable_tag_object_and_peeled_commit",
    }


def canary_receipt(name: str) -> dict[str, object]:
    return {
        "result": "passed",
        "receipt": {"ref": f"receipts/canary-{name}.json", "sha256": SHA_C},
    }


def update_manifest() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/update-manifest/v1",
        "update_id": f"update_{SHA_A}",
        "created_at": "2026-08-13T13:00:00Z",
        "target": {
            "target_id": "repo:johan-sdd",
            "status": "clean",
            "disposable_worktree": True,
        },
        "current": {
            "manifest_sha256": SHA_A,
            "pins_sha256": SHA_B,
            "upstreams": [
                upstream_pin("github-spec-kit", "v0.16.3", GIT_A, GIT_B),
                upstream_pin("matt-pocock-skills", "v1.2.3", GIT_C, GIT_D),
            ],
        },
        "candidate": {
            "manifest_sha256": SHA_B,
            "pins_sha256": SHA_C,
            "upstreams": [
                upstream_pin("github-spec-kit", "v0.17.0", GIT_C, GIT_D),
                upstream_pin("matt-pocock-skills", "v1.3.0", GIT_A, GIT_B),
            ],
        },
        "bindings": {
            "trust_root": {
                "path": "manifests/upstreams.lock.json",
                "sha256": SHA_A,
            },
            "allowlist": {
                "sha256": SHA_B,
                "entries": [
                    "pinned-upstream-content",
                    "product-owned-adapters",
                    "product-owned-presets",
                    "registered-repository-generated-overlays",
                ],
            },
            "prestate": {
                "content_sha256": SHA_A,
                "pins_sha256": SHA_B,
                "manifest_sha256": SHA_A,
            },
        },
        "authority_delta": {
            "status": "passed",
            "baseline_sha256": SHA_A,
            "candidate_sha256": SHA_B,
            "checked_fields": [
                "hooks",
                "installer",
                "host-policy",
                "trust-root",
                "allowlist",
                "agent-home",
                "permissions",
                "runner",
                "target-root",
            ],
            "prohibited_changes": [],
        },
        "canaries": {
            "environment": "disposable_worktree",
            "manifest_and_schema_validation": canary_receipt("manifest-schema"),
            "profiles": {
                "lean": canary_receipt("profile-lean"),
                "full": canary_receipt("profile-full"),
            },
            "adapters": {
                "codex": canary_receipt("adapter-codex"),
                "claude": canary_receipt("adapter-claude"),
            },
            "host_preview": canary_receipt("host-preview"),
            "rollback_drill": canary_receipt("rollback-drill"),
        },
        "apply": {
            "phase": "applied",
            "preview_receipt": {
                "ref": "receipts/update-preview.json",
                "sha256": SHA_A,
            },
            "apply_receipt": {
                "ref": "receipts/update-apply.json",
                "sha256": SHA_B,
            },
        },
    }


def test_update_manifest_binds_pins_prestate_canaries_and_receipts() -> None:
    assert_schema_valid("update-manifest.schema.json", update_manifest())


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [("reference_type", "branch"), ("anchored_in_trust_root", False)],
)
def test_update_manifest_rejects_mutable_or_unanchored_pins(
    field: str,
    unsafe_value: object,
) -> None:
    manifest = update_manifest()
    manifest["candidate"]["upstreams"][0][field] = unsafe_value  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("update-manifest.schema.json", manifest)


def test_update_manifest_rejects_prohibited_authority_expansion() -> None:
    manifest = update_manifest()
    manifest["authority_delta"]["status"] = "failed"  # type: ignore[index]
    manifest["authority_delta"]["prohibited_changes"] = ["permissions"]  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("update-manifest.schema.json", manifest)


def test_update_manifest_rejects_incomplete_canary_or_apply_receipt() -> None:
    incomplete_canary = update_manifest()
    incomplete_canary["canaries"]["adapters"].pop("claude")  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("update-manifest.schema.json", incomplete_canary)

    partial_apply = update_manifest()
    partial_apply["apply"].pop("apply_receipt")  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("update-manifest.schema.json", partial_apply)


def rollback_component(expected: str) -> dict[str, object]:
    return {
        "expected_preupdate_sha256": expected,
        "observed_postrollback_sha256": expected,
        "status": "matched",
    }


def rollback_receipt() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/rollback-receipt/v1",
        "rollback_id": f"rollback_{SHA_A}",
        "update": {
            "update_id": f"update_{SHA_B}",
            "update_manifest": {
                "ref": "receipts/update-manifest.json",
                "sha256": SHA_A,
            },
            "failed_apply_receipt": {
                "ref": "receipts/update-apply-failed.json",
                "sha256": SHA_B,
            },
            "failed_phase": "apply",
            "failed_at": "2026-08-13T13:10:00Z",
        },
        "snapshots": {
            "pre_update": {
                "content_sha256": SHA_A,
                "pins_sha256": SHA_B,
                "manifest_sha256": SHA_C,
            },
            "failed_update": {
                "content_sha256": SHA_B,
                "pins_sha256": SHA_C,
                "manifest_sha256": SHA_A,
            },
            "post_rollback": {
                "content_sha256": SHA_A,
                "pins_sha256": SHA_B,
                "manifest_sha256": SHA_C,
            },
        },
        "readback": {
            "completed_at": "2026-08-13T13:12:00Z",
            "status": "passed",
            "components": {
                "content": rollback_component(SHA_A),
                "pins": rollback_component(SHA_B),
                "manifest": rollback_component(SHA_C),
            },
            "evidence": {
                "ref": "evidence/rollback-readback.json",
                "sha256": SHA_C,
            },
        },
        "terminal_status": "rolled_back",
        "terminal_at": "2026-08-13T13:12:00Z",
    }


def test_rollback_receipt_binds_failed_update_and_exact_hash_readback() -> None:
    assert_schema_valid("rollback-receipt.schema.json", rollback_receipt())


def test_rollback_receipt_rejects_partial_rollback() -> None:
    missing_pin_snapshot = rollback_receipt()
    missing_pin_snapshot["snapshots"]["post_rollback"].pop("pins_sha256")  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("rollback-receipt.schema.json", missing_pin_snapshot)

    mismatched_pin_readback = rollback_receipt()
    mismatched_pin_readback["readback"]["components"]["pins"]["status"] = "mismatched"  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("rollback-receipt.schema.json", mismatched_pin_readback)
