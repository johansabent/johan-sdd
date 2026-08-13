from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from johan_sdd.contracts import validate_semantics


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
MANIFESTS = ROOT / "manifests"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def assert_schema_valid(schema_name: str, instance: dict[str, object]) -> None:
    schema = load_json(SCHEMAS / schema_name)
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(instance)


def desired_state() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/desired-state/v1",
        "target_id": "agent-home:shared",
        "generated_from": SHA_A,
        "trust_root_sha256": SHA_B,
        "allowlist_sha256": SHA_C,
        "operations": [
            {
                "path": "skills/spec-driven-delivery/SKILL.md",
                "action": "replace",
                "content_ref": f"sha256:{SHA_A}",
            }
        ],
    }


def preview() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/preview/v1",
        "preview_id": f"preview_{SHA_A}",
        "desired_state_sha256": SHA_A,
        "target_id": "agent-home:shared",
        "measured_prestate_sha256": SHA_B,
        "trust_root_sha256": SHA_B,
        "allowlist_sha256": SHA_C,
        "operations": desired_state()["operations"],
        "created_at": "2026-08-13T12:00:00Z",
        "expires_at": "2026-08-13T12:15:00Z",
    }


def apply_receipt() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/apply-receipt/v1",
        "receipt_id": f"apply_{SHA_A}",
        "preview_sha256": SHA_C,
        "desired_state_sha256": SHA_A,
        "target_id": "agent-home:shared",
        "measured_prestate_sha256": SHA_B,
        "operations": preview()["operations"],
        "preview_expires_at": "2026-08-13T12:15:00Z",
        "applied_at": "2026-08-13T12:10:00Z",
        "actor_policy": {
            "actor_id": "host-owner:shared-agents",
            "policy_id": "host-policy:personal-agent-home",
            "policy_revision": 7,
            "policy_sha256": SHA_C,
        },
        "readback": {
            "poststate_sha256": SHA_C,
            "operations": [
                {
                    "path": "skills/spec-driven-delivery/SKILL.md",
                    "result": "replaced",
                    "content_sha256": SHA_A,
                }
            ],
        },
        "rollback": {"status": "not-required"},
    }


def test_portable_core_does_not_require_johan_host_names() -> None:
    charter = load_json(MANIFESTS / "integration-charter.v1.json")
    portable = copy.deepcopy(charter)
    portable.pop("host_adapters")
    assert_schema_valid("integration-charter.schema.json", portable)
    core_text = json.dumps(portable, sort_keys=True)
    assert "using-johan-skills" not in core_text
    assert "ask-matt" not in core_text


def test_desired_state_preview_and_apply_receipt_bind_portable_transaction() -> None:
    for schema_name, instance in [
        ("desired-state.schema.json", desired_state()),
        ("preview.schema.json", preview()),
        ("apply-receipt.schema.json", apply_receipt()),
    ]:
        assert_schema_valid(schema_name, instance)
        assert validate_semantics(instance) == []


@pytest.mark.parametrize(
    ("unsafe_path", "code"),
    [
        ("../escape", "path.dot-segment"),
        ("skills\\windows.md", "path.not-posix"),
        ("/absolute/file", "path.absolute"),
        ("skills/./file", "path.dot-segment"),
        ("skills//file", "path.not-normalized"),
    ],
)
def test_desired_state_rejects_nonportable_paths(unsafe_path: str, code: str) -> None:
    instance = desired_state()
    instance["operations"][0]["path"] = unsafe_path  # type: ignore[index]
    errors = validate_semantics(instance)
    assert errors[0]["code"] == code
    assert errors[0]["path"] == "/operations/0/path"


def test_remove_operation_cannot_smuggle_content() -> None:
    instance = desired_state()
    operation = instance["operations"][0]  # type: ignore[index]
    operation["action"] = "remove"
    errors = validate_semantics(instance)
    assert errors == [
        {
            "code": "operation.remove-has-content",
            "path": "/operations/0/content_ref",
            "message": "remove operations must omit content_ref",
        }
    ]


def test_apply_receipt_rejects_expired_or_changed_operation_plan() -> None:
    receipt = apply_receipt()
    receipt["applied_at"] = "2026-08-13T12:16:00Z"
    receipt["readback"]["operations"][0]["path"] = "other/path"  # type: ignore[index]
    assert [error["code"] for error in validate_semantics(receipt)] == [
        "apply.preview-expired",
        "apply.operation-mismatch",
    ]


def test_apply_readback_must_match_each_exact_operation_result() -> None:
    receipt = apply_receipt()
    receipt["readback"]["operations"][0]["result"] = "created"  # type: ignore[index]
    assert validate_semantics(receipt) == [
        {
            "code": "apply.result-mismatch",
            "path": "/readback/operations/0/result",
            "message": "replace operations require a replaced readback result",
        }
    ]


def test_apply_receipt_cannot_drop_planned_content_reference() -> None:
    receipt = apply_receipt()
    receipt["operations"][0].pop("content_ref")  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("apply-receipt.schema.json", receipt)


def session_claim(
    session_id: str = "session-01",
    *,
    mode: str = "feature",
    kind: str = "linked",
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "mode": mode,
        "owner": {"agent": "codex", "model": "gpt-5.6-terra"},
        "process": {
            "host": "dev-host",
            "pid": 4242,
            "started_at": "2026-08-13T12:00:00Z",
        },
        "lease": {
            "token_hash": f"sha256:{SHA_A}",
            "generation": 1,
            "acquired_at": "2026-08-13T12:00:00Z",
            "heartbeat_at": "2026-08-13T12:10:00Z",
            "expires_at": "2026-08-13T13:40:00Z",
            "ttl_seconds": 5400,
        },
        "worktree": {
            "repo_id": "repo:johan-sdd",
            "worktree_id": f"worktree:{session_id}",
            "path": f"D:/repo-worktrees/{session_id}",
            "kind": kind,
            "branch": f"codex/session/{session_id}",
        },
        "state": "working",
        "dirty": False,
        "authority_decision_ref": f"authority:{session_id}:1",
        "resources": [
            {
                "resource_type": "repo-files",
                "resource_id": f"worktree:{session_id}",
                "access": "exclusive",
            }
        ],
    }


def session_registry(*claims: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "agent-work-session/v1",
        "revision": 1,
        "claims": list(claims or [session_claim()]),
    }


def recovery(session_id: str = "session-01") -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/pause-recovery/v1",
        "synthetic_commit": "1" * 40,
        "protected_ref": f"refs/agent-sessions/{session_id}",
        "original_head": "2" * 40,
        "original_status_sha256": SHA_B,
        "untracked_paths": ["notes/recovery.md"],
        "secret_scan": {
            "status": "passed",
            "scanner": "johan-sdd/secret-scan/v1",
            "completed_at": "2026-08-13T12:09:00Z",
        },
    }


def test_session_claim_registry_accepts_typed_feature_claim() -> None:
    registry = session_registry()
    assert_schema_valid("session-claims.schema.json", registry)
    assert validate_semantics(registry) == []


def test_session_schema_enforces_date_time_format() -> None:
    registry = session_registry()
    registry["claims"][0]["lease"]["heartbeat_at"] = "yesterday"  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("session-claims.schema.json", registry)


def test_session_lease_times_and_ttl_are_coherent() -> None:
    claim = session_claim()
    claim["lease"]["heartbeat_at"] = "2026-08-13T11:59:00Z"  # type: ignore[index]
    claim["lease"]["expires_at"] = "2026-08-13T12:30:00Z"  # type: ignore[index]
    errors = validate_semantics(session_registry(claim))
    assert [error["code"] for error in errors] == [
        "lease.heartbeat-before-acquisition",
        "lease.ttl-mismatch",
    ]


def test_session_worktree_path_is_canonical_and_process_precedes_lease() -> None:
    claim = session_claim()
    claim["worktree"]["path"] = "D:\\repo-worktrees\\session-01\\"  # type: ignore[index]
    claim["process"]["started_at"] = "2026-08-13T12:01:00Z"  # type: ignore[index]
    errors = validate_semantics(session_registry(claim))
    assert [error["code"] for error in errors] == [
        "worktree.path-not-canonical",
        "process.started-after-lease",
    ]


def test_session_worktree_path_must_be_absolute() -> None:
    claim = session_claim()
    claim["worktree"]["path"] = "repo-worktrees/session-01"  # type: ignore[index]
    assert validate_semantics(session_registry(claim)) == [
        {
            "code": "worktree.path-not-absolute",
            "path": "/claims/0/worktree/path",
            "message": "canonical worktree paths must be absolute host paths",
        }
    ]


def test_feature_claim_requires_linked_worktree() -> None:
    registry = session_registry(session_claim(kind="primary"))
    assert validate_semantics(registry) == [
        {
            "code": "worktree.feature-requires-linked",
            "path": "/claims/0/worktree/kind",
            "message": "feature sessions require an isolated linked worktree",
        }
    ]


def test_micro_claim_requires_clean_primary_and_cannot_pause() -> None:
    claim = session_claim(mode="micro", kind="linked")
    claim["state"] = "paused"
    claim["dirty"] = True
    errors = validate_semantics(session_registry(claim))
    assert [error["code"] for error in errors] == [
        "worktree.micro-requires-primary",
        "session.micro-cannot-pause",
        "session.micro-must-be-clean",
        "session.dirty-pause-missing-recovery",
    ]


def test_paused_clean_claim_can_omit_recovery_only_with_explicit_dirty_false() -> None:
    claim = session_claim()
    claim["state"] = "paused"
    assert claim["dirty"] is False
    registry = session_registry(claim)
    assert_schema_valid("session-claims.schema.json", registry)
    assert validate_semantics(registry) == []


def test_dirty_pause_requires_complete_recovery_contract() -> None:
    claim = session_claim()
    claim["state"] = "paused"
    claim["dirty"] = True
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("session-claims.schema.json", session_registry(claim))

    claim["recovery"] = recovery()
    registry = session_registry(claim)
    assert_schema_valid("session-claims.schema.json", registry)
    assert_schema_valid("pause-recovery.schema.json", recovery())
    assert validate_semantics(registry) == []


def test_recovery_paths_and_ref_are_bound_to_session() -> None:
    claim = session_claim()
    claim["state"] = "paused"
    claim["dirty"] = True
    claim["recovery"] = recovery("other-session")
    claim["recovery"]["untracked_paths"] = ["../secret.env"]  # type: ignore[index]
    errors = validate_semantics(session_registry(claim))
    assert [error["code"] for error in errors] == [
        "recovery.ref-session-mismatch",
        "path.dot-segment",
    ]


def test_standalone_recovery_uses_the_same_path_semantics() -> None:
    snapshot = recovery()
    snapshot["untracked_paths"] = ["/absolute/secret.env"]
    assert validate_semantics(snapshot) == [
        {
            "code": "path.absolute",
            "path": "/untracked_paths/0",
            "message": "paths must be repository-relative",
        }
    ]


def test_active_claims_reject_duplicate_sessions_worktrees_and_exclusive_resources() -> None:
    first = session_claim("session-01")
    second = session_claim("session-01")
    second["worktree"]["worktree_id"] = first["worktree"]["worktree_id"]  # type: ignore[index]
    second["worktree"]["path"] = first["worktree"]["path"]  # type: ignore[index]
    second["resources"] = [
        {
            "resource_type": "tracker",
            "resource_id": "tracker:JOH-1",
            "access": "exclusive",
        },
        {
            "resource_type": "tracker",
            "resource_id": "tracker:JOH-1",
            "access": "exclusive",
        },
    ]
    first["resources"] = copy.deepcopy(second["resources"][:1])  # type: ignore[index]
    errors = validate_semantics(session_registry(first, second))
    assert {error["code"] for error in errors} == {
        "session.duplicate-id",
        "worktree.conflict",
        "resource.duplicate",
        "resource.conflict",
    }


def capture_packet() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/capture-packet/v2",
        "capture_id": f"cap_{SHA_A}",
        "packet_digest": SHA_B,
        "session_id": "session-01",
        "lifecycle_cursor": "00000001",
        "generator": {
            "actor_id": "session-owner:session-01",
            "agent": "codex",
            "model": "gpt-5.6-terra",
        },
        "authority_decision": {
            "decision_ref": "authority:session-01:1",
            "decision_sha256": SHA_C,
        },
        "payload": {
            "event_type": "working",
            "occurred_at": "2026-08-13T12:10:00Z",
            "summary": "Foundation contracts are being validated.",
            "next_action": "Complete the current contract slice.",
            "evidence_refs": [f"sha256:{SHA_A}"],
        },
    }


def promotion_request() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/promotion-request/v1",
        "request_id": f"promotion_{SHA_A}",
        "capture_id": f"cap_{SHA_A}",
        "packet_sha256": SHA_B,
        "generator_actor_id": "session-owner:session-01",
        "promoter": {
            "actor_id": "dashboard-promoter:personal",
            "policy_id": "promotion-policy:personal-dev",
            "policy_revision": 3,
            "policy_sha256": SHA_C,
        },
        "authority": {
            "revision": 4,
            "decision_ref": "authority:session-01:1",
            "decision_sha256": SHA_C,
            "mode": "post_cutover_buzz_authority",
            "sink": "buzz_event",
        },
        "lock": {
            "lock_id": "capture:session-01",
            "fencing_token": 11,
            "acquired_at": "2026-08-13T12:11:00Z",
        },
        "target": {
            "target_id": "dashboard:session-01",
            "preimage_digest": SHA_A,
            "next_digest": SHA_B,
        },
        "phase": "prepared",
    }


def promotion_receipt() -> dict[str, object]:
    receipt = promotion_request()
    receipt["schema_version"] = "johan-sdd/promotion-receipt/v1"
    receipt["receipt_id"] = f"receipt_{SHA_C}"
    receipt["phase"] = "committed"
    receipt["committed_at"] = "2026-08-13T12:12:00Z"
    receipt["readback_digest"] = SHA_B
    return receipt


def test_capture_and_promotion_contracts_bind_distinct_actors_and_fencing() -> None:
    packet = capture_packet()
    request = promotion_request()
    receipt = promotion_receipt()
    assert_schema_valid("capture-packet.v2.schema.json", packet)
    assert_schema_valid("promotion-request.schema.json", request)
    assert_schema_valid("promotion-receipt.schema.json", receipt)
    assert validate_semantics(packet) == []
    assert validate_semantics(request) == []
    assert validate_semantics(receipt) == []


def test_generator_and_promoter_must_be_distinct() -> None:
    request = promotion_request()
    request["promoter"]["actor_id"] = request["generator_actor_id"]  # type: ignore[index]
    assert validate_semantics(request) == [
        {
            "code": "promotion.actor-not-distinct",
            "path": "/promoter/actor_id",
            "message": "capture generator and promoter must be distinct actors",
        }
    ]


@pytest.mark.parametrize(
    ("mode", "sink"),
    [
        ("pre_cutover_json_authority", "session_artifact_v1"),
        ("blocked_authority_transition", "none"),
        ("post_cutover_buzz_authority", "buzz_event"),
        ("post_cutover_fallback_evidence", "noncanonical_fallback_ledger"),
    ],
)
def test_promotion_uses_exact_sink_from_external_authority_decision(mode: str, sink: str) -> None:
    request = promotion_request()
    request["authority"]["mode"] = mode  # type: ignore[index]
    request["authority"]["sink"] = sink  # type: ignore[index]
    if mode == "blocked_authority_transition":
        request["target"]["next_digest"] = request["target"]["preimage_digest"]  # type: ignore[index]
    assert_schema_valid("promotion-request.schema.json", request)
    assert validate_semantics(request) == []


def test_promotion_rejects_wrong_sink_and_unproven_committed_digest() -> None:
    receipt = promotion_receipt()
    receipt["authority"]["mode"] = "post_cutover_fallback_evidence"  # type: ignore[index]
    receipt["authority"]["sink"] = "session_artifact_v1"  # type: ignore[index]
    receipt["readback_digest"] = SHA_C
    assert [error["code"] for error in validate_semantics(receipt)] == [
        "promotion.sink-mismatch",
        "promotion.readback-mismatch",
    ]


def test_blocked_authority_cannot_plan_a_target_change() -> None:
    request = promotion_request()
    request["authority"]["mode"] = "blocked_authority_transition"  # type: ignore[index]
    request["authority"]["sink"] = "none"  # type: ignore[index]
    assert validate_semantics(request) == [
        {
            "code": "promotion.blocked-changes-target",
            "path": "/target/next_digest",
            "message": "blocked authority must preserve the target preimage",
        }
    ]


def test_promotion_phase_rejects_fields_from_another_phase() -> None:
    receipt = promotion_receipt()
    receipt["phase"] = "prepared"
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("promotion-receipt.schema.json", receipt)


def evidence_packet(event_type: str = "slice", artifact_kind: str = "slice-manifest") -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/evidence-packet/v1",
        "event_type": event_type,
        "work_id": "work-01",
        "agent": {"name": "codex", "model": "gpt-5.6-terra"},
        "git": {"base_sha": "1" * 40, "final_sha": "2" * 40},
        "worktree_ref": "worktree:work-01",
        "claim_ref": "claim:session-01:generation-1",
        "contracts": [{"ref": "contract:integration-charter/v1", "sha256": SHA_A}],
        "changes": [
            {
                "path": "schemas/evidence-packet.schema.json",
                "sha256": SHA_B,
                "summary": "Strengthen reconstructable evidence.",
            }
        ],
        "verification": [
            {
                "command": "uv run --locked pytest -q",
                "exit_code": 0,
                "result": "passed",
                "log_ref": {"ref": "logs/pytest.txt", "sha256": SHA_C},
            }
        ],
        "artifacts": [{"kind": artifact_kind, "ref": "artifacts/slice.json", "sha256": SHA_A}],
        "logs": [{"ref": "logs/pytest.txt", "sha256": SHA_C}],
        "decisions": [
            {
                "decision": "Use the public semantic validator seam.",
                "rationale": "It keeps callers independent from validator internals.",
            }
        ],
        "risks": [
            {
                "risk": "Schema and semantic validation could diverge.",
                "mitigation": "Run adversarial tests through both seams.",
            }
        ],
        "next": {
            "consumer": "root-coordinator",
            "action": "Review and integrate the verified contract slice.",
        },
    }


def test_evidence_packet_is_reconstructable_without_conversation_history() -> None:
    packet = evidence_packet()
    assert_schema_valid("evidence-packet.schema.json", packet)
    assert validate_semantics(packet) == []


@pytest.mark.parametrize("field", ["contracts", "changes", "verification", "artifacts", "logs"])
def test_evidence_packet_rejects_empty_proof(field: str) -> None:
    packet = evidence_packet()
    packet[field] = []
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("evidence-packet.schema.json", packet)


def test_evidence_event_requires_its_reconstruction_artifact() -> None:
    packet = evidence_packet("rollback", "slice-manifest")
    assert validate_semantics(packet) == [
        {
            "code": "evidence.missing-event-artifact",
            "path": "/artifacts",
            "message": "rollback evidence requires a rollback-receipt artifact",
        }
    ]


@pytest.mark.parametrize(
    "path",
    [
        ("host_integration", "preview"),
        ("host_integration", "apply"),
        ("sessions", "authority_derivation"),
        ("sessions", "dirty_pause", "snapshot_algorithm"),
        ("capture", "promotion_protocol"),
        ("updater", "never_automatic"),
        ("evidence", "required_at"),
        ("evidence", "missing_or_unreproducible"),
    ],
)
def test_integration_charter_rejects_removed_safety_rule(path: tuple[str, ...]) -> None:
    charter = load_json(MANIFESTS / "integration-charter.v1.json")
    mutated = copy.deepcopy(charter)
    parent = mutated
    for segment in path[:-1]:
        parent = parent[segment]  # type: ignore[index,assignment]
    parent.pop(path[-1])
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("integration-charter.schema.json", mutated)


def test_integration_charter_is_recursively_closed() -> None:
    charter = load_json(MANIFESTS / "integration-charter.v1.json")
    charter["sessions"]["registry"]["silent_escape_hatch"] = True  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        assert_schema_valid("integration-charter.schema.json", charter)


def test_integration_charter_semantics_require_every_updater_prohibition() -> None:
    charter = load_json(MANIFESTS / "integration-charter.v1.json")
    charter["updater"]["never_automatic"].remove("trust-root")  # type: ignore[index]
    assert validate_semantics(charter) == [
        {
            "code": "updater.missing-prohibition",
            "path": "/updater/never_automatic",
            "message": "updater must prohibit automatic changes to: trust-root",
        }
    ]


def test_current_integration_charter_passes_shape_and_semantics() -> None:
    charter = load_json(MANIFESTS / "integration-charter.v1.json")
    assert_schema_valid("integration-charter.schema.json", charter)
    assert validate_semantics(charter) == []
