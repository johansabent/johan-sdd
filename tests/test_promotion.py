from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from johan_sdd.capture import (
    authority_decision_ref,
    derive_authority_decision,
    generate_capture_packet,
    write_cutover_marker,
)
from johan_sdd.capture.promotion import (
    FilePromotionTarget,
    PromotionActorError,
    PromotionConflictError,
    PromotionFailedError,
    PromotionRecoveryRequired,
    promote_capture,
)
from johan_sdd.contracts import validate_semantics


SHA_A = "a" * 64
ROOT = Path(__file__).resolve().parents[1]


def validate(schema_name: str, document: dict[str, object]) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(document)


def lifecycle(tmp_path: Path) -> tuple[dict[str, object], dict[str, object]]:
    marker = write_cutover_marker(
        tmp_path / "cutover.json",
        cutover_at="2026-08-13T12:00:00Z",
        decision_ref=f"decision:{SHA_A}",
        prestate_sha256=SHA_A,
        verification_refs=[{"ref": "evidence/cutover.json", "sha256": SHA_A}],
        expected_revision=0,
        expected_marker_sha256="absent",
    )
    decision = derive_authority_decision(
        session_id="session-01",
        started_at="2026-08-13T12:00:00Z",
        marker=marker,
        buzz_readiness="ready",
        transition_health="healthy",
        derived_at="2026-08-13T12:00:01Z",
    )
    claim = {
        "session_id": "session-01",
        "owner": {"agent": "codex", "model": "gpt-5.6-sol"},
        "authority_decision_ref": authority_decision_ref(decision),
    }
    packet = generate_capture_packet(
        session_claim=claim,
        lifecycle_cursor=1,
        authority_decision=decision,
        payload={
            "event_type": "working",
            "occurred_at": "2026-08-13T12:01:00Z",
            "summary": "Ready for promotion.",
            "next_action": "Commit through the Buzz sink.",
            "evidence_refs": [f"sha256:{SHA_A}"],
        },
    )
    return decision, packet


def promoter(actor_id: str = "promoter:dashboard") -> dict[str, object]:
    return {
        "actor_id": actor_id,
        "policy_id": "policy:personal-dev",
        "policy_revision": 1,
        "policy_sha256": SHA_A,
    }


def promote(
    tmp_path: Path,
    decision: dict[str, object],
    packet: dict[str, object],
    *,
    target: FilePromotionTarget | None = None,
):
    return promote_capture(
        packet=packet,
        authority_decision=decision,
        promoter=promoter(),
        target=target
        or FilePromotionTarget(
            path=tmp_path / "buzz" / f"{packet['capture_id']}.json",
            target_id="buzz:session-01:00000001",
            sink="buzz_event",
        ),
        receipt_directory=tmp_path / "receipts",
        lock_directory=tmp_path / "locks",
        clock=lambda: "2026-08-13T12:02:00Z",
    )


def test_promotion_commits_exactly_one_sink_with_durable_phase_receipts(tmp_path: Path) -> None:
    decision, packet = lifecycle(tmp_path)
    target = FilePromotionTarget(
        path=tmp_path / "buzz" / f"{packet['capture_id']}.json",
        target_id="buzz:session-01:00000001",
        sink="buzz_event",
    )

    outcome = promote(tmp_path, decision, packet, target=target)

    assert outcome.phase == "committed"
    assert outcome.target_changed is True
    assert target.path.exists()
    assert json.loads(target.path.read_text(encoding="utf-8")) == packet
    assert outcome.prepared_receipt_path.exists()
    assert outcome.terminal_receipt_path.exists()
    assert outcome.prepared_receipt["phase"] == "prepared"
    assert outcome.terminal_receipt["phase"] == "committed"
    assert outcome.terminal_receipt["readback_digest"] == outcome.request["target"]["next_digest"]
    assert not (tmp_path / "legacy-session-artifact.json").exists()
    validate("promotion-request.schema.json", outcome.request)
    validate("promotion-receipt.schema.json", outcome.prepared_receipt)
    validate("promotion-receipt.schema.json", outcome.terminal_receipt)
    assert validate_semantics(outcome.request) == []
    assert validate_semantics(outcome.terminal_receipt) == []


def test_same_capture_id_and_digest_is_idempotent(tmp_path: Path) -> None:
    decision, packet = lifecycle(tmp_path)

    first = promote(tmp_path, decision, packet)
    second = promote(tmp_path, decision, packet)

    assert first.target_changed is True
    assert second.target_changed is False
    assert second.terminal_receipt["phase"] == "committed"
    assert second.request["lock"]["fencing_token"] > first.request["lock"]["fencing_token"]


def test_same_capture_id_with_a_different_digest_is_a_durable_conflict(tmp_path: Path) -> None:
    decision, packet = lifecycle(tmp_path)
    target = FilePromotionTarget(
        path=tmp_path / "buzz" / f"{packet['capture_id']}.json",
        target_id="buzz:session-01:00000001",
        sink="buzz_event",
    )
    target.path.parent.mkdir(parents=True)
    corrupt = dict(packet)
    corrupt["packet_digest"] = "f" * 64
    target.path.write_text(json.dumps(corrupt), encoding="utf-8")

    with pytest.raises(PromotionConflictError) as captured:
        promote(tmp_path, decision, packet, target=target)

    assert captured.value.receipt["phase"] == "failed"
    assert captured.value.receipt_path.exists()
    assert json.loads(target.path.read_text(encoding="utf-8"))["packet_digest"] == "f" * 64
    validate("promotion-receipt.schema.json", captured.value.receipt)


def test_generator_and_promoter_are_distinct_actors(tmp_path: Path) -> None:
    decision, packet = lifecycle(tmp_path)

    with pytest.raises(PromotionActorError):
        promote_capture(
            packet=packet,
            authority_decision=decision,
            promoter=promoter("session-owner:session-01"),
            target=FilePromotionTarget(
                path=tmp_path / "buzz.json",
                target_id="buzz:session-01:00000001",
                sink="buzz_event",
            ),
            receipt_directory=tmp_path / "receipts",
            lock_directory=tmp_path / "locks",
            clock=lambda: "2026-08-13T12:02:00Z",
        )
    assert not (tmp_path / "buzz.json").exists()


def test_post_cutover_buzz_cannot_write_legacy_or_fallback_sink(tmp_path: Path) -> None:
    decision, packet = lifecycle(tmp_path)

    for sink in ("session_artifact_v1", "noncanonical_fallback_ledger"):
        with pytest.raises(PromotionConflictError):
            promote(
                tmp_path,
                decision,
                packet,
                target=FilePromotionTarget(
                    path=tmp_path / f"{sink}.json",
                    target_id=f"wrong:{sink}",
                    sink=sink,
                ),
            )
        assert not (tmp_path / f"{sink}.json").exists()


class ReadbackFailureTarget(FilePromotionTarget):
    def readback_digest(self) -> str:
        return "0" * 64


class RecoveryFailureTarget(ReadbackFailureTarget):
    def restore(self, snapshot: bytes | None, *, expected_current_digest: str) -> None:
        raise OSError("simulated rollback failure")


def test_failed_commit_rolls_back_and_emits_failed_receipt(tmp_path: Path) -> None:
    decision, packet = lifecycle(tmp_path)
    target = ReadbackFailureTarget(
        path=tmp_path / "buzz.json",
        target_id="buzz:session-01:00000001",
        sink="buzz_event",
    )

    with pytest.raises(PromotionFailedError) as captured:
        promote(tmp_path, decision, packet, target=target)

    assert captured.value.receipt["phase"] == "failed"
    assert captured.value.receipt_path.exists()
    assert not target.path.exists()


def test_unrecoverable_commit_emits_needs_recovery_and_rollback_evidence(tmp_path: Path) -> None:
    decision, packet = lifecycle(tmp_path)
    target = RecoveryFailureTarget(
        path=tmp_path / "buzz.json",
        target_id="buzz:session-01:00000001",
        sink="buzz_event",
    )

    with pytest.raises(PromotionRecoveryRequired) as captured:
        promote(tmp_path, decision, packet, target=target)

    assert captured.value.receipt["phase"] == "needs_recovery"
    assert captured.value.receipt_path.exists()
    assert captured.value.rollback_evidence_path.exists()
    assert target.path.exists()
    validate("promotion-receipt.schema.json", captured.value.receipt)
