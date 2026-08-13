from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from johan_sdd.capture.authority import (
    AuthorityContinuityError,
    CutoverConflictError,
    derive_authority_decision,
    read_cutover_marker,
    write_cutover_marker,
)


SHA_A = "a" * 64
ROOT = Path(__file__).resolve().parents[1]


def validate(schema_name: str, document: dict[str, object]) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(document)


def test_authority_is_derived_from_marker_readiness_and_health_without_override() -> None:
    decision = derive_authority_decision(
        session_id="session-01",
        started_at="2026-08-13T12:00:00Z",
        marker=None,
        buzz_readiness="unavailable",
        transition_health="healthy",
        derived_at="2026-08-13T12:01:00Z",
    )

    assert decision["derivation"]["caller_override"] is False
    assert decision["decision"] == {
        "mode": "pre_cutover_json_authority",
        "sink": "session_artifact_v1",
    }
    validate("authority-decision.schema.json", decision)


def test_new_post_cutover_authority_has_exactly_one_derived_sink(tmp_path: Path) -> None:
    marker = write_cutover_marker(
        tmp_path / "cutover.json",
        cutover_at="2026-08-13T12:00:00Z",
        decision_ref=f"decision:{SHA_A}",
        prestate_sha256=SHA_A,
        verification_refs=[{"ref": "evidence/cutover.json", "sha256": SHA_A}],
        expected_revision=0,
        expected_marker_sha256="absent",
    )

    buzz = derive_authority_decision(
        session_id="session-02",
        started_at="2026-08-13T12:00:00Z",
        marker=marker,
        buzz_readiness="ready",
        transition_health="healthy",
        derived_at="2026-08-13T12:01:00Z",
    )
    fallback = derive_authority_decision(
        session_id="session-03",
        started_at="2026-08-13T12:00:01Z",
        marker=marker,
        buzz_readiness="unavailable",
        transition_health="healthy",
        derived_at="2026-08-13T12:01:00Z",
    )
    blocked = derive_authority_decision(
        session_id="session-04",
        started_at="2026-08-13T12:00:01Z",
        marker=marker,
        buzz_readiness="ready",
        transition_health="blocked",
        derived_at="2026-08-13T12:01:00Z",
    )

    assert buzz["decision"] == {"mode": "post_cutover_buzz_authority", "sink": "buzz_event"}
    assert fallback["decision"] == {
        "mode": "post_cutover_fallback_evidence",
        "sink": "noncanonical_fallback_ledger",
    }
    assert blocked["decision"] == {"mode": "blocked_authority_transition", "sink": "none"}
    validate("authority-decision.schema.json", buzz)
    validate("authority-decision.schema.json", fallback)
    validate("authority-decision.schema.json", blocked)


def test_continuation_preserves_original_buzz_mode_during_outage(tmp_path: Path) -> None:
    marker = write_cutover_marker(
        tmp_path / "cutover.json",
        cutover_at="2026-08-13T12:00:00Z",
        decision_ref=f"decision:{SHA_A}",
        prestate_sha256=SHA_A,
        verification_refs=[{"ref": "evidence/cutover.json", "sha256": SHA_A}],
        expected_revision=0,
        expected_marker_sha256="absent",
    )
    original = derive_authority_decision(
        session_id="session-01",
        started_at="2026-08-13T12:00:00Z",
        marker=marker,
        buzz_readiness="ready",
        transition_health="healthy",
        derived_at="2026-08-13T12:01:00Z",
    )

    continuation = derive_authority_decision(
        session_id="session-01",
        started_at="2026-08-13T12:00:00Z",
        marker=marker,
        buzz_readiness="unavailable",
        transition_health="healthy",
        derived_at="2026-08-13T12:02:00Z",
        original_decision=original,
    )

    assert continuation["decision"] == original["decision"]
    assert continuation["derivation"]["reason"] == "enrolled_authority_continuity"
    validate("authority-decision.schema.json", continuation)


def test_continuation_rejects_a_tampered_original_authority_receipt(tmp_path: Path) -> None:
    marker = write_cutover_marker(
        tmp_path / "cutover.json",
        cutover_at="2026-08-13T12:00:00Z",
        decision_ref=f"decision:{SHA_A}",
        prestate_sha256=SHA_A,
        verification_refs=[{"ref": "evidence/cutover.json", "sha256": SHA_A}],
        expected_revision=0,
        expected_marker_sha256="absent",
    )
    original = derive_authority_decision(
        session_id="session-01",
        started_at="2026-08-13T12:00:00Z",
        marker=marker,
        buzz_readiness="ready",
        transition_health="healthy",
        derived_at="2026-08-13T12:01:00Z",
    )
    original["decision"] = {  # type: ignore[assignment]
        "mode": "post_cutover_fallback_evidence",
        "sink": "noncanonical_fallback_ledger",
    }

    with pytest.raises(AuthorityContinuityError, match="integrity"):
        derive_authority_decision(
            session_id="session-01",
            started_at="2026-08-13T12:00:00Z",
            marker=marker,
            buzz_readiness="unavailable",
            transition_health="healthy",
            derived_at="2026-08-13T12:02:00Z",
            original_decision=original,
        )


def test_session_started_before_observed_cutover_requires_enrollment_receipt(tmp_path: Path) -> None:
    marker = write_cutover_marker(
        tmp_path / "cutover.json",
        cutover_at="2026-08-13T12:00:00Z",
        decision_ref=f"decision:{SHA_A}",
        prestate_sha256=SHA_A,
        verification_refs=[{"ref": "evidence/cutover.json", "sha256": SHA_A}],
        expected_revision=0,
        expected_marker_sha256="absent",
    )

    with pytest.raises(AuthorityContinuityError):
        derive_authority_decision(
            session_id="session-01",
            started_at="2026-08-13T11:59:59Z",
            marker=marker,
            buzz_readiness="ready",
            transition_health="healthy",
            derived_at="2026-08-13T12:01:00Z",
        )


def test_cutover_marker_is_monotonic_and_uses_revision_cas(tmp_path: Path) -> None:
    path = tmp_path / "cutover.json"
    first = write_cutover_marker(
        path,
        cutover_at="2026-08-13T12:00:00Z",
        decision_ref=f"decision:{SHA_A}",
        prestate_sha256=SHA_A,
        verification_refs=[{"ref": "evidence/first.json", "sha256": SHA_A}],
        expected_revision=0,
        expected_marker_sha256="absent",
    )
    second = write_cutover_marker(
        path,
        decision_ref=f"decision:{'b' * 64}",
        prestate_sha256="b" * 64,
        verification_refs=[{"ref": "evidence/second.json", "sha256": "b" * 64}],
        expected_revision=1,
        expected_marker_sha256=first["marker_sha256"],
    )

    assert second["revision"] == 2
    assert second["cutover_at"] == first["cutover_at"]
    assert read_cutover_marker(path) == second
    assert json.loads(path.read_text(encoding="utf-8")) == second
    validate("cutover-marker.schema.json", second)

    with pytest.raises(CutoverConflictError):
        write_cutover_marker(
            path,
            decision_ref=f"decision:{'c' * 64}",
            prestate_sha256="c" * 64,
            verification_refs=[{"ref": "evidence/stale.json", "sha256": "c" * 64}],
            expected_revision=1,
            expected_marker_sha256=first["marker_sha256"],
        )
