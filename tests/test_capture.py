from __future__ import annotations

import copy

import pytest

from johan_sdd.capture import authority_decision_ref, derive_authority_decision
from johan_sdd.capture.packet import (
    CaptureValidationError,
    canonical_capture_bytes,
    generate_capture_packet,
    verify_capture_packet,
)


def authority() -> dict[str, object]:
    return derive_authority_decision(
        session_id="session-01",
        started_at="2026-08-13T12:00:00Z",
        marker=None,
        buzz_readiness="unavailable",
        transition_health="healthy",
        derived_at="2026-08-13T12:00:01Z",
    )


def claim(decision: dict[str, object]) -> dict[str, object]:
    return {
        "session_id": "session-01",
        "owner": {"agent": "codex", "model": "gpt-5.6-sol"},
        "authority_decision_ref": authority_decision_ref(decision),
    }


def payload() -> dict[str, object]:
    return {
        "event_type": "working",
        "occurred_at": "2026-08-13T12:01:00Z",
        "summary": "The lifecycle slice is green.",
        "next_action": "Promote the capture through its enrolled authority.",
        "evidence_refs": [f"sha256:{'a' * 64}"],
    }


def test_capture_packet_uses_frozen_canonical_digest_and_capture_id_formula() -> None:
    decision = authority()
    packet = generate_capture_packet(
        session_claim=claim(decision),
        lifecycle_cursor=1,
        authority_decision=decision,
        payload=payload(),
    )

    assert packet["lifecycle_cursor"] == "00000001"
    assert packet["packet_digest"] == "081d742314cf35f33cd9b521ce011e1ef2b02c1d58c162affb8cb849f8eaac0e"
    assert packet["capture_id"] == "cap_bd75cd9ae5dea58cded675536a278a6ba0a671ce9c8afb4a9bb51973748c9064"
    assert verify_capture_packet(packet) is None


def test_capture_serialization_is_deterministic_and_compact() -> None:
    decision = authority()
    packet = generate_capture_packet(
        session_claim=claim(decision),
        lifecycle_cursor="00000001",
        authority_decision=decision,
        payload=dict(reversed(list(payload().items()))),
    )
    rendered = canonical_capture_bytes(packet)

    assert rendered.startswith(b'{"authority_decision":')
    assert b"\n" not in rendered
    assert canonical_capture_bytes(copy.deepcopy(packet)) == rendered


def test_capture_generator_identity_comes_from_the_enrolled_session_owner() -> None:
    decision = authority()
    session_claim = claim(decision)
    session_claim["owner"] = {"agent": "claude", "model": "claude-opus"}

    packet = generate_capture_packet(
        session_claim=session_claim,
        lifecycle_cursor=1,
        authority_decision=decision,
        payload=payload(),
    )

    assert packet["generator"] == {
        "actor_id": "session-owner:session-01",
        "agent": "claude",
        "model": "claude-opus",
    }
    assert "authority_mode" not in packet
    assert "sink" not in packet


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"transcript": "conversation"}), "unsupported payload fields"),
        (lambda value: value.update({"summary": ""}), "summary"),
        (lambda value: value.update({"event_type": "wrap"}), "event_type"),
    ],
)
def test_capture_payload_is_constrained(
    mutation: object,
    message: str,
) -> None:
    decision = authority()
    event = payload()
    mutation(event)  # type: ignore[operator]

    with pytest.raises(CaptureValidationError, match=message):
        generate_capture_packet(
            session_claim=claim(decision),
            lifecycle_cursor=1,
            authority_decision=decision,
            payload=event,
        )


def test_capture_rejects_a_decision_not_enrolled_by_the_session() -> None:
    decision = authority()
    session_claim = claim(decision)
    session_claim["authority_decision_ref"] = f"authority:{'f' * 64}"

    with pytest.raises(CaptureValidationError, match="enrolled authority"):
        generate_capture_packet(
            session_claim=session_claim,
            lifecycle_cursor=1,
            authority_decision=decision,
            payload=payload(),
        )


def test_capture_integrity_detects_tampering() -> None:
    decision = authority()
    packet = generate_capture_packet(
        session_claim=claim(decision),
        lifecycle_cursor=1,
        authority_decision=decision,
        payload=payload(),
    )
    packet["payload"]["summary"] = "tampered"  # type: ignore[index]

    with pytest.raises(CaptureValidationError, match="packet_digest"):
        verify_capture_packet(packet)
