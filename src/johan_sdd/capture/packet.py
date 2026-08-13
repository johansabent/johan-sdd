"""Generation and integrity checks for non-canonical capture packets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from datetime import datetime
import hashlib
import re
from typing import Any

from ._canonical import canonical_bytes, canonical_digest
from .authority import authority_decision_digest, authority_decision_ref


_EVENT_TYPES = {"starting", "working", "paused", "blocked", "closing", "closed", "abandoned"}
_PACKET_FIELDS = {
    "schema_version",
    "capture_id",
    "packet_digest",
    "session_id",
    "lifecycle_cursor",
    "generator",
    "authority_decision",
    "payload",
}
_PAYLOAD_FIELDS = {"event_type", "occurred_at", "summary", "next_action", "evidence_refs"}
_SHA_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


class CaptureValidationError(ValueError):
    """A capture cannot be generated or its identity cannot be verified."""


def _cursor(value: str | int) -> str:
    if isinstance(value, bool):
        raise CaptureValidationError("lifecycle_cursor must be an integer or decimal string")
    if isinstance(value, int):
        if value < 0:
            raise CaptureValidationError("lifecycle_cursor cannot be negative")
        rendered = f"{value:08d}"
    elif isinstance(value, str):
        rendered = value
    else:
        raise CaptureValidationError("lifecycle_cursor must be an integer or decimal string")
    if not re.fullmatch(r"[0-9]{8,20}", rendered):
        raise CaptureValidationError("lifecycle_cursor must contain 8 to 20 decimal digits")
    return rendered


def _validate_timestamp(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CaptureValidationError("occurred_at must be an RFC 3339 UTC timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CaptureValidationError("occurred_at must be an RFC 3339 UTC timestamp") from exc


def _payload(value: Mapping[str, Any]) -> dict[str, Any]:
    unexpected = set(value) - _PAYLOAD_FIELDS
    missing = _PAYLOAD_FIELDS - set(value)
    if unexpected:
        raise CaptureValidationError(f"unsupported payload fields: {sorted(unexpected)!r}")
    if missing:
        raise CaptureValidationError(f"missing payload fields: {sorted(missing)!r}")
    if value["event_type"] not in _EVENT_TYPES:
        raise CaptureValidationError("event_type is not a lifecycle event")
    _validate_timestamp(value["occurred_at"])
    for field in ("summary", "next_action"):
        item = value[field]
        if not isinstance(item, str) or not item or len(item) > 1000:
            raise CaptureValidationError(f"{field} must contain 1 to 1000 characters")
    refs = value["evidence_refs"]
    if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)):
        raise CaptureValidationError("evidence_refs must be an array")
    if any(not isinstance(item, str) or not _SHA_REF.fullmatch(item) for item in refs):
        raise CaptureValidationError("evidence_refs must contain SHA-256 references")
    if len(set(refs)) != len(refs):
        raise CaptureValidationError("evidence_refs must be unique")
    return copy.deepcopy(dict(value))


def _digest_material(packet: Mapping[str, Any]) -> dict[str, Any]:
    material = copy.deepcopy(dict(packet))
    material.pop("capture_id", None)
    material.pop("packet_digest", None)
    return material


def _capture_id(session_id: str, cursor: str, decision_ref: str, packet_digest: str) -> str:
    identity = "\0".join((session_id, cursor, decision_ref, packet_digest)).encode("utf-8")
    return f"cap_{hashlib.sha256(identity).hexdigest()}"


def generate_capture_packet(
    *,
    session_claim: Mapping[str, Any],
    lifecycle_cursor: str | int,
    authority_decision: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Generate one packet from enrolled session and authority receipts.

    There is intentionally no authority mode, sink, actor, agent, or model
    argument.  Those values are derived from durable enrollment documents.
    """

    session_id = session_claim.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise CaptureValidationError("session claim has no session_id")
    owner = session_claim.get("owner")
    if not isinstance(owner, Mapping):
        raise CaptureValidationError("session claim has no owner")
    agent = owner.get("agent")
    model = owner.get("model")
    if not isinstance(agent, str) or not agent or not isinstance(model, str) or not model:
        raise CaptureValidationError("session owner requires agent and model")
    decision_session = authority_decision.get("session")
    if not isinstance(decision_session, Mapping) or decision_session.get("session_id") != session_id:
        raise CaptureValidationError("authority decision belongs to another session")

    decision_ref = authority_decision_ref(authority_decision)
    if session_claim.get("authority_decision_ref") != decision_ref:
        raise CaptureValidationError("capture decision does not match the session's enrolled authority")
    cursor = _cursor(lifecycle_cursor)
    packet: dict[str, Any] = {
        "schema_version": "johan-sdd/capture-packet/v2",
        "session_id": session_id,
        "lifecycle_cursor": cursor,
        "generator": {
            "actor_id": f"session-owner:{session_id}",
            "agent": agent,
            "model": model,
        },
        "authority_decision": {
            "decision_ref": decision_ref,
            "decision_sha256": authority_decision_digest(authority_decision),
        },
        "payload": _payload(payload),
    }
    packet_digest = canonical_digest(packet)
    packet["packet_digest"] = packet_digest
    packet["capture_id"] = _capture_id(session_id, cursor, decision_ref, packet_digest)
    return packet


def verify_capture_packet(packet: Mapping[str, Any]) -> None:
    if set(packet) != _PACKET_FIELDS:
        raise CaptureValidationError("capture packet fields do not match capture-packet/v2")
    if packet.get("schema_version") != "johan-sdd/capture-packet/v2":
        raise CaptureValidationError("capture-packet/v1 is unsupported; capture-packet/v2 is required")
    session_id = packet.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise CaptureValidationError("session_id must not be empty")
    cursor = _cursor(packet.get("lifecycle_cursor"))  # type: ignore[arg-type]
    generator = packet.get("generator")
    if not isinstance(generator, Mapping) or set(generator) != {"actor_id", "agent", "model"}:
        raise CaptureValidationError("generator identity is incomplete")
    if generator.get("actor_id") != f"session-owner:{session_id}":
        raise CaptureValidationError("generator actor is not the enrolled session owner")
    if any(not isinstance(generator.get(field), str) or not generator.get(field) for field in ("agent", "model")):
        raise CaptureValidationError("generator identity is incomplete")
    authority = packet.get("authority_decision")
    if not isinstance(authority, Mapping) or set(authority) != {"decision_ref", "decision_sha256"}:
        raise CaptureValidationError("authority decision reference is incomplete")
    decision_ref = authority.get("decision_ref")
    decision_sha = authority.get("decision_sha256")
    if not isinstance(decision_ref, str) or not decision_ref:
        raise CaptureValidationError("authority decision reference is incomplete")
    if not isinstance(decision_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", decision_sha):
        raise CaptureValidationError("authority decision digest is invalid")
    payload = packet.get("payload")
    if not isinstance(payload, Mapping):
        raise CaptureValidationError("payload must be an object")
    _payload(payload)

    expected_digest = canonical_digest(_digest_material(packet))
    if packet.get("packet_digest") != expected_digest:
        raise CaptureValidationError("packet_digest does not match canonical packet content")
    expected_id = _capture_id(session_id, cursor, decision_ref, expected_digest)
    if packet.get("capture_id") != expected_id:
        raise CaptureValidationError("capture_id does not match the frozen identity formula")


def canonical_capture_bytes(packet: Mapping[str, Any]) -> bytes:
    verify_capture_packet(packet)
    return canonical_bytes(packet)
