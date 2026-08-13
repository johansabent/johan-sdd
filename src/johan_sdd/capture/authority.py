"""Durable cutover markers and caller-independent lifecycle authority."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from datetime import datetime
from pathlib import Path
import re
from typing import Any

from ._canonical import canonical_digest
from ._io import atomic_write_json, exclusive_lock, read_json


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SINKS = {
    "pre_cutover_json_authority": "session_artifact_v1",
    "blocked_authority_transition": "none",
    "post_cutover_buzz_authority": "buzz_event",
    "post_cutover_fallback_evidence": "noncanonical_fallback_ledger",
}


class CutoverConflictError(RuntimeError):
    """The durable marker no longer matches the caller's measured pre-state."""


class AuthorityContinuityError(ValueError):
    """A continuation cannot prove and preserve its enrolled authority."""


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"invalid UTC timestamp: {value!r}") from exc
    if not value.endswith("Z") or parsed.utcoffset() is None:
        raise ValueError(f"timestamp must be UTC and end in Z: {value!r}")
    return parsed


def _validate_sha256(value: str, field: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _marker_hash(marker: Mapping[str, Any]) -> str:
    material = dict(marker)
    material.pop("marker_sha256", None)
    return canonical_digest(material)


def read_cutover_marker(path: str | Path) -> dict[str, Any] | None:
    marker_path = Path(path)
    if not marker_path.exists():
        return None
    marker = read_json(marker_path)
    if marker.get("schema_version") != "johan-sdd/cutover-marker/v1":
        raise ValueError("unsupported cutover marker schema")
    if marker.get("state") != "cutover_active":
        raise ValueError("cutover marker cannot be deactivated")
    if marker.get("marker_sha256") != _marker_hash(marker):
        raise ValueError("cutover marker digest does not match its content")
    return marker


def write_cutover_marker(
    path: str | Path,
    *,
    decision_ref: str,
    prestate_sha256: str,
    verification_refs: Sequence[Mapping[str, str]],
    expected_revision: int,
    expected_marker_sha256: str,
    cutover_at: str | None = None,
    lock_timeout: float = 10.0,
) -> dict[str, Any]:
    """Create or advance the marker using a revision-and-digest CAS.

    The cutover time, identity, transition, and active state are immutable after
    the first successful write.  Later revisions may append replacement evidence
    while preserving the one-way cutover.
    """

    marker_path = Path(path)
    lock_path = marker_path.with_name(f"{marker_path.name}.lock")
    _validate_sha256(prestate_sha256, "prestate_sha256")
    if not re.fullmatch(r"decision:[0-9a-f]{64}", decision_ref):
        raise ValueError("decision_ref must be a durable decision digest reference")
    refs = [dict(item) for item in verification_refs]
    if not refs:
        raise ValueError("verification_refs must not be empty")
    for item in refs:
        if set(item) != {"ref", "sha256"}:
            raise ValueError("each verification reference requires only ref and sha256")
        if not re.fullmatch(r"evidence/[A-Za-z0-9._/-]+\.json", item["ref"]):
            raise ValueError("verification evidence refs must be repository-relative JSON paths")
        _validate_sha256(item["sha256"], "verification_refs.sha256")

    with exclusive_lock(lock_path, timeout=lock_timeout):
        current = read_cutover_marker(marker_path)
        actual_revision = 0 if current is None else current["revision"]
        actual_digest = "absent" if current is None else current["marker_sha256"]
        if expected_revision != actual_revision or expected_marker_sha256 != actual_digest:
            raise CutoverConflictError(
                f"cutover marker changed: expected revision/digest "
                f"{expected_revision}/{expected_marker_sha256}, observed {actual_revision}/{actual_digest}"
            )

        if current is None:
            if cutover_at is None:
                raise ValueError("cutover_at is required when creating a marker")
            _timestamp(cutover_at)
            immutable = {
                "cutover_at": cutover_at,
                "state": "cutover_active",
                "transition": {
                    "from": "legacy_session_artifact_v1",
                    "to": "buzz_event_authority",
                },
                "mutation_policy": "append_evidence_only_no_cutover_rollback",
            }
        else:
            if cutover_at is not None and cutover_at != current["cutover_at"]:
                raise ValueError("cutover_at is immutable")
            immutable = {
                key: copy.deepcopy(current[key])
                for key in ("cutover_at", "state", "transition", "mutation_policy")
            }

        revision = actual_revision + 1
        marker: dict[str, Any] = {
            "schema_version": "johan-sdd/cutover-marker/v1",
            "revision": revision,
            **immutable,
            "cas": {
                "operation": "compare_and_swap_append",
                "expected_revision": expected_revision,
                "expected_marker_sha256": expected_marker_sha256,
                "advance_by": 1,
            },
            "evidence": {
                "decision_ref": decision_ref,
                "prestate_sha256": prestate_sha256,
                "verification_refs": refs,
            },
        }
        if current is None:
            marker_seed = canonical_digest(marker)
            marker["marker_id"] = f"cutover_{marker_seed}"
        else:
            marker["marker_id"] = current["marker_id"]
        marker["marker_sha256"] = _marker_hash(marker)
        atomic_write_json(marker_path, marker)
        observed = read_cutover_marker(marker_path)
        if observed != marker:
            raise OSError("cutover marker readback did not match the committed document")
        return marker


def _marker_observation(marker: Mapping[str, Any] | None) -> dict[str, Any]:
    if marker is None:
        return {"state": "absent"}
    required = ("marker_id", "revision", "marker_sha256", "cutover_at")
    if any(key not in marker for key in required):
        raise ValueError("cutover marker is incomplete")
    if marker.get("marker_sha256") != _marker_hash(marker):
        raise ValueError("cutover marker digest does not match its content")
    return {
        "state": "present",
        "marker_id": marker["marker_id"],
        "marker_revision": marker["revision"],
        "marker_sha256": marker["marker_sha256"],
        "cutover_at": marker["cutover_at"],
    }


def authority_decision_ref(decision: Mapping[str, Any]) -> str:
    verify_authority_decision(decision)
    decision_id = decision.get("decision_id")
    if not isinstance(decision_id, str) or not re.fullmatch(r"authority_[0-9a-f]{64}", decision_id):
        raise ValueError("authority decision has no valid decision_id")
    return f"authority:{decision_id.removeprefix('authority_')}"


def authority_decision_digest(decision: Mapping[str, Any]) -> str:
    verify_authority_decision(decision)
    return canonical_digest(decision)


def verify_authority_decision(decision: Mapping[str, Any]) -> None:
    """Verify the immutable receipt identity and its cross-field derivation."""

    if decision.get("schema_version") != "johan-sdd/authority-decision/v1":
        raise ValueError("unsupported authority decision schema")
    if decision.get("immutability") != "immutable_append_only_receipt":
        raise ValueError("authority decision is not immutable")
    choice = decision.get("decision")
    if not isinstance(choice, Mapping) or _SINKS.get(choice.get("mode")) != choice.get("sink"):
        raise ValueError("authority decision has an invalid mode/sink pair")
    derivation = decision.get("derivation")
    if not isinstance(derivation, Mapping) or derivation.get("caller_override") is not False:
        raise ValueError("authority decision permits a caller override")
    inputs = {
        "session": decision.get("session"),
        "marker_observation": decision.get("marker_observation"),
        "readiness": decision.get("readiness"),
    }
    if derivation.get("inputs_sha256") != canonical_digest(inputs):
        raise ValueError("authority decision input digest failed integrity verification")
    decision_id = decision.get("decision_id")
    material = dict(decision)
    material.pop("decision_id", None)
    expected_id = f"authority_{canonical_digest(material)}"
    if decision_id != expected_id:
        raise ValueError("authority decision receipt failed integrity verification")


def derive_authority_decision(
    *,
    session_id: str,
    started_at: str,
    marker: Mapping[str, Any] | None,
    buzz_readiness: str,
    transition_health: str,
    derived_at: str,
    original_decision: Mapping[str, Any] | None = None,
    revision: int = 1,
) -> dict[str, Any]:
    """Derive one immutable authority receipt; callers cannot name mode/sink."""

    if not session_id:
        raise ValueError("session_id must not be empty")
    started = _timestamp(started_at)
    _timestamp(derived_at)
    if buzz_readiness not in {"ready", "unavailable"}:
        raise ValueError("buzz_readiness must be ready or unavailable")
    if transition_health not in {"healthy", "blocked"}:
        raise ValueError("transition_health must be healthy or blocked")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise ValueError("revision must be a positive integer")

    observation = _marker_observation(marker)
    readiness = {"buzz": buzz_readiness, "transition_health": transition_health}
    session: dict[str, Any] = {"session_id": session_id, "started_at": started_at}

    if original_decision is not None:
        try:
            verify_authority_decision(original_decision)
        except ValueError as exc:
            raise AuthorityContinuityError(f"original authority integrity failure: {exc}") from exc
        original_session = original_decision.get("session")
        original_choice = original_decision.get("decision")
        if not isinstance(original_session, Mapping) or original_session.get("session_id") != session_id:
            raise AuthorityContinuityError("original decision is for a different session")
        if not isinstance(original_choice, Mapping):
            raise AuthorityContinuityError("original decision has no authority choice")
        original_mode = original_choice.get("mode")
        original_sink = original_choice.get("sink")
        if _SINKS.get(original_mode) != original_sink:
            raise AuthorityContinuityError("original decision has an invalid mode/sink pair")
        session.update(
            {
                "decision_stage": "continuation",
                "relation_to_cutover": (
                    "no_marker_observed"
                    if marker is None
                    else (
                        "started_before_cutover"
                        if started < _timestamp(str(marker["cutover_at"]))
                        else "started_at_or_after_cutover"
                    )
                ),
                "original_decision_ref": authority_decision_ref(original_decision),
                "original_mode": original_mode,
                "original_sink": original_sink,
            }
        )
        mode = str(original_mode)
        sink = str(original_sink)
        reason = "enrolled_authority_continuity"
    elif marker is None:
        session.update(
            {"decision_stage": "initial_enrollment", "relation_to_cutover": "no_marker_observed"}
        )
        mode, sink, reason = (
            "pre_cutover_json_authority",
            "session_artifact_v1",
            "no_cutover_marker_observed",
        )
    else:
        cutover = _timestamp(str(marker["cutover_at"]))
        if started < cutover:
            raise AuthorityContinuityError(
                "a session started before cutover must supply its original enrollment decision"
            )
        session.update(
            {"decision_stage": "initial_enrollment", "relation_to_cutover": "started_at_or_after_cutover"}
        )
        if transition_health == "blocked":
            mode, sink, reason = "blocked_authority_transition", "none", "transition_blocked"
        elif buzz_readiness == "ready":
            mode, sink, reason = "post_cutover_buzz_authority", "buzz_event", "buzz_ready"
        else:
            mode, sink, reason = (
                "post_cutover_fallback_evidence",
                "noncanonical_fallback_ledger",
                "buzz_unavailable",
            )

    inputs = {
        "session": session,
        "marker_observation": observation,
        "readiness": readiness,
    }
    decision: dict[str, Any] = {
        "schema_version": "johan-sdd/authority-decision/v1",
        "revision": revision,
        **inputs,
        "derivation": {
            "derived_at": derived_at,
            "inputs_sha256": canonical_digest(inputs),
            "caller_override": False,
            "reason": reason,
        },
        "decision": {"mode": mode, "sink": sink},
        "immutability": "immutable_append_only_receipt",
    }
    decision["decision_id"] = f"authority_{canonical_digest(decision)}"
    return decision
