"""Locked, fenced promotion of a capture into one authority sink."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from ._canonical import canonical_bytes, canonical_digest
from ._io import atomic_write_bytes, exclusive_lock
from .authority import authority_decision_digest, authority_decision_ref
from .packet import canonical_capture_bytes, verify_capture_packet


_SINKS = {
    "pre_cutover_json_authority": "session_artifact_v1",
    "blocked_authority_transition": "none",
    "post_cutover_buzz_authority": "buzz_event",
    "post_cutover_fallback_evidence": "noncanonical_fallback_ledger",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class PromotionError(RuntimeError):
    """Base class for promotion failures that may carry durable evidence."""

    def __init__(
        self,
        message: str,
        *,
        receipt: Mapping[str, Any] | None = None,
        receipt_path: Path | None = None,
    ) -> None:
        super().__init__(message)
        self.receipt = dict(receipt or {})
        self.receipt_path = receipt_path


class PromotionActorError(PromotionError):
    """The promoter is the capture generator or has invalid policy identity."""


class PromotionConflictError(PromotionError):
    """Authority, sink, capture identity, or target pre-state conflicts."""


class PromotionFailedError(PromotionError):
    """A target write failed and was restored to its prior state."""


class PromotionRecoveryRequired(PromotionError):
    """A target write failed and automatic restoration was not proven."""

    def __init__(
        self,
        message: str,
        *,
        receipt: Mapping[str, Any],
        receipt_path: Path,
        rollback_evidence_path: Path,
    ) -> None:
        super().__init__(message, receipt=receipt, receipt_path=receipt_path)
        self.rollback_evidence_path = rollback_evidence_path


@dataclass(frozen=True)
class FilePromotionTarget:
    """A single file-backed sink with compare-and-swap operations."""

    path: Path
    target_id: str
    sink: str

    def snapshot(self) -> bytes | None:
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            return None

    def measure(self) -> str:
        snapshot = self.snapshot()
        return "absent" if snapshot is None else hashlib.sha256(snapshot).hexdigest()

    def readback_digest(self) -> str:
        return self.measure()

    def commit(self, content: bytes, *, expected_preimage: str) -> None:
        observed = self.measure()
        if observed != expected_preimage:
            raise PromotionConflictError(
                f"target changed before commit: expected {expected_preimage}, observed {observed}"
            )
        atomic_write_bytes(self.path, content)

    def restore(self, snapshot: bytes | None, *, expected_current_digest: str) -> None:
        observed = self.measure()
        if observed != expected_current_digest:
            raise PromotionConflictError(
                f"target changed before rollback: expected {expected_current_digest}, observed {observed}"
            )
        if snapshot is None:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
        else:
            atomic_write_bytes(self.path, snapshot)


@dataclass(frozen=True)
class PromotionOutcome:
    phase: str
    request: dict[str, Any]
    prepared_receipt: dict[str, Any]
    terminal_receipt: dict[str, Any]
    request_path: Path
    prepared_receipt_path: Path
    terminal_receipt_path: Path
    target_changed: bool


def _write_immutable(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = canonical_bytes(document)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        existing = path.read_bytes()
        if existing != content:
            raise PromotionConflictError(f"immutable promotion artifact already exists with other content: {path}")
        return
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _next_fencing_token(path: Path) -> int:
    try:
        current_text = path.read_text(encoding="ascii")
        current = int(current_text)
    except FileNotFoundError:
        current = 0
    except ValueError as exc:
        raise PromotionConflictError(f"invalid fencing counter: {path}") from exc
    token = current + 1
    atomic_write_bytes(path, str(token).encode("ascii"))
    return token


def _validate_promoter(promoter: Mapping[str, Any], generator_actor_id: str) -> dict[str, Any]:
    expected = {"actor_id", "policy_id", "policy_revision", "policy_sha256"}
    if set(promoter) != expected:
        raise PromotionActorError("promoter identity requires actor and complete policy binding")
    actor = promoter.get("actor_id")
    if not isinstance(actor, str) or not actor:
        raise PromotionActorError("promoter actor_id must not be empty")
    if actor == generator_actor_id:
        raise PromotionActorError("capture generator and promoter must be distinct actors")
    if not isinstance(promoter.get("policy_id"), str) or not promoter["policy_id"]:
        raise PromotionActorError("promoter policy_id must not be empty")
    revision = promoter.get("policy_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise PromotionActorError("promoter policy_revision must be positive")
    digest = promoter.get("policy_sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise PromotionActorError("promoter policy_sha256 must be a lowercase SHA-256 digest")
    return dict(promoter)


def _request_id(request: Mapping[str, Any]) -> str:
    material = dict(request)
    material.pop("request_id", None)
    return f"promotion_{canonical_digest(material)}"


def _receipt(request: Mapping[str, Any], phase: str, **fields: Any) -> dict[str, Any]:
    receipt = dict(request)
    receipt["schema_version"] = "johan-sdd/promotion-receipt/v1"
    receipt["phase"] = phase
    receipt.update(fields)
    receipt["receipt_id"] = f"receipt_{canonical_digest(receipt)}"
    return receipt


def _persist_request_and_prepared(
    request: dict[str, Any], receipt_directory: Path
) -> tuple[dict[str, Any], Path, Path]:
    request_path = receipt_directory / f"{request['request_id']}.request.json"
    prepared = _receipt(request, "prepared")
    prepared_path = receipt_directory / f"{request['request_id']}.{prepared['receipt_id']}.prepared.json"
    _write_immutable(request_path, request)
    _write_immutable(prepared_path, prepared)
    return prepared, request_path, prepared_path


def _terminal_path(receipt_directory: Path, receipt: Mapping[str, Any]) -> Path:
    return receipt_directory / (
        f"{receipt['request_id']}.{receipt['receipt_id']}.{receipt['phase']}.json"
    )


def _failed(
    *,
    request: dict[str, Any],
    receipt_directory: Path,
    code: str,
    message: str,
    exception_type: type[PromotionError],
) -> PromotionError:
    receipt = _receipt(request, "failed", error={"code": code, "message": message})
    receipt_path = _terminal_path(receipt_directory, receipt)
    _write_immutable(receipt_path, receipt)
    return exception_type(message, receipt=receipt, receipt_path=receipt_path)


def _existing_capture(snapshot: bytes | None) -> Mapping[str, Any] | None:
    if snapshot is None:
        return None
    try:
        value = json.loads(snapshot.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


def promote_capture(
    *,
    packet: Mapping[str, Any],
    authority_decision: Mapping[str, Any],
    promoter: Mapping[str, Any],
    target: FilePromotionTarget,
    receipt_directory: str | Path,
    lock_directory: str | Path,
    clock: Callable[[], str] = _utc_now,
    lock_timeout: float = 10.0,
) -> PromotionOutcome:
    """Promote a verified capture under one cross-process lock and fence."""

    verify_capture_packet(packet)
    generator = packet["generator"]
    if not isinstance(generator, Mapping):  # defensive after public integrity validation
        raise PromotionConflictError("capture generator identity is invalid")
    generator_actor_id = str(generator["actor_id"])
    promoter_document = _validate_promoter(promoter, generator_actor_id)

    decision_ref = authority_decision_ref(authority_decision)
    decision_digest = authority_decision_digest(authority_decision)
    packet_authority = packet["authority_decision"]
    if not isinstance(packet_authority, Mapping):  # defensive after public integrity validation
        raise PromotionConflictError("capture authority reference is invalid")
    if (
        packet_authority.get("decision_ref") != decision_ref
        or packet_authority.get("decision_sha256") != decision_digest
    ):
        raise PromotionConflictError("capture is not bound to the supplied authority decision")
    choice = authority_decision.get("decision")
    if not isinstance(choice, Mapping):
        raise PromotionConflictError("authority decision has no mode/sink")
    mode = choice.get("mode")
    sink = choice.get("sink")
    if _SINKS.get(mode) != sink:
        raise PromotionConflictError("authority decision has an invalid mode/sink pair")

    receipt_root = Path(receipt_directory)
    lock_root = Path(lock_directory)
    lock_key = hashlib.sha256(target.target_id.encode("utf-8")).hexdigest()
    lock_path = lock_root / f"{lock_key}.lock"
    fence_path = lock_root / f"{lock_key}.fence"
    content = canonical_capture_bytes(packet)
    next_digest = hashlib.sha256(content).hexdigest()

    with exclusive_lock(lock_path, timeout=lock_timeout):
        fence = _next_fencing_token(fence_path)
        acquired_at = clock()
        snapshot = target.snapshot()
        preimage = "absent" if snapshot is None else hashlib.sha256(snapshot).hexdigest()
        request: dict[str, Any] = {
            "schema_version": "johan-sdd/promotion-request/v1",
            "capture_id": packet["capture_id"],
            "packet_sha256": next_digest,
            "generator_actor_id": generator_actor_id,
            "promoter": promoter_document,
            "authority": {
                "revision": authority_decision["revision"],
                "decision_ref": decision_ref,
                "decision_sha256": decision_digest,
                "mode": mode,
                "sink": sink,
            },
            "lock": {
                "lock_id": f"promotion:{lock_key}",
                "fencing_token": fence,
                "acquired_at": acquired_at,
            },
            "target": {
                "target_id": target.target_id,
                "preimage_digest": preimage,
                "next_digest": preimage if sink == "none" else next_digest,
            },
            "phase": "prepared",
        }
        request["request_id"] = _request_id(request)
        prepared, request_path, prepared_path = _persist_request_and_prepared(request, receipt_root)

        if target.sink != sink:
            error = _failed(
                request=request,
                receipt_directory=receipt_root,
                code="promotion.sink-conflict",
                message=f"target sink {target.sink!r} does not match derived authority sink {sink!r}",
                exception_type=PromotionConflictError,
            )
            raise error
        if sink == "none":
            error = _failed(
                request=request,
                receipt_directory=receipt_root,
                code="promotion.authority-blocked",
                message="blocked authority permits no lifecycle write",
                exception_type=PromotionConflictError,
            )
            raise error

        existing = _existing_capture(snapshot)
        target_changed = True
        if existing is not None and existing.get("capture_id") == packet["capture_id"]:
            if existing.get("packet_digest") != packet["packet_digest"] or preimage != next_digest:
                error = _failed(
                    request=request,
                    receipt_directory=receipt_root,
                    code="promotion.capture-conflict",
                    message="capture ID already exists with a different digest or content",
                    exception_type=PromotionConflictError,
                )
                raise error
            target_changed = False
        elif snapshot is not None:
            error = _failed(
                request=request,
                receipt_directory=receipt_root,
                code="promotion.target-occupied",
                message="promotion target already contains another capture",
                exception_type=PromotionConflictError,
            )
            raise error

        try:
            if target_changed:
                # FilePromotionTarget repeats the preimage measurement here,
                # immediately before replacement, providing the target CAS.
                target.commit(content, expected_preimage=preimage)
            readback = target.readback_digest()
            if readback != next_digest:
                raise OSError(
                    f"target readback mismatch: planned {next_digest}, observed {readback}"
                )
        except Exception as exc:
            try:
                target.restore(snapshot, expected_current_digest=next_digest)
            except Exception as rollback_exc:
                rollback_evidence = {
                    "request_id": request["request_id"],
                    "target_id": target.target_id,
                    "attempted_at": clock(),
                    "snapshot_digest": preimage,
                    "planned_digest": next_digest,
                    "write_error": str(exc),
                    "rollback_error": str(rollback_exc),
                }
                rollback_path = receipt_root / f"{request['request_id']}.rollback-evidence.json"
                _write_immutable(rollback_path, rollback_evidence)
                recovery = _receipt(
                    request,
                    "needs_recovery",
                    error={"code": "promotion.rollback-unproven", "message": str(exc)},
                    rollback_receipt_sha256=canonical_digest(rollback_evidence),
                )
                recovery_path = _terminal_path(receipt_root, recovery)
                _write_immutable(recovery_path, recovery)
                raise PromotionRecoveryRequired(
                    str(exc),
                    receipt=recovery,
                    receipt_path=recovery_path,
                    rollback_evidence_path=rollback_path,
                ) from exc
            failed = _failed(
                request=request,
                receipt_directory=receipt_root,
                code="promotion.commit-failed",
                message=str(exc),
                exception_type=PromotionFailedError,
            )
            raise failed from exc

        committed = _receipt(
            request,
            "committed",
            committed_at=clock(),
            readback_digest=readback,
        )
        committed_path = _terminal_path(receipt_root, committed)
        _write_immutable(committed_path, committed)
        return PromotionOutcome(
            phase="committed",
            request=request,
            prepared_receipt=prepared,
            terminal_receipt=committed,
            request_path=request_path,
            prepared_receipt_path=prepared_path,
            terminal_receipt_path=committed_path,
            target_changed=target_changed,
        )
