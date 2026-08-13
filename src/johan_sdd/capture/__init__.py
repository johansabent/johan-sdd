"""Lifecycle authority, capture generation, and promotion."""

from .authority import (
    AuthorityContinuityError,
    CutoverConflictError,
    authority_decision_digest,
    authority_decision_ref,
    derive_authority_decision,
    read_cutover_marker,
    verify_authority_decision,
    write_cutover_marker,
)
from .packet import (
    CaptureValidationError,
    canonical_capture_bytes,
    generate_capture_packet,
    verify_capture_packet,
)
from .promotion import (
    FilePromotionTarget,
    PromotionActorError,
    PromotionConflictError,
    PromotionFailedError,
    PromotionOutcome,
    PromotionRecoveryRequired,
    promote_capture,
)

__all__ = [
    "AuthorityContinuityError",
    "CutoverConflictError",
    "authority_decision_digest",
    "authority_decision_ref",
    "derive_authority_decision",
    "read_cutover_marker",
    "verify_authority_decision",
    "write_cutover_marker",
    "CaptureValidationError",
    "canonical_capture_bytes",
    "generate_capture_packet",
    "verify_capture_packet",
    "FilePromotionTarget",
    "PromotionActorError",
    "PromotionConflictError",
    "PromotionFailedError",
    "PromotionOutcome",
    "PromotionRecoveryRequired",
    "promote_capture",
]
