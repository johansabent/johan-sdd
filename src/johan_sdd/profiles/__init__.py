"""Deterministic delivery-profile selection.

The module deliberately validates downgrade receipts locally instead of importing a
host validator.  A host can validate the complete JSON Schema separately; this
portable seam enforces the policy decisions required to select a profile.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
import re


Profile = str
HARD_TRIGGERS = (
    "public-contract-change",
    "architecture-change",
    "security-or-identity",
    "data-migration",
    "multi-system-coordination",
    "destructive-or-external-effect",
    "high-uncertainty-or-high-blast-radius",
)
_SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_PORTABLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_PORTABLE_REF = re.compile(r"^[a-z][a-z0-9-]*:[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$")


class ProfilePolicyError(ValueError):
    """Raised when a requested profile would violate the delivery charter."""


@dataclass(frozen=True)
class ProfileSelection:
    """A profile plus the stable explanation required by the charter."""

    profile: Profile
    reason: str
    hard_triggers: tuple[str, ...]


def select_profile(
    triggers: Iterable[str] = (),
    *,
    requested_profile: Profile | None = None,
    downgrade_receipt: Mapping[str, object] | None = None,
) -> ProfileSelection:
    """Select ``lean`` by default and require proof for a downgrade.

    ``requested_profile='full'`` is an explicit escalation.  A request for
    ``lean`` is a downgrade only when a receipt is supplied; this makes the
    exceptional path explicit and keeps callers from silently suppressing the
    profile decision.
    """

    if requested_profile not in (None, "lean", "full"):
        raise ProfilePolicyError("requested profile must be lean or full")

    observed = tuple(sorted(set(triggers).intersection(HARD_TRIGGERS)))
    if observed:
        if requested_profile == "lean":
            raise ProfilePolicyError("a hard trigger cannot be downgraded to lean")
        return ProfileSelection("full", f"full profile: {', '.join(observed)}", observed)

    if requested_profile == "full":
        return ProfileSelection("full", "full profile: explicit escalation", ())

    if requested_profile == "lean":
        _validate_downgrade_receipt(downgrade_receipt)
        return ProfileSelection("lean", "lean profile: validated human downgrade receipt", ())

    return ProfileSelection("lean", "default lean profile: no full trigger was observed", ())


def _validate_downgrade_receipt(receipt: Mapping[str, object] | None) -> None:
    if receipt is None:
        raise ProfilePolicyError("lean downgrade requires a human decision receipt")
    if receipt.get("schema_version") != "johan-sdd/human-decision-receipt/v1":
        raise ProfilePolicyError("human decision receipt has an unsupported schema version")
    if not isinstance(receipt.get("receipt_id"), str) or not _PORTABLE_ID.fullmatch(receipt["receipt_id"]):
        raise ProfilePolicyError("human decision receipt requires a portable receipt ID")
    if receipt.get("decision") != "profile-downgrade":
        raise ProfilePolicyError("human decision receipt must record a profile downgrade")
    if receipt.get("from_profile") != "full" or receipt.get("to_profile") != "lean":
        raise ProfilePolicyError("human decision receipt must downgrade full to lean")
    hard_trigger_refs = receipt.get("hard_trigger_refs")
    if hard_trigger_refs != []:
        raise ProfilePolicyError("human decision receipt must record no hard trigger refs")
    human = receipt.get("human")
    if not isinstance(human, Mapping) or not isinstance(human.get("actor_id"), str):
        raise ProfilePolicyError("human decision receipt requires a human actor")
    if not human["actor_id"].startswith("human:"):
        raise ProfilePolicyError("human decision receipt requires a human actor")
    work_ref = receipt.get("work_ref")
    if not isinstance(work_ref, Mapping) or not isinstance(work_ref.get("ref"), str):
        raise ProfilePolicyError("human decision receipt requires a portable work reference")
    if not _PORTABLE_REF.fullmatch(work_ref["ref"]):
        raise ProfilePolicyError("human decision receipt requires a portable work reference")
    if not isinstance(work_ref.get("sha256"), str) or not _SHA256_REF.fullmatch(work_ref["sha256"]):
        raise ProfilePolicyError("human decision receipt requires a portable work reference")
    rationale = receipt.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ProfilePolicyError("human decision receipt requires a rationale")
    recorded_at = _parse_timestamp(receipt.get("recorded_at"))
    confirmed_at = _parse_timestamp(human.get("confirmed_at"))
    if recorded_at is None or confirmed_at is None:
        raise ProfilePolicyError("human decision receipt requires RFC 3339 timestamps")
    if confirmed_at > recorded_at:
        raise ProfilePolicyError("human confirmation cannot follow receipt recording")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError:
        return None


__all__ = ["HARD_TRIGGERS", "ProfilePolicyError", "ProfileSelection", "select_profile"]
