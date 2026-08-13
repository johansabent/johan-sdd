"""Registerable command metadata and pure handlers for a later CLI root."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass

from johan_sdd.profiles import select_profile
from johan_sdd.routing import WorkAssessment, route_delivery


@dataclass(frozen=True)
class CommandDescriptor:
    name: str
    argv_prefix: tuple[str, str]
    output_schema: str
    exit_codes: tuple[int, int, int, int] = (0, 2, 3, 4)


_COMMANDS = (
    CommandDescriptor("select-profile", ("johan-sdd", "select-profile"), "johan-sdd/profile-selection/v1"),
    CommandDescriptor("route", ("johan-sdd", "route"), "johan-sdd/delivery-route/v1"),
)


def command_descriptors() -> tuple[CommandDescriptor, ...]:
    """Return immutable metadata for root entrypoint registration."""
    return _COMMANDS


def command_handlers() -> Mapping[str, Callable[[Mapping[str, object]], dict[str, object]]]:
    """Return pure handlers; parsing and I/O remain the root entrypoint's job."""
    return {"select-profile": _select_profile, "route": _route}


def _select_profile(payload: Mapping[str, object]) -> dict[str, object]:
    requested = payload.get("requested_profile")
    triggers = payload.get("triggers", ())
    if not isinstance(requested, (str, type(None))):
        raise ValueError("requested_profile must be a string")
    if not isinstance(triggers, (list, tuple)) or not all(isinstance(item, str) for item in triggers):
        raise ValueError("triggers must be a sequence of strings")
    receipt = payload.get("downgrade_receipt")
    if not isinstance(receipt, (dict, type(None))):
        raise ValueError("downgrade_receipt must be an object")
    return asdict(select_profile(triggers, requested_profile=requested, downgrade_receipt=receipt))


def _route(payload: Mapping[str, object]) -> dict[str, object]:
    fields = ("files_changed", "additions", "deletions", "change_kinds", "observed_surfaces", "primary_checkout", "working_tree_clean", "scope")
    missing = [field for field in fields if field not in payload]
    if missing:
        raise ValueError(f"route input missing: {', '.join(missing)}")
    change_kinds = payload["change_kinds"]
    surfaces = payload["observed_surfaces"]
    if not isinstance(change_kinds, (list, tuple)) or not all(isinstance(item, str) for item in change_kinds):
        raise ValueError("change_kinds must be a sequence of strings")
    if not isinstance(surfaces, (list, tuple)) or not all(isinstance(item, str) for item in surfaces):
        raise ValueError("observed_surfaces must be a sequence of strings")
    assessment = WorkAssessment(
        files_changed=_integer(payload["files_changed"], "files_changed"),
        additions=_integer(payload["additions"], "additions"),
        deletions=_integer(payload["deletions"], "deletions"),
        change_kinds=tuple(change_kinds),
        observed_surfaces=tuple(surfaces),
        primary_checkout=_boolean(payload["primary_checkout"], "primary_checkout"),
        working_tree_clean=_boolean(payload["working_tree_clean"], "working_tree_clean"),
        scope=_string(payload["scope"], "scope"),
        requires_durable_feature_artifacts=_boolean(payload.get("requires_durable_feature_artifacts", False), "requires_durable_feature_artifacts"),
        elevated_risk=_boolean(payload.get("elevated_risk", False), "elevated_risk"),
    )
    return asdict(route_delivery(assessment))


def _integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value


__all__ = ["CommandDescriptor", "command_descriptors", "command_handlers"]
