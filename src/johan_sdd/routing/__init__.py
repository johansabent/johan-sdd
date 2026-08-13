"""Deterministic delivery-lane classification."""

from __future__ import annotations

from dataclasses import dataclass


Lane = str
_MICRO_SURFACES = frozenset({"documentation", "non-operational-configuration"})
_MICRO_KINDS = frozenset({"add", "modify"})


@dataclass(frozen=True)
class WorkAssessment:
    """Measured facts used to classify work; no caller selects a lane directly."""

    files_changed: int
    additions: int
    deletions: int
    change_kinds: tuple[str, ...]
    observed_surfaces: tuple[str, ...]
    primary_checkout: bool
    working_tree_clean: bool
    scope: str
    requires_durable_feature_artifacts: bool = False
    elevated_risk: bool = False

    @property
    def changed_lines(self) -> int:
        return self.additions + self.deletions


@dataclass(frozen=True)
class DeliveryRoute:
    lane: Lane
    reason: str


def route_delivery(assessment: WorkAssessment) -> DeliveryRoute:
    """Return one charter lane from measured facts, escalating ambiguity."""

    _validate_assessment(assessment)
    if assessment.scope == "unknown":
        return DeliveryRoute("feature", "feature: work scope is unknown")
    if assessment.scope == "medium_or_large":
        return DeliveryRoute("feature", "feature: work scope is medium or large")
    if assessment.requires_durable_feature_artifacts:
        return DeliveryRoute("feature", "feature: durable feature artifacts are required")
    if assessment.elevated_risk:
        return DeliveryRoute("feature", "feature: elevated-risk surface requires delivery spine")
    if _is_micro(assessment):
        return DeliveryRoute("micro", "micro: assessment satisfies the deterministic admission contract")
    return DeliveryRoute("small", "small: bounded engineering work without durable feature artifacts")


def _is_micro(assessment: WorkAssessment) -> bool:
    return (
        assessment.files_changed <= 3
        and assessment.changed_lines <= 50
        and assessment.primary_checkout
        and assessment.working_tree_clean
        and bool(assessment.change_kinds)
        and bool(assessment.observed_surfaces)
        and set(assessment.change_kinds) <= _MICRO_KINDS
        and set(assessment.observed_surfaces) <= _MICRO_SURFACES
    )


def _validate_assessment(assessment: WorkAssessment) -> None:
    if assessment.scope not in {"bounded", "medium_or_large", "unknown"}:
        raise ValueError("scope must be bounded, medium_or_large, or unknown")
    if any(value < 0 for value in (assessment.files_changed, assessment.additions, assessment.deletions)):
        raise ValueError("change counts cannot be negative")
    if not assessment.change_kinds or not assessment.observed_surfaces:
        raise ValueError("assessment requires observed change kinds and surfaces")


__all__ = ["DeliveryRoute", "Lane", "WorkAssessment", "route_delivery"]
