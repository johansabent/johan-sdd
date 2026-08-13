"""Portable adapter joining routing and engineering-flow interfaces."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re

from johan_sdd.profiles import ProfileSelection, select_profile
from johan_sdd.routing import DeliveryRoute, WorkAssessment, route_delivery


PHASE_ROUTER_V1 = "phase-router/v1"
ENGINEERING_FLOW_HUB_V1 = "engineering-flow-hub/v1"
SPEC_DRIVEN_DELIVERY_V1 = "spec-driven-delivery/v1"
_DECISION_ID = re.compile(r"^authority_[0-9a-f]{64}$")
_SINKS = {
    "pre_cutover_json_authority": "session_artifact_v1",
    "blocked_authority_transition": "none",
    "post_cutover_buzz_authority": "buzz_event",
    "post_cutover_fallback_evidence": "noncanonical_fallback_ledger",
}


class AuthorityDecisionError(ValueError):
    """An externally supplied lifecycle decision is not an immutable contract."""


@dataclass(frozen=True)
class JohanHostAdapterMetadata:
    interface: str
    phase_router: str
    engineering_flow_hub: str
    optional: bool = True


JOHAN_HOST_ADAPTER = JohanHostAdapterMetadata(
    interface="johan-host-adapter/v1",
    phase_router="using-johan-skills",
    engineering_flow_hub="ask-matt",
)


@dataclass(frozen=True)
class DeliveryPlan:
    interface: str
    lane: str
    profile: str
    profile_reason: str
    phase_router_interface: str
    engineering_flow_hub_interface: str
    delivery_spine: bool
    engineering_modules: tuple[str, ...]


@dataclass(frozen=True)
class LifecycleRoute:
    decision_id: str
    revision: int
    mode: str
    sink: str

    @property
    def sinks(self) -> tuple[str, ...]:
        """The sole permitted sink; tuple shape makes dual-write unrepresentable."""
        return (self.sink,)


class ContractPhaseRouter:
    """Host-neutral phase-router/v1 implementation."""

    interface = PHASE_ROUTER_V1

    def select(self, triggers: tuple[str, ...], requested_profile: str | None) -> ProfileSelection:
        return select_profile(triggers, requested_profile=requested_profile)


class ContractEngineeringFlowHub:
    """Host-neutral engineering-flow-hub/v1 implementation."""

    interface = ENGINEERING_FLOW_HUB_V1

    def modules_for(self, lane: str) -> tuple[str, ...]:
        if lane == "micro":
            return ()
        return ("shaping", "tdd", "diagnosis", "prototype", "review")


class SpecDrivenDeliveryAdapter:
    """Compose the two portable interfaces into a single delivery plan."""

    interface = SPEC_DRIVEN_DELIVERY_V1

    def __init__(self, phase_router: ContractPhaseRouter, engineering_flow_hub: ContractEngineeringFlowHub) -> None:
        self._phase_router = phase_router
        self._engineering_flow_hub = engineering_flow_hub

    def plan(
        self,
        assessment: WorkAssessment,
        *,
        triggers: tuple[str, ...] = (),
        requested_profile: str | None = None,
    ) -> DeliveryPlan:
        route: DeliveryRoute = route_delivery(assessment)
        selection = self._phase_router.select(triggers, requested_profile)
        return DeliveryPlan(
            interface=self.interface,
            lane=route.lane,
            profile=selection.profile,
            profile_reason=selection.reason,
            phase_router_interface=self._phase_router.interface,
            engineering_flow_hub_interface=self._engineering_flow_hub.interface,
            delivery_spine=route.lane == "feature",
            engineering_modules=self._engineering_flow_hub.modules_for(route.lane),
        )


def lifecycle_route(authority_decision: Mapping[str, object]) -> LifecycleRoute:
    """Consume an immutable external decision and expose exactly one lifecycle sink.

    This adapter intentionally does not derive, store, or mutate a decision.  Its
    caller must obtain that immutable receipt from the lifecycle authority owner.
    """

    if authority_decision.get("schema_version") != "johan-sdd/authority-decision/v1":
        raise AuthorityDecisionError("authority decision has an unsupported schema version")
    if authority_decision.get("immutability") != "immutable_append_only_receipt":
        raise AuthorityDecisionError("authority decision must be immutable")
    decision_id = authority_decision.get("decision_id")
    revision = authority_decision.get("revision")
    decision = authority_decision.get("decision")
    if not isinstance(decision_id, str) or not _DECISION_ID.fullmatch(decision_id):
        raise AuthorityDecisionError("authority decision requires a stable decision ID")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise AuthorityDecisionError("authority decision requires a positive immutable revision")
    if not isinstance(decision, Mapping):
        raise AuthorityDecisionError("authority decision requires a mode and sink")
    mode, sink = decision.get("mode"), decision.get("sink")
    if mode not in _SINKS:
        raise AuthorityDecisionError("authority decision has an unsupported mode")
    if sink != _SINKS[mode]:
        raise AuthorityDecisionError("authority decision sink does not match its mode")
    return LifecycleRoute(decision_id=decision_id, revision=revision, mode=mode, sink=sink)


__all__ = [
    "AuthorityDecisionError",
    "ContractEngineeringFlowHub",
    "ContractPhaseRouter",
    "DeliveryPlan",
    "ENGINEERING_FLOW_HUB_V1",
    "JOHAN_HOST_ADAPTER",
    "JohanHostAdapterMetadata",
    "LifecycleRoute",
    "PHASE_ROUTER_V1",
    "SPEC_DRIVEN_DELIVERY_V1",
    "SpecDrivenDeliveryAdapter",
    "lifecycle_route",
]
