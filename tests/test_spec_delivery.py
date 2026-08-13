from __future__ import annotations

import pytest

from johan_sdd.routing import WorkAssessment
from johan_sdd.spec_delivery import (
    AuthorityDecisionError,
    ContractEngineeringFlowHub,
    ContractPhaseRouter,
    SpecDrivenDeliveryAdapter,
    lifecycle_route,
)


def _assessment() -> WorkAssessment:
    return WorkAssessment(
        files_changed=4,
        additions=20,
        deletions=4,
        change_kinds=("modify",),
        observed_surfaces=("code",),
        primary_checkout=False,
        working_tree_clean=False,
        scope="bounded",
    )


def _authority_decision(mode: str = "post_cutover_buzz_authority") -> dict[str, object]:
    sinks = {
        "pre_cutover_json_authority": "session_artifact_v1",
        "blocked_authority_transition": "none",
        "post_cutover_buzz_authority": "buzz_event",
        "post_cutover_fallback_evidence": "noncanonical_fallback_ledger",
    }
    return {
        "schema_version": "johan-sdd/authority-decision/v1",
        "decision_id": f"authority_{'a' * 64}",
        "revision": 1,
        "decision": {"mode": mode, "sink": sinks[mode]},
        "immutability": "immutable_append_only_receipt",
    }


def test_adapter_joins_the_two_portable_interfaces_without_host_dependency() -> None:
    adapter = SpecDrivenDeliveryAdapter(ContractPhaseRouter(), ContractEngineeringFlowHub())

    plan = adapter.plan(_assessment())

    assert plan.interface == "spec-driven-delivery/v1"
    assert plan.lane == "small"
    assert plan.profile == "lean"
    assert plan.phase_router_interface == "phase-router/v1"
    assert plan.engineering_flow_hub_interface == "engineering-flow-hub/v1"
    assert plan.delivery_spine is False
    assert plan.engineering_modules == ("shaping", "tdd", "diagnosis", "prototype", "review")


def test_feature_plan_enables_delivery_spine() -> None:
    adapter = SpecDrivenDeliveryAdapter(ContractPhaseRouter(), ContractEngineeringFlowHub())
    plan = adapter.plan(
        WorkAssessment(
            files_changed=8,
            additions=90,
            deletions=10,
            change_kinds=("modify",),
            observed_surfaces=("code",),
            primary_checkout=False,
            working_tree_clean=False,
            scope="medium_or_large",
        ),
        requested_profile="full",
    )

    assert plan.lane == "feature"
    assert plan.delivery_spine is True
    assert plan.profile == "full"


@pytest.mark.parametrize(
    ("mode", "sink"),
    [
        ("pre_cutover_json_authority", "session_artifact_v1"),
        ("blocked_authority_transition", "none"),
        ("post_cutover_buzz_authority", "buzz_event"),
        ("post_cutover_fallback_evidence", "noncanonical_fallback_ledger"),
    ],
)
def test_lifecycle_route_consumes_external_immutable_decision_without_dual_write(mode: str, sink: str) -> None:
    route = lifecycle_route(_authority_decision(mode))

    assert route.mode == mode
    assert route.sink == sink
    assert route.sinks == (sink,)
    assert route.decision_id == f"authority_{'a' * 64}"


def test_lifecycle_route_rejects_mutable_or_inconsistent_authority_decision() -> None:
    decision = _authority_decision()
    decision["immutability"] = "mutable"
    with pytest.raises(AuthorityDecisionError, match="immutable"):
        lifecycle_route(decision)

    decision = _authority_decision()
    decision["decision"] = {"mode": "post_cutover_buzz_authority", "sink": "session_artifact_v1"}
    with pytest.raises(AuthorityDecisionError, match="sink"):
        lifecycle_route(decision)
