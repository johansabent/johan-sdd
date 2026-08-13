from __future__ import annotations

from johan_sdd.routing import WorkAssessment, route_delivery


def test_documentation_change_admitted_by_micro_contract_routes_micro() -> None:
    route = route_delivery(
        WorkAssessment(
            files_changed=2,
            additions=12,
            deletions=3,
            change_kinds=("add", "modify"),
            observed_surfaces=("documentation",),
            primary_checkout=True,
            working_tree_clean=True,
            scope="bounded",
        )
    )

    assert route.lane == "micro"
    assert route.reason == "micro: assessment satisfies the deterministic admission contract"


def test_engineering_work_without_feature_artifacts_routes_small() -> None:
    route = route_delivery(
        WorkAssessment(
            files_changed=4,
            additions=20,
            deletions=4,
            change_kinds=("modify",),
            observed_surfaces=("code",),
            primary_checkout=False,
            working_tree_clean=False,
            scope="bounded",
        )
    )

    assert route.lane == "small"
    assert route.reason == "small: bounded engineering work without durable feature artifacts"


def test_ambiguity_and_feature_artifacts_fail_closed_to_feature() -> None:
    ambiguous = route_delivery(
        WorkAssessment(
            files_changed=1,
            additions=1,
            deletions=0,
            change_kinds=("modify",),
            observed_surfaces=("documentation",),
            primary_checkout=True,
            working_tree_clean=True,
            scope="unknown",
        )
    )
    feature = route_delivery(
        WorkAssessment(
            files_changed=1,
            additions=1,
            deletions=0,
            change_kinds=("modify",),
            observed_surfaces=("documentation",),
            primary_checkout=True,
            working_tree_clean=True,
            scope="bounded",
            requires_durable_feature_artifacts=True,
        )
    )

    assert ambiguous.lane == "feature"
    assert ambiguous.reason == "feature: work scope is unknown"
    assert feature.lane == "feature"
    assert feature.reason == "feature: durable feature artifacts are required"


def test_micro_admission_is_rejected_for_deletion_or_dirty_primary_checkout() -> None:
    route = route_delivery(
        WorkAssessment(
            files_changed=1,
            additions=0,
            deletions=4,
            change_kinds=("delete",),
            observed_surfaces=("documentation",),
            primary_checkout=True,
            working_tree_clean=False,
            scope="bounded",
        )
    )

    assert route.lane == "small"
    assert route.reason == "small: bounded engineering work without durable feature artifacts"
