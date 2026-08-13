from __future__ import annotations

import pytest

from johan_sdd.profiles import ProfilePolicyError, select_profile


def _receipt() -> dict[str, object]:
    digest = "a" * 64
    return {
        "schema_version": "johan-sdd/human-decision-receipt/v1",
        "receipt_id": "receipt-profile-01",
        "decision": "profile-downgrade",
        "recorded_at": "2026-08-13T12:01:00Z",
        "work_ref": {"ref": "work:router-envelope", "sha256": f"sha256:{digest}"},
        "from_profile": "full",
        "to_profile": "lean",
        "hard_trigger_refs": [],
        "human": {"actor_id": "human:johan", "confirmed_at": "2026-08-13T12:00:00Z"},
        "rationale": "The initially elevated scope was clarified as local documentation.",
    }


def test_lean_is_the_explained_default() -> None:
    selection = select_profile()

    assert selection.profile == "lean"
    assert selection.reason == "default lean profile: no full trigger was observed"
    assert selection.hard_triggers == ()


def test_hard_trigger_selects_full_in_stable_contract_order() -> None:
    selection = select_profile(
        ["security-or-identity", "public-contract-change", "security-or-identity"]
    )

    assert selection.profile == "full"
    assert selection.hard_triggers == ("public-contract-change", "security-or-identity")
    assert selection.reason == "full profile: public-contract-change, security-or-identity"


def test_requested_escalation_is_always_allowed() -> None:
    selection = select_profile(requested_profile="full")

    assert selection.profile == "full"
    assert selection.reason == "full profile: explicit escalation"


def test_downgrade_requires_a_valid_human_receipt_and_no_hard_trigger() -> None:
    with pytest.raises(ProfilePolicyError, match="human decision receipt"):
        select_profile(requested_profile="lean", downgrade_receipt=None)

    selection = select_profile(requested_profile="lean", downgrade_receipt=_receipt())
    assert selection.profile == "lean"
    assert selection.reason == "lean profile: validated human downgrade receipt"

    with pytest.raises(ProfilePolicyError, match="hard trigger"):
        select_profile(
            ["architecture-change"],
            requested_profile="lean",
            downgrade_receipt=_receipt(),
        )


def test_downgrade_rejects_a_receipt_that_is_not_the_versioned_contract() -> None:
    receipt = _receipt()
    receipt["human"] = {"actor_id": "agent:codex", "confirmed_at": "2026-08-13T12:00:00Z"}

    with pytest.raises(ProfilePolicyError, match="human actor"):
        select_profile(requested_profile="lean", downgrade_receipt=receipt)
