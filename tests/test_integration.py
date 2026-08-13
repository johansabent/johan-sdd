from __future__ import annotations

from johan_sdd.capture import (
    authority_decision_ref,
    derive_authority_decision,
    generate_capture_packet,
)
from johan_sdd.evidence import build_evidence_artifact, build_evidence_packet
from johan_sdd.routing import WorkAssessment
from johan_sdd.spec_delivery import (
    ContractEngineeringFlowHub,
    ContractPhaseRouter,
    SpecDrivenDeliveryAdapter,
    lifecycle_route,
)


SHA_A = "a" * 64
SHA_B = "b" * 64


def test_delivery_decision_flows_through_authority_capture_and_evidence() -> None:
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
    decision = derive_authority_decision(
        session_id="integration-session",
        started_at="2026-08-13T12:00:00Z",
        marker=None,
        buzz_readiness="unavailable",
        transition_health="healthy",
        derived_at="2026-08-13T12:00:01Z",
    )
    route = lifecycle_route(decision)
    packet = generate_capture_packet(
        session_claim={
            "session_id": "integration-session",
            "owner": {"agent": "codex", "model": "gpt-5"},
            "authority_decision_ref": authority_decision_ref(decision),
        },
        lifecycle_cursor=1,
        authority_decision=decision,
        payload={
            "event_type": "working",
            "occurred_at": "2026-08-13T12:01:00Z",
            "summary": "The full delivery slice is ready for promotion.",
            "next_action": "Promote through the one enrolled lifecycle sink.",
            "evidence_refs": [f"sha256:{SHA_A}"],
        },
    )
    artifact = build_evidence_artifact(
        artifact_id="slice:integration-session",
        kind="slice-manifest",
        produced_at="2026-08-13T12:02:00Z",
        subject={"ref": "capture:" + packet["capture_id"], "sha256": "sha256:" + packet["packet_digest"]},
        inputs=[{"ref": "contract:integration-charter/v1", "sha256": f"sha256:{SHA_A}"}],
        commands=[
            {
                "argv": ["uv", "run", "--locked", "pytest", "-q"],
                "exit_code": 0,
                "output": {"ref": "log:integration.txt", "sha256": f"sha256:{SHA_B}"},
            }
        ],
        outputs=[{"ref": "artifact:capture.json", "sha256": "sha256:" + packet["packet_digest"]}],
    )
    evidence = build_evidence_packet(
        event_type="slice",
        work_id="integration-session",
        agent={"name": "codex", "model": "gpt-5"},
        git={"base_sha": "1" * 40, "final_sha": "2" * 40},
        worktree_ref="worktree:integration",
        claim_ref="claim:integration-session:generation-1",
        contracts=[{"ref": "contract:integration-charter/v1", "sha256": SHA_A}],
        changes=[{"path": "src/johan_sdd", "sha256": SHA_A, "summary": "Integrate delivery modules."}],
        verification=[
            {
                "command": "uv run --locked pytest -q",
                "exit_code": 0,
                "result": "passed",
                "log_ref": {"ref": "log:integration.txt", "sha256": SHA_B},
            }
        ],
        artifacts=[("artifact:integration.json", artifact)],
        logs=[{"ref": "log:integration.txt", "sha256": SHA_B}],
        next_consumer="root-coordinator",
        next_action="Promote the verified capture.",
    )

    assert plan.lane == "feature" and plan.profile == "full" and plan.delivery_spine is True
    assert route.sinks == ("session_artifact_v1",)
    assert packet["authority_decision"]["decision_ref"] == authority_decision_ref(decision)
    assert evidence["artifacts"][0]["kind"] == "slice-manifest"
    assert "transcript" not in evidence
