from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from johan_sdd.contracts import validate_semantics
from johan_sdd.evidence import (
    EvidenceValidationError,
    build_evidence_artifact,
    build_evidence_packet,
    canonical_evidence_bytes,
    evidence_digest,
)


ROOT = Path(__file__).resolve().parents[1]
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def validate(schema_name: str, document: dict[str, object]) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(document)


def artifact(kind: str = "slice-manifest") -> dict[str, object]:
    return build_evidence_artifact(
        artifact_id="slice:work-01",
        kind=kind,
        produced_at="2026-08-13T12:00:00Z",
        subject={"ref": "git:commit/" + "1" * 40, "sha256": f"sha256:{SHA_A}"},
        inputs=[{"ref": "contract:integration-charter/v1", "sha256": f"sha256:{SHA_A}"}],
        commands=[
            {
                "argv": ["uv", "run", "--locked", "pytest", "-q"],
                "exit_code": 0,
                "output": {"ref": "log:pytest.txt", "sha256": f"sha256:{SHA_B}"},
            }
        ],
        outputs=[{"ref": "artifact:test-results.json", "sha256": f"sha256:{SHA_C}"}],
    )


def packet(*, event_type: str = "slice", artifact_kind: str = "slice-manifest") -> dict[str, object]:
    proof = artifact(artifact_kind)
    return build_evidence_packet(
        event_type=event_type,
        work_id="work-01",
        agent={"name": "codex", "model": "gpt-5.6-sol"},
        git={"base_sha": "1" * 40, "final_sha": "2" * 40},
        worktree_ref="worktree:capture-evidence",
        claim_ref="claim:capture-evidence-20260813:generation-1",
        contracts=[{"ref": "contract:integration-charter/v1", "sha256": SHA_A}],
        changes=[
            {
                "path": "src/johan_sdd/evidence/__init__.py",
                "sha256": SHA_B,
                "summary": "Add reconstructable evidence builders.",
            }
        ],
        verification=[
            {
                "command": "uv run --locked pytest -q tests/test_evidence.py",
                "exit_code": 0,
                "result": "passed",
                "log_ref": {"ref": "log:pytest.txt", "sha256": SHA_B},
            }
        ],
        artifacts=[("artifact:slice.json", proof)],
        logs=[{"ref": "log:pytest.txt", "sha256": SHA_B}],
        decisions=[{"decision": "Use structured reconstruction inputs.", "rationale": "No transcript is required."}],
        risks=[{"risk": "Referenced logs may disappear.", "mitigation": "Bind each durable log by SHA-256."}],
        next_consumer="root-coordinator",
        next_action="Integrate the verified lifecycle slice.",
    )


def test_evidence_artifact_is_reconstructable_from_structured_inputs_without_transcript() -> None:
    proof = artifact()

    validate("evidence-artifact.schema.json", proof)
    assert proof["reconstruction"]["commands"][0]["argv"] == [  # type: ignore[index]
        "uv",
        "run",
        "--locked",
        "pytest",
        "-q",
    ]
    assert "transcript" not in canonical_evidence_bytes(proof).decode("utf-8")


def test_evidence_packet_binds_the_reconstructing_artifact_digest() -> None:
    proof = artifact()
    result = packet()

    validate("evidence-packet.schema.json", result)
    assert validate_semantics(result) == []
    assert result["artifacts"] == [
        {
            "kind": "slice-manifest",
            "ref": "artifact:slice.json",
            "sha256": evidence_digest(proof),
        }
    ]


@pytest.mark.parametrize("field", ["contracts", "changes", "verification", "artifacts", "logs"])
def test_evidence_packet_refuses_empty_proof(field: str) -> None:
    arguments = {
        "event_type": "slice",
        "work_id": "work-01",
        "agent": {"name": "codex", "model": "gpt-5.6-sol"},
        "git": {"base_sha": "1" * 40, "final_sha": "2" * 40},
        "worktree_ref": "worktree:capture-evidence",
        "claim_ref": "claim:session-01:generation-1",
        "contracts": [{"ref": "contract:charter/v1", "sha256": SHA_A}],
        "changes": [{"path": "file.py", "sha256": SHA_A, "summary": "Changed."}],
        "verification": [{"command": "pytest", "exit_code": 0, "result": "passed", "log_ref": {"ref": "log:test", "sha256": SHA_A}}],
        "artifacts": [("artifact:slice.json", artifact())],
        "logs": [{"ref": "log:test", "sha256": SHA_A}],
        "next_consumer": "root",
        "next_action": "Integrate.",
    }
    arguments[field] = []

    with pytest.raises(EvidenceValidationError, match=field):
        build_evidence_packet(**arguments)  # type: ignore[arg-type]


def test_evidence_event_requires_the_matching_reconstruction_artifact() -> None:
    with pytest.raises(EvidenceValidationError, match="rollback-receipt"):
        packet(event_type="rollback", artifact_kind="slice-manifest")


def test_evidence_serialization_and_digest_are_deterministic() -> None:
    result = packet()

    assert canonical_evidence_bytes(result) == canonical_evidence_bytes(json.loads(json.dumps(result)))
    assert evidence_digest(result) == "d466be435b63c1d3c069cdb2493b3ce4dbcdc8e2c986804901b0d8b1045d1d38"
