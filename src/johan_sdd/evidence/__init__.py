"""Builders for compaction-resistant, transcript-independent evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from datetime import datetime
import re
from typing import Any

from johan_sdd.capture._canonical import canonical_bytes, canonical_digest


_ARTIFACT_KINDS = {
    "slice-manifest",
    "session-capture",
    "handoff-manifest",
    "closeout-receipt",
    "update-manifest",
    "rollback-receipt",
}
_EVENT_ARTIFACTS = {
    "slice": "slice-manifest",
    "pause": "session-capture",
    "handoff": "handoff-manifest",
    "close": "closeout-receipt",
    "update": "update-manifest",
    "rollback": "rollback-receipt",
}
_PORTABLE_REF = re.compile(r"^[a-z][a-z0-9-]*:[A-Za-z0-9][A-Za-z0-9._:/@+=-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")


class EvidenceValidationError(ValueError):
    """Structured evidence is incomplete or outside its frozen contract."""


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise EvidenceValidationError(f"{field} must not be empty")
    return value


def _artifact_hashed_ref(value: Mapping[str, Any], field: str) -> dict[str, str]:
    if set(value) != {"ref", "sha256"}:
        raise EvidenceValidationError(f"{field} requires only ref and sha256")
    ref = _nonempty_string(value.get("ref"), f"{field}.ref")
    digest = _nonempty_string(value.get("sha256"), f"{field}.sha256")
    if not _PORTABLE_REF.fullmatch(ref):
        raise EvidenceValidationError(f"{field}.ref is not a portable reference")
    if not _SHA256_REF.fullmatch(digest):
        raise EvidenceValidationError(f"{field}.sha256 must use the sha256:<digest> form")
    return {"ref": ref, "sha256": digest}


def _packet_hashed_ref(value: Mapping[str, Any], field: str) -> dict[str, str]:
    if set(value) != {"ref", "sha256"}:
        raise EvidenceValidationError(f"{field} requires only ref and sha256")
    ref = _nonempty_string(value.get("ref"), f"{field}.ref")
    digest = _nonempty_string(value.get("sha256"), f"{field}.sha256")
    if not _SHA256.fullmatch(digest):
        raise EvidenceValidationError(f"{field}.sha256 must be a lowercase SHA-256 digest")
    return {"ref": ref, "sha256": digest}


def _required_sequence(value: Sequence[Any], field: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not value:
        raise EvidenceValidationError(f"{field} must not be empty")
    return value


def build_evidence_artifact(
    *,
    artifact_id: str,
    kind: str,
    produced_at: str,
    subject: Mapping[str, Any],
    inputs: Sequence[Mapping[str, Any]],
    commands: Sequence[Mapping[str, Any]],
    outputs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build the event artifact needed to replay its verification evidence."""

    artifact_id = _nonempty_string(artifact_id, "artifact_id")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", artifact_id):
        raise EvidenceValidationError("artifact_id contains unsupported characters")
    if kind not in _ARTIFACT_KINDS:
        raise EvidenceValidationError("kind is not an evidence artifact kind")
    _nonempty_string(produced_at, "produced_at")
    try:
        datetime.fromisoformat(produced_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceValidationError("produced_at must be a date-time") from exc

    input_refs = [
        _artifact_hashed_ref(item, f"inputs[{index}]")
        for index, item in enumerate(_required_sequence(inputs, "inputs"))
    ]
    output_refs = [
        _artifact_hashed_ref(item, f"outputs[{index}]")
        for index, item in enumerate(_required_sequence(outputs, "outputs"))
    ]
    command_documents: list[dict[str, Any]] = []
    for index, command in enumerate(_required_sequence(commands, "commands")):
        if set(command) != {"argv", "exit_code", "output"}:
            raise EvidenceValidationError(f"commands[{index}] requires argv, exit_code, and output")
        argv = command.get("argv")
        if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)) or not argv:
            raise EvidenceValidationError(f"commands[{index}].argv must not be empty")
        argv_copy = [_nonempty_string(item, f"commands[{index}].argv") for item in argv]
        exit_code = command.get("exit_code")
        if not isinstance(exit_code, int) or isinstance(exit_code, bool) or exit_code < 0:
            raise EvidenceValidationError(f"commands[{index}].exit_code must be non-negative")
        command_output = command.get("output")
        if not isinstance(command_output, Mapping):
            raise EvidenceValidationError(f"commands[{index}].output must be a hashed reference")
        command_documents.append(
            {
                "argv": argv_copy,
                "exit_code": exit_code,
                "output": _artifact_hashed_ref(command_output, f"commands[{index}].output"),
            }
        )

    return {
        "schema_version": "johan-sdd/evidence-artifact/v1",
        "artifact_id": artifact_id,
        "kind": kind,
        "produced_at": produced_at,
        "subject": _artifact_hashed_ref(subject, "subject"),
        "reconstruction": {
            "inputs": input_refs,
            "commands": command_documents,
            "outputs": output_refs,
        },
    }


def _validate_artifact(document: Mapping[str, Any]) -> None:
    expected = {"schema_version", "artifact_id", "kind", "produced_at", "subject", "reconstruction"}
    if set(document) != expected or document.get("schema_version") != "johan-sdd/evidence-artifact/v1":
        raise EvidenceValidationError("artifact does not match evidence-artifact/v1")
    reconstruction = document.get("reconstruction")
    if not isinstance(reconstruction, Mapping):
        raise EvidenceValidationError("artifact reconstruction is missing")
    # Rebuilding through the public seam gives one source of validation truth.
    build_evidence_artifact(
        artifact_id=document["artifact_id"],
        kind=document["kind"],
        produced_at=document["produced_at"],
        subject=document["subject"],
        inputs=reconstruction.get("inputs", []),
        commands=reconstruction.get("commands", []),
        outputs=reconstruction.get("outputs", []),
    )


def build_evidence_packet(
    *,
    event_type: str,
    work_id: str,
    agent: Mapping[str, Any],
    git: Mapping[str, Any],
    worktree_ref: str,
    claim_ref: str,
    contracts: Sequence[Mapping[str, Any]],
    changes: Sequence[Mapping[str, Any]],
    verification: Sequence[Mapping[str, Any]],
    artifacts: Sequence[tuple[str, Mapping[str, Any]]],
    logs: Sequence[Mapping[str, Any]],
    next_consumer: str,
    next_action: str,
    decisions: Sequence[Mapping[str, Any]] = (),
    risks: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Build a self-contained evidence index from durable proof artifacts."""

    required_kind = _EVENT_ARTIFACTS.get(event_type)
    if required_kind is None:
        raise EvidenceValidationError("event_type is not an evidence lifecycle event")
    work_id = _nonempty_string(work_id, "work_id")
    worktree_ref = _nonempty_string(worktree_ref, "worktree_ref")
    claim_ref = _nonempty_string(claim_ref, "claim_ref")
    if set(agent) != {"name", "model"}:
        raise EvidenceValidationError("agent requires name and model")
    agent_document = {
        "name": _nonempty_string(agent.get("name"), "agent.name"),
        "model": _nonempty_string(agent.get("model"), "agent.model"),
    }
    if set(git) != {"base_sha", "final_sha"}:
        raise EvidenceValidationError("git requires base_sha and final_sha")
    git_document = {
        "base_sha": _nonempty_string(git.get("base_sha"), "git.base_sha"),
        "final_sha": _nonempty_string(git.get("final_sha"), "git.final_sha"),
    }
    if any(not _GIT_SHA.fullmatch(value) for value in git_document.values()):
        raise EvidenceValidationError("git SHAs must contain 40 to 64 lowercase hex characters")

    contract_documents = [
        _packet_hashed_ref(item, f"contracts[{index}]")
        for index, item in enumerate(_required_sequence(contracts, "contracts"))
    ]
    change_documents: list[dict[str, str]] = []
    for index, change in enumerate(_required_sequence(changes, "changes")):
        if set(change) != {"path", "sha256", "summary"}:
            raise EvidenceValidationError(f"changes[{index}] is incomplete")
        digest = _nonempty_string(change.get("sha256"), f"changes[{index}].sha256")
        if not _SHA256.fullmatch(digest):
            raise EvidenceValidationError(f"changes[{index}].sha256 is invalid")
        change_documents.append(
            {
                "path": _nonempty_string(change.get("path"), f"changes[{index}].path"),
                "sha256": digest,
                "summary": _nonempty_string(change.get("summary"), f"changes[{index}].summary"),
            }
        )

    verification_documents: list[dict[str, Any]] = []
    for index, check in enumerate(_required_sequence(verification, "verification")):
        if set(check) != {"command", "exit_code", "result", "log_ref"}:
            raise EvidenceValidationError(f"verification[{index}] is incomplete")
        exit_code = check.get("exit_code")
        if not isinstance(exit_code, int) or isinstance(exit_code, bool):
            raise EvidenceValidationError(f"verification[{index}].exit_code must be an integer")
        log_ref = check.get("log_ref")
        if not isinstance(log_ref, Mapping):
            raise EvidenceValidationError(f"verification[{index}].log_ref is invalid")
        verification_documents.append(
            {
                "command": _nonempty_string(check.get("command"), f"verification[{index}].command"),
                "exit_code": exit_code,
                "result": _nonempty_string(check.get("result"), f"verification[{index}].result"),
                "log_ref": _packet_hashed_ref(log_ref, f"verification[{index}].log_ref"),
            }
        )

    artifact_documents: list[dict[str, str]] = []
    for index, item in enumerate(_required_sequence(artifacts, "artifacts")):
        if not isinstance(item, tuple) or len(item) != 2:
            raise EvidenceValidationError(f"artifacts[{index}] must be a (ref, artifact) pair")
        ref, document = item
        _nonempty_string(ref, f"artifacts[{index}].ref")
        if not isinstance(document, Mapping):
            raise EvidenceValidationError(f"artifacts[{index}] must contain an artifact object")
        _validate_artifact(document)
        artifact_documents.append(
            {"kind": document["kind"], "ref": ref, "sha256": evidence_digest(document)}
        )
    if not any(item["kind"] == required_kind for item in artifact_documents):
        raise EvidenceValidationError(f"{event_type} evidence requires a {required_kind} artifact")

    log_documents = [
        _packet_hashed_ref(item, f"logs[{index}]")
        for index, item in enumerate(_required_sequence(logs, "logs"))
    ]

    decision_documents: list[dict[str, str]] = []
    for index, item in enumerate(decisions):
        if set(item) != {"decision", "rationale"}:
            raise EvidenceValidationError(f"decisions[{index}] is incomplete")
        decision_documents.append(
            {
                "decision": _nonempty_string(item.get("decision"), f"decisions[{index}].decision"),
                "rationale": _nonempty_string(item.get("rationale"), f"decisions[{index}].rationale"),
            }
        )
    risk_documents: list[dict[str, str]] = []
    for index, item in enumerate(risks):
        if set(item) != {"risk", "mitigation"}:
            raise EvidenceValidationError(f"risks[{index}] is incomplete")
        risk_documents.append(
            {
                "risk": _nonempty_string(item.get("risk"), f"risks[{index}].risk"),
                "mitigation": _nonempty_string(item.get("mitigation"), f"risks[{index}].mitigation"),
            }
        )

    return {
        "schema_version": "johan-sdd/evidence-packet/v1",
        "event_type": event_type,
        "work_id": work_id,
        "agent": agent_document,
        "git": git_document,
        "worktree_ref": worktree_ref,
        "claim_ref": claim_ref,
        "contracts": contract_documents,
        "changes": change_documents,
        "verification": verification_documents,
        "artifacts": artifact_documents,
        "logs": log_documents,
        "decisions": decision_documents,
        "risks": risk_documents,
        "next": {
            "consumer": _nonempty_string(next_consumer, "next.consumer"),
            "action": _nonempty_string(next_action, "next.action"),
        },
    }


def canonical_evidence_bytes(document: Mapping[str, Any]) -> bytes:
    return canonical_bytes(copy.deepcopy(dict(document)))


def evidence_digest(document: Mapping[str, Any]) -> str:
    return canonical_digest(document)


__all__ = [
    "EvidenceValidationError",
    "build_evidence_artifact",
    "build_evidence_packet",
    "canonical_evidence_bytes",
    "evidence_digest",
]
