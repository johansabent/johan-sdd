from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
SHA_A = "a" * 64
SHA_B = "b" * 64


def validate(schema_name: str, instance: dict[str, object]) -> None:
    schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(instance)


def ref(value: str = "artifact:input-01") -> dict[str, str]:
    return {"ref": value, "sha256": f"sha256:{SHA_A}"}


def test_cli_invocation_binds_portable_grammar_input_and_machine_output() -> None:
    invocation = {
        "schema_version": "johan-sdd/cli-invocation/v1",
        "invocation_id": "cli-01",
        "argv": ["johan-sdd", "assess-micro", "--json"],
        "command": "assess-micro",
        "input_refs": [ref()],
        "output": {
            "format": "json",
            "media_type": "application/json",
            "schema_ref": "schema:micro-assessment/v1",
        },
        "exit_codes": {
            "success": 0,
            "validation_error": 2,
            "policy_blocked": 3,
            "operational_failure": 4,
        },
    }
    validate("cli-invocation.schema.json", invocation)

    malformed = copy.deepcopy(invocation)
    malformed["input_refs"][0]["ref"] = "C:\\host\\secret.txt"  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        validate("cli-invocation.schema.json", malformed)


@pytest.mark.parametrize(
    "command",
    [
        "select-profile",
        "route",
        "claim-session",
        "heartbeat-session",
        "pause-session",
        "release-session",
        "generate-capture",
        "promote-capture",
        "emit-desired-state",
        "preview-host-apply",
        "record-host-apply",
        "preview-update",
        "apply-update",
        "rollback-update",
        "validate-contract",
        "assess-micro",
        "resolve-content",
        "scan-secrets",
        "record-decision",
        "emit-evidence",
    ],
)
def test_cli_contract_freezes_every_public_operational_command(command: str) -> None:
    invocation = {
        "schema_version": "johan-sdd/cli-invocation/v1",
        "invocation_id": f"cli:{command}",
        "argv": ["johan-sdd", command, "--json"],
        "command": command,
        "input_refs": [ref()],
        "output": {
            "format": "json",
            "media_type": "application/json",
            "schema_ref": "schema:evidence-artifact/v1",
        },
        "exit_codes": {
            "success": 0,
            "validation_error": 2,
            "policy_blocked": 3,
            "operational_failure": 4,
        },
    }

    validate("cli-invocation.schema.json", invocation)


def test_cli_contract_allows_human_text_without_claiming_a_json_schema() -> None:
    invocation = {
        "schema_version": "johan-sdd/cli-invocation/v1",
        "invocation_id": "cli:route-text",
        "argv": ["johan-sdd", "route"],
        "command": "route",
        "input_refs": [ref()],
        "output": {"format": "text", "media_type": "text/plain"},
        "exit_codes": {
            "success": 0,
            "validation_error": 2,
            "policy_blocked": 3,
            "operational_failure": 4,
        },
    }

    validate("cli-invocation.schema.json", invocation)


def test_human_receipt_is_required_to_downgrade_from_full_without_hard_trigger() -> None:
    receipt = {
        "schema_version": "johan-sdd/human-decision-receipt/v1",
        "receipt_id": "decision-01",
        "decision": "profile-downgrade",
        "recorded_at": "2026-08-13T12:00:00Z",
        "work_ref": ref("work:delivery-01"),
        "from_profile": "full",
        "to_profile": "lean",
        "hard_trigger_refs": [],
        "human": {"actor_id": "human:owner-01", "confirmed_at": "2026-08-13T12:00:00Z"},
        "rationale": "The measured work has no full-profile trigger.",
    }
    validate("human-decision-receipt.schema.json", receipt)

    invalid = copy.deepcopy(receipt)
    invalid["hard_trigger_refs"] = [ref("trigger:security")]  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        validate("human-decision-receipt.schema.json", invalid)


def test_content_bundle_verifies_resolution_with_logical_refs_not_host_paths() -> None:
    bundle = {
        "schema_version": "johan-sdd/content-bundle/v1",
        "bundle_id": "bundle-01",
        "generated_at": "2026-08-13T12:00:00Z",
        "resolver": {"id": "resolver:portable-v1", "ruleset_ref": ref("ruleset:content-v1")},
        "entries": [
            {
                "logical_path": "templates/plan.md",
                "requested_ref": ref("content:plan-template"),
                "resolved_ref": f"sha256:{SHA_A}",
                "content_sha256": SHA_A,
                "verified": True,
            }
        ],
    }
    validate("content-bundle.schema.json", bundle)

    invalid = copy.deepcopy(bundle)
    invalid["entries"][0]["logical_path"] = "/host/templates/plan.md"  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        validate("content-bundle.schema.json", invalid)


@pytest.mark.parametrize(
    "kind",
    [
        "slice-manifest",
        "session-capture",
        "handoff-manifest",
        "closeout-receipt",
        "update-manifest",
        "rollback-receipt",
    ],
)
def test_each_evidence_artifact_kind_has_a_reconstructable_minimum(kind: str) -> None:
    artifact = {
        "schema_version": "johan-sdd/evidence-artifact/v1",
        "artifact_id": f"artifact:{kind}",
        "kind": kind,
        "produced_at": "2026-08-13T12:00:00Z",
        "subject": ref("work:delivery-01"),
        "reconstruction": {
            "inputs": [ref("input:measured-state")],
            "commands": [
                {
                    "argv": ["johan-sdd", "verify"],
                    "exit_code": 0,
                    "output": ref("output:verification"),
                }
            ],
            "outputs": [ref("output:artifact")],
        },
    }
    validate("evidence-artifact.schema.json", artifact)

    incomplete = copy.deepcopy(artifact)
    incomplete["reconstruction"]["commands"] = []  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        validate("evidence-artifact.schema.json", incomplete)


def test_micro_assessment_records_deterministic_counts_and_portable_surface_taxonomy() -> None:
    assessment = {
        "schema_version": "johan-sdd/micro-assessment/v1",
        "assessment_id": "micro-01",
        "repository_ref": ref("repo:delivery-01"),
        "base_ref": ref("git:base"),
        "preflight": {"primary_checkout": True, "working_tree_clean": True},
        "counting": {
            "line_formula": "additions-plus-deletions",
            "rename_rule": "count-source-and-destination-lines-as-deletion-and-addition",
            "deletion_rule": "count-deleted-path-and-deleted-lines",
        },
        "changes": {
            "files_changed": 2,
            "additions": 12,
            "deletions": 8,
            "changed_lines": 20,
        },
        "change_kinds": ["modify"],
        "observed_surfaces": ["documentation", "non-operational-configuration"],
        "verdict": "admitted",
    }
    validate("micro-assessment.schema.json", assessment)

    invalid = copy.deepcopy(assessment)
    invalid["observed_surfaces"] = ["code"]  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        validate("micro-assessment.schema.json", invalid)

    renamed = copy.deepcopy(assessment)
    renamed["change_kinds"] = ["rename"]
    with pytest.raises(jsonschema.ValidationError):
        validate("micro-assessment.schema.json", renamed)

    dirty_primary = copy.deepcopy(assessment)
    dirty_primary["preflight"]["working_tree_clean"] = False  # type: ignore[index]
    with pytest.raises(jsonschema.ValidationError):
        validate("micro-assessment.schema.json", dirty_primary)


def test_secret_scan_receipt_binds_ruleset_identity_digest_findings_and_status() -> None:
    receipt = {
        "schema_version": "johan-sdd/secret-scan-receipt/v1",
        "receipt_id": "secret-scan-01",
        "completed_at": "2026-08-13T12:00:00Z",
        "subject": ref("worktree:delivery-01"),
        "ruleset": {
            "id": "ruleset:secret-shaped-v1",
            "version": "1.0.0",
            "sha256": SHA_B,
        },
        "scanned_inputs": [ref("input:worktree-content")],
        "status": "passed",
        "findings": [],
    }
    validate("secret-scan-receipt.schema.json", receipt)

    invalid = copy.deepcopy(receipt)
    invalid["findings"] = [
        {
            "rule_id": "credential-shaped",
            "fingerprint": f"sha256:{SHA_A}",
            "severity": "suspicious",
            "location_ref": "path:untracked/example.env",
        }
    ]
    with pytest.raises(jsonschema.ValidationError):
        validate("secret-scan-receipt.schema.json", invalid)
