from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from johan_sdd.contracts import validate_semantics


SHA_A = "a" * 64
SHA_B = "b" * 64
ROOT = Path(__file__).resolve().parents[1]


EXPECTED_CONTRACTS = {
    path.removesuffix(".schema.json"): f"../schemas/{path}"
    for path in [
        "apply-receipt.schema.json",
        "authority-decision.schema.json",
        "capture-packet.v2.schema.json",
        "cli-invocation.schema.json",
        "content-bundle.schema.json",
        "cutover-marker.schema.json",
        "desired-state.schema.json",
        "evidence-artifact.schema.json",
        "evidence-packet.schema.json",
        "human-decision-receipt.schema.json",
        "integration-charter.schema.json",
        "micro-assessment.schema.json",
        "pause-recovery.schema.json",
        "preview.schema.json",
        "promotion-receipt.schema.json",
        "promotion-request.schema.json",
        "rollback-receipt.schema.json",
        "secret-scan-receipt.schema.json",
        "session-claims.schema.json",
        "update-manifest.schema.json",
        "upstreams-lock.schema.json",
    ]
}


def hashed_ref(ref: str, digest: str = SHA_A) -> dict[str, str]:
    return {"ref": ref, "sha256": f"sha256:{digest}"}


def test_charter_registers_every_executable_contract_with_an_exact_path() -> None:
    charter = json.loads(
        (ROOT / "manifests" / "integration-charter.v1.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (ROOT / "schemas" / "integration-charter.schema.json").read_text(encoding="utf-8")
    )

    assert charter["contract_registry"] == EXPECTED_CONTRACTS
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(charter)
    assert validate_semantics(charter) == []


def test_content_bundle_rejects_digest_mismatch_and_duplicate_logical_path() -> None:
    document = {
        "schema_version": "johan-sdd/content-bundle/v1",
        "bundle_id": "bundle-01",
        "generated_at": "2026-08-13T12:00:00Z",
        "resolver": {
            "id": "resolver:portable-v1",
            "ruleset_ref": hashed_ref("ruleset:content-v1"),
        },
        "entries": [
            {
                "logical_path": "templates/plan.md",
                "requested_ref": hashed_ref("content:plan-template"),
                "resolved_ref": f"sha256:{SHA_A}",
                "content_sha256": SHA_B,
                "verified": True,
            },
            {
                "logical_path": "templates/plan.md",
                "requested_ref": hashed_ref("content:other-template"),
                "resolved_ref": f"sha256:{SHA_A}",
                "content_sha256": SHA_A,
                "verified": True,
            },
        ],
    }

    codes = {error["code"] for error in validate_semantics(document)}

    assert codes == {"content.digest-mismatch", "content.duplicate-logical-path"}


def test_micro_assessment_rejects_inconsistent_counts() -> None:
    document = {
        "schema_version": "johan-sdd/micro-assessment/v1",
        "changes": {
            "files_changed": 2,
            "additions": 12,
            "deletions": 8,
            "changed_lines": 19,
        },
        "verdict": "admitted",
    }

    assert validate_semantics(document) == [
        {
            "code": "micro.changed-lines-mismatch",
            "path": "/changes/changed_lines",
            "message": "changed_lines must equal additions plus deletions",
        }
    ]


def test_human_decision_rejects_confirmation_after_receipt() -> None:
    document = {
        "schema_version": "johan-sdd/human-decision-receipt/v1",
        "recorded_at": "2026-08-13T12:00:00Z",
        "human": {"confirmed_at": "2026-08-13T12:01:00Z"},
    }

    assert validate_semantics(document) == [
        {
            "code": "decision.confirmed-after-recorded",
            "path": "/human/confirmed_at",
            "message": "human confirmation cannot occur after the receipt is recorded",
        }
    ]


def test_cutover_marker_requires_exact_revision_advance() -> None:
    document = {
        "schema_version": "johan-sdd/cutover-marker/v1",
        "revision": 5,
        "cas": {"expected_revision": 2, "expected_marker_sha256": SHA_A},
    }

    assert validate_semantics(document) == [
        {
            "code": "cutover.invalid-revision-advance",
            "path": "/revision",
            "message": "marker revision must equal expected_revision plus one",
        }
    ]


def test_update_manifest_binds_current_state_to_measured_prestate() -> None:
    document = {
        "schema_version": "johan-sdd/update-manifest/v1",
        "current": {"manifest_sha256": SHA_A, "pins_sha256": SHA_A},
        "bindings": {
            "prestate": {
                "manifest_sha256": SHA_B,
                "pins_sha256": SHA_A,
                "content_sha256": SHA_A,
            }
        },
    }

    assert validate_semantics(document) == [
        {
            "code": "update.prestate-mismatch",
            "path": "/bindings/prestate/manifest_sha256",
            "message": "measured prestate must match the current update manifest and pins",
        }
    ]


def test_rollback_receipt_rejects_hashes_that_do_not_restore_preupdate_state() -> None:
    document = {
        "schema_version": "johan-sdd/rollback-receipt/v1",
        "terminal_status": "rolled_back",
        "snapshots": {
            "pre_update": {
                "content_sha256": SHA_A,
                "pins_sha256": SHA_A,
                "manifest_sha256": SHA_A,
            },
            "post_rollback": {
                "content_sha256": SHA_A,
                "pins_sha256": SHA_B,
                "manifest_sha256": SHA_A,
            },
        },
        "readback": {
            "components": {
                "content": {
                    "expected_preupdate_sha256": SHA_A,
                    "observed_postrollback_sha256": SHA_A,
                    "status": "matched",
                },
                "pins": {
                    "expected_preupdate_sha256": SHA_A,
                    "observed_postrollback_sha256": SHA_B,
                    "status": "matched",
                },
                "manifest": {
                    "expected_preupdate_sha256": SHA_A,
                    "observed_postrollback_sha256": SHA_A,
                    "status": "matched",
                },
            }
        },
    }

    errors = validate_semantics(document)

    assert {error["code"] for error in errors} == {
        "rollback.snapshot-mismatch",
        "rollback.readback-mismatch",
    }
