from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import jsonschema

from johan_sdd.contracts import validate_semantics
from johan_sdd.updater import UpdatePayload, UpdateSkip, apply_update

from test_updater import payload, preview_fixture


ROOT = Path(__file__).resolve().parents[1]


def test_prestate_drift_is_rejected_before_updater_writes(tmp_path: Path) -> None:
    target, _current, _candidate, preview = preview_fixture(tmp_path)
    assert not isinstance(preview, UpdateSkip)
    (target.root / "manifest.json").write_text("drift", encoding="utf-8")

    result = apply_update(preview, target=target, now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc))

    assert result.status == "rejected"
    assert result.reason == "prestate-drift"
    assert (target.root / "manifest.json").read_text(encoding="utf-8") == "drift"


def test_tampered_update_preview_is_rejected_before_writes(tmp_path: Path) -> None:
    target, current, _candidate, preview = preview_fixture(tmp_path)
    assert not isinstance(preview, UpdateSkip)
    preview.document["canaries"]["environment"] = "primary-worktree"

    result = apply_update(preview, target=target, now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc))

    assert result.status == "rejected"
    assert result.reason == "preview-tampered"
    assert target.read_payload() == current


def test_apply_failure_restores_exact_content_pins_and_manifest(tmp_path: Path) -> None:
    conflicting = UpdatePayload(
        content={
            "adapters/blocker": b"file",
            "adapters/blocker/child": b"cannot be written beneath a file",
        },
        pins=b"candidate pins",
        manifest=b"candidate manifest",
    )
    target, current, _candidate, preview = preview_fixture(tmp_path, conflicting)
    assert not isinstance(preview, UpdateSkip)

    result = apply_update(preview, target=target, now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc))

    assert result.status == "rolled_back"
    assert target.read_payload() == current
    assert result.readback == current.hashes()
    receipt = result.rollback_receipt
    assert receipt is not None
    schema = json.loads((ROOT / "schemas" / "rollback-receipt.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(receipt)
    assert receipt["terminal_status"] == "rolled_back"
    assert receipt["snapshots"]["post_rollback"] == current.hashes()
    assert all(
        component["status"] == "matched"
        for component in receipt["readback"]["components"].values()
    )
    assert validate_semantics(receipt) == []
    update_schema = json.loads(
        (ROOT / "schemas" / "update-manifest.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(
        update_schema, format_checker=jsonschema.FormatChecker()
    ).validate(result.document)
