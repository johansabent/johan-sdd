from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from johan_sdd.updater import (
    CanaryReceipts,
    DisposableUpdateTarget,
    UpdateContractError,
    UpdatePayload,
    UpdateSkip,
    apply_update,
    preview_update,
)
from johan_sdd.contracts import validate_semantics


ROOT = Path(__file__).resolve().parents[1]
SHA_A = "a" * 64
SHA_B = "b" * 64


def immutable_pin(version: str, fill: str) -> dict[str, object]:
    return {
        "id": "example-upstream",
        "source": "https://github.com/example/upstream",
        "version": version,
        "reference_type": "annotated_tag",
        "tag_object": fill * 40,
        "peeled_commit": ("f" if fill != "f" else "e") * 40,
        "anchored_in_trust_root": True,
        "trust_root_entry_sha256": fill * 64,
        "immutability": "immutable_tag_object_and_peeled_commit",
    }


def receipt(name: str) -> dict[str, str]:
    return {"ref": f"receipts/{name}.json", "sha256": hashlib.sha256(name.encode()).hexdigest()}


def canaries() -> CanaryReceipts:
    return CanaryReceipts(
        manifest_and_schema_validation=receipt("manifest-schema"),
        lean=receipt("profile-lean"),
        full=receipt("profile-full"),
        codex=receipt("adapter-codex"),
        claude=receipt("adapter-claude"),
        host_preview=receipt("host-preview"),
        rollback_drill=receipt("rollback-drill"),
    )


def payload(label: str) -> UpdatePayload:
    return UpdatePayload(
        content={"adapters/example.txt": f"content:{label}".encode()},
        pins=json.dumps({"release": label}, sort_keys=True).encode(),
        manifest=json.dumps({"manifest": label}, sort_keys=True).encode(),
    )


def authority() -> dict[str, str]:
    return {
        "hooks": "unchanged",
        "installer": "unchanged",
        "host-policy": "unchanged",
        "trust-root": "unchanged",
        "allowlist": "unchanged",
        "agent-home": "unchanged",
        "permissions": "unchanged",
        "runner": "unchanged",
        "target-root": "unchanged",
    }


def write_payload(root: Path, value: UpdatePayload) -> None:
    (root / "content").mkdir(parents=True)
    for relative, content in value.content.items():
        destination = root / "content" / Path(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    (root / "pins.json").write_bytes(value.pins)
    (root / "manifest.json").write_bytes(value.manifest)


def preview_fixture(tmp_path: Path, candidate_payload: UpdatePayload | None = None):
    current = payload("current")
    candidate = candidate_payload or payload("candidate")
    root = tmp_path / "update-target"
    write_payload(root, current)
    target = DisposableUpdateTarget(
        sandbox_root=tmp_path,
        relative_path="update-target",
        target_id="canary:example",
        known=True,
        clean=True,
    )
    result = preview_update(
        target=target,
        current_upstreams=[immutable_pin("v1.0.0", "a")],
        candidate_upstreams=[immutable_pin("v1.1.0", "b")],
        candidate_payload=candidate,
        trust_root_sha256=SHA_A,
        allowlist_sha256=SHA_B,
        authority_baseline=authority(),
        authority_candidate=authority(),
        canary_receipts=canaries(),
        now=datetime(2026, 8, 13, 12, tzinfo=timezone.utc),
    )
    return target, current, candidate, result


@pytest.mark.parametrize(("known", "clean", "reason"), [(False, True, "unknown-target"), (True, False, "dirty-target")])
def test_unknown_or_dirty_targets_are_skipped_and_reported(
    tmp_path: Path, known: bool, clean: bool, reason: str
) -> None:
    target = DisposableUpdateTarget(
        sandbox_root=tmp_path,
        relative_path="candidate",
        target_id="canary:example",
        known=known,
        clean=clean,
    )

    result = preview_update(
        target=target,
        current_upstreams=[immutable_pin("v1.0.0", "a")],
        candidate_upstreams=[immutable_pin("v1.1.0", "b")],
        candidate_payload=payload("candidate"),
        trust_root_sha256=SHA_A,
        allowlist_sha256=SHA_B,
        authority_baseline=authority(),
        authority_candidate=authority(),
        canary_receipts=canaries(),
        now=datetime(2026, 8, 13, 12, tzinfo=timezone.utc),
    )

    assert result == UpdateSkip(target_id="canary:example", reason=reason)
    assert not target.root.exists()


def test_preview_requires_immutable_trust_anchored_annotated_tag_and_peeled_commit(
    tmp_path: Path,
) -> None:
    target = DisposableUpdateTarget(tmp_path, "candidate", "canary:example", True, True)
    bad_pin = immutable_pin("v1.1.0", "b")
    bad_pin["reference_type"] = "lightweight_tag"

    with pytest.raises(UpdateContractError, match="annotated tag"):
        preview_update(
            target=target,
            current_upstreams=[immutable_pin("v1.0.0", "a")],
            candidate_upstreams=[bad_pin],
            candidate_payload=payload("candidate"),
            trust_root_sha256=SHA_A,
            allowlist_sha256=SHA_B,
            authority_baseline=authority(),
            authority_candidate=authority(),
            canary_receipts=canaries(),
            now=datetime(2026, 8, 13, 12, tzinfo=timezone.utc),
        )


def test_preview_rejects_authority_delta_and_self_expansion(tmp_path: Path) -> None:
    target = DisposableUpdateTarget(tmp_path, "candidate", "canary:example", True, True)
    expanded = authority()
    expanded["runner"] = "new-admin-runner"

    with pytest.raises(UpdateContractError, match="authority delta.*runner"):
        preview_update(
            target=target,
            current_upstreams=[immutable_pin("v1.0.0", "a")],
            candidate_upstreams=[immutable_pin("v1.1.0", "b")],
            candidate_payload=payload("candidate"),
            trust_root_sha256=SHA_A,
            allowlist_sha256=SHA_B,
            authority_baseline=authority(),
            authority_candidate=expanded,
            canary_receipts=canaries(),
            now=datetime(2026, 8, 13, 12, tzinfo=timezone.utc),
        )

    with pytest.raises(UpdateContractError, match="outside the updater allowlist"):
        UpdatePayload(
            content={"hooks/post-apply": b"self expansion"},
            pins=b"pins",
            manifest=b"manifest",
        )


def test_preview_binds_current_candidate_prestate_and_all_canary_receipts(tmp_path: Path) -> None:
    target, current, candidate, result = preview_fixture(tmp_path)
    assert not isinstance(result, UpdateSkip)

    document = result.document
    schema = json.loads((ROOT / "schemas" / "update-manifest.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(document)
    assert document["apply"]["phase"] == "previewed"
    assert document["bindings"]["prestate"] == current.hashes()
    assert document["current"]["manifest_sha256"] == current.hashes()["manifest_sha256"]
    assert document["candidate"]["pins_sha256"] == candidate.hashes()["pins_sha256"]
    assert document["authority_delta"]["status"] == "passed"
    assert document["canaries"] == canaries().as_manifest()


def test_apply_updates_exact_content_pins_and_manifest_with_hash_readback(tmp_path: Path) -> None:
    target, _current, candidate, preview = preview_fixture(tmp_path)
    assert not isinstance(preview, UpdateSkip)

    result = apply_update(preview, target=target, now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc))

    assert result.document["apply"]["phase"] == "applied"
    assert result.readback == candidate.hashes()
    assert target.read_payload() == candidate
    schema = json.loads((ROOT / "schemas" / "update-manifest.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        result.document
    )
    assert validate_semantics(result.document) == []
