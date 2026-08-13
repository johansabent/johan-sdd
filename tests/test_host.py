from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest
import jsonschema

from johan_sdd.contracts import validate_semantics
from johan_sdd.host import (
    HostAuthorization,
    HostContractError,
    MappingContentResolver,
    SandboxTargetResolver,
    apply_preview,
    build_preview,
    emit_desired_state,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def test_portable_core_emits_only_content_addressed_desired_state() -> None:
    desired = emit_desired_state(
        target_id="sandbox:agent-config",
        generated_from=SHA_A,
        trust_root_sha256=SHA_B,
        allowlist_sha256=SHA_C,
        operations=[
            {
                "path": "skills/example/SKILL.md",
                "action": "replace",
                "content_ref": f"sha256:{SHA_A}",
            }
        ],
    )

    assert desired == {
        "schema_version": "johan-sdd/desired-state/v1",
        "target_id": "sandbox:agent-config",
        "generated_from": SHA_A,
        "trust_root_sha256": SHA_B,
        "allowlist_sha256": SHA_C,
        "operations": [
            {
                "path": "skills/example/SKILL.md",
                "action": "replace",
                "content_ref": f"sha256:{SHA_A}",
            }
        ],
    }
    assert not any("target_path" in key or "content" == key for key in desired)


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "C:/absolute",
        "skills\\windows.md",
        "skills//duplicate.md",
        ".agents/AGENTS.md",
        "nested/.agents/config.toml",
    ],
)
def test_desired_state_rejects_paths_that_are_not_portable_product_paths(path: str) -> None:
    with pytest.raises(HostContractError):
        emit_desired_state(
            target_id="sandbox:agent-config",
            generated_from=SHA_A,
            trust_root_sha256=SHA_B,
            allowlist_sha256=SHA_C,
            operations=[
                {"path": path, "action": "create", "content_ref": f"sha256:{SHA_A}"}
            ],
        )


def test_only_sandbox_target_resolver_turns_target_id_into_a_path(tmp_path: Path) -> None:
    resolver = SandboxTargetResolver(
        sandbox_root=tmp_path,
        targets={"sandbox:agent-config": "targets/agent-config"},
    )

    resolved = resolver.resolve_target("sandbox:agent-config")

    assert resolved.root == (tmp_path / "targets" / "agent-config").resolve()
    assert resolved.sandbox_root == tmp_path.resolve()
    with pytest.raises(HostContractError):
        resolver.resolve_target("unknown")
    with pytest.raises(HostContractError):
        SandboxTargetResolver(tmp_path, {"bad": "../outside"})


def test_preview_binds_desired_prestate_policy_and_verified_content(tmp_path: Path) -> None:
    content = b"new content\n"
    content_digest = hashlib.sha256(content).hexdigest()
    target = tmp_path / "targets" / "agent-config"
    target.mkdir(parents=True)
    (target / "old.txt").write_text("old\n", encoding="utf-8")
    desired = emit_desired_state(
        target_id="sandbox:agent-config",
        generated_from=SHA_A,
        trust_root_sha256=SHA_B,
        allowlist_sha256=SHA_C,
        operations=[
            {
                "path": "skills/example/SKILL.md",
                "action": "create",
                "content_ref": f"sha256:{content_digest}",
            }
        ],
    )
    resolver = SandboxTargetResolver(tmp_path, {"sandbox:agent-config": "targets/agent-config"})
    authorization = HostAuthorization(
        actor_id="host-owner:test",
        policy_id="host-policy:sandbox",
        policy_revision=1,
        policy_sha256="d" * 64,
        trust_root_sha256=SHA_B,
        allowlist_sha256=SHA_C,
        allowed_paths=frozenset({"skills/example/SKILL.md"}),
    )
    now = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)

    preview = build_preview(
        desired,
        content_resolver=MappingContentResolver({f"sha256:{content_digest}": content}),
        target_resolver=resolver,
        authorization=authorization,
        now=now,
        ttl=timedelta(minutes=15),
    )

    assert preview.document["desired_state_sha256"] == canonical_hash(desired)
    assert preview.document["target_id"] == desired["target_id"]
    assert preview.document["trust_root_sha256"] == SHA_B
    assert preview.document["allowlist_sha256"] == SHA_C
    assert preview.document["operations"] == desired["operations"]
    assert preview.document["created_at"] == "2026-08-13T12:00:00Z"
    assert preview.document["expires_at"] == "2026-08-13T12:15:00Z"
    assert preview.content[f"sha256:{content_digest}"] == content
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "preview.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        preview.document
    )
    assert validate_semantics(preview.document) == []


def test_apply_executes_ordered_operations_and_returns_exact_readback(tmp_path: Path) -> None:
    target = tmp_path / "targets" / "agent-config"
    (target / "existing").mkdir(parents=True)
    (target / "existing" / "replace.txt").write_text("before", encoding="utf-8")
    (target / "remove.txt").write_text("remove", encoding="utf-8")
    create = b"created"
    replace = b"after"
    create_ref = f"sha256:{hashlib.sha256(create).hexdigest()}"
    replace_ref = f"sha256:{hashlib.sha256(replace).hexdigest()}"
    desired = emit_desired_state(
        target_id="sandbox:agent-config",
        generated_from=SHA_A,
        trust_root_sha256=SHA_B,
        allowlist_sha256=SHA_C,
        operations=[
            {"path": "new/file.txt", "action": "create", "content_ref": create_ref},
            {"path": "existing/replace.txt", "action": "replace", "content_ref": replace_ref},
            {"path": "remove.txt", "action": "remove"},
        ],
    )
    authorization = HostAuthorization(
        actor_id="host-owner:test",
        policy_id="host-policy:sandbox",
        policy_revision=1,
        policy_sha256="d" * 64,
        trust_root_sha256=SHA_B,
        allowlist_sha256=SHA_C,
        allowed_paths=frozenset(
            {"new/file.txt", "existing/replace.txt", "remove.txt"}
        ),
    )
    resolver = SandboxTargetResolver(tmp_path, {desired["target_id"]: "targets/agent-config"})
    preview = build_preview(
        desired,
        content_resolver=MappingContentResolver({create_ref: create, replace_ref: replace}),
        target_resolver=resolver,
        authorization=authorization,
        now=datetime(2026, 8, 13, 12, tzinfo=timezone.utc),
    )

    receipt = apply_preview(
        preview,
        target_resolver=resolver,
        authorization=authorization,
        now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
    )

    assert (target / "new" / "file.txt").read_bytes() == create
    assert (target / "existing" / "replace.txt").read_bytes() == replace
    assert not (target / "remove.txt").exists()
    assert receipt["readback"]["operations"] == [
        {
            "path": "new/file.txt",
            "result": "created",
            "content_sha256": create_ref.removeprefix("sha256:"),
        },
        {
            "path": "existing/replace.txt",
            "result": "replaced",
            "content_sha256": replace_ref.removeprefix("sha256:"),
        },
        {"path": "remove.txt", "result": "removed"},
    ]
    assert receipt["rollback"] == {"status": "not-required"}
    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schemas" / "apply-receipt.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(receipt)
    assert validate_semantics(receipt) == []
