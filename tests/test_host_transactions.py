from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

import pytest

from johan_sdd.host import (
    HostAuthorization,
    HostTransactionError,
    MappingContentResolver,
    PreviewRejected,
    SandboxTargetResolver,
    apply_preview,
    build_preview,
    emit_desired_state,
)


def setup_transaction(tmp_path: Path, operations: list[dict[str, str]]):
    target = tmp_path / "targets" / "agent-config"
    target.mkdir(parents=True)
    resolver = SandboxTargetResolver(tmp_path, {"sandbox:agent-config": "targets/agent-config"})
    references = {
        operation["content_ref"]: operation["content_ref"].encode()
        for operation in operations
        if "content_ref" in operation
    }
    references = {
        f"sha256:{hashlib.sha256(content).hexdigest()}": content
        for content in references.values()
    }
    normalized_operations: list[dict[str, str]] = []
    contents = iter(references)
    for operation in operations:
        normalized = dict(operation)
        if "content_ref" in normalized:
            normalized["content_ref"] = next(contents)
        normalized_operations.append(normalized)
    authorization = HostAuthorization(
        actor_id="host-owner:test",
        policy_id="host-policy:sandbox",
        policy_revision=1,
        policy_sha256="d" * 64,
        trust_root_sha256="b" * 64,
        allowlist_sha256="c" * 64,
        allowed_paths=frozenset(operation["path"] for operation in normalized_operations),
    )
    desired = emit_desired_state(
        target_id="sandbox:agent-config",
        generated_from="a" * 64,
        trust_root_sha256="b" * 64,
        allowlist_sha256="c" * 64,
        operations=normalized_operations,
    )
    preview = build_preview(
        desired,
        content_resolver=MappingContentResolver(references),
        target_resolver=resolver,
        authorization=authorization,
        now=datetime(2026, 8, 13, 12, tzinfo=timezone.utc),
        ttl=timedelta(minutes=15),
    )
    return target, resolver, authorization, preview


def test_expired_preview_fails_before_any_write(tmp_path: Path) -> None:
    target, resolver, authorization, preview = setup_transaction(
        tmp_path,
        [{"path": "new.txt", "action": "create", "content_ref": "content:new"}],
    )

    with pytest.raises(PreviewRejected, match="expired"):
        apply_preview(
            preview,
            target_resolver=resolver,
            authorization=authorization,
            now=datetime(2026, 8, 13, 12, 16, tzinfo=timezone.utc),
        )

    assert list(target.iterdir()) == []


def test_prestate_drift_fails_before_any_write(tmp_path: Path) -> None:
    target, resolver, authorization, preview = setup_transaction(
        tmp_path,
        [{"path": "new.txt", "action": "create", "content_ref": "content:new"}],
    )
    (target / "drift.txt").write_text("changed after preview", encoding="utf-8")

    with pytest.raises(PreviewRejected, match="pre-state"):
        apply_preview(
            preview,
            target_resolver=resolver,
            authorization=authorization,
            now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
        )

    assert not (target / "new.txt").exists()
    assert (target / "drift.txt").read_text(encoding="utf-8") == "changed after preview"


def test_tampered_preview_fails_before_any_write(tmp_path: Path) -> None:
    target, resolver, authorization, preview = setup_transaction(
        tmp_path,
        [{"path": "new.txt", "action": "create", "content_ref": "content:new"}],
    )
    preview.document["expires_at"] = "2026-08-13T13:00:00Z"

    with pytest.raises(PreviewRejected, match="identity"):
        apply_preview(
            preview,
            target_resolver=resolver,
            authorization=authorization,
            now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
        )

    assert list(target.iterdir()) == []


def test_mid_apply_failure_restores_the_full_prestate_snapshot(tmp_path: Path) -> None:
    target = tmp_path / "targets" / "agent-config"
    target.mkdir(parents=True)
    (target / "keep.txt").write_text("original", encoding="utf-8")
    (target / "blocker").write_text("a file blocks a child path", encoding="utf-8")
    before = {path.relative_to(target).as_posix(): path.read_bytes() for path in target.rglob("*") if path.is_file()}

    resolver = SandboxTargetResolver(tmp_path, {"sandbox:agent-config": "targets/agent-config"})
    first = b"changed"
    second = b"never written"
    first_ref = f"sha256:{hashlib.sha256(first).hexdigest()}"
    second_ref = f"sha256:{hashlib.sha256(second).hexdigest()}"
    authorization = HostAuthorization(
        actor_id="host-owner:test",
        policy_id="host-policy:sandbox",
        policy_revision=1,
        policy_sha256="d" * 64,
        trust_root_sha256="b" * 64,
        allowlist_sha256="c" * 64,
        allowed_paths=frozenset({"keep.txt", "blocker/child.txt"}),
    )
    desired = emit_desired_state(
        target_id="sandbox:agent-config",
        generated_from="a" * 64,
        trust_root_sha256="b" * 64,
        allowlist_sha256="c" * 64,
        operations=[
            {"path": "keep.txt", "action": "replace", "content_ref": first_ref},
            {"path": "blocker/child.txt", "action": "create", "content_ref": second_ref},
        ],
    )
    preview = build_preview(
        desired,
        content_resolver=MappingContentResolver({first_ref: first, second_ref: second}),
        target_resolver=resolver,
        authorization=authorization,
        now=datetime(2026, 8, 13, 12, tzinfo=timezone.utc),
    )

    with pytest.raises(HostTransactionError) as failure:
        apply_preview(
            preview,
            target_resolver=resolver,
            authorization=authorization,
            now=datetime(2026, 8, 13, 12, 1, tzinfo=timezone.utc),
        )

    after = {path.relative_to(target).as_posix(): path.read_bytes() for path in target.rglob("*") if path.is_file()}
    assert after == before
    assert failure.value.rollback_status == "completed"
