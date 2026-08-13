from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest

from johan_sdd.sessions import (
    ClaimConflict,
    ProcessStatus,
    RegistryInvalid,
    RevisionConflict,
    SessionRegistry,
)


UTC = timezone.utc
SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schemas" / "session-claims.schema.json").read_text(
        encoding="utf-8"
    )
)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", os.fspath(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Test User")
    git(repo, "config", "user.email", "test@example.invalid")
    (repo / "tracked.txt").write_text("base\n", encoding="utf-8")
    git(repo, "add", "tracked.txt")
    git(repo, "commit", "-qm", "base")
    return repo


def claim(repo: Path, session_id: str = "session-01", *, resource: str = "src/a.py") -> dict[str, object]:
    now = datetime(2026, 8, 13, 12, tzinfo=UTC)
    token = f"token-{session_id}"
    return {
        "session_id": session_id,
        "mode": "feature",
        "owner": {"agent": "codex", "model": "gpt-5"},
        "process": {
            "host": socket.gethostname(),
            "pid": os.getpid(),
            "started_at": "2026-08-13T11:59:00Z",
        },
        "lease": {
            "token_hash": f"sha256:{hashlib.sha256(token.encode()).hexdigest()}",
            "generation": 1,
            "acquired_at": now.isoformat().replace("+00:00", "Z"),
            "heartbeat_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=90)).isoformat().replace("+00:00", "Z"),
            "ttl_seconds": 5400,
        },
        "worktree": {
            "repo_id": "repo:test",
            "worktree_id": f"worktree:{session_id}",
            "path": repo.resolve().as_posix(),
            "kind": "linked",
            "branch": f"codex/{session_id}",
        },
        "state": "working",
        "dirty": False,
        "authority_decision_ref": f"authority:{session_id}:1",
        "resources": [
            {"resource_type": "repo-files", "resource_id": resource, "access": "exclusive"}
        ],
    }


def test_registry_lives_in_git_common_dir_and_supports_claim_heartbeat_release(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-qb", "sessions", os.fspath(linked))
    clock = iter(
        [
            datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
            datetime(2026, 8, 13, 12, 20, tzinfo=UTC),
        ]
    )
    registry = SessionRegistry(linked, now=lambda: next(clock))
    document = registry.claim(claim(linked), lease_token="token-session-01", expected_revision=0)

    common_dir = Path(git(linked, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    assert registry.path == common_dir / "agent-work-session.v1.json"
    assert document["revision"] == 1
    jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker()).validate(document)

    document = registry.heartbeat(
        "session-01", lease_token="token-session-01", expected_revision=1
    )
    assert document["revision"] == 2
    assert document["claims"][0]["lease"]["heartbeat_at"] == "2026-08-13T12:20:00Z"
    assert document["claims"][0]["lease"]["expires_at"] == "2026-08-13T13:50:00Z"

    document = registry.release(
        "session-01", lease_token="token-session-01", expected_revision=2
    )
    assert document["revision"] == 3
    assert document["claims"][0]["state"] == "closed"


def test_registry_revision_is_compare_and_swap(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    registry = SessionRegistry(repo)
    registry.claim(claim(repo), lease_token="token-session-01", expected_revision=0)

    with pytest.raises(RevisionConflict, match="expected revision 0, found 1"):
        registry.release("session-01", lease_token="token-session-01", expected_revision=0)

    with pytest.raises(RevisionConflict, match="non-negative integer"):
        registry.release("session-01", lease_token="token-session-01", expected_revision=True)


def test_corrupt_or_semantically_invalid_registry_is_inspectable_but_blocks_mutation(
    tmp_path: Path,
) -> None:
    repo = init_repo(tmp_path)
    registry = SessionRegistry(repo)
    registry.path.write_text("{broken", encoding="utf-8")

    inspection = registry.inspect()
    assert inspection.document is None
    assert inspection.raw_text == "{broken"
    assert inspection.errors[0].code == "registry.invalid-json"
    with pytest.raises(RegistryInvalid):
        registry.claim(claim(repo), lease_token="token-session-01", expected_revision=0)

    registry.path.write_text(
        json.dumps({"schema_version": "agent-work-session/v1", "revision": 0, "claims": "bad"}),
        encoding="utf-8",
    )
    inspection = registry.inspect()
    assert inspection.document is not None
    assert {error.code for error in inspection.errors} == {"registry.shape"}
    with pytest.raises(RegistryInvalid):
        registry.claim(claim(repo), lease_token="token-session-01", expected_revision=0)


def test_semantically_conflicting_registry_is_inspectable_but_blocks_mutation(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    registry = SessionRegistry(repo, now=lambda: datetime(2026, 8, 13, 12, tzinfo=UTC))
    first = claim(repo)
    second = claim(repo, "session-02")
    first["worktree"]["path"] = (tmp_path / "one").resolve().as_posix()  # type: ignore[index]
    second["worktree"]["path"] = (tmp_path / "two").resolve().as_posix()  # type: ignore[index]
    registry.path.write_text(
        json.dumps({"schema_version": "agent-work-session/v1", "revision": 1, "claims": [first, second]}),
        encoding="utf-8",
    )

    inspection = registry.inspect()
    assert inspection.document is not None
    assert {error.code for error in inspection.errors} == {"resource.conflict"}
    with pytest.raises(RegistryInvalid, match="resource.conflict"):
        registry.release("session-01", lease_token="token-session-01", expected_revision=1)


def test_conflicting_resource_is_blocked_but_shared_reads_can_coexist(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    now = lambda: datetime(2026, 8, 13, 12, tzinfo=UTC)
    registry = SessionRegistry(repo, now=now)
    first = claim(repo, resource="tracker:JOH-1")
    first["worktree"]["path"] = (tmp_path / "one").resolve().as_posix()  # type: ignore[index]
    registry.claim(first, lease_token="token-session-01", expected_revision=0)

    second = claim(repo, "session-02", resource="tracker:JOH-1")
    second["worktree"]["path"] = (tmp_path / "two").resolve().as_posix()  # type: ignore[index]
    evaluation = registry.evaluate(second)
    assert evaluation.revision == 1
    assert evaluation.conflicts[0].kind == "resource"
    with pytest.raises(ClaimConflict) as raised:
        registry.claim(second, lease_token="token-session-02", expected_revision=1)
    assert raised.value.conflicts[0].kind == "resource"

    first["resources"][0]["access"] = "shared-read"  # type: ignore[index]
    registry = SessionRegistry(repo, now=now)
    registry.path.unlink()
    registry.claim(first, lease_token="token-session-01", expected_revision=0)
    second["resources"][0]["access"] = "shared-read"  # type: ignore[index]
    assert registry.claim(second, lease_token="token-session-02", expected_revision=1)["revision"] == 2


def test_expiry_alone_never_abandons_live_or_unproven_owner(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    expired = claim(repo)
    expired["worktree"]["path"] = (tmp_path / "one").resolve().as_posix()  # type: ignore[index]
    expired["process"]["started_at"] = "2026-08-13T09:59:00Z"  # type: ignore[index]
    expired["lease"]["acquired_at"] = "2026-08-13T10:00:00Z"  # type: ignore[index]
    expired["lease"]["heartbeat_at"] = "2026-08-13T10:00:00Z"  # type: ignore[index]
    expired["lease"]["expires_at"] = "2026-08-13T11:30:00Z"  # type: ignore[index]
    now = lambda: datetime(2026, 8, 13, 12, tzinfo=UTC)

    for proof in (ProcessStatus.LIVE, ProcessStatus.UNKNOWN):
        registry = SessionRegistry(repo, now=now, process_probe=lambda process, proof=proof: proof)
        if registry.path.exists():
            registry.path.unlink()
        registry.claim(expired, lease_token="token-session-01", expected_revision=0)
        contender = claim(repo, "session-02", resource="src/a.py")
        contender["worktree"]["path"] = (tmp_path / "two").resolve().as_posix()  # type: ignore[index]
        with pytest.raises(ClaimConflict):
            registry.claim(contender, lease_token="token-session-02", expected_revision=1)


@pytest.mark.parametrize("proof", [ProcessStatus.DEAD, ProcessStatus.HOST_UNREACHABLE])
def test_expired_owner_is_abandoned_only_with_process_or_host_proof(
    tmp_path: Path, proof: ProcessStatus
) -> None:
    repo = init_repo(tmp_path)
    now = lambda: datetime(2026, 8, 13, 12, tzinfo=UTC)
    registry = SessionRegistry(repo, now=now, process_probe=lambda process: proof)
    expired = claim(repo)
    expired["worktree"]["path"] = (tmp_path / "one").resolve().as_posix()  # type: ignore[index]
    expired["process"]["started_at"] = "2026-08-13T09:59:00Z"  # type: ignore[index]
    expired["lease"]["acquired_at"] = "2026-08-13T10:00:00Z"  # type: ignore[index]
    expired["lease"]["heartbeat_at"] = "2026-08-13T10:00:00Z"  # type: ignore[index]
    expired["lease"]["expires_at"] = "2026-08-13T11:30:00Z"  # type: ignore[index]
    registry.claim(expired, lease_token="token-session-01", expected_revision=0)

    contender = claim(repo, "session-02", resource="src/a.py")
    contender["worktree"]["path"] = (tmp_path / "two").resolve().as_posix()  # type: ignore[index]
    document = registry.claim(contender, lease_token="token-session-02", expected_revision=1)

    assert document["claims"][0]["state"] == "abandoned"
    assert document["claims"][1]["state"] == "working"
