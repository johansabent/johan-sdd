from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from johan_sdd.sessions import (
    LeaseTokenMismatch,
    OpenedSession,
    SessionError,
    SessionRegistry,
    close_work_session,
    open_work_session,
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


def test_open_work_session_shapes_and_registers_a_feature_claim(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-qb", "feat/session-open", os.fspath(linked))
    now = datetime(2026, 8, 13, 12, tzinfo=UTC)

    opened = open_work_session(
        linked,
        session_id="session-open-01",
        mode="feature",
        owner={"agent": "grok", "model": "grok-4.6"},
        resources=[
            {
                "resource_type": "repo-files",
                "resource_id": "src/johan_sdd/sessions",
                "access": "exclusive",
            }
        ],
        authority_decision_ref="authority:test:1",
        now=lambda: now,
    )

    assert opened.session_id == "session-open-01"
    assert opened.revision == 1
    assert opened.lease_token
    claim = opened.claim
    assert claim["mode"] == "feature"
    assert claim["state"] == "working"
    assert claim["dirty"] is False
    assert claim["owner"] == {"agent": "grok", "model": "grok-4.6"}
    assert claim["worktree"] == {
        "repo_id": "repo",
        "worktree_id": "linked",
        "path": linked.resolve().as_posix(),
        "kind": "linked",
        "branch": "feat/session-open",
    }
    assert claim["process"]["host"] == socket.gethostname()
    assert claim["process"]["pid"] == os.getpid()
    assert claim["lease"]["token_hash"] == (
        "sha256:" + hashlib.sha256(opened.lease_token.encode("utf-8")).hexdigest()
    )
    assert claim["lease"]["ttl_seconds"] == 5400
    assert claim["lease"]["acquired_at"] == "2026-08-13T12:00:00Z"
    assert claim["resources"] == [
        {
            "resource_type": "repo-files",
            "resource_id": "src/johan_sdd/sessions",
            "access": "exclusive",
        }
    ]
    jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker()).validate(
        opened.document
    )

    inspection = SessionRegistry(linked).inspect()
    assert inspection.document is not None
    assert inspection.document["revision"] == 1
    assert inspection.document["claims"][0]["session_id"] == "session-open-01"


def test_open_work_session_rejects_feature_mode_on_primary_checkout(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)

    with pytest.raises(SessionError, match="linked worktree"):
        open_work_session(
            repo,
            session_id="session-open-02",
            mode="feature",
            owner={"agent": "grok", "model": "grok-4.6"},
            resources=[
                {"resource_type": "repo-files", "resource_id": "src/a.py", "access": "exclusive"}
            ],
            authority_decision_ref="authority:test:1",
        )


def _open_feature(repo: Path, session_id: str = "session-open-01") -> OpenedSession:
    linked = repo.parent / "linked"
    if not linked.exists():
        git(repo, "worktree", "add", "-qb", "feat/session-open", os.fspath(linked))
    return open_work_session(
        linked,
        session_id=session_id,
        mode="feature",
        owner={"agent": "grok", "model": "grok-4.6"},
        resources=[
            {"resource_type": "repo-files", "resource_id": "src/johan_sdd/sessions", "access": "exclusive"}
        ],
        authority_decision_ref="authority:test:1",
        now=lambda: datetime(2026, 8, 13, 12, tzinfo=UTC),
    )


def test_close_work_session_releases_owned_claim(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    opened = _open_feature(repo)
    linked = tmp_path / "linked"

    document = close_work_session(linked, opened.session_id, lease_token=opened.lease_token)

    assert document["revision"] == 2
    assert document["claims"][0]["state"] == "closed"
    inspection = SessionRegistry(linked).inspect()
    assert inspection.document is not None
    assert inspection.document["claims"][0]["state"] == "closed"


def test_close_work_session_rejects_a_wrong_lease_token(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    opened = _open_feature(repo)

    with pytest.raises(LeaseTokenMismatch):
        close_work_session(tmp_path / "linked", opened.session_id, lease_token="not-the-token")


def test_open_work_session_registers_micro_on_clean_primary(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)

    opened = open_work_session(
        repo,
        session_id="session-micro-01",
        mode="micro",
        owner={"agent": "grok", "model": "grok-4.6"},
        resources=[
            {
                "resource_type": "global-agents",
                "resource_id": "agent-home:shared",
                "access": "exclusive",
            }
        ],
        authority_decision_ref="authority:test:1",
        now=lambda: datetime(2026, 8, 13, 12, tzinfo=UTC),
    )

    assert opened.claim["mode"] == "micro"
    assert opened.claim["worktree"]["kind"] == "primary"
    assert opened.claim["worktree"]["worktree_id"] == "primary"
    assert opened.claim["resources"][0]["resource_type"] == "global-agents"


def test_open_work_session_rejects_dirty_feature_without_recovery(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-qb", "feat/session-open", os.fspath(linked))
    (linked / "tracked.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(SessionError, match="clean worktree"):
        open_work_session(
            linked,
            session_id="session-dirty-01",
            mode="feature",
            owner={"agent": "grok", "model": "grok-4.6"},
            resources=[
                {"resource_type": "repo-files", "resource_id": "tracked.txt", "access": "exclusive"}
            ],
            authority_decision_ref="authority:test:1",
        )


def test_open_work_session_records_an_explicit_caller_process(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-qb", "feat/session-open", os.fspath(linked))
    process = {
        "host": "caller-host",
        "pid": 4242,
        "started_at": "2026-08-13T11:59:00Z",
    }

    opened = open_work_session(
        linked,
        session_id="session-process-01",
        mode="feature",
        owner={"agent": "grok", "model": "grok-4.6"},
        resources=[
            {"resource_type": "repo-files", "resource_id": "src/johan_sdd/sessions", "access": "exclusive"}
        ],
        authority_decision_ref="authority:test:1",
        process=process,
        now=lambda: datetime(2026, 8, 13, 12, tzinfo=UTC),
    )

    assert opened.claim["process"] == process


def test_open_work_session_rejects_micro_on_dirty_primary(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(SessionError, match="clean primary checkout"):
        open_work_session(
            repo,
            session_id="session-micro-02",
            mode="micro",
            owner={"agent": "grok", "model": "grok-4.6"},
            resources=[
                {"resource_type": "repo-files", "resource_id": "tracked.txt", "access": "exclusive"}
            ],
            authority_decision_ref="authority:test:1",
        )


def test_open_work_session_rejects_micro_on_linked_worktree(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-qb", "feat/session-open", os.fspath(linked))

    with pytest.raises(SessionError, match="primary checkout"):
        open_work_session(
            linked,
            session_id="session-micro-03",
            mode="micro",
            owner={"agent": "grok", "model": "grok-4.6"},
            resources=[
                {"resource_type": "repo-files", "resource_id": "tracked.txt", "access": "exclusive"}
            ],
            authority_decision_ref="authority:test:1",
        )


def test_module_cli_opens_and_closes_without_a_hand_built_claim(tmp_path: Path, capsys) -> None:
    from johan_sdd.sessions.__main__ import main as session_main

    repo = init_repo(tmp_path)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-qb", "feat/session-open", os.fspath(linked))
    payload = tmp_path / "open.json"
    payload.write_text(
        json.dumps(
            {
                "repository": os.fspath(linked),
                "session_id": "session-cli-01",
                "mode": "feature",
                "owner": {"agent": "grok", "model": "grok-4.6"},
                "resources": [
                    {
                        "resource_type": "global-agents",
                        "resource_id": "agent-home:shared",
                        "access": "exclusive",
                    }
                ],
                "authority_decision_ref": "authority:test:1",
            }
        ),
        encoding="utf-8",
    )

    assert session_main(["open", "--input", os.fspath(payload)]) == 0
    opened = json.loads(capsys.readouterr().out)
    assert opened["session_id"] == "session-cli-01"
    assert opened["revision"] == 1
    assert opened["lease_token"]
    assert "token_hash" in opened["claim"]["lease"]

    close_payload = tmp_path / "close.json"
    close_payload.write_text(
        json.dumps(
            {
                "repository": os.fspath(linked),
                "session_id": opened["session_id"],
                "lease_token": opened["lease_token"],
            }
        ),
        encoding="utf-8",
    )
    assert session_main(["close", "--input", os.fspath(close_payload)]) == 0
    closed = json.loads(capsys.readouterr().out)
    assert closed["revision"] == 2
    assert closed["claims"][0]["state"] == "closed"

