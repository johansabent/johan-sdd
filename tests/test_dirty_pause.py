from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from johan_sdd.sessions import DirtyPauseRejected, SecretMaterialError, create_dirty_pause


RECOVERY_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schemas" / "pause-recovery.schema.json").read_text(
        encoding="utf-8"
    )
)


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", os.fspath(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()


def init_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    linked = tmp_path / "linked"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Test User")
    git(repo, "config", "user.email", "test@example.invalid")
    (repo / "modified.txt").write_text("before\n", encoding="utf-8")
    (repo / "deleted.txt").write_text("delete me\n", encoding="utf-8")
    (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    git(repo, "worktree", "add", "-qb", "pause-test", os.fspath(linked))
    return repo, linked


def snapshot(repo: Path) -> tuple[str, str, bytes, bytes | None]:
    head = git(repo, "rev-parse", "HEAD")
    branch = git(repo, "symbolic-ref", "HEAD")
    status = subprocess.run(
        ["git", "-C", os.fspath(repo), "status", "--porcelain=v2", "-z", "--untracked-files=all"],
        check=True,
        capture_output=True,
    ).stdout
    index = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-path", "index"))
    return head, branch, status, index.read_bytes() if index.exists() else None


def test_dirty_pause_captures_modified_deleted_and_untracked_without_touching_checkout(
    tmp_path: Path,
) -> None:
    _, linked = init_repo(tmp_path)
    (linked / "modified.txt").write_text("after\n", encoding="utf-8")
    (linked / "deleted.txt").unlink()
    (linked / "untracked.txt").write_text("new\n", encoding="utf-8")
    (linked / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    before = snapshot(linked)
    temp_indexes = tmp_path / "indexes"
    temp_indexes.mkdir()

    recovery = create_dirty_pause(
        linked,
        "session-01",
        mode="feature",
        now=lambda: datetime(2026, 8, 13, 12, tzinfo=timezone.utc),
        temp_dir=temp_indexes,
    )

    assert recovery["schema_version"] == "johan-sdd/pause-recovery/v1"
    jsonschema.Draft202012Validator(
        RECOVERY_SCHEMA, format_checker=jsonschema.FormatChecker()
    ).validate(recovery)
    assert recovery["protected_ref"] == "refs/agent-sessions/session-01"
    assert recovery["original_head"] == before[0]
    assert recovery["original_status_sha256"] == hashlib.sha256(before[2]).hexdigest()
    assert recovery["untracked_paths"] == ["untracked.txt"]
    tree = recovery["synthetic_commit"]
    assert git(linked, "show", f"{tree}:modified.txt") == "after"
    assert git(linked, "show", f"{tree}:untracked.txt") == "new"
    missing = subprocess.run(
        ["git", "-C", os.fspath(linked), "cat-file", "-e", f"{tree}:deleted.txt"],
        capture_output=True,
    )
    assert missing.returncode != 0
    ignored = subprocess.run(
        ["git", "-C", os.fspath(linked), "cat-file", "-e", f"{tree}:ignored.txt"],
        capture_output=True,
    )
    assert ignored.returncode != 0
    assert git(linked, "rev-parse", "refs/agent-sessions/session-01") == tree
    assert snapshot(linked) == before
    assert list(temp_indexes.iterdir()) == []


def test_dirty_pause_rejects_primary_and_micro_inputs(tmp_path: Path) -> None:
    primary, linked = init_repo(tmp_path)
    with pytest.raises(DirtyPauseRejected, match="linked worktree"):
        create_dirty_pause(primary, "session-primary", mode="feature")
    with pytest.raises(DirtyPauseRejected, match="feature"):
        create_dirty_pause(linked, "session-micro", mode="micro")

    (linked / "modified.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(DirtyPauseRejected, match="outside the worktree"):
        create_dirty_pause(linked, "session-inside-index", mode="feature", temp_dir=linked)


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        ("credentials.txt", "ordinary text\n"),
        ("notes.txt", "-----BEGIN PRIVATE KEY-----\n"),
    ],
)
def test_secret_suspicion_stops_before_protected_ref_and_cleans_temp_index(
    tmp_path: Path, relative_path: str, content: str
) -> None:
    _, linked = init_repo(tmp_path)
    (linked / relative_path).write_text(content, encoding="utf-8")
    temp_indexes = tmp_path / "indexes"
    temp_indexes.mkdir()

    with pytest.raises(SecretMaterialError):
        create_dirty_pause(linked, "session-secret", mode="feature", temp_dir=temp_indexes)

    ref_check = subprocess.run(
        ["git", "-C", os.fspath(linked), "show-ref", "--verify", "--quiet", "refs/agent-sessions/session-secret"],
        capture_output=True,
    )
    assert ref_check.returncode != 0
    assert list(temp_indexes.iterdir()) == []
