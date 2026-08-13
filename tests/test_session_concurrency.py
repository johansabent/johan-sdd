from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from johan_sdd.sessions import SessionError, SessionRegistry


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", os.fspath(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def contender(repo: str, session_id: str, gate, results) -> None:  # type: ignore[no-untyped-def]
    path = Path(repo)
    token = f"token-{session_id}"
    now = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)
    value = {
        "session_id": session_id,
        "mode": "feature",
        "owner": {"agent": "codex", "model": "gpt-5"},
        "process": {"host": socket.gethostname(), "pid": os.getpid(), "started_at": "2026-08-13T11:59:00Z"},
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
            "path": (path.parent / session_id).resolve().as_posix(),
            "kind": "linked",
            "branch": f"codex/{session_id}",
        },
        "state": "working",
        "dirty": False,
        "authority_decision_ref": f"authority:{session_id}:1",
        "resources": [{"resource_type": "tracker", "resource_id": "tracker:JOH-1", "access": "exclusive"}],
    }
    gate.wait()
    try:
        SessionRegistry(path).claim(value, lease_token=token, expected_revision=0)
    except SessionError as exc:
        results.put(("error", type(exc).__name__))
    else:
        results.put(("ok", session_id))


def test_registry_serializes_processes_and_never_loses_a_winner(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    context = multiprocessing.get_context("spawn")
    gate = context.Event()
    results = context.Queue()
    processes = [
        context.Process(target=contender, args=(os.fspath(repo), f"session-0{i}", gate, results))
        for i in (1, 2)
    ]
    for process in processes:
        process.start()
    gate.set()
    outcomes = [results.get(timeout=15) for _ in processes]
    for process in processes:
        process.join(timeout=15)
        assert process.exitcode == 0

    assert sorted(outcome[0] for outcome in outcomes) == ["error", "ok"]
    document = json.loads(SessionRegistry(repo).path.read_text(encoding="utf-8"))
    assert document["revision"] == 1
    assert len(document["claims"]) == 1
