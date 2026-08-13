from __future__ import annotations

import multiprocessing
from pathlib import Path
from queue import Empty
from typing import Any

from johan_sdd.capture.promotion import (
    FilePromotionTarget,
    PromotionConflictError,
    promote_capture,
)

from test_promotion import lifecycle, promoter


def _clock() -> str:
    return "2026-08-13T12:02:00Z"


def _promote_worker(
    packet: dict[str, Any],
    decision: dict[str, Any],
    root: str,
    queue: multiprocessing.Queue[Any],
) -> None:
    path = Path(root)
    try:
        outcome = promote_capture(
            packet=packet,
            authority_decision=decision,
            promoter=promoter(),
            target=FilePromotionTarget(
                path=path / "sink" / "event.json",
                target_id="buzz:session-01:cursor",
                sink="buzz_event",
            ),
            receipt_directory=path / "receipts",
            lock_directory=path / "locks",
            clock=_clock,
            lock_timeout=20.0,
        )
    except PromotionConflictError as exc:
        queue.put(("conflict", exc.receipt.get("phase"), None))
    except Exception as exc:  # pragma: no cover - returned to the parent for a useful failure
        queue.put(("error", type(exc).__name__, str(exc)))
    else:
        queue.put(
            (
                "committed",
                outcome.target_changed,
                outcome.request["lock"]["fencing_token"],
            )
        )


def _run_race(
    tmp_path: Path,
    decision: dict[str, Any],
    packets: list[dict[str, Any]],
) -> list[tuple[Any, ...]]:
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(target=_promote_worker, args=(packet, decision, str(tmp_path), queue))
        for packet in packets
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0
    results: list[tuple[Any, ...]] = []
    for _ in processes:
        try:
            results.append(queue.get(timeout=5))
        except Empty as exc:  # pragma: no cover - only explains a wedged child
            raise AssertionError("promotion worker returned no result") from exc
    return results


def test_cross_process_replay_is_serialized_idempotently_with_unique_fences(tmp_path: Path) -> None:
    decision, packet = lifecycle(tmp_path)

    results = _run_race(tmp_path, decision, [packet] * 6)

    assert [result[0] for result in results] == ["committed"] * 6
    assert sum(result[1] is True for result in results) == 1
    fences = {result[2] for result in results}
    assert fences == {1, 2, 3, 4, 5, 6}
    assert len(list((tmp_path / "sink").glob("*.json"))) == 1
    assert len(list((tmp_path / "receipts").glob("*.json"))) == 18


def test_cross_process_competing_captures_commit_one_and_conflict_one(tmp_path: Path) -> None:
    decision, first = lifecycle(tmp_path)
    second = dict(first)
    second["lifecycle_cursor"] = "00000002"
    # A separately generated capture is required; reuse the public helper rather
    # than forging identity fields in the worker race.
    from johan_sdd.capture import generate_capture_packet

    second = generate_capture_packet(
        session_claim={
            "session_id": "session-01",
            "owner": {"agent": "codex", "model": "gpt-5.6-sol"},
            "authority_decision_ref": first["authority_decision"]["decision_ref"],
        },
        lifecycle_cursor=2,
        authority_decision=decision,
        payload={
            "event_type": "working",
            "occurred_at": "2026-08-13T12:01:01Z",
            "summary": "A competing lifecycle event.",
            "next_action": "Resolve the serialized conflict.",
            "evidence_refs": [f"sha256:{'b' * 64}"],
        },
    )

    results = _run_race(tmp_path, decision, [first, second])

    assert sorted(result[0] for result in results) == ["committed", "conflict"]
    assert len(list((tmp_path / "sink").glob("*.json"))) == 1
