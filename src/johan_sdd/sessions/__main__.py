"""JSON open/close adapter for session claims. Not the portable johan-sdd CLI."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from johan_sdd.sessions import SessionError, close_work_session, open_work_session


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m johan_sdd.sessions")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("open", "close"):
        command = subparsers.add_parser(name)
        command.add_argument("--input", default="-", help="UTF-8 JSON object path, or '-' for stdin.")
    arguments = parser.parse_args(argv)
    try:
        payload = _read_payload(arguments.input)
        if arguments.command == "open":
            opened = open_work_session(
                _string(payload["repository"], "repository"),
                session_id=_string(payload["session_id"], "session_id"),
                mode=_string(payload["mode"], "mode"),
                owner=_object(payload["owner"], "owner"),
                resources=_resources(payload["resources"]),
                authority_decision_ref=_string(
                    payload["authority_decision_ref"], "authority_decision_ref"
                ),
                lease_token=_optional_string(payload.get("lease_token"), "lease_token"),
                ttl_seconds=_optional_int(payload.get("ttl_seconds"), "ttl_seconds", 5400),
            )
            result = {
                "session_id": opened.session_id,
                "lease_token": opened.lease_token,
                "revision": opened.revision,
                "claim": opened.claim,
            }
        else:
            result = close_work_session(
                _string(payload["repository"], "repository"),
                _string(payload["session_id"], "session_id"),
                lease_token=_string(payload["lease_token"], "lease_token"),
                expected_revision=_optional_int(payload.get("expected_revision"), "expected_revision"),
            )
    except KeyError as error:
        return _emit_error("validation_error", ValueError(f"missing {error.args[0]}"), 2)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return _emit_error("validation_error", error, 2)
    except SessionError as error:
        return _emit_error("session_error", error, 3)
    except OSError as error:
        return _emit_error("operational_failure", error, 4)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


def _read_payload(source: str) -> Mapping[str, object]:
    raw = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    payload = json.loads(raw)
    if not isinstance(payload, Mapping):
        raise ValueError("input must be a JSON object")
    return payload


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field)


def _optional_int(value: object, field: str, default: int | None = None) -> int | None:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    return value


def _object(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not all(isinstance(item, str) for item in value.values()):
        raise ValueError(f"{field} must be an object of strings")
    return {str(key): str(item) for key, item in value.items()}


def _resources(value: object) -> list[dict[str, str]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("resources must be a sequence of objects")
    return [_object(item, "resources") for item in value]


def _emit_error(kind: str, error: Exception, exit_code: int) -> int:
    print(
        json.dumps(
            {"error": kind, "message": str(error)},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        file=sys.stderr,
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
