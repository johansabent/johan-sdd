"""Portable command-line entrypoint for the delivery routing seam."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import sys
from typing import Any

from johan_sdd import __version__
from johan_sdd.cli import command_descriptors, command_handlers
from johan_sdd.profiles import ProfilePolicyError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="johan-sdd",
        description="Portable orchestration for spec-driven delivery.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for descriptor in command_descriptors():
        command = subparsers.add_parser(descriptor.name)
        command.add_argument(
            "--input",
            default="-",
            help="UTF-8 JSON object path, or '-' for stdin (default).",
        )
        command.add_argument("--format", choices=("json", "text"), default="json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        payload = _read_payload(arguments.input)
        result = command_handlers()[arguments.command](payload)
    except ProfilePolicyError as error:
        return _emit_error("policy_blocked", error, 3)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return _emit_error("validation_error", error, 2)
    except OSError as error:
        return _emit_error("operational_failure", error, 4)
    _emit_result(result, arguments.format)
    return 0


def _read_payload(source: str) -> Mapping[str, object]:
    raw = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    payload = json.loads(raw)
    if not isinstance(payload, Mapping):
        raise ValueError("input must be a JSON object")
    return payload


def _emit_result(result: Mapping[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return
    for key in sorted(result):
        value = result[key]
        rendered = value if isinstance(value, (str, int, float, bool)) or value is None else json.dumps(value, ensure_ascii=False, sort_keys=True)
        print(f"{key}={rendered}")


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

