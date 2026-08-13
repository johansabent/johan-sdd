"""Minimal package entrypoint while the command modules are implemented."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from johan_sdd import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="johan-sdd",
        description="Portable orchestration for spec-driven delivery.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

