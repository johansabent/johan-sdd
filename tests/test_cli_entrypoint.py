from __future__ import annotations

import json

from johan_sdd.__main__ import build_parser, main


def test_entrypoint_registers_the_two_deep_public_commands() -> None:
    parser = build_parser()
    subcommands = next(
        action for action in parser._actions if action.dest == "command"  # noqa: SLF001
    )

    assert set(subcommands.choices) == {"select-profile", "route"}


def test_select_profile_reads_json_file_and_emits_machine_output(tmp_path, capsys) -> None:
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps({"requested_profile": "full"}), encoding="utf-8")

    exit_code = main(["select-profile", "--input", str(input_path)])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["profile"] == "full"


def test_route_supports_stdin_and_human_text(monkeypatch, capsys) -> None:
    payload = {
        "files_changed": 1,
        "additions": 2,
        "deletions": 0,
        "change_kinds": ["modify"],
        "observed_surfaces": ["documentation"],
        "primary_checkout": True,
        "working_tree_clean": True,
        "scope": "bounded",
    }
    monkeypatch.setattr("sys.stdin.read", lambda: json.dumps(payload))

    exit_code = main(["route", "--input", "-", "--format", "text"])

    assert exit_code == 0
    assert "lane=micro" in capsys.readouterr().out


def test_invalid_input_and_policy_block_have_stable_exit_codes(tmp_path, capsys) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not json", encoding="utf-8")
    assert main(["route", "--input", str(invalid)]) == 2
    assert "validation_error" in capsys.readouterr().err

    blocked = tmp_path / "blocked.json"
    blocked.write_text(
        json.dumps({"requested_profile": "lean", "triggers": ["security"]}),
        encoding="utf-8",
    )
    assert main(["select-profile", "--input", str(blocked)]) == 3
    assert "policy_blocked" in capsys.readouterr().err


def test_missing_input_file_is_an_operational_failure(capsys) -> None:
    assert main(["route", "--input", "missing.json"]) == 4
    assert "operational_failure" in capsys.readouterr().err
