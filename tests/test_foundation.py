from __future__ import annotations

import importlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
MANIFESTS = ROOT / "manifests"
SRC = ROOT / "src"


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_every_json_and_toml_contract_parses() -> None:
    json_paths = sorted((*SCHEMAS.glob("*.json"), *MANIFESTS.glob("*.json")))
    assert json_paths
    for path in json_paths:
        assert isinstance(load_json(path), dict), path

    toml_paths = sorted(ROOT.rglob("*.toml"))
    assert toml_paths
    for path in toml_paths:
        with path.open("rb") as stream:
            assert isinstance(tomllib.load(stream), dict), path


def test_every_schema_is_valid_draft_2020_12() -> None:
    for path in sorted(SCHEMAS.glob("*.json")):
        jsonschema.Draft202012Validator.check_schema(load_json(path))


@pytest.mark.parametrize(
    ("manifest_name", "schema_name"),
    [
        ("upstreams.lock.json", "upstreams-lock.schema.json"),
        ("integration-charter.v1.json", "integration-charter.schema.json"),
    ],
)
def test_manifest_matches_its_schema(manifest_name: str, schema_name: str) -> None:
    jsonschema.Draft202012Validator(
        load_json(SCHEMAS / schema_name),
        format_checker=jsonschema.FormatChecker(),
    ).validate(load_json(MANIFESTS / manifest_name))


def test_upstream_pins_are_exact_and_immutable() -> None:
    lock = load_json(MANIFESTS / "upstreams.lock.json")
    upstreams = {item["id"]: item for item in lock["upstreams"]}  # type: ignore[index]

    assert upstreams["github-spec-kit"] == {
        "id": "github-spec-kit",
        "owner": "github",
        "repository": "spec-kit",
        "source": "https://github.com/github/spec-kit",
        "version": "v0.16.3",
        "tag_object": "0a5ee5b25d0b4e08425c23f0633197cb33fe8c74",
        "peeled_commit": "b85aaeda4a7aec37a6620bba9d77ab37c6589141",
        "license": "MIT",
        "role": "delivery-spine",
    }
    assert upstreams["matt-pocock-skills"] == {
        "id": "matt-pocock-skills",
        "owner": "mattpocock",
        "repository": "skills",
        "source": "https://github.com/mattpocock/skills",
        "version": "v1.2.3",
        "tag_object": "835450ef244ab7335f75d95b83e7d979eae22a6d",
        "peeled_commit": "6acc160e4e0cd062dbbbd7a1b26ae92855edf07e",
        "license": "MIT",
        "role": "engineering-flow-modules",
    }


def test_package_and_charter_versions_agree() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    charter = load_json(MANIFESTS / "integration-charter.v1.json")

    sys.path.insert(0, str(SRC))
    try:
        package = importlib.import_module("johan_sdd")
        assert package.__version__ == pyproject["project"]["version"]
        assert package.__version__ == charter["product"]["version"]  # type: ignore[index]
    finally:
        sys.path.remove(str(SRC))
        sys.modules.pop("johan_sdd", None)


def test_routing_and_host_boundaries_are_frozen() -> None:
    charter = load_json(MANIFESTS / "integration-charter.v1.json")
    assert charter["profiles"]["default"] == "lean"  # type: ignore[index]
    assert set(charter["profiles"]["definitions"]) == {"lean", "full"}  # type: ignore[index]
    assert charter["routing"]["dual_write"] == "forbidden"  # type: ignore[index]
    assert charter["routing"]["interfaces"] == {  # type: ignore[index]
        "phase_router": "phase-router/v1",
        "engineering_flow_hub": "engineering-flow-hub/v1",
    }
    assert charter["host_adapters"] == [  # type: ignore[index]
        {
            "interface": "johan-host-adapter/v1",
            "phase_router": "using-johan-skills",
            "engineering_flow_hub": "ask-matt",
        }
    ]
    assert charter["host_integration"]["direct_agent_home_writes"] is False  # type: ignore[index]
    assert charter["host_integration"]["apply_actor"] == "separately-authorized-host-owner"  # type: ignore[index]

    micro = charter["routing"]["lanes"]["micro"]  # type: ignore[index]
    assert micro["admission"]["max_files"] == 3
    assert micro["admission"]["max_changed_lines"] == 50
    assert micro["dirty_pause"] is False

    selection = charter["profiles"]["selection"]  # type: ignore[index]
    assert selection["override_policy"]["escalation"] == "natural-language-always-allowed"
    assert selection["override_policy"]["downgrade"] == {
        "requires_no_hard_trigger": True,
        "requires_human_decision_receipt": True,
    }

    small = charter["routing"]["lanes"]["small"]  # type: ignore[index]
    assert small["mutable_worktree"] == "isolated-required"
    assert small["readonly_checkout"] == "primary-allowed"


def test_dirty_pause_requires_complete_synthetic_commit_without_real_index_mutation() -> None:
    charter = load_json(MANIFESTS / "integration-charter.v1.json")
    dirty_pause = charter["sessions"]["dirty_pause"]  # type: ignore[index]

    assert dirty_pause["snapshot_algorithm"] == [
        "create-temporary-GIT_INDEX_FILE-outside-real-index",
        "git-read-tree-original-HEAD",
        "git-add-A-against-entire-nonignored-worktree",
        "git-write-tree",
        "git-commit-tree-with-parent-original-HEAD",
        "git-update-ref-refs/agent-sessions/session-id-to-synthetic-commit",
        "delete-temporary-index",
    ]
    assert set(dirty_pause["must_include"]) == {
        "tracked-modifications",
        "tracked-deletions",
        "untracked-nonignored-files",
    }
    assert set(dirty_pause["must_not_touch"]) == {"real-index", "worktree", "current-branch", "HEAD"}
    assert dirty_pause["protected_ref_lifetime"] == "until-explicit-verified-cleanup"
    assert "ref-to-HEAD" in dirty_pause["insufficient_methods"]
    assert "git-stash-create-without-complete-untracked-tree" in dirty_pause["insufficient_methods"]


def capture_packet() -> dict[str, object]:
    return {
        "schema_version": "johan-sdd/capture-packet/v2",
        "capture_id": f"cap_{'a' * 64}",
        "packet_digest": "b" * 64,
        "session_id": "session-01",
        "lifecycle_cursor": "00000001",
        "generator": {
            "actor_id": "session-owner:session-01",
            "agent": "codex",
            "model": "gpt-5.6-terra",
        },
        "authority_decision": {
            "decision_ref": "authority:session-01:1",
            "decision_sha256": "c" * 64,
        },
        "payload": {
            "event_type": "working",
            "occurred_at": "2026-08-13T12:10:00Z",
            "summary": "Foundation contracts are being validated.",
            "next_action": "Complete the current contract slice.",
            "evidence_refs": [f"sha256:{'d' * 64}"],
        },
    }


def test_capture_v2_records_generator_and_constrained_lifecycle_payload() -> None:
    schema = load_json(SCHEMAS / "capture-packet.v2.schema.json")
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(capture_packet())


def test_capture_generator_cannot_select_authority_or_sink() -> None:
    schema = load_json(SCHEMAS / "capture-packet.v2.schema.json")
    packet = capture_packet()
    packet["authority_mode"] = "pre_cutover_json_authority"
    packet["sink"] = "session_artifact_v1"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(packet)


def git_tracked_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode("utf-8") for item in completed.stdout.split(b"\0") if item]


def test_committed_product_is_publicly_portable() -> None:
    tracked = git_tracked_files()
    if not tracked:
        tracked = [
            *ROOT.glob(".agents/**/*"),
            *ROOT.glob(".codex/**/*"),
            *ROOT.glob("*.md"),
            *ROOT.glob("*.toml"),
            *ROOT.glob("LICENSE"),
            *ROOT.glob("docs/**/*"),
            *ROOT.glob("manifests/**/*"),
            *ROOT.glob("schemas/**/*"),
            *ROOT.glob("src/**/*"),
        ]

    forbidden_host_path = re.compile(
        r"(?i)(?:[a-z]:[\\/](?:users|usuarios)[\\/]johan(?:[\\/]|$)|/(?:home|users)/johan(?:/|$))"
    )
    probable_secret = re.compile(
        r"(?i)(?:api[_-]?key|access[_-]?token|password)\s*[:=]\s*['\"][A-Za-z0-9_./+=-]{16,}['\"]"
    )

    violations: list[str] = []
    for path in tracked:
        if not path.is_file() or path == Path(__file__) or ".git" in path.parts:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if forbidden_host_path.search(content):
            violations.append(f"host path: {path.relative_to(ROOT)}")
        if probable_secret.search(content):
            violations.append(f"probable secret: {path.relative_to(ROOT)}")

    assert violations == [], "public portability violations:\n" + "\n".join(violations)


def test_runtime_is_pinned_to_python_311() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["requires-python"] == ">=3.11,<3.12"
