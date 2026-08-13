from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema

from johan_sdd.contracts import validate_semantics
from johan_sdd.evidence import evidence_digest


ROOT = Path(__file__).resolve().parents[1]


def portable_text_digest(path: Path) -> str:
    """Hash the repository's canonical LF form, independent of checkout policy."""
    content = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(content).hexdigest()


def test_local_runtime_closeout_is_reconstructable_and_hash_bound() -> None:
    artifact_path = ROOT / "evidence" / "artifacts" / "local-runtime-closeout.json"
    packet_path = ROOT / "evidence" / "packets" / "local-runtime-closeout.json"
    log_path = ROOT / "evidence" / "logs" / "local-runtime-verification.txt"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    packet = json.loads(packet_path.read_text(encoding="utf-8"))

    for schema_name, document in (
        ("evidence-artifact.schema.json", artifact),
        ("evidence-packet.schema.json", packet),
    ):
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(document)

    assert validate_semantics(packet) == []
    assert packet["artifacts"][0]["sha256"] == evidence_digest(artifact)
    assert packet["logs"][0]["sha256"] == portable_text_digest(log_path)
    assert packet["contracts"][0]["sha256"] == portable_text_digest(
        ROOT / "manifests" / "integration-charter.v1.json"
    )
    assert packet["changes"][0]["sha256"] == portable_text_digest(
        ROOT / "src" / "johan_sdd" / "__main__.py"
    )


def test_dashboard_pr109_pilot_is_cross_agent_reconstructable_and_portable() -> None:
    artifact_path = ROOT / "evidence" / "artifacts" / "dashboard-pr109-pilot.json"
    packet_path = ROOT / "evidence" / "packets" / "dashboard-pr109-pilot.json"
    log_path = ROOT / "evidence" / "logs" / "dashboard-pr109-pilot.txt"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    log_text = log_path.read_text(encoding="utf-8")
    log = dict(
        line.split("=", 1)
        for line in log_text.splitlines()
        if line and "=" in line
    )

    for schema_name, document in (
        ("evidence-artifact.schema.json", artifact),
        ("evidence-packet.schema.json", packet),
    ):
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(document)

    assert validate_semantics(packet) == []
    assert packet["artifacts"][0]["sha256"] == evidence_digest(artifact)
    assert packet["logs"][0]["sha256"] == portable_text_digest(log_path)
    assert packet["contracts"][0]["sha256"] == portable_text_digest(
        ROOT / "manifests" / "integration-charter.v1.json"
    )
    assert packet["changes"][0]["sha256"] == log["dashboard_diff_sha256"]
    assert artifact["subject"]["sha256"] == f"sha256:{log['dashboard_diff_sha256']}"
    assert '"lane":"feature"' in log["codex_route_result"]
    assert '"profile":"full"' in log["codex_profile_result"]
    assert '"lane":"feature"' in log["grok_result"]
    assert '"profile":"full"' in log["grok_result"]
    assert log["capture_first_target_changed"] == "true"
    assert log["capture_replay_target_changed"] == "false"
    assert "D:\\" not in log_text and "C:\\" not in log_text
