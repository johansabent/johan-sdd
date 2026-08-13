from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema

from johan_sdd.contracts import validate_semantics
from johan_sdd.evidence import evidence_digest


ROOT = Path(__file__).resolve().parents[1]


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    assert packet["logs"][0]["sha256"] == file_digest(log_path)
    assert packet["contracts"][0]["sha256"] == file_digest(
        ROOT / "manifests" / "integration-charter.v1.json"
    )
    assert packet["changes"][0]["sha256"] == file_digest(
        ROOT / "src" / "johan_sdd" / "__main__.py"
    )
