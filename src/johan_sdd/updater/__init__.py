"""Transactional updater for clean, known, disposable canary targets."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
_AUTHORITY_FIELDS = (
    "hooks",
    "installer",
    "host-policy",
    "trust-root",
    "allowlist",
    "agent-home",
    "permissions",
    "runner",
    "target-root",
)
_CONTENT_PREFIXES = frozenset({"upstream", "adapters", "presets", "overlays"})
_ALLOWLIST_ENTRIES = [
    "pinned-upstream-content",
    "product-owned-adapters",
    "product-owned-presets",
    "registered-repository-generated-overlays",
]


class UpdateContractError(ValueError):
    """The candidate or its update evidence violates the immutable contract."""


@dataclass(frozen=True)
class UpdateSkip:
    target_id: str
    reason: str


@dataclass(frozen=True)
class UpdatePayload:
    """The three exact components governed by update and rollback."""

    content: Mapping[str, bytes]
    pins: bytes
    manifest: bytes

    def __post_init__(self) -> None:
        normalized: dict[str, bytes] = {}
        for path, payload in self.content.items():
            logical_path = _normalize_content_path(path)
            if logical_path in normalized:
                raise UpdateContractError(f"duplicate candidate content path: {logical_path}")
            if logical_path.split("/", 1)[0] not in _CONTENT_PREFIXES:
                raise UpdateContractError(
                    f"candidate content is outside the updater allowlist: {logical_path}"
                )
            normalized[logical_path] = bytes(payload)
        if not normalized:
            raise UpdateContractError("candidate content cannot be empty")
        object.__setattr__(self, "content", normalized)
        object.__setattr__(self, "pins", bytes(self.pins))
        object.__setattr__(self, "manifest", bytes(self.manifest))

    def hashes(self) -> dict[str, str]:
        return {
            "content_sha256": _content_hash(self.content),
            "pins_sha256": _sha256(self.pins),
            "manifest_sha256": _sha256(self.manifest),
        }


@dataclass(frozen=True)
class DisposableUpdateTarget:
    """A host-owned target path constrained beneath an explicit sandbox."""

    sandbox_root: Path
    relative_path: str
    target_id: str
    known: bool
    clean: bool

    def __post_init__(self) -> None:
        normalized = _normalize_relative_path(self.relative_path)
        if any(part.casefold() == ".agents" for part in self.sandbox_root.resolve().parts):
            raise UpdateContractError("agent homes cannot be updater sandboxes")
        root = (self.sandbox_root.resolve() / Path(*PurePosixPath(normalized).parts)).resolve()
        _require_beneath(root, self.sandbox_root.resolve())
        object.__setattr__(self, "relative_path", normalized)

    @property
    def root(self) -> Path:
        return (self.sandbox_root.resolve() / Path(*PurePosixPath(self.relative_path).parts)).resolve()

    def read_payload(self) -> UpdatePayload:
        root = self.root
        content_root = root / "content"
        content: dict[str, bytes] = {}
        if content_root.exists():
            for path in sorted(content_root.rglob("*"), key=lambda item: item.as_posix()):
                if path.is_symlink():
                    raise UpdateContractError("update targets cannot contain symbolic links")
                if path.is_file():
                    content[path.relative_to(content_root).as_posix()] = path.read_bytes()
        if not content:
            raise UpdateContractError("known update targets require existing content")
        pins_path = root / "pins.json"
        manifest_path = root / "manifest.json"
        if not pins_path.is_file() or not manifest_path.is_file():
            raise UpdateContractError("known update targets require pins.json and manifest.json")
        return UpdatePayload(
            content=content,
            pins=pins_path.read_bytes(),
            manifest=manifest_path.read_bytes(),
        )


@dataclass(frozen=True)
class CanaryReceipts:
    manifest_and_schema_validation: Mapping[str, str]
    lean: Mapping[str, str]
    full: Mapping[str, str]
    codex: Mapping[str, str]
    claude: Mapping[str, str]
    host_preview: Mapping[str, str]
    rollback_drill: Mapping[str, str]

    def __post_init__(self) -> None:
        for name in (
            "manifest_and_schema_validation",
            "lean",
            "full",
            "codex",
            "claude",
            "host_preview",
            "rollback_drill",
        ):
            _validate_receipt_ref(getattr(self, name), name)

    def as_manifest(self) -> dict[str, object]:
        def passed(value: Mapping[str, str]) -> dict[str, object]:
            return {"result": "passed", "receipt": dict(value)}

        return {
            "environment": "disposable_worktree",
            "manifest_and_schema_validation": passed(self.manifest_and_schema_validation),
            "profiles": {"lean": passed(self.lean), "full": passed(self.full)},
            "adapters": {"codex": passed(self.codex), "claude": passed(self.claude)},
            "host_preview": passed(self.host_preview),
            "rollback_drill": passed(self.rollback_drill),
        }


@dataclass(frozen=True)
class UpdatePreview:
    document: dict[str, object]
    candidate: UpdatePayload
    candidate_binding_sha256: str
    document_binding_sha256: str
    target_id: str


@dataclass(frozen=True)
class UpdateApplyResult:
    status: str
    document: dict[str, object]
    readback: Mapping[str, str]
    reason: str | None = None
    rollback_receipt: dict[str, object] | None = None


@dataclass(frozen=True)
class _TreeSnapshot:
    directories: tuple[str, ...]
    files: Mapping[str, bytes]


def preview_update(
    *,
    target: DisposableUpdateTarget,
    current_upstreams: Sequence[Mapping[str, object]],
    candidate_upstreams: Sequence[Mapping[str, object]],
    candidate_payload: UpdatePayload,
    trust_root_sha256: str,
    allowlist_sha256: str,
    authority_baseline: Mapping[str, object],
    authority_candidate: Mapping[str, object],
    canary_receipts: CanaryReceipts,
    now: datetime,
) -> UpdatePreview | UpdateSkip:
    """Admit and bind one update candidate without mutating its target."""

    if not target.known:
        return UpdateSkip(target_id=target.target_id, reason="unknown-target")
    if not target.clean:
        return UpdateSkip(target_id=target.target_id, reason="dirty-target")
    _require_digest(trust_root_sha256, "trust_root_sha256")
    _require_digest(allowlist_sha256, "allowlist_sha256")
    current_pins = _validate_pin_set(current_upstreams)
    candidate_pins = _validate_pin_set(candidate_upstreams)
    changed = [
        field
        for field in _AUTHORITY_FIELDS
        if authority_baseline.get(field) != authority_candidate.get(field)
    ]
    if changed:
        raise UpdateContractError(f"authority delta is prohibited: {', '.join(changed)}")
    if set(authority_baseline) != set(_AUTHORITY_FIELDS) or set(authority_candidate) != set(
        _AUTHORITY_FIELDS
    ):
        raise UpdateContractError("authority comparison must cover exactly every prohibited field")

    current_payload = target.read_payload()
    current_hashes = current_payload.hashes()
    candidate_hashes = candidate_payload.hashes()
    baseline_hash = _canonical_hash(dict(authority_baseline))
    candidate_authority_hash = _canonical_hash(dict(authority_candidate))
    body: dict[str, object] = {
        "schema_version": "johan-sdd/update-manifest/v1",
        "created_at": _timestamp(now),
        "target": {
            "target_id": target.target_id,
            "status": "clean",
            "disposable_worktree": True,
        },
        "current": {
            "manifest_sha256": current_hashes["manifest_sha256"],
            "pins_sha256": current_hashes["pins_sha256"],
            "upstreams": current_pins,
        },
        "candidate": {
            "manifest_sha256": candidate_hashes["manifest_sha256"],
            "pins_sha256": candidate_hashes["pins_sha256"],
            "upstreams": candidate_pins,
        },
        "bindings": {
            "trust_root": {
                "path": "manifests/upstreams.lock.json",
                "sha256": trust_root_sha256,
            },
            "allowlist": {"sha256": allowlist_sha256, "entries": list(_ALLOWLIST_ENTRIES)},
            "prestate": current_hashes,
        },
        "authority_delta": {
            "status": "passed",
            "baseline_sha256": baseline_hash,
            "candidate_sha256": candidate_authority_hash,
            "checked_fields": list(_AUTHORITY_FIELDS),
            "prohibited_changes": [],
        },
        "canaries": canary_receipts.as_manifest(),
    }
    update_id = f"update_{_canonical_hash({'manifest': body, 'candidate_content': candidate_hashes['content_sha256']})}"
    preview_receipt = _receipt_ref(f"update-preview-{update_id.removeprefix('update_')}", update_id)
    document = {
        **body,
        "update_id": update_id,
        "apply": {"phase": "previewed", "preview_receipt": preview_receipt},
    }
    return UpdatePreview(
        document=document,
        candidate=candidate_payload,
        candidate_binding_sha256=_payload_binding(candidate_payload),
        document_binding_sha256=_canonical_hash(document),
        target_id=target.target_id,
    )


def apply_update(
    preview: UpdatePreview,
    *,
    target: DisposableUpdateTarget,
    now: datetime,
) -> UpdateApplyResult:
    """Apply a bound candidate or restore the exact old target on any failure."""

    if not target.known:
        return UpdateApplyResult("rejected", preview.document, {}, "unknown-target")
    if not target.clean:
        return UpdateApplyResult("rejected", preview.document, {}, "dirty-target")
    if preview.target_id != target.target_id:
        return UpdateApplyResult("rejected", preview.document, {}, "target-mismatch")
    if _canonical_hash(preview.document) != preview.document_binding_sha256:
        return UpdateApplyResult("rejected", preview.document, {}, "preview-tampered")
    current = target.read_payload()
    current_hashes = current.hashes()
    bindings = preview.document.get("bindings")
    prestate = bindings.get("prestate") if isinstance(bindings, Mapping) else None
    if current_hashes != prestate:
        return UpdateApplyResult(
            status="rejected",
            document=copy.deepcopy(preview.document),
            readback=current_hashes,
            reason="prestate-drift",
        )
    if _payload_binding(preview.candidate) != preview.candidate_binding_sha256:
        return UpdateApplyResult(
            status="rejected",
            document=copy.deepcopy(preview.document),
            readback=current_hashes,
            reason="candidate-drift",
        )
    candidate_contract = preview.document.get("candidate")
    candidate_hashes = preview.candidate.hashes()
    if not isinstance(candidate_contract, Mapping) or any(
        candidate_contract.get(field) != candidate_hashes[field]
        for field in ("pins_sha256", "manifest_sha256")
    ):
        return UpdateApplyResult(
            status="rejected",
            document=copy.deepcopy(preview.document),
            readback=current_hashes,
            reason="candidate-binding-mismatch",
        )

    snapshot = _take_tree_snapshot(target.root)
    try:
        _write_payload(target.root, preview.candidate)
        observed_payload = target.read_payload()
        observed_hashes = observed_payload.hashes()
        if observed_payload != preview.candidate or observed_hashes != candidate_hashes:
            raise UpdateContractError("candidate readback did not match exact applied bytes")
    except Exception as error:
        failed_hashes = _best_effort_hashes(target, current_hashes)
        try:
            _restore_tree_snapshot(target.root, snapshot)
            restored = target.read_payload()
            restored_hashes = restored.hashes()
        except Exception as rollback_error:  # pragma: no cover - platform failure guard
            return _rollback_failed_result(
                preview,
                current_hashes,
                failed_hashes,
                str(error),
                str(rollback_error),
                now,
            )
        if restored != current or restored_hashes != current_hashes:
            return _rollback_failed_result(
                preview,
                current_hashes,
                failed_hashes,
                str(error),
                "rollback readback did not restore exact content",
                now,
            )
        rollback_receipt = _rollback_receipt(
            preview,
            pre_update=current_hashes,
            failed_update=failed_hashes,
            post_rollback=restored_hashes,
            terminal_at=now,
        )
        document = copy.deepcopy(preview.document)
        document["apply"] = {
            "phase": "rolled_back",
            "preview_receipt": preview.document["apply"]["preview_receipt"],  # type: ignore[index]
            "apply_receipt": _receipt_ref("update-apply-failed", str(error)),
            "failure_receipt": _receipt_ref("update-failure", str(error)),
            "rollback_receipt": _receipt_ref(
                f"rollback-{str(rollback_receipt['rollback_id']).removeprefix('rollback_')}",
                rollback_receipt,
            ),
        }
        return UpdateApplyResult(
            status="rolled_back",
            document=document,
            readback=restored_hashes,
            reason=str(error),
            rollback_receipt=rollback_receipt,
        )

    apply_receipt = {
        "update_id": preview.document["update_id"],
        "prestate": current_hashes,
        "candidate": candidate_hashes,
        "readback": observed_hashes,
        "applied_at": _timestamp(now),
    }
    document = copy.deepcopy(preview.document)
    document["apply"] = {
        "phase": "applied",
        "preview_receipt": preview.document["apply"]["preview_receipt"],  # type: ignore[index]
        "apply_receipt": _receipt_ref("update-apply", apply_receipt),
    }
    return UpdateApplyResult(
        status="applied",
        document=document,
        readback=observed_hashes,
    )


def _validate_pin_set(upstreams: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    if not upstreams:
        raise UpdateContractError("updates require at least one immutable upstream pin")
    normalized: list[dict[str, object]] = []
    seen: set[object] = set()
    required = {
        "id",
        "source",
        "version",
        "reference_type",
        "tag_object",
        "peeled_commit",
        "anchored_in_trust_root",
        "trust_root_entry_sha256",
        "immutability",
    }
    for pin in upstreams:
        if set(pin) != required:
            raise UpdateContractError("immutable pin contains missing or unknown fields")
        if pin["id"] in seen:
            raise UpdateContractError("upstream pin IDs must be unique")
        seen.add(pin["id"])
        if pin["reference_type"] != "annotated_tag":
            raise UpdateContractError("candidate reference must be an annotated tag object")
        if pin["anchored_in_trust_root"] is not True:
            raise UpdateContractError("candidate pin must already be anchored in the trust root")
        if pin["immutability"] != "immutable_tag_object_and_peeled_commit":
            raise UpdateContractError("candidate pin must bind immutable tag object and peeled commit")
        if not isinstance(pin["tag_object"], str) or not _GIT_SHA.fullmatch(pin["tag_object"]):
            raise UpdateContractError("annotated tag object must be an exact Git SHA")
        if not isinstance(pin["peeled_commit"], str) or not _GIT_SHA.fullmatch(pin["peeled_commit"]):
            raise UpdateContractError("peeled commit must be an exact Git SHA")
        if not isinstance(pin["version"], str) or not _VERSION.fullmatch(pin["version"]):
            raise UpdateContractError("upstream version must be an immutable semantic tag")
        if not isinstance(pin["source"], str) or not pin["source"].startswith("https://github.com/"):
            raise UpdateContractError("upstream source must be an HTTPS GitHub repository")
        trust_digest = pin["trust_root_entry_sha256"]
        if not isinstance(trust_digest, str):
            raise UpdateContractError("trust root entry digest is required")
        _require_digest(trust_digest, "trust_root_entry_sha256")
        normalized.append(dict(pin))
    return normalized


def _write_payload(root: Path, payload: UpdatePayload) -> None:
    content_root = root / "content"
    if content_root.exists():
        shutil.rmtree(content_root)
    content_root.mkdir(parents=True)
    for relative, content in sorted(payload.content.items()):
        destination = content_root / Path(*PurePosixPath(relative).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    (root / "pins.json").write_bytes(payload.pins)
    (root / "manifest.json").write_bytes(payload.manifest)


def _rollback_receipt(
    preview: UpdatePreview,
    *,
    pre_update: Mapping[str, str],
    failed_update: Mapping[str, str],
    post_rollback: Mapping[str, str],
    terminal_at: datetime,
) -> dict[str, object]:
    update_id = str(preview.document["update_id"])
    update_ref = _receipt_ref(f"update-manifest-{update_id.removeprefix('update_')}", preview.document)
    failed_apply = _receipt_ref("update-apply-failed", failed_update)
    components: dict[str, object] = {}
    for component in ("content", "pins", "manifest"):
        field = f"{component}_sha256"
        expected = pre_update[field]
        observed = post_rollback[field]
        components[component] = {
            "expected_preupdate_sha256": expected,
            "observed_postrollback_sha256": observed,
            "status": "matched" if expected == observed else "mismatched",
        }
    body: dict[str, object] = {
        "schema_version": "johan-sdd/rollback-receipt/v1",
        "update": {
            "update_id": update_id,
            "update_manifest": update_ref,
            "failed_apply_receipt": failed_apply,
            "failed_phase": "apply",
            "failed_at": _timestamp(terminal_at),
        },
        "snapshots": {
            "pre_update": dict(pre_update),
            "failed_update": dict(failed_update),
            "post_rollback": dict(post_rollback),
        },
        "readback": {
            "completed_at": _timestamp(terminal_at),
            "status": "passed",
            "components": components,
            "evidence": {
                "ref": f"evidence/rollback-{update_id.removeprefix('update_')}.json",
                "sha256": _canonical_hash(components),
            },
        },
        "terminal_status": "rolled_back",
        "terminal_at": _timestamp(terminal_at),
    }
    return {"rollback_id": f"rollback_{_canonical_hash(body)}", **body}


def _rollback_failed_result(
    preview: UpdatePreview,
    pre_update: Mapping[str, str],
    failed_update: Mapping[str, str],
    apply_error: str,
    rollback_error: str,
    terminal_at: datetime,
) -> UpdateApplyResult:
    zero = "0" * 64
    post = {"content_sha256": zero, "pins_sha256": zero, "manifest_sha256": zero}
    successful_shape = _rollback_receipt(
        preview,
        pre_update=pre_update,
        failed_update=failed_update,
        post_rollback=post,
        terminal_at=terminal_at,
    )
    successful_shape["terminal_status"] = "rollback_failed"
    successful_shape["readback"]["status"] = "failed"  # type: ignore[index]
    successful_shape["error"] = {
        "code": "rollback-failed",
        "message": f"apply failed ({apply_error}); rollback failed ({rollback_error})",
    }
    successful_shape.pop("rollback_id", None)
    successful_shape = {
        "rollback_id": f"rollback_{_canonical_hash(successful_shape)}", **successful_shape
    }
    document = copy.deepcopy(preview.document)
    document["apply"] = {
        "phase": "failed",
        "preview_receipt": preview.document["apply"]["preview_receipt"],  # type: ignore[index]
        "apply_receipt": _receipt_ref("update-apply-failed", failed_update),
        "failure_receipt": _receipt_ref("rollback-failure", successful_shape["error"]),
    }
    return UpdateApplyResult(
        status="rollback_failed",
        document=document,
        readback=post,
        reason=str(successful_shape["error"]),
        rollback_receipt=successful_shape,
    )


def _take_tree_snapshot(root: Path) -> _TreeSnapshot:
    if root.is_symlink() or not root.is_dir():
        raise UpdateContractError("known update targets must be real directories")
    directories: list[str] = []
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise UpdateContractError("update targets cannot contain symbolic links")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            directories.append(relative)
        elif path.is_file():
            files[relative] = path.read_bytes()
        else:
            raise UpdateContractError(f"unsupported update target entry: {relative}")
    return _TreeSnapshot(tuple(directories), files)


def _restore_tree_snapshot(root: Path, snapshot: _TreeSnapshot) -> None:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    for relative in sorted(snapshot.directories, key=lambda value: (value.count("/"), value)):
        (root / Path(*PurePosixPath(relative).parts)).mkdir()
    for relative, payload in snapshot.files.items():
        destination = root / Path(*PurePosixPath(relative).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


def _best_effort_hashes(
    target: DisposableUpdateTarget, fallback: Mapping[str, str]
) -> dict[str, str]:
    try:
        return target.read_payload().hashes()
    except Exception:
        root = target.root
        content: dict[str, bytes] = {}
        content_root = root / "content"
        if content_root.exists():
            for path in content_root.rglob("*"):
                if path.is_file():
                    content[path.relative_to(content_root).as_posix()] = path.read_bytes()
        return {
            "content_sha256": _content_hash(content),
            "pins_sha256": _sha256((root / "pins.json").read_bytes())
            if (root / "pins.json").is_file()
            else fallback["pins_sha256"],
            "manifest_sha256": _sha256((root / "manifest.json").read_bytes())
            if (root / "manifest.json").is_file()
            else fallback["manifest_sha256"],
        }


def _validate_receipt_ref(value: Mapping[str, str], name: str) -> None:
    if set(value) != {"ref", "sha256"}:
        raise UpdateContractError(f"{name} requires an exact receipt reference")
    reference = value["ref"]
    if not re.fullmatch(r"receipts/[A-Za-z0-9._/-]+\.json", reference):
        raise UpdateContractError(f"{name} receipt path is invalid")
    _require_digest(value["sha256"], f"{name} receipt digest")


def _receipt_ref(name: str, value: object) -> dict[str, str]:
    return {"ref": f"receipts/{name}.json", "sha256": _canonical_hash(value)}


def _normalize_content_path(value: object) -> str:
    normalized = _normalize_relative_path(value)
    if any(part.casefold() == ".agents" for part in normalized.split("/")):
        raise UpdateContractError("candidate content cannot address an agent home")
    return normalized


def _normalize_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise UpdateContractError("paths must be non-empty strings")
    if "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise UpdateContractError("paths must be relative POSIX paths")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise UpdateContractError("paths must be normalized without dot segments")
    return PurePosixPath(value).as_posix()


def _require_beneath(path: Path, parent: Path) -> None:
    try:
        path.relative_to(parent)
    except ValueError as error:
        raise UpdateContractError("update target escapes its sandbox") from error
    if path == parent:
        raise UpdateContractError("update target must be a child of its sandbox")


def _require_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise UpdateContractError(f"{name} must be a lowercase SHA-256 digest")


def _content_hash(content: Mapping[str, bytes]) -> str:
    return _canonical_hash(
        [{"path": path, "sha256": _sha256(payload)} for path, payload in sorted(content.items())]
    )


def _payload_binding(payload: UpdatePayload) -> str:
    return _canonical_hash(payload.hashes())


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256(encoded)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise UpdateContractError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


__all__ = [
    "CanaryReceipts",
    "DisposableUpdateTarget",
    "UpdateApplyResult",
    "UpdateContractError",
    "UpdatePayload",
    "UpdatePreview",
    "UpdateSkip",
    "apply_update",
    "preview_update",
]
