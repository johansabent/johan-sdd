"""Host-neutral desired state plus explicitly authorized sandbox application.

The portable seam in this module is :func:`emit_desired_state`: it names an
abstract target and content digests, never host paths or content bytes.  Target
resolution and mutation happen only through a separately constructed host
adapter seam.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Protocol


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class HostContractError(ValueError):
    """A desired state, content bundle, policy, or target violates the contract."""


class PreviewRejected(HostContractError):
    """A preview is no longer authorized for application."""


class HostTransactionError(RuntimeError):
    """Application failed after mutation began and rollback was attempted."""

    def __init__(self, message: str, *, rollback_status: str) -> None:
        super().__init__(message)
        self.rollback_status = rollback_status


class ContentResolver(Protocol):
    """Resolve one immutable content reference without knowing a host target."""

    def resolve_content(self, content_ref: str) -> bytes: ...


@dataclass(frozen=True)
class ResolvedTarget:
    """A target proven to live beneath one disposable sandbox boundary."""

    target_id: str
    root: Path
    sandbox_root: Path


class TargetResolver(Protocol):
    """Host-owned seam that resolves an abstract target identifier."""

    def resolve_target(self, target_id: str) -> ResolvedTarget: ...


@dataclass(frozen=True)
class HostAuthorization:
    actor_id: str
    policy_id: str
    policy_revision: int
    policy_sha256: str
    trust_root_sha256: str
    allowlist_sha256: str
    allowed_paths: frozenset[str]

    def __post_init__(self) -> None:
        if not self.actor_id or not self.policy_id or self.policy_revision < 1:
            raise HostContractError("host authorization must identify a revisioned actor policy")
        for name in ("policy_sha256", "trust_root_sha256", "allowlist_sha256"):
            _require_digest(getattr(self, name), name)
        normalized = frozenset(_normalize_product_path(path) for path in self.allowed_paths)
        if normalized != self.allowed_paths:
            raise HostContractError("allowed paths must already be normalized")


class MappingContentResolver:
    """Small content-addressed resolver suitable for bundled or test content."""

    def __init__(self, content: Mapping[str, bytes]) -> None:
        verified: dict[str, bytes] = {}
        for content_ref, value in content.items():
            digest = _content_digest_from_ref(content_ref)
            payload = bytes(value)
            if _sha256(payload) != digest:
                raise HostContractError(f"content does not match reference {content_ref}")
            verified[content_ref] = payload
        self._content = verified

    def resolve_content(self, content_ref: str) -> bytes:
        try:
            content = self._content[content_ref]
        except KeyError as error:
            raise HostContractError(f"content reference is unavailable: {content_ref}") from error
        if _sha256(content) != _content_digest_from_ref(content_ref):
            raise HostContractError(f"content digest changed for {content_ref}")
        return content


class SandboxTargetResolver:
    """Resolve allowlisted target IDs strictly beneath one sandbox root.

    Target values are portable relative paths.  In particular, callers cannot
    smuggle an absolute path (including an agent home) through desired state.
    """

    def __init__(self, sandbox_root: Path, targets: Mapping[str, str]) -> None:
        self._sandbox_root = sandbox_root.resolve()
        if ".agents" in {part.casefold() for part in self._sandbox_root.parts}:
            raise HostContractError("an agent home cannot be used as a product sandbox")
        resolved: dict[str, Path] = {}
        for target_id, relative in targets.items():
            _require_target_id(target_id)
            normalized = _normalize_product_path(relative)
            root = (self._sandbox_root / Path(*PurePosixPath(normalized).parts)).resolve()
            _require_beneath(root, self._sandbox_root)
            resolved[target_id] = root
        self._targets = resolved

    def resolve_target(self, target_id: str) -> ResolvedTarget:
        _require_target_id(target_id)
        try:
            root = self._targets[target_id]
        except KeyError as error:
            raise HostContractError(f"target_id is not authorized: {target_id}") from error
        _require_beneath(root, self._sandbox_root)
        return ResolvedTarget(target_id=target_id, root=root, sandbox_root=self._sandbox_root)


@dataclass(frozen=True)
class HostPreview:
    """A preview document with the exact verified content needed to apply it."""

    document: dict[str, object]
    content: Mapping[str, bytes]
    authorization_sha256: str


@dataclass(frozen=True)
class _Snapshot:
    directories: tuple[str, ...]
    files: Mapping[str, bytes]


def emit_desired_state(
    *,
    target_id: str,
    generated_from: str,
    trust_root_sha256: str,
    allowlist_sha256: str,
    operations: Sequence[Mapping[str, str]],
) -> dict[str, object]:
    """Emit portable desired state without resolving a target or loading content."""

    _require_target_id(target_id)
    for name, digest in (
        ("generated_from", generated_from),
        ("trust_root_sha256", trust_root_sha256),
        ("allowlist_sha256", allowlist_sha256),
    ):
        _require_digest(digest, name)
    normalized_operations = _validate_operations(operations)
    return {
        "schema_version": "johan-sdd/desired-state/v1",
        "target_id": target_id,
        "generated_from": generated_from,
        "trust_root_sha256": trust_root_sha256,
        "allowlist_sha256": allowlist_sha256,
        "operations": normalized_operations,
    }


def build_preview(
    desired_state: Mapping[str, object],
    *,
    content_resolver: ContentResolver,
    target_resolver: TargetResolver,
    authorization: HostAuthorization,
    now: datetime,
    ttl: timedelta = timedelta(minutes=15),
) -> HostPreview:
    """Measure a target and bind desired state, policy, pre-state, and content."""

    desired = _validated_desired_state(desired_state)
    timestamp = _utc(now)
    if ttl <= timedelta(0):
        raise HostContractError("preview TTL must be positive")
    if desired["trust_root_sha256"] != authorization.trust_root_sha256:
        raise HostContractError("desired state trust root is not authorized")
    if desired["allowlist_sha256"] != authorization.allowlist_sha256:
        raise HostContractError("desired state allowlist is not authorized")
    operations = desired["operations"]
    assert isinstance(operations, list)
    _authorize_operations(operations, authorization)
    target = _resolve_sandbox_target(target_resolver, str(desired["target_id"]))
    snapshot = _take_snapshot(target.root)
    content: dict[str, bytes] = {}
    for operation in operations:
        content_ref = operation.get("content_ref")
        if content_ref is None:
            continue
        payload = bytes(content_resolver.resolve_content(content_ref))
        if _sha256(payload) != _content_digest_from_ref(content_ref):
            raise HostContractError(f"resolver returned unverified content for {content_ref}")
        content[content_ref] = payload

    body: dict[str, object] = {
        "schema_version": "johan-sdd/preview/v1",
        "desired_state_sha256": _canonical_hash(desired),
        "target_id": desired["target_id"],
        "measured_prestate_sha256": _snapshot_hash(snapshot),
        "trust_root_sha256": desired["trust_root_sha256"],
        "allowlist_sha256": desired["allowlist_sha256"],
        "operations": operations,
        "created_at": _timestamp(timestamp),
        "expires_at": _timestamp(timestamp + ttl),
    }
    document = {"preview_id": f"preview_{_canonical_hash(body)}", **body}
    return HostPreview(
        document=document,
        content=content,
        authorization_sha256=_authorization_hash(authorization),
    )


def apply_preview(
    preview: HostPreview,
    *,
    target_resolver: TargetResolver,
    authorization: HostAuthorization,
    now: datetime,
) -> dict[str, object]:
    """Apply an unexpired, unchanged preview transactionally to its sandbox target."""

    document = preview.document
    preview_id = document.get("preview_id")
    if not isinstance(preview_id, str):
        raise PreviewRejected("preview identity is missing")
    identity_body = {key: value for key, value in document.items() if key != "preview_id"}
    if preview_id != f"preview_{_canonical_hash(identity_body)}":
        raise PreviewRejected("preview identity does not match its bound document")
    operations = _validate_operations(_require_sequence(document, "operations"))
    _authorize_operations(operations, authorization)
    if preview.authorization_sha256 != _authorization_hash(authorization):
        raise PreviewRejected("host authorization changed after preview")
    applied_at = _utc(now)
    expires_at = _parse_timestamp(document.get("expires_at"))
    if applied_at > expires_at:
        raise PreviewRejected("preview expired before application")
    target_id = str(document.get("target_id", ""))
    target = _resolve_sandbox_target(target_resolver, target_id)
    snapshot = _take_snapshot(target.root)
    if _snapshot_hash(snapshot) != document.get("measured_prestate_sha256"):
        raise PreviewRejected("target pre-state changed after preview")
    for content_ref, payload in preview.content.items():
        if _sha256(payload) != _content_digest_from_ref(content_ref):
            raise PreviewRejected("preview content changed after verification")
    for operation in operations:
        content_ref = operation.get("content_ref")
        if content_ref is not None and content_ref not in preview.content:
            raise PreviewRejected(f"preview content is missing: {content_ref}")

    target.root.mkdir(parents=True, exist_ok=True)
    readback: list[dict[str, str]] = []
    try:
        for operation in operations:
            readback.append(_apply_operation(target, operation, preview.content))
        post_snapshot = _take_snapshot(target.root)
    except Exception as error:
        try:
            _restore_snapshot(target.root, snapshot)
            rollback_status = "completed"
        except Exception as rollback_error:  # pragma: no cover - platform failure guard
            raise HostTransactionError(
                f"host apply failed ({error}); rollback failed ({rollback_error})",
                rollback_status="failed",
            ) from rollback_error
        raise HostTransactionError(
            f"host apply failed and the full snapshot was restored: {error}",
            rollback_status=rollback_status,
        ) from error

    preview_sha256 = _canonical_hash(document)
    body: dict[str, object] = {
        "schema_version": "johan-sdd/apply-receipt/v1",
        "preview_sha256": preview_sha256,
        "desired_state_sha256": document["desired_state_sha256"],
        "target_id": target_id,
        "measured_prestate_sha256": document["measured_prestate_sha256"],
        "operations": operations,
        "preview_expires_at": document["expires_at"],
        "applied_at": _timestamp(applied_at),
        "actor_policy": {
            "actor_id": authorization.actor_id,
            "policy_id": authorization.policy_id,
            "policy_revision": authorization.policy_revision,
            "policy_sha256": authorization.policy_sha256,
        },
        "readback": {
            "poststate_sha256": _snapshot_hash(post_snapshot),
            "operations": readback,
        },
        "rollback": {"status": "not-required"},
    }
    return {"receipt_id": f"apply_{_canonical_hash(body)}", **body}


def _apply_operation(
    target: ResolvedTarget,
    operation: Mapping[str, str],
    content: Mapping[str, bytes],
) -> dict[str, str]:
    relative = _normalize_product_path(operation["path"])
    destination = target.root / Path(*PurePosixPath(relative).parts)
    _require_beneath(destination.resolve(strict=False), target.root.resolve())
    action = operation["action"]
    if action == "create" and destination.exists():
        raise FileExistsError(f"create target already exists: {relative}")
    if action in {"replace", "remove"} and not destination.is_file():
        raise FileNotFoundError(f"{action} target is not a file: {relative}")
    if action == "remove":
        destination.unlink()
        return {"path": relative, "result": "removed"}
    content_ref = operation["content_ref"]
    payload = content[content_ref]
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.johan-sdd-{os.getpid()}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(destination)
    return {
        "path": relative,
        "result": "created" if action == "create" else "replaced",
        "content_sha256": _sha256(destination.read_bytes()),
    }


def _validated_desired_state(document: Mapping[str, object]) -> dict[str, object]:
    if document.get("schema_version") != "johan-sdd/desired-state/v1":
        raise HostContractError("unsupported desired-state schema version")
    expected = {
        "schema_version",
        "target_id",
        "generated_from",
        "trust_root_sha256",
        "allowlist_sha256",
        "operations",
    }
    if set(document) != expected:
        raise HostContractError("desired state contains missing or unknown fields")
    target_id = str(document["target_id"])
    _require_target_id(target_id)
    for name in ("generated_from", "trust_root_sha256", "allowlist_sha256"):
        value = document[name]
        if not isinstance(value, str):
            raise HostContractError(f"{name} must be a SHA-256 digest")
        _require_digest(value, name)
    operations = _validate_operations(_require_sequence(document, "operations"))
    return {**document, "target_id": target_id, "operations": operations}


def _validate_operations(operations: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    if not operations:
        raise HostContractError("desired state must contain at least one operation")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for operation in operations:
        if not isinstance(operation, Mapping):
            raise HostContractError("each operation must be an object")
        action = operation.get("action")
        if action not in {"create", "replace", "remove"}:
            raise HostContractError("operation action must be create, replace, or remove")
        if "path" not in operation:
            raise HostContractError("operation path is required")
        path = _normalize_product_path(operation["path"])
        if path in seen:
            raise HostContractError(f"duplicate operation path: {path}")
        seen.add(path)
        if action == "remove":
            if set(operation) != {"path", "action"}:
                raise HostContractError("remove operations cannot carry content")
            normalized.append({"path": path, "action": action})
            continue
        if set(operation) != {"path", "action", "content_ref"}:
            raise HostContractError("create and replace operations require only a content_ref")
        content_ref = operation.get("content_ref")
        if not isinstance(content_ref, str):
            raise HostContractError("content_ref must be a SHA-256 reference")
        _content_digest_from_ref(content_ref)
        normalized.append({"path": path, "action": action, "content_ref": content_ref})
    return normalized


def _authorize_operations(
    operations: Sequence[Mapping[str, str]], authorization: HostAuthorization
) -> None:
    denied = [operation["path"] for operation in operations if operation["path"] not in authorization.allowed_paths]
    if denied:
        raise HostContractError(f"operations are outside the host allowlist: {', '.join(denied)}")


def _resolve_sandbox_target(resolver: TargetResolver, target_id: str) -> ResolvedTarget:
    resolved = resolver.resolve_target(target_id)
    if resolved.target_id != target_id:
        raise HostContractError("target resolver returned a different target_id")
    root = resolved.root.resolve()
    sandbox = resolved.sandbox_root.resolve()
    if ".agents" in {part.casefold() for part in root.parts}:
        raise HostContractError("product transactions cannot target an agent home")
    _require_beneath(root, sandbox)
    return ResolvedTarget(target_id=target_id, root=root, sandbox_root=sandbox)


def _take_snapshot(root: Path) -> _Snapshot:
    if not root.exists():
        return _Snapshot((), {})
    if root.is_symlink() or not root.is_dir():
        raise HostContractError("sandbox targets must be real directories")
    directories: list[str] = []
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise HostContractError("sandbox targets cannot contain symbolic links")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            directories.append(relative)
        elif path.is_file():
            files[relative] = path.read_bytes()
        else:
            raise HostContractError(f"unsupported sandbox entry: {relative}")
    return _Snapshot(tuple(directories), files)


def _restore_snapshot(root: Path, snapshot: _Snapshot) -> None:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    for relative in sorted(snapshot.directories, key=lambda value: (value.count("/"), value)):
        (root / Path(*PurePosixPath(relative).parts)).mkdir()
    for relative, payload in snapshot.files.items():
        destination = root / Path(*PurePosixPath(relative).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


def _snapshot_hash(snapshot: _Snapshot) -> str:
    document = {
        "directories": list(snapshot.directories),
        "files": [
            {"path": path, "sha256": _sha256(payload)}
            for path, payload in sorted(snapshot.files.items())
        ],
    }
    return _canonical_hash(document)


def _authorization_hash(authorization: HostAuthorization) -> str:
    return _canonical_hash(
        {
            "actor_id": authorization.actor_id,
            "policy_id": authorization.policy_id,
            "policy_revision": authorization.policy_revision,
            "policy_sha256": authorization.policy_sha256,
            "trust_root_sha256": authorization.trust_root_sha256,
            "allowlist_sha256": authorization.allowlist_sha256,
            "allowed_paths": sorted(authorization.allowed_paths),
        }
    )


def _normalize_product_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise HostContractError("paths must be non-empty strings")
    if "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise HostContractError("paths must be relative POSIX paths")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise HostContractError("paths must be normalized without dot segments")
    if any(part.casefold() == ".agents" for part in parts):
        raise HostContractError("product paths cannot address .agents")
    normalized = PurePosixPath(value).as_posix()
    if normalized != value:
        raise HostContractError("paths must already be normalized")
    return normalized


def _require_sequence(document: Mapping[str, object], field: str) -> Sequence[Mapping[str, str]]:
    value = document.get(field)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise HostContractError(f"{field} must be an array")
    return value  # type: ignore[return-value]


def _require_target_id(value: str) -> None:
    if not _TARGET_ID.fullmatch(value):
        raise HostContractError("target_id is not valid")


def _require_digest(value: str, name: str) -> None:
    if not _SHA256.fullmatch(value):
        raise HostContractError(f"{name} must be a lowercase SHA-256 digest")


def _content_digest_from_ref(content_ref: str) -> str:
    if not isinstance(content_ref, str) or not content_ref.startswith("sha256:"):
        raise HostContractError("content_ref must use sha256:<digest>")
    digest = content_ref.removeprefix("sha256:")
    _require_digest(digest, "content_ref")
    return digest


def _require_beneath(path: Path, parent: Path) -> None:
    try:
        path.relative_to(parent)
    except ValueError as error:
        raise HostContractError("resolved target escapes its sandbox") from error
    if path == parent:
        raise HostContractError("a target must be a child of its sandbox root")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256(payload)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise HostContractError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise PreviewRejected("preview expiry is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PreviewRejected("preview expiry is invalid") from error
    return _utc(parsed)


__all__ = [
    "ContentResolver",
    "HostAuthorization",
    "HostContractError",
    "HostPreview",
    "HostTransactionError",
    "MappingContentResolver",
    "PreviewRejected",
    "ResolvedTarget",
    "SandboxTargetResolver",
    "TargetResolver",
    "apply_preview",
    "build_preview",
    "emit_desired_state",
]
