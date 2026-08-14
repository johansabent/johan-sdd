"""Process-safe session claims and lossless dirty-pause snapshots."""

from __future__ import annotations

import copy
import ctypes
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, Mapping, Sequence

from johan_sdd.contracts import validate_semantics


UTC = timezone.utc
REGISTRY_NAME = "agent-work-session.v1.json"
_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_OID = re.compile(r"^[0-9a-f]{40,64}$")
_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_ACTIVE_STATES = frozenset({"starting", "working", "paused", "blocked", "closing"})
_STATES = _ACTIVE_STATES | {"closed", "abandoned"}
_RESOURCE_TYPES = frozenset({"repo-files", "git-metadata", "tracker", "capture", "global-agents"})


class SessionError(RuntimeError):
    """Base class for session operations that fail closed."""


class RegistryInvalid(SessionError):
    """The durable registry cannot safely be used for mutation."""


class RevisionConflict(SessionError):
    """The registry revision changed after the caller measured it."""


class ClaimNotFound(SessionError):
    """No claim has the requested session ID."""


class LeaseTokenMismatch(SessionError):
    """A lifecycle operation did not prove possession of the lease token."""


class DirtyPauseRejected(SessionError):
    """The checkout or lane is ineligible for dirty pause."""


class SecretMaterialError(DirtyPauseRejected):
    """Secret-shaped material made a recovery snapshot unsafe."""

    def __init__(self, findings: Sequence[str]) -> None:
        self.findings = tuple(findings)
        super().__init__("secret-shaped material detected: " + ", ".join(self.findings))


class ProcessStatus(str, Enum):
    LIVE = "live"
    DEAD = "dead"
    HOST_UNREACHABLE = "host-unreachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RegistryError:
    code: str
    message: str


@dataclass(frozen=True)
class RegistryInspection:
    document: dict[str, object] | None
    errors: tuple[RegistryError, ...]
    raw_text: str | None


@dataclass(frozen=True)
class Conflict:
    kind: str
    owner_session_id: str
    resource_type: str | None = None
    resource_id: str | None = None


@dataclass(frozen=True)
class ConflictEvaluation:
    revision: int
    conflicts: tuple[Conflict, ...]


class ClaimConflict(SessionError):
    def __init__(self, conflicts: Sequence[Conflict]) -> None:
        self.conflicts = tuple(conflicts)
        summary = ", ".join(
            f"{item.kind}:{item.owner_session_id}"
            + (f":{item.resource_type}:{item.resource_id}" if item.resource_type else "")
            for item in self.conflicts
        )
        super().__init__(f"claim conflicts with active ownership ({summary})")


def _run_git(repo: Path, *args: str, env: Mapping[str, str] | None = None) -> bytes:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    try:
        return subprocess.run(
            ["git", "-C", os.fspath(repo), *args],
            check=True,
            capture_output=True,
            env=process_env,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise SessionError(f"git {' '.join(args)} failed: {detail or exc}") from exc


def _git_text(repo: Path, *args: str, env: Mapping[str, str] | None = None) -> str:
    return _run_git(repo, *args, env=env).decode("utf-8", errors="strict").strip()


def _git_path(repo: Path, *args: str) -> Path:
    return Path(_git_text(repo, *args)).resolve(strict=False)


def _format_time(value: datetime) -> str:
    value = value.astimezone(UTC)
    if value.microsecond:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not _DATE_TIME.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None


def _token_hash(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise LeaseTokenMismatch("lease token must be a non-empty string")
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _duplicates_fail(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _exact_keys(
    value: object,
    required: set[str],
    optional: set[str] = frozenset(),
) -> bool:
    return isinstance(value, dict) and required <= value.keys() and value.keys() <= required | optional


def _valid_time(value: object) -> bool:
    return _parse_time(value) is not None


def _valid_recovery(value: object) -> bool:
    required = {
        "schema_version",
        "synthetic_commit",
        "protected_ref",
        "original_head",
        "original_status_sha256",
        "untracked_paths",
        "secret_scan",
    }
    if not _exact_keys(value, required):
        return False
    assert isinstance(value, dict)
    scan = value["secret_scan"]
    return bool(
        value["schema_version"] == "johan-sdd/pause-recovery/v1"
        and isinstance(value["synthetic_commit"], str)
        and _OID.fullmatch(value["synthetic_commit"])
        and isinstance(value["protected_ref"], str)
        and _SESSION_ID.fullmatch(value["protected_ref"].removeprefix("refs/agent-sessions/"))
        and value["protected_ref"].startswith("refs/agent-sessions/")
        and isinstance(value["original_head"], str)
        and _OID.fullmatch(value["original_head"])
        and isinstance(value["original_status_sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", value["original_status_sha256"])
        and isinstance(value["untracked_paths"], list)
        and all(isinstance(path, str) and path for path in value["untracked_paths"])
        and len(value["untracked_paths"]) == len(set(value["untracked_paths"]))
        and _exact_keys(scan, {"status", "scanner", "completed_at"})
        and isinstance(scan, dict)
        and scan["status"] == "passed"
        and isinstance(scan["scanner"], str)
        and bool(scan["scanner"])
        and _valid_time(scan["completed_at"])
    )


def _valid_claim(value: object) -> bool:
    required = {
        "session_id", "mode", "owner", "process", "lease", "worktree", "state", "dirty",
        "authority_decision_ref", "resources",
    }
    if not _exact_keys(value, required, {"recovery"}):
        return False
    assert isinstance(value, dict)
    owner, process, lease, worktree, resources = (
        value["owner"], value["process"], value["lease"], value["worktree"], value["resources"]
    )
    if not (
        isinstance(value["session_id"], str) and _SESSION_ID.fullmatch(value["session_id"])
        and isinstance(value["mode"], str) and value["mode"] in {"feature", "micro"}
        and _exact_keys(owner, {"agent", "model"})
        and isinstance(owner, dict)
        and all(isinstance(owner[key], str) and owner[key] for key in ("agent", "model"))
        and _exact_keys(process, {"host", "pid", "started_at"})
        and isinstance(process, dict)
        and isinstance(process["host"], str) and bool(process["host"])
        and isinstance(process["pid"], int) and not isinstance(process["pid"], bool) and process["pid"] >= 1
        and _valid_time(process["started_at"])
        and _exact_keys(lease, {"token_hash", "generation", "acquired_at", "heartbeat_at", "expires_at", "ttl_seconds"})
        and isinstance(lease, dict)
        and isinstance(lease["token_hash"], str) and _HASH.fullmatch(lease["token_hash"])
        and isinstance(lease["generation"], int) and not isinstance(lease["generation"], bool) and lease["generation"] >= 1
        and all(_valid_time(lease[key]) for key in ("acquired_at", "heartbeat_at", "expires_at"))
        and isinstance(lease["ttl_seconds"], int) and not isinstance(lease["ttl_seconds"], bool)
        and 60 <= lease["ttl_seconds"] <= 86400
        and _exact_keys(worktree, {"repo_id", "worktree_id", "path", "kind", "branch"})
        and isinstance(worktree, dict)
        and all(isinstance(worktree[key], str) and worktree[key] for key in ("repo_id", "worktree_id", "path", "branch"))
        and isinstance(worktree["kind"], str) and worktree["kind"] in {"primary", "linked"}
        and isinstance(value["state"], str) and value["state"] in _STATES
        and type(value["dirty"]) is bool
        and isinstance(value["authority_decision_ref"], str) and bool(value["authority_decision_ref"])
        and isinstance(resources, list) and bool(resources)
    ):
        return False
    for resource in resources:
        if not (
            _exact_keys(resource, {"resource_type", "resource_id", "access"})
            and isinstance(resource, dict)
            and isinstance(resource["resource_type"], str) and resource["resource_type"] in _RESOURCE_TYPES
            and isinstance(resource["resource_id"], str) and bool(resource["resource_id"])
            and isinstance(resource["access"], str) and resource["access"] in {"exclusive", "shared-read"}
        ):
            return False
    if len({json.dumps(resource, sort_keys=True) for resource in resources}) != len(resources):
        return False
    recovery_present = "recovery" in value
    if recovery_present and not _valid_recovery(value["recovery"]):
        return False
    if value["mode"] == "feature" and worktree["kind"] != "linked":
        return False
    if value["mode"] == "micro" and (
        worktree["kind"] != "primary" or value["dirty"] is not False or value["state"] == "paused"
    ):
        return False
    if value["dirty"] is True and (
        not recovery_present or value["mode"] != "feature" or value["state"] != "paused"
    ):
        return False
    if recovery_present and (value["dirty"] is not True or value["state"] != "paused"):
        return False
    return True


def _shape_errors(document: object) -> tuple[RegistryError, ...]:
    if not _exact_keys(document, {"schema_version", "revision", "claims"}):
        return (RegistryError("registry.shape", "registry must contain only schema_version, revision, and claims"),)
    assert isinstance(document, dict)
    if document["schema_version"] != "agent-work-session/v1":
        return (RegistryError("registry.shape", "unsupported session registry schema_version"),)
    revision = document["revision"]
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        return (RegistryError("registry.shape", "revision must be a non-negative integer"),)
    claims = document["claims"]
    if not isinstance(claims, list) or not all(_valid_claim(claim) for claim in claims):
        return (RegistryError("registry.shape", "one or more claims violate the registered schema"),)
    semantic = validate_semantics(document)
    return tuple(
        RegistryError(str(error["code"]), f"{error['path']}: {error['message']}")
        for error in semantic
    )


def _read_inspection(path: Path) -> RegistryInspection:
    if not path.exists():
        return RegistryInspection(
            document={"schema_version": "agent-work-session/v1", "revision": 0, "claims": []},
            errors=(),
            raw_text=None,
        )
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        return RegistryInspection(None, (RegistryError("registry.unreadable", str(exc)),), None)
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeError as exc:
        return RegistryInspection(
            None,
            (RegistryError("registry.invalid-encoding", str(exc)),),
            raw_bytes.decode("utf-8", errors="replace"),
        )
    try:
        value = json.loads(raw, object_pairs_hook=_duplicates_fail)
    except (json.JSONDecodeError, ValueError) as exc:
        return RegistryInspection(None, (RegistryError("registry.invalid-json", str(exc)),), raw)
    if not isinstance(value, dict):
        return RegistryInspection(None, (RegistryError("registry.shape", "registry root must be an object"),), raw)
    return RegistryInspection(value, _shape_errors(value), raw)


@contextmanager
def _exclusive_lock(path: Path, timeout: float) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    acquired = False
    try:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b"\0")
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise SessionError(f"timed out acquiring registry lock {path}") from exc
                time.sleep(0.01)
        yield
    finally:
        try:
            if acquired:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _atomic_write(path: Path, document: Mapping[str, object]) -> None:
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _default_process_probe(process: Mapping[str, object]) -> ProcessStatus:
    if str(process.get("host", "")).casefold() != socket.gethostname().casefold():
        return ProcessStatus.UNKNOWN
    pid = process.get("pid")
    started_at = _parse_time(process.get("started_at"))
    if not isinstance(pid, int) or isinstance(pid, bool) or started_at is None:
        return ProcessStatus.UNKNOWN
    actual = _process_start_time(pid)
    if actual is False:
        return ProcessStatus.DEAD
    if actual is None:
        return ProcessStatus.UNKNOWN
    return ProcessStatus.LIVE if abs((actual - started_at).total_seconds()) <= 2 else ProcessStatus.DEAD


def _process_start_time(pid: int) -> datetime | None | bool:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.GetProcessTimes.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )
        kernel32.GetProcessTimes.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            return False if error in {87, 1168} else None
        try:
            creation = ctypes.c_ulonglong()
            exit_time = ctypes.c_ulonglong()
            kernel = ctypes.c_ulonglong()
            user = ctypes.c_ulonglong()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user),
            ):
                return None
            unix_seconds = creation.value / 10_000_000 - 11_644_473_600
            return datetime.fromtimestamp(unix_seconds, UTC)
        finally:
            kernel32.CloseHandle(handle)
    stat = Path(f"/proc/{pid}/stat")
    if not stat.exists():
        return False
    try:
        fields = stat.read_text(encoding="ascii").rsplit(")", 1)[1].split()
        ticks = int(fields[19])
        boot_line = next(
            line for line in Path("/proc/stat").read_text(encoding="ascii").splitlines()
            if line.startswith("btime ")
        )
        boot = int(boot_line.split()[1])
        return datetime.fromtimestamp(boot + ticks / os.sysconf("SC_CLK_TCK"), UTC)
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def _conflicts(existing: Sequence[Mapping[str, object]], proposed: Mapping[str, object]) -> tuple[Conflict, ...]:
    result: list[Conflict] = []
    proposed_id = str(proposed["session_id"])
    proposed_worktree = proposed["worktree"]
    proposed_resources = proposed["resources"]
    assert isinstance(proposed_worktree, Mapping) and isinstance(proposed_resources, Sequence)
    for claim in existing:
        if claim.get("state") not in _ACTIVE_STATES:
            continue
        owner_id = str(claim.get("session_id"))
        if owner_id == proposed_id:
            result.append(Conflict("session", owner_id))
        worktree = claim.get("worktree")
        if isinstance(worktree, Mapping) and str(worktree.get("path", "")).casefold() == str(proposed_worktree["path"]).casefold():
            result.append(Conflict("worktree", owner_id))
        resources = claim.get("resources")
        if not isinstance(resources, Sequence):
            continue
        for wanted in proposed_resources:
            if not isinstance(wanted, Mapping):
                continue
            for held in resources:
                if not isinstance(held, Mapping):
                    continue
                if (
                    held.get("resource_type") == wanted.get("resource_type")
                    and held.get("resource_id") == wanted.get("resource_id")
                    and (held.get("access") == "exclusive" or wanted.get("access") == "exclusive")
                ):
                    result.append(
                        Conflict("resource", owner_id, str(wanted["resource_type"]), str(wanted["resource_id"]))
                    )
    return tuple(result)


class SessionRegistry:
    """The single serialized mutation seam for one repository's session registry."""

    def __init__(
        self,
        repository: str | os.PathLike[str],
        *,
        now: Callable[[], datetime] | None = None,
        process_probe: Callable[[Mapping[str, object]], ProcessStatus] | None = None,
        lock_timeout: float = 10.0,
    ) -> None:
        self.repository = Path(repository).resolve(strict=True)
        common_dir = _git_path(
            self.repository, "rev-parse", "--path-format=absolute", "--git-common-dir"
        )
        self.path = common_dir / REGISTRY_NAME
        self._lock_path = common_dir / f"{REGISTRY_NAME}.lock"
        self._now = now or (lambda: datetime.now(UTC))
        self._process_probe = process_probe or _default_process_probe
        self._lock_timeout = lock_timeout

    def inspect(self) -> RegistryInspection:
        """Return parseable evidence even when corruption blocks mutations."""
        with _exclusive_lock(self._lock_path, self._lock_timeout):
            return _read_inspection(self.path)

    def evaluate(self, claim: Mapping[str, object]) -> ConflictEvaluation:
        """Evaluate a shaped claim against the latest proven-active ownership."""
        proposed = copy.deepcopy(dict(claim))
        if not _valid_claim(proposed):
            raise RegistryInvalid("proposed claim violates session-claims.schema.json")
        with _exclusive_lock(self._lock_path, self._lock_timeout):
            inspection = _read_inspection(self.path)
            if inspection.document is None or inspection.errors:
                detail = "; ".join(f"{error.code}: {error.message}" for error in inspection.errors)
                raise RegistryInvalid(detail or "registry cannot be safely read")
            document = copy.deepcopy(inspection.document)
            claims = document["claims"]
            assert isinstance(claims, list)
            self._retire_proven_stale(claims, self._now())
            return ConflictEvaluation(int(document["revision"]), _conflicts(claims, proposed))

    def claim(
        self,
        claim: Mapping[str, object],
        *,
        lease_token: str,
        expected_revision: int,
    ) -> dict[str, object]:
        proposed = copy.deepcopy(dict(claim))
        if not _valid_claim(proposed):
            raise RegistryInvalid("proposed claim violates session-claims.schema.json")
        lease = proposed["lease"]
        assert isinstance(lease, dict)
        if not hmac.compare_digest(str(lease["token_hash"]), _token_hash(lease_token)):
            raise LeaseTokenMismatch("lease token does not match proposed token_hash")
        with _exclusive_lock(self._lock_path, self._lock_timeout):
            document = self._mutation_document(expected_revision)
            claims = document["claims"]
            assert isinstance(claims, list)
            self._retire_proven_stale(claims, self._now())
            conflicts = _conflicts(claims, proposed)
            if conflicts:
                raise ClaimConflict(conflicts)
            claims.append(proposed)
            return self._commit(document)

    def heartbeat(
        self,
        session_id: str,
        *,
        lease_token: str,
        expected_revision: int,
    ) -> dict[str, object]:
        with _exclusive_lock(self._lock_path, self._lock_timeout):
            document = self._mutation_document(expected_revision)
            claim = self._owned_claim(document, session_id, lease_token)
            if claim.get("state") not in _ACTIVE_STATES:
                raise SessionError(f"session {session_id!r} is not active")
            lease = claim["lease"]
            assert isinstance(lease, dict)
            heartbeat = self._now()
            lease["heartbeat_at"] = _format_time(heartbeat)
            lease["expires_at"] = _format_time(heartbeat + timedelta(seconds=int(lease["ttl_seconds"])))
            return self._commit(document)

    def release(
        self,
        session_id: str,
        *,
        lease_token: str,
        expected_revision: int,
    ) -> dict[str, object]:
        with _exclusive_lock(self._lock_path, self._lock_timeout):
            document = self._mutation_document(expected_revision)
            claim = self._owned_claim(document, session_id, lease_token)
            claim["state"] = "closed"
            return self._commit(document)

    def _mutation_document(self, expected_revision: int) -> dict[str, object]:
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            raise RevisionConflict("expected revision must be a non-negative integer")
        inspection = _read_inspection(self.path)
        if inspection.document is None or inspection.errors:
            detail = "; ".join(f"{error.code}: {error.message}" for error in inspection.errors)
            raise RegistryInvalid(detail or "registry cannot be safely read")
        found = inspection.document["revision"]
        if found != expected_revision:
            raise RevisionConflict(f"expected revision {expected_revision}, found {found}")
        return copy.deepcopy(inspection.document)

    def _owned_claim(
        self, document: Mapping[str, object], session_id: str, lease_token: str
    ) -> dict[str, object]:
        claims = document["claims"]
        assert isinstance(claims, list)
        for claim in claims:
            if isinstance(claim, dict) and claim.get("session_id") == session_id:
                lease = claim["lease"]
                assert isinstance(lease, dict)
                if not hmac.compare_digest(str(lease["token_hash"]), _token_hash(lease_token)):
                    raise LeaseTokenMismatch(f"lease token does not own session {session_id!r}")
                return claim
        raise ClaimNotFound(f"session {session_id!r} does not exist")

    def _retire_proven_stale(self, claims: Sequence[dict[str, object]], now: datetime) -> None:
        for claim in claims:
            if claim.get("state") not in _ACTIVE_STATES:
                continue
            lease = claim.get("lease")
            process = claim.get("process")
            if not isinstance(lease, Mapping) or not isinstance(process, Mapping):
                raise RegistryInvalid("active claim lacks shaped lease/process evidence")
            expires = _parse_time(lease.get("expires_at"))
            if expires is None:
                raise RegistryInvalid("active claim has invalid lease expiry")
            if now <= expires:
                continue
            proof = self._process_probe(process)
            if proof in {ProcessStatus.DEAD, ProcessStatus.HOST_UNREACHABLE}:
                claim["state"] = "abandoned"

    def _commit(self, document: dict[str, object]) -> dict[str, object]:
        document["revision"] = int(document["revision"]) + 1
        errors = _shape_errors(document)
        if errors:
            detail = "; ".join(f"{error.code}: {error.message}" for error in errors)
            raise RegistryInvalid(detail)
        _atomic_write(self.path, document)
        readback = _read_inspection(self.path)
        if readback.document != document or readback.errors:
            raise RegistryInvalid("registry atomic write failed verified readback")
        return copy.deepcopy(document)


_SECRET_PATH = re.compile(
    r"(^|[/_.-])(\.env(?:\.|$)|credentials?|secrets?|id_rsa|id_ed25519|private[-_.]?key|tokens?)([/_.-]|$)",
    re.IGNORECASE,
)
_SECRET_CONTENT = (
    re.compile(br"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(br"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(br"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(br"(?i)(?:api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"),
)


def _changed_paths(repo: Path) -> tuple[list[str], list[str]]:
    changed_raw = _run_git(repo, "diff", "--name-only", "-z", "HEAD", "--")
    untracked_raw = _run_git(repo, "ls-files", "--others", "--exclude-standard", "-z", "--")
    decode = lambda value: [part.decode("utf-8", errors="surrogateescape") for part in value.split(b"\0") if part]
    changed = decode(changed_raw)
    untracked = decode(untracked_raw)
    return sorted(set(changed) | set(untracked)), sorted(set(untracked))


def _scan_changed_paths(repo: Path, paths: Sequence[str]) -> tuple[str, ...]:
    findings: list[str] = []
    root = repo.resolve(strict=True)
    for relative in paths:
        if _SECRET_PATH.search(relative):
            findings.append(f"path:{relative}")
        candidate = (root / Path(relative)).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError:
            findings.append(f"outside-worktree:{relative}")
            continue
        if not candidate.is_file():
            continue
        try:
            content = candidate.read_bytes()
        except OSError:
            findings.append(f"unreadable:{relative}")
            continue
        if any(pattern.search(content) for pattern in _SECRET_CONTENT):
            findings.append(f"content:{relative}")
    return tuple(findings)


def _snapshot_checkout(repo: Path) -> tuple[str, str, bytes, bytes | None]:
    head = _git_text(repo, "rev-parse", "HEAD")
    branch = _git_text(repo, "symbolic-ref", "-q", "HEAD")
    status = _run_git(repo, "status", "--porcelain=v2", "-z", "--untracked-files=all")
    index = _git_path(repo, "rev-parse", "--path-format=absolute", "--git-path", "index")
    return head, branch, status, index.read_bytes() if index.exists() else None


def create_dirty_pause(
    repository: str | os.PathLike[str],
    session_id: str,
    *,
    mode: str,
    now: Callable[[], datetime] | None = None,
    temp_dir: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Create a protected synthetic commit without changing checkout state."""
    if mode != "feature":
        raise DirtyPauseRejected("dirty pause is available only to the feature lane")
    if not _SESSION_ID.fullmatch(session_id):
        raise DirtyPauseRejected("session_id is not safe for a protected ref")
    repo = _git_path(Path(repository).resolve(strict=True), "rev-parse", "--show-toplevel")
    git_dir = _git_path(repo, "rev-parse", "--path-format=absolute", "--git-dir")
    common_dir = _git_path(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if git_dir == common_dir:
        raise DirtyPauseRejected("dirty pause requires an isolated linked worktree")

    before = _snapshot_checkout(repo)
    if not before[2]:
        raise DirtyPauseRejected("dirty pause requires a dirty worktree")
    paths, untracked = _changed_paths(repo)
    findings = _scan_changed_paths(repo, paths)
    if findings:
        raise SecretMaterialError(findings)
    ref = f"refs/agent-sessions/{session_id}"
    if subprocess.run(
        ["git", "-C", os.fspath(repo), "show-ref", "--verify", "--quiet", ref],
        capture_output=True,
    ).returncode == 0:
        raise DirtyPauseRejected(f"protected ref already exists: {ref}")

    temp_parent = Path(temp_dir).resolve(strict=True) if temp_dir is not None else None
    if temp_parent is not None:
        try:
            temp_parent.relative_to(repo)
        except ValueError:
            pass
        else:
            raise DirtyPauseRejected("temporary index directory must be outside the worktree")
    descriptor, index_name = tempfile.mkstemp(prefix="johan-sdd-index-", dir=temp_parent)
    os.close(descriptor)
    temporary_index = Path(index_name)
    temporary_index.unlink()
    created_ref = False
    try:
        index_env = {"GIT_INDEX_FILE": os.fspath(temporary_index)}
        _run_git(repo, "read-tree", before[0], env=index_env)
        _run_git(repo, "add", "-A", "--", ".", env=index_env)
        tree = _git_text(repo, "write-tree", env=index_env)
        identity_env = {
            **index_env,
            "GIT_AUTHOR_NAME": "johan-sdd dirty pause",
            "GIT_AUTHOR_EMAIL": "noreply@johan-sdd.invalid",
            "GIT_COMMITTER_NAME": "johan-sdd dirty pause",
            "GIT_COMMITTER_EMAIL": "noreply@johan-sdd.invalid",
        }
        synthetic = _git_text(
            repo,
            "commit-tree", tree, "-p", before[0], "-m", f"johan-sdd dirty pause {session_id}",
            env=identity_env,
        )
        zero_oid = "0" * len(before[0])
        _run_git(repo, "update-ref", ref, synthetic, zero_oid)
        created_ref = True
        recovery: dict[str, object] = {
            "schema_version": "johan-sdd/pause-recovery/v1",
            "synthetic_commit": synthetic,
            "protected_ref": ref,
            "original_head": before[0],
            "original_status_sha256": hashlib.sha256(before[2]).hexdigest(),
            "untracked_paths": untracked,
            "secret_scan": {
                "status": "passed",
                "scanner": "johan-sdd/secret-scan/v1",
                "completed_at": _format_time((now or (lambda: datetime.now(UTC)))()),
            },
        }
        if not _valid_recovery(recovery) or validate_semantics(recovery):
            raise DirtyPauseRejected("generated recovery record failed contract validation")
        after = _snapshot_checkout(repo)
        if after != before:
            raise DirtyPauseRejected("synthetic snapshot changed the real index, worktree, branch, or HEAD")
        if _git_text(repo, "rev-parse", ref) != synthetic:
            raise DirtyPauseRejected("protected ref readback did not match the synthetic commit")
        return recovery
    except Exception:
        if created_ref:
            subprocess.run(
                ["git", "-C", os.fspath(repo), "update-ref", "-d", ref, synthetic], capture_output=True
            )
        raise
    finally:
        temporary_index.unlink(missing_ok=True)


@dataclass(frozen=True)
class OpenedSession:
    """A newly registered claim plus the one-time lease token."""

    session_id: str
    lease_token: str
    revision: int
    claim: dict[str, object]
    document: dict[str, object]


def describe_worktree(repository: str | os.PathLike[str]) -> dict[str, str]:
    """Measure the live checkout's canonical worktree object."""
    repo = _git_path(Path(repository).resolve(strict=True), "rev-parse", "--show-toplevel")
    git_dir = _git_path(repo, "rev-parse", "--path-format=absolute", "--git-dir")
    common_dir = _git_path(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    kind = "primary" if git_dir == common_dir else "linked"
    return {
        "repo_id": common_dir.parent.name if common_dir.name == ".git" else common_dir.name,
        "worktree_id": "primary" if kind == "primary" else repo.name,
        "path": repo.as_posix(),
        "kind": kind,
        "branch": _git_text(repo, "symbolic-ref", "--short", "HEAD"),
    }


def _current_process(now: datetime) -> dict[str, object]:
    started = _process_start_time(os.getpid())
    if not isinstance(started, datetime) or started > now:
        started = now
    return {"host": socket.gethostname(), "pid": os.getpid(), "started_at": _format_time(started)}


def open_work_session(
    repository: str | os.PathLike[str],
    *,
    session_id: str,
    mode: str,
    owner: Mapping[str, str],
    resources: Sequence[Mapping[str, str]],
    authority_decision_ref: str,
    lease_token: str | None = None,
    ttl_seconds: int = 5400,
    process: Mapping[str, object] | None = None,
    now: Callable[[], datetime] | None = None,
) -> OpenedSession:
    """Shape a claim from live git/process identity and register it."""
    clock = now or (lambda: datetime.now(UTC))
    instant = clock()
    worktree = describe_worktree(repository)
    if mode == "feature" and worktree["kind"] != "linked":
        raise SessionError("feature mode requires a linked worktree")
    if mode == "micro" and worktree["kind"] != "primary":
        raise SessionError("micro mode requires the primary checkout")
    dirty = bool(
        _run_git(Path(worktree["path"]), "status", "--porcelain=v2", "-z", "--untracked-files=all")
    )
    if mode == "micro" and dirty:
        raise SessionError("micro mode requires a clean primary checkout")
    if mode == "feature" and dirty:
        raise SessionError("feature working claim requires a clean worktree")
    token = lease_token or secrets.token_hex(32)
    claim = {
        "session_id": session_id,
        "mode": mode,
        "owner": {"agent": owner["agent"], "model": owner["model"]},
        "process": dict(process) if process is not None else _current_process(instant),
        "lease": {
            "token_hash": _token_hash(token),
            "generation": 1,
            "acquired_at": _format_time(instant),
            "heartbeat_at": _format_time(instant),
            "expires_at": _format_time(instant + timedelta(seconds=ttl_seconds)),
            "ttl_seconds": ttl_seconds,
        },
        "worktree": worktree,
        "state": "working",
        "dirty": False,
        "authority_decision_ref": authority_decision_ref,
        "resources": [dict(resource) for resource in resources],
    }
    registry = SessionRegistry(repository, now=clock)
    inspection = registry.inspect()
    if inspection.document is None or inspection.errors:
        detail = "; ".join(f"{error.code}: {error.message}" for error in inspection.errors)
        raise RegistryInvalid(detail or "registry cannot be safely read")
    document = registry.claim(
        claim,
        lease_token=token,
        expected_revision=int(inspection.document["revision"]),
    )
    stored = next(
        item
        for item in document["claims"]
        if isinstance(item, dict) and item.get("session_id") == session_id
    )
    return OpenedSession(
        session_id=session_id,
        lease_token=token,
        revision=int(document["revision"]),
        claim=copy.deepcopy(stored),
        document=document,
    )


def close_work_session(
    repository: str | os.PathLike[str],
    session_id: str,
    *,
    lease_token: str,
    expected_revision: int | None = None,
) -> dict[str, object]:
    """Close an owned claim; inspects the current revision when omitted."""
    registry = SessionRegistry(repository)
    revision = expected_revision
    if revision is None:
        inspection = registry.inspect()
        if inspection.document is None or inspection.errors:
            detail = "; ".join(f"{error.code}: {error.message}" for error in inspection.errors)
            raise RegistryInvalid(detail or "registry cannot be safely read")
        revision = int(inspection.document["revision"])
    return registry.release(session_id, lease_token=lease_token, expected_revision=revision)


__all__ = [
    "ClaimConflict",
    "ClaimNotFound",
    "Conflict",
    "ConflictEvaluation",
    "DirtyPauseRejected",
    "LeaseTokenMismatch",
    "OpenedSession",
    "ProcessStatus",
    "RegistryInspection",
    "RegistryInvalid",
    "RevisionConflict",
    "SecretMaterialError",
    "SessionError",
    "SessionRegistry",
    "close_work_session",
    "create_dirty_pause",
    "describe_worktree",
    "open_work_session",
]
