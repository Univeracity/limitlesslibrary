"""Capture small, independently authored methods and queue opted-in public sharing."""

from __future__ import annotations

import argparse
import os
import platform
import re
import secrets
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .contracts import canonical_json_bytes, sha256_json, strict_json_loads
from .official_service import activated_service_connector
from .publication import PublicationError, publish_draft
from .service_connector import ServiceConnectorError
from .service_contracts import PublicServiceContractError, validate_source_free_method
from .service_identity import ServiceIdentityError, installation_publisher_authority

_TASK_KIND = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_METHOD_REF = re.compile(r"^method:([0-9a-f]{64})$")
_PLATFORM = re.compile(r"^(?:any|[a-z][a-z0-9._-]{0,63})$")
_MAX_RECORDS = 2000


class MethodCaptureError(ValueError):
    """The method or local capture store cannot be used safely."""


def default_method_store(*, environ: dict[str, str] | None = None) -> Path:
    environment = os.environ if environ is None else environ
    configured = environment.get("XDG_DATA_HOME")
    home = environment.get("HOME")
    if configured:
        root = Path(configured)
    elif home:
        root = Path(home) / ".local" / "share"
    else:
        raise MethodCaptureError("a per-user method store is unavailable")
    if not root.is_absolute() or ".." in root.parts:
        raise MethodCaptureError("the per-user method store is invalid")
    return root / "limitless-library" / "methods"


def _directory(path: Path) -> Path:
    if os.name != "posix":
        raise MethodCaptureError("private method capture currently requires a POSIX host")
    selected = Path(path)
    if not selected.is_absolute() or ".." in selected.parts or selected.is_symlink():
        raise MethodCaptureError("method store must be an absolute, non-symlink directory")
    selected.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = selected.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise MethodCaptureError("method store must be owned and private")
    return selected


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise MethodCaptureError("method record write was incomplete")
            written += count
        os.fsync(descriptor)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def _read(path: Path, maximum: int = 64 * 1024) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size > maximum
        or before.st_mode & 0o077
        or before.st_uid != os.geteuid()
    ):
        raise MethodCaptureError("stored method material is unsafe")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        current = os.fstat(descriptor)
        payload = os.read(descriptor, maximum + 1)
        if current.st_ino != before.st_ino or current.st_dev != before.st_dev or len(payload) != before.st_size:
            raise MethodCaptureError("stored method material changed while reading")
        return payload
    finally:
        os.close(descriptor)


def _input(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"title", "taskKind", "method", "observedOutcome", "platform"}:
        raise MethodCaptureError("method registration has unsupported or missing fields")
    title = value["title"]
    task = value["taskKind"]
    outcome = value["observedOutcome"]
    target_platform = value["platform"]
    if not isinstance(title, str) or not title.strip() or len(title) > 120 or "\x00" in title:
        raise MethodCaptureError("method title is invalid")
    if not isinstance(task, str) or len(task) > 100 or _TASK_KIND.fullmatch(task) is None:
        raise MethodCaptureError("method task kind is invalid")
    if not isinstance(outcome, str) or not outcome.strip() or len(outcome) > 400 or "\x00" in outcome:
        raise MethodCaptureError("observed outcome must briefly state what the receiver checked")
    if not isinstance(target_platform, str) or _PLATFORM.fullmatch(target_platform) is None:
        raise MethodCaptureError("method platform is invalid")
    try:
        method = validate_source_free_method(value["method"])
    except PublicServiceContractError as error:
        raise MethodCaptureError(f"method does not meet the source-free method contract: {error}") from error
    return {
        "title": title.strip(),
        "taskKind": task,
        "method": method,
        "observedOutcome": outcome.strip(),
        "platform": target_platform,
    }


def _publication(value: dict[str, Any], capture_digest: str) -> dict[str, Any]:
    interface = "limitless.mcp/v1"
    return {
        "schemaVersion": "limitless.publication-draft/1.0",
        "candidate": {
            "title": value["title"],
            "summary": value["method"]["summary"],
            "treatment": "source-free-method",
            "capabilities": sorted({interface, value["taskKind"]}),
        },
        "lineage": {
            "lineageId": "lineage:method-" + capture_digest[7:39],
            "version": "1.0.0",
            "releaseClass": "initial",
            "parents": [],
            "supersedes": None,
        },
        "objects": [{"role": "method", "path": "method.json"}],
        "compatibility": {
            "supportedTargets": [
                {
                    "platform": value["platform"],
                    "architecture": "any",
                    "runtime": "any",
                    "versionRange": "any",
                    "interfaces": [interface],
                }
            ],
            "verifiedTargets": [],
        },
        "buildContext": {
            "platform": platform.system().lower() or "unknown",
            "architecture": platform.machine().lower() or "unknown",
            "runtime": "limitless-library",
            "version": __version__,
            "interfaces": [interface],
        },
        "evidenceDigests": [
            sha256_json(
                {"schemaVersion": "limitless.method-outcome-note/0.1", "observedOutcome": value["observedOutcome"]}
            )
        ],
        "rights": {"license": "CC0-1.0", "allowedUses": ["derive-method"], "hasAuthority": True},
    }


def _status(folder: Path) -> str:
    status = folder / "submission-status.json"
    if not status.exists():
        return "queued" if (folder / "publication.json").exists() else "local"
    try:
        value = strict_json_loads(_read(status, 4096).decode("utf-8"))
    except (UnicodeError, ValueError) as error:
        raise MethodCaptureError("method submission status is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"status", "reason"}
        or value["status"] not in {"queued", "retryable", "submitted", "active", "rejected", "policy-attention"}
    ):
        raise MethodCaptureError("method submission status is invalid")
    return value["status"]


def _write_status(folder: Path, status: str, reason: str | None) -> None:
    target = folder / "submission-status.json"
    temporary = folder / f".submission-status.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    _write_new(temporary, canonical_json_bytes({"status": status, "reason": reason}) + b"\n")
    os.replace(temporary, target)


def register_method(
    store_path: Path, value: Any, *, public_policy_digest: str | None = None, schedule: bool = True
) -> dict[str, Any]:
    """One local capture; queue public submission only under standing owner consent."""
    if public_policy_digest is not None and (
        not isinstance(public_policy_digest, str) or _DIGEST.fullmatch(public_policy_digest) is None
    ):
        raise MethodCaptureError("public method sharing requires an exact reviewed policy digest")
    checked = _input(value)
    store = _directory(store_path)
    import fcntl

    lock = os.open(
        store / ".register.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _register_locked(store, checked, public_policy_digest, schedule)
    finally:
        os.close(lock)


def _register_locked(
    store: Path, checked: dict[str, Any], public_policy_digest: str | None, schedule: bool
) -> dict[str, Any]:
    capture_digest = sha256_json(checked)
    reference = "method:" + capture_digest[7:]
    folder = store / capture_digest[7:]
    new = not folder.exists()
    if new and len([item for item in store.iterdir() if re.fullmatch(r"[0-9a-f]{64}", item.name)]) >= _MAX_RECORDS:
        raise MethodCaptureError("method store exceeds its bounded capacity")
    folder.mkdir(mode=0o700, exist_ok=True)
    if folder.is_symlink() or folder.stat().st_mode & 0o077 or folder.stat().st_uid != os.geteuid():
        raise MethodCaptureError("method record directory is unsafe")
    method_payload = canonical_json_bytes(checked["method"]) + b"\n"
    capture_payload = (
        canonical_json_bytes({"schemaVersion": "limitless.method-capture/0.1", "methodRef": reference, **checked})
        + b"\n"
    )
    for name, payload in (("capture.json", capture_payload), ("method.json", method_payload)):
        path = folder / name
        if path.exists():
            if _read(path) != payload:
                raise MethodCaptureError("stored method differs from its digest-bound record")
        else:
            _write_new(path, payload)
    if public_policy_digest is not None:
        draft = canonical_json_bytes(_publication(checked, capture_digest)) + b"\n"
        path = folder / "publication.json"
        if path.exists():
            if _read(path) != draft:
                raise MethodCaptureError("method publication draft differs from its captured record")
        else:
            _write_new(path, draft)
        if (
            schedule
            and _status(folder) not in {"active", "rejected"}
            and not schedule_submission(store, public_policy_digest)
        ):
            _write_status(folder, "retryable", "worker-unavailable")
    return {
        "schemaVersion": "limitless.method-registration-result/0.1",
        "status": "registered" if new else "duplicate",
        "methodRef": reference,
        "destination": "public" if (folder / "publication.json").exists() else "local",
        "submission": _status(folder),
    }


def schedule_submission(store: Path, public_policy_digest: str) -> bool:
    """Keep the agent's post-task registration call independent of service latency."""
    try:
        subprocess.Popen(  # nosec B603
            [
                sys.executable,
                "-m",
                "limitless_library.method_capture",
                "--sync",
                str(store),
                "--policy-digest",
                public_policy_digest,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        return False
    return True


def sync_methods(store_path: Path, public_policy_digest: str, *, limit: int = 8) -> dict[str, int]:
    """Retry a bounded batch; existing publication state supplies idempotency."""
    if (
        not isinstance(public_policy_digest, str)
        or _DIGEST.fullmatch(public_policy_digest) is None
        or type(limit) is not int
        or not 1 <= limit <= 32
    ):
        raise MethodCaptureError("method sync arguments are invalid")
    import fcntl

    store = _directory(store_path)
    lock = os.open(store / ".sync.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"processed": 0, "submitted": 0, "attention": 0}
        folders = sorted(path for path in store.iterdir() if re.fullmatch(r"[0-9a-f]{64}", path.name))
        if len(folders) > _MAX_RECORDS:
            raise MethodCaptureError("method store exceeds its bounded capacity")
        processed = submitted = attention = 0
        for folder in folders:
            if processed >= limit:
                break
            if folder.is_symlink() or not folder.is_dir() or folder.stat().st_mode & 0o077:
                raise MethodCaptureError("method record directory is unsafe")
            draft = folder / "publication.json"
            if not draft.exists() or _status(folder) in {"active", "rejected"}:
                continue
            processed += 1
            try:
                connector = activated_service_connector()
                signer, publisher = installation_publisher_authority(service_id=connector.profile.service_id)
                result = publish_draft(
                    connector,
                    draft_path=draft,
                    state_path=None,
                    signer=signer,
                    publisher=publisher,
                    accepted_publication_policy_digest=public_policy_digest,
                )
                admission = result.get("admissionState")
                state = "active" if admission == "active" else "rejected" if admission == "rejected" else "submitted"
                _write_status(folder, state, None)
                submitted += 1
            except (PublicationError, ServiceConnectorError, ServiceIdentityError, OSError, ValueError) as error:
                # Policy drift needs owner review; transient service failure can retry.
                reason = "policy-review-required" if "policy" in str(error).lower() else "service-unavailable"
                _write_status(folder, "policy-attention" if reason == "policy-review-required" else "retryable", reason)
                attention += 1
        return {"processed": processed, "submitted": submitted, "attention": attention}
    finally:
        os.close(lock)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync", type=Path, required=True)
    parser.add_argument("--policy-digest", required=True)
    args = parser.parse_args()
    sync_methods(args.sync, args.policy_digest)


if __name__ == "__main__":
    main()
