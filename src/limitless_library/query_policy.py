"""Separate, owner-controlled authorization for objective-based queries."""

from __future__ import annotations

import os
import platform
import secrets
import stat
from pathlib import Path
from typing import Any

from .contracts import ContractError, canonical_json_bytes, strict_json_loads, write_new_json
from .schemas import SchemaError, validate
from .service_contracts import validate_service_receiver_context


class QueryPolicyError(ValueError):
    """Query policy or receiver facts cannot be used safely."""


MAX_QUERY_POLICY_BYTES = 16 * 1024


def default_query_policy() -> dict[str, Any]:
    return {
        "schemaVersion": "limitless.query-policy/1.0",
        "executionMode": "local",
        "localReceiver": None,
        "serviceReceiver": None,
        "requestedUses": ["adopt", "instantiate"],
        "tenantScopes": ["private", "public"],
        "allowExact": False,
    }


def validate_query_policy(value: Any) -> dict[str, Any]:
    try:
        validate(value, "query-policy-1.0.schema.json", "query policy")
        if value["serviceReceiver"] is not None:
            validate_service_receiver_context(value["serviceReceiver"])
        if value["allowExact"] and value["localReceiver"] is None and value["serviceReceiver"] is None:
            raise QueryPolicyError("exact selection requires owner-configured receiver facts")
        if len(canonical_json_bytes(value)) + 1 > MAX_QUERY_POLICY_BYTES:
            raise QueryPolicyError("query policy exceeds its private record byte limit")
    except (SchemaError, ValueError) as error:
        raise QueryPolicyError(str(error)) from error
    return value


def read_private_json(path: Path, *, maximum: int) -> dict[str, Any]:
    if os.name != "posix":
        raise QueryPolicyError("private query records currently require a POSIX host")
    selected = Path(path)
    if not selected.is_absolute() or ".." in selected.parts or selected.is_symlink():
        raise QueryPolicyError("private record path must be absolute and not a symbolic link")
    descriptor = os.open(selected, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > maximum
            or os.name == "posix"
            and (info.st_uid != os.geteuid() or info.st_mode & 0o077)
        ):
            raise QueryPolicyError("private record must be bounded, owned, and private")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) != info.st_size or len(raw) > maximum:
            raise QueryPolicyError("private record changed or exceeded its limit")
        value = strict_json_loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise QueryPolicyError("private record must be a JSON object")
        return value
    finally:
        os.close(descriptor)


def private_directory(path: Path, *, create: bool = True) -> Path:
    if os.name != "posix":
        raise QueryPolicyError("private query storage currently requires a POSIX host")
    selected = Path(path)
    if not selected.is_absolute() or ".." in selected.parts or selected.is_symlink():
        raise QueryPolicyError("private directory must be absolute and not a symbolic link")
    if create:
        selected.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = selected.lstat()
    if not stat.S_ISDIR(info.st_mode) or os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise QueryPolicyError("private directory must be owned and private")
    return selected


def load_query_policy(path: Path | None) -> dict[str, Any]:
    if path is None:
        return default_query_policy()
    selected = Path(path)
    if not selected.is_absolute() or ".." in selected.parts or selected.is_symlink():
        raise QueryPolicyError("query policy path must be absolute and not a symbolic link")
    if not selected.exists():
        return default_query_policy()
    try:
        return validate_query_policy(read_private_json(selected, maximum=MAX_QUERY_POLICY_BYTES))
    except (OSError, UnicodeError, ValueError) as error:
        raise QueryPolicyError("saved query policy cannot be used safely") from error


def create_query_policy(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    """Create a reviewed policy without replacing prior owner configuration."""
    checked = validate_query_policy(value)
    selected = Path(path)
    private_directory(selected.parent)
    try:
        write_new_json(selected, checked)
    except (ContractError, OSError) as error:
        raise QueryPolicyError(str(error)) from error
    return checked


def save_query_policy(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    """Atomically replace only this separate owner policy, not legacy settings."""
    checked = validate_query_policy(value)
    selected = Path(path)
    if not selected.is_absolute() or ".." in selected.parts or selected.is_symlink():
        raise QueryPolicyError("query policy path must be absolute and not a symbolic link")
    private_directory(selected.parent)
    if selected.exists():
        read_private_json(selected, maximum=MAX_QUERY_POLICY_BYTES)
    temporary = selected.parent / f".query-policy-{secrets.token_hex(16)}.tmp"
    try:
        write_new_json(temporary, checked)
        os.replace(temporary, selected)
    finally:
        temporary.unlink(missing_ok=True)
    return checked


def resolve_receivers(policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Project only known local-device facts or explicit actual-target facts."""
    system = platform.system().lower() or "unknown"
    architecture = platform.machine().lower() or "unknown"
    service = policy["serviceReceiver"]
    if service is None:
        service = {
            "receiverId": "receiver:local-device",
            "allowedUse": "derive-method",
            "interfaces": ["limitless.mcp/v1"],
            "execution": {
                "platform": system,
                "architecture": architecture,
                "runtime": "python",
                "version": platform.python_version(),
            },
            "targets": [
                {
                    "id": "target:local-device",
                    "platform": system,
                    "architecture": architecture,
                    "runtime": "any",
                    "versionRange": "any",
                    "interfaces": ["limitless.mcp/v1"],
                }
            ],
            "compatibilityMode": "all-targets",
            "selectedTarget": None,
        }
    local = policy["localReceiver"]
    if local is None:
        targets = service["targets"]
        if service["compatibilityMode"] == "one-target":
            targets = [target for target in targets if target["id"] == service["selectedTarget"]]
        platforms = {target["platform"] for target in targets}
        local = {"constraints": sorted(platforms) if len(platforms) == 1 else [], "toolchain": {}}
    return local, validate_service_receiver_context(service)
