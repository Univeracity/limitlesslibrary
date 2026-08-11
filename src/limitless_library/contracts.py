"""Canonical records and defensive filesystem primitives."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import mkstemp
from typing import Any


class ContractError(ValueError):
    """A record or path is ambiguous, invalid, or unsafe."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise json.JSONDecodeError(f"duplicate JSON object key {key!r}", "", 0)
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> Any:
    raise json.JSONDecodeError(f"invalid JSON constant {value!r}", value, 0)


def strict_json_loads(value: str) -> Any:
    return json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_nonfinite)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot load strict JSON object from {path}: {error}") from error
    if not isinstance(value, dict):
        raise ContractError(f"JSON root in {path} must be an object")
    return value


def without(value: dict[str, Any], field: str) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != field}


def relative_path(value: str, field: str = "path") -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ContractError(f"{field} must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ContractError(f"{field} must be a canonical relative POSIX path")
    return path


def regular_file_under(root: Path, relative: str, field: str = "path") -> Path:
    parts = relative_path(relative, field).parts
    root = root.resolve()
    current = root
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise ContractError(f"{field} is unavailable: {relative}") from error
        if stat.S_ISLNK(info.st_mode):
            raise ContractError(f"{field} crosses a symlink: {relative}")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise ContractError(f"{field} must identify a regular file: {relative}")
    return current


def safe_destination(root: Path, relative: str) -> Path:
    parts = relative_path(relative, "installation target").parts
    root = root.resolve()
    current = root
    for part in parts[:-1]:
        current = current / part
        if current.exists() or current.is_symlink():
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ContractError(f"installation target has an unsafe parent: {relative}")
    destination = current / parts[-1]
    if destination.exists() or destination.is_symlink():
        raise ContractError(f"refusing to overwrite receiver path: {relative}")
    return destination


def parse_utc(value: str, field: str = "timestamp") -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (AttributeError, ValueError) as error:
        raise ContractError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ContractError(f"{field} must include an offset")
    return parsed.astimezone(UTC)


def utc_now() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


def write_new_bytes(path: Path, value: bytes, *, mode: int = 0o600) -> None:
    """Publish bytes atomically without overwriting an existing record."""

    destination = Path(path)
    if not destination.name:
        raise ContractError("output must name a file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise ContractError(f"refusing to overwrite immutable output: {destination}") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def write_new_json(path: Path, value: Any) -> None:
    write_new_bytes(path, canonical_json_bytes(value) + b"\n")


def tree_digest(root: Path) -> str:
    """Digest regular receiver files, excluding VCS and Limitless evidence."""

    root = root.resolve()
    manifest: list[dict[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if any(part in {".git", ".limitless"} for part in relative.parts):
            continue
        if path.is_symlink():
            raise ContractError(f"receiver tree contains a symlink: {relative.as_posix()}")
        if path.is_file():
            manifest.append({"path": relative.as_posix(), "digest": sha256_file(path)})
    return sha256_json(manifest)
