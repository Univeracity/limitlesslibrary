"""Canonical, non-executing directory bundles for explicit receiver adapters."""

from __future__ import annotations

import re
import unicodedata
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .contracts import canonical_json_bytes, relative_path, sha256_bytes, strict_json_loads

EXACT_FILE_BUNDLE_SCHEMA_VERSION = "limitless.exact-file-bundle/1.0"
MAX_EXACT_FILE_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_EXACT_FILE_BUNDLE_DECODED_BYTES = 48 * 1024 * 1024
MAX_EXACT_FILE_BYTES = 48 * 1024 * 1024
MAX_EXACT_FILE_BUNDLE_FILES = 512

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_MODES = frozenset({"0644", "0755"})


class ExactFileBundleError(ValueError):
    """An exact-file bundle is ambiguous, noncanonical, or outside its limits."""


@dataclass(frozen=True)
class ExactBundleFile:
    path: str
    mode: str
    byte_length: int
    content_digest: str
    data: bytes


@dataclass(frozen=True)
class ExactFileBundle:
    schema_version: str
    files: tuple[ExactBundleFile, ...]

    @property
    def decoded_byte_length(self) -> int:
        return sum(item.byte_length for item in self.files)


def _path(value: Any) -> str:
    if not isinstance(value, str):
        raise ExactFileBundleError("exact bundle file path is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise ExactFileBundleError("exact bundle file path is invalid") from error
    if (
        len(encoded) > 500
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ExactFileBundleError("exact bundle file path is invalid")
    try:
        path = relative_path(value, "exact bundle file path")
    except ValueError as error:
        raise ExactFileBundleError("exact bundle file path is invalid") from error
    if ".git" in path.parts:
        raise ExactFileBundleError("exact bundle cannot contain Git metadata")
    return path.as_posix()


def _data(value: Any) -> bytes:
    if not isinstance(value, str) or _BASE64URL.fullmatch(value) is None or len(value) % 4 == 1:
        raise ExactFileBundleError("exact bundle file data is invalid")
    try:
        decoded = urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (TypeError, ValueError) as error:
        raise ExactFileBundleError("exact bundle file data is invalid") from error
    if urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ExactFileBundleError("exact bundle file data is noncanonical")
    return decoded


def _file(value: Any) -> ExactBundleFile:
    if not isinstance(value, dict) or set(value) != {
        "path",
        "mode",
        "byteLength",
        "contentDigest",
        "data",
    }:
        raise ExactFileBundleError("exact bundle file has an unsupported shape")
    path = _path(value["path"])
    mode = value["mode"]
    length = value["byteLength"]
    digest = value["contentDigest"]
    if mode not in _MODES:
        raise ExactFileBundleError("exact bundle file mode is invalid")
    if isinstance(length, bool) or not isinstance(length, int) or not 0 <= length <= MAX_EXACT_FILE_BYTES:
        raise ExactFileBundleError("exact bundle file byteLength is invalid")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise ExactFileBundleError("exact bundle file contentDigest is invalid")
    data = _data(value["data"])
    if len(data) != length or sha256_bytes(data) != digest:
        raise ExactFileBundleError("exact bundle file bytes differ from their descriptor")
    return ExactBundleFile(
        path=path,
        mode=mode,
        byte_length=length,
        content_digest=digest,
        data=data,
    )


def parse_exact_file_bundle(payload: bytes) -> ExactFileBundle:
    """Parse and independently verify one canonical exact-file bundle."""

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_EXACT_FILE_BUNDLE_BYTES:
        raise ExactFileBundleError("exact bundle payload size is invalid")
    try:
        value = strict_json_loads(payload.decode("utf-8"))
        canonical = canonical_json_bytes(value)
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise ExactFileBundleError("exact bundle payload is invalid") from error
    if canonical != payload:
        raise ExactFileBundleError("exact bundle payload is not canonical JSON")
    if (
        not isinstance(value, dict)
        or set(value) != {"schemaVersion", "files"}
        or value.get("schemaVersion") != EXACT_FILE_BUNDLE_SCHEMA_VERSION
        or not isinstance(value.get("files"), list)
        or not 1 <= len(value["files"]) <= MAX_EXACT_FILE_BUNDLE_FILES
    ):
        raise ExactFileBundleError("exact bundle has an unsupported shape")
    files = tuple(_file(item) for item in value["files"])
    paths = [item.path for item in files]
    if paths != sorted(set(paths)):
        raise ExactFileBundleError("exact bundle file paths must be sorted and unique")
    if sum(item.byte_length for item in files) > MAX_EXACT_FILE_BUNDLE_DECODED_BYTES:
        raise ExactFileBundleError("exact bundle decoded bytes exceed their limit")
    return ExactFileBundle(
        schema_version=EXACT_FILE_BUNDLE_SCHEMA_VERSION,
        files=files,
    )


def build_exact_file_bundle(
    files: Mapping[str, bytes],
    *,
    executable_paths: Iterable[str] = (),
) -> bytes:
    """Build one canonical bundle from an explicit file mapping."""

    try:
        supplied = dict(files)
        executables = {_path(item) for item in executable_paths}
    except (TypeError, ValueError) as error:
        raise ExactFileBundleError("exact bundle files are invalid") from error
    if not 1 <= len(supplied) <= MAX_EXACT_FILE_BUNDLE_FILES:
        raise ExactFileBundleError("exact bundle files are invalid")
    checked: dict[str, bytes] = {}
    for raw_path, data in supplied.items():
        path = _path(raw_path)
        if path in checked or not isinstance(data, bytes):
            raise ExactFileBundleError("exact bundle files are invalid")
        checked[path] = data
    if not executables.issubset(checked):
        raise ExactFileBundleError("exact bundle executable paths are invalid")
    if sum(len(data) for data in checked.values()) > MAX_EXACT_FILE_BUNDLE_DECODED_BYTES:
        raise ExactFileBundleError("exact bundle decoded bytes exceed their limit")
    encoded = canonical_json_bytes(
        {
            "schemaVersion": EXACT_FILE_BUNDLE_SCHEMA_VERSION,
            "files": [
                {
                    "path": path,
                    "mode": "0755" if path in executables else "0644",
                    "byteLength": len(checked[path]),
                    "contentDigest": sha256_bytes(checked[path]),
                    "data": urlsafe_b64encode(checked[path]).rstrip(b"=").decode("ascii"),
                }
                for path in sorted(checked)
            ],
        }
    )
    if len(encoded) > MAX_EXACT_FILE_BUNDLE_BYTES:
        raise ExactFileBundleError("exact bundle payload exceeds its limit")
    parse_exact_file_bundle(encoded)
    return encoded
