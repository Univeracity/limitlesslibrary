from __future__ import annotations

import json

import pytest

from limitless_library.contracts import canonical_json_bytes, sha256_bytes
from limitless_library.exact_file_bundle import (
    EXACT_FILE_BUNDLE_SCHEMA_VERSION,
    ExactFileBundleError,
    build_exact_file_bundle,
    parse_exact_file_bundle,
)


def test_exact_file_bundle_is_canonical_sorted_and_self_verifying() -> None:
    payload = build_exact_file_bundle(
        {
            "plugin/run.sh": b"#!/bin/sh\nexit 0\n",
            "manifest.json": b'{"schemaVersion":1}\n',
        },
        executable_paths={"plugin/run.sh"},
    )

    bundle = parse_exact_file_bundle(payload)

    assert bundle.schema_version == EXACT_FILE_BUNDLE_SCHEMA_VERSION
    assert [item.path for item in bundle.files] == ["manifest.json", "plugin/run.sh"]
    assert [item.mode for item in bundle.files] == ["0644", "0755"]
    assert bundle.files[0].content_digest == sha256_bytes(bundle.files[0].data)
    assert bundle.decoded_byte_length == sum(item.byte_length for item in bundle.files)
    assert canonical_json_bytes(json.loads(payload)) == payload


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("path", "../outside", "path"),
        ("path", ".git/config", "Git metadata"),
        ("mode", "04755", "mode"),
        ("byteLength", 99, "bytes differ"),
        ("contentDigest", "sha256:" + "0" * 64, "bytes differ"),
        ("data", "a", "data"),
    ],
)
def test_exact_file_bundle_rejects_descriptor_and_byte_mutations(
    field: str,
    value: object,
    message: str,
) -> None:
    payload = build_exact_file_bundle({"manifest.json": b"{}\n"})
    changed = json.loads(payload)
    changed["files"][0][field] = value

    with pytest.raises(ExactFileBundleError, match=message):
        parse_exact_file_bundle(canonical_json_bytes(changed))


def test_exact_file_bundle_rejects_noncanonical_or_ambiguous_input() -> None:
    payload = build_exact_file_bundle({"manifest.json": b"{}\n"})
    with pytest.raises(ExactFileBundleError, match="canonical JSON"):
        parse_exact_file_bundle(payload + b"\n")

    duplicate = b'{"files":[],"files":[],"schemaVersion":"' + EXACT_FILE_BUNDLE_SCHEMA_VERSION.encode("ascii") + b'"}'
    with pytest.raises(ExactFileBundleError, match="invalid"):
        parse_exact_file_bundle(duplicate)

    with pytest.raises(ExactFileBundleError, match="executable paths"):
        build_exact_file_bundle(
            {"manifest.json": b"{}\n"},
            executable_paths={"missing.sh"},
        )
