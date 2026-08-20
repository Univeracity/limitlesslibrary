"""Static, language-neutral vectors for public service root rotation."""

from __future__ import annotations

import unittest
from base64 import urlsafe_b64decode
from copy import deepcopy
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from limitless_library.contracts import load_json, sha256_json
from limitless_library.service_contracts import (
    PublicServiceContractError,
    advance_service_root_trust,
    latest_service_root_keys,
    validate_service_root_key_transition_set,
)

CORPUS_PATH = Path(str(files("limitless_library.conformance").joinpath("public-service-root-transition-1.0.json")))
CORPUS_SCHEMA_VERSION = "limitless.public-service-root-transition-conformance/1.0"


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _replace_pointer(value: dict[str, Any], pointer: str, replacement: Any) -> dict[str, Any]:
    result = deepcopy(value)
    parts = pointer.removeprefix("/").split("/")
    current: Any = result
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    final = parts[-1]
    if isinstance(current, list):
        current[int(final)] = replacement
    else:
        current[final] = replacement
    return result


class PublicServiceRootTransitionConformanceTests(unittest.TestCase):
    def _corpus(self) -> dict[str, Any]:
        value = load_json(CORPUS_PATH)
        self.assertEqual(
            {"schemaVersion", "trustedRootKey", "record", "expected", "invalidCases", "corpusDigest"},
            set(value),
        )
        self.assertEqual(CORPUS_SCHEMA_VERSION, value["schemaVersion"])
        self.assertEqual(
            value["corpusDigest"],
            sha256_json({key: item for key, item in value.items() if key != "corpusDigest"}),
        )
        return value

    def test_static_chain_advances_from_the_pinned_root_to_the_expected_tip(self) -> None:
        corpus = self._corpus()
        trusted = corpus["trustedRootKey"]
        initial_roots = {trusted["keyId"]: _decode(trusted["publicKey"])}
        checked = validate_service_root_key_transition_set(corpus["record"], trusted_root_keys=initial_roots)
        expected = corpus["expected"]
        self.assertEqual(expected["serviceId"], checked["serviceId"])
        self.assertEqual(expected["latestSequence"], checked["latestSequence"])
        self.assertEqual(expected["latestTransitionDigest"], checked["latestTransitionDigest"])
        current = expected["currentRootKey"]
        self.assertEqual({current["keyId"]: _decode(current["publicKey"])}, latest_service_root_keys(checked))

        roots, sequence, digest = advance_service_root_trust(
            checked["transitions"][0],
            trusted_root_keys=initial_roots,
            expected_service_id=expected["serviceId"],
            expected_sequence=1,
            expected_previous_transition_digest=None,
            at=datetime.fromisoformat(expected["effectiveAt"]).astimezone(UTC),
        )
        self.assertEqual({current["keyId"]: _decode(current["publicKey"])}, roots)
        self.assertEqual((expected["latestSequence"], expected["latestTransitionDigest"]), (sequence, digest))

    def test_declared_substitutions_replays_and_signature_mutations_fail_closed(self) -> None:
        corpus = self._corpus()
        trusted = corpus["trustedRootKey"]
        initial_roots = {trusted["keyId"]: _decode(trusted["publicKey"])}
        for case in corpus["invalidCases"]:
            with self.subTest(case=case["id"]):
                candidate = _replace_pointer(corpus["record"], case["path"], case["value"])
                with self.assertRaises(PublicServiceContractError):
                    validate_service_root_key_transition_set(candidate, trusted_root_keys=initial_roots)


if __name__ == "__main__":
    unittest.main()
