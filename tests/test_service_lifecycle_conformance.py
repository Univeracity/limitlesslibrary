"""Static, language-neutral vectors for the public query/outcome lifecycle."""

from __future__ import annotations

import unittest
from base64 import urlsafe_b64decode
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import Any

from limitless_library.contracts import load_json, sha256_json
from limitless_library.service_contracts import (
    PublicServiceContractError,
    active_result_keys,
    validate_service_discovery,
    validate_service_outcome_attempt,
    validate_service_outcome_receipt,
    validate_service_query,
    validate_service_query_result,
)

CORPUS_PATH = Path(str(files("limitless_library.conformance").joinpath("public-service-lifecycle-1.1.json")))
LEGACY_CORPUS_PATH = Path(
    str(files("limitless_library.conformance").joinpath("public-service-lifecycle-1.0.json"))
)
CORPUS_SCHEMA_VERSION = "limitless.public-service-lifecycle-conformance/1.1"


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


class PublicServiceLifecycleConformanceTests(unittest.TestCase):
    def _corpus(self) -> dict[str, Any]:
        value = load_json(CORPUS_PATH)
        self.assertEqual(
            {
                "schemaVersion",
                "rootPublicKey",
                "servicePublicKey",
                "discovery",
                "query",
                "result",
                "outcomeAttempt",
                "outcomeReceipt",
                "expected",
                "invalidCases",
                "corpusDigest",
            },
            set(value),
        )
        self.assertEqual(CORPUS_SCHEMA_VERSION, value["schemaVersion"])
        self.assertEqual(
            value["corpusDigest"],
            sha256_json({key: item for key, item in value.items() if key != "corpusDigest"}),
        )
        return value

    @staticmethod
    def _keys(corpus: dict[str, Any]) -> tuple[dict[str, bytes], dict[str, bytes]]:
        root = corpus["rootPublicKey"]
        service = corpus["servicePublicKey"]
        return ({root["keyId"]: _decode(root["publicKey"])}, {service["keyId"]: _decode(service["publicKey"])})

    def _validate_record(
        self,
        name: str,
        value: dict[str, Any],
        *,
        corpus: dict[str, Any],
        at: datetime,
    ) -> dict[str, Any]:
        root_keys, service_keys = self._keys(corpus)
        if name == "discovery":
            return validate_service_discovery(value, root_public_keys=root_keys, at=at)
        if name == "query":
            return validate_service_query(value, at=at)
        if name == "result":
            return validate_service_query_result(value, public_keys=service_keys, expected_query=corpus["query"], at=at)
        if name == "outcomeAttempt":
            return validate_service_outcome_attempt(value, at=at)
        if name == "outcomeReceipt":
            return validate_service_outcome_receipt(
                value,
                public_keys=service_keys,
                expected_attempt=corpus["outcomeAttempt"],
                expected_decision_ref=corpus["result"]["decisionRef"],
            )
        raise AssertionError(f"unsupported conformance record: {name}")

    def test_static_lifecycle_is_current_signed_and_end_to_end_bound(self) -> None:
        corpus = self._corpus()
        expected = corpus["expected"]
        at = datetime.fromisoformat(expected["validAt"]).astimezone(UTC)
        checked_discovery = self._validate_record("discovery", corpus["discovery"], corpus=corpus, at=at)
        _root_keys, expected_service_keys = self._keys(corpus)
        self.assertEqual(expected_service_keys, active_result_keys(checked_discovery, at=at))
        checked_query = self._validate_record("query", corpus["query"], corpus=corpus, at=at)
        checked_result = self._validate_record("result", corpus["result"], corpus=corpus, at=at)
        checked_attempt = self._validate_record("outcomeAttempt", corpus["outcomeAttempt"], corpus=corpus, at=at)
        checked_receipt = self._validate_record("outcomeReceipt", corpus["outcomeReceipt"], corpus=corpus, at=at)
        self.assertEqual(expected["queryDigest"], checked_query["queryDigest"])
        self.assertEqual(expected["decisionRef"], checked_result["decisionRef"])
        self.assertEqual(expected["treatment"], checked_result["treatment"])
        self.assertEqual(expected["resultDigest"], checked_receipt["resultDigest"])
        self.assertEqual(checked_attempt["attemptDigest"], checked_receipt["attemptDigest"])
        self.assertEqual(expected["outcomeRef"], checked_receipt["outcomeRef"])

    def test_legacy_lifecycle_remains_validation_compatible(self) -> None:
        corpus = load_json(LEGACY_CORPUS_PATH)
        self.assertEqual(
            corpus["corpusDigest"],
            sha256_json(
                {
                    key: item
                    for key, item in corpus.items()
                    if key != "corpusDigest"
                }
            ),
        )
        at = datetime.fromisoformat(corpus["expected"]["validAt"]).astimezone(UTC)
        for name in ("discovery", "query", "result", "outcomeAttempt", "outcomeReceipt"):
            self._validate_record(name, corpus[name], corpus=corpus, at=at)

    def test_declared_lifecycle_mutations_fail_closed(self) -> None:
        corpus = self._corpus()
        at = datetime.fromisoformat(corpus["expected"]["validAt"]).astimezone(UTC)
        for case in corpus["invalidCases"]:
            with self.subTest(case=case["id"]):
                candidate = _replace_pointer(corpus[case["record"]], case["path"], case["value"])
                with self.assertRaises(PublicServiceContractError):
                    self._validate_record(case["record"], candidate, corpus=corpus, at=at)

    def test_any_platform_and_architecture_are_receiver_wildcards(self) -> None:
        corpus = self._corpus()
        at = datetime.fromisoformat(corpus["expected"]["validAt"]).astimezone(UTC)
        result = deepcopy(corpus["result"])
        result["selection"]["compatibility"]["platforms"] = ["any"]
        result["selection"]["compatibility"]["architectures"] = ["any"]
        unsigned = {
            key: value
            for key, value in result.items()
            if key not in {"resultDigest", "signature"}
        }
        result["resultDigest"] = sha256_json(unsigned)

        checked = validate_service_query_result(
            result,
            expected_query=corpus["query"],
            at=at,
        )

        self.assertEqual(["any"], checked["selection"]["compatibility"]["platforms"])
        self.assertEqual(["any"], checked["selection"]["compatibility"]["architectures"])

    def test_short_lived_records_expire_and_unknown_service_keys_fail_closed(self) -> None:
        corpus = self._corpus()
        expired = datetime.fromisoformat(corpus["expected"]["validAt"]).astimezone(UTC) + timedelta(minutes=6)
        for name in ("query", "result", "outcomeAttempt"):
            with self.subTest(record=name), self.assertRaisesRegex(PublicServiceContractError, "not current"):
                self._validate_record(name, corpus[name], corpus=corpus, at=expired)
        with self.assertRaisesRegex(PublicServiceContractError, "unknown"):
            validate_service_query_result(corpus["result"], public_keys={}, expected_query=corpus["query"])


if __name__ == "__main__":
    unittest.main()
