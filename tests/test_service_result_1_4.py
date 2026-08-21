from __future__ import annotations

from base64 import urlsafe_b64decode
from copy import deepcopy
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

import pytest

from limitless_library.contracts import load_json, sha256_json
from limitless_library.service_contracts import (
    SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_3,
    SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4,
    SERVICE_QUERY_RESULT_SCHEMA_VERSIONS,
    PublicServiceContractError,
    build_service_query,
    build_service_query_result,
    validate_service_query,
    validate_service_query_result,
)
from limitless_library.service_identity import InstallationSigner

CORPUS = Path(str(files("limitless_library.conformance").joinpath("public-service-lifecycle-1.1.json")))
ARTIFACT_CORPUS = Path(str(files("limitless_library.conformance").joinpath("public-service-artifact-result-1.4.json")))
NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
FORMAT = "limitless.exact-file-bundle/1.0"
MEDIA_TYPE = "application/vnd.limitless.exact-file-bundle+json"


def _fixture() -> tuple[dict, dict, dict, InstallationSigner, str]:
    corpus = load_json(CORPUS)
    query = build_service_query(
        request_id="request:artifact-1-4-conformance",
        objective=corpus["query"]["objective"],
        receiver_context=corpus["query"]["receiverContext"],
        requested_audiences=corpus["query"]["requestedAudiences"],
        requested_treatments=["exact-component"],
        execution_mode="service",
        history_mode="local-only",
        client_name="limitless-library-conformance",
        client_version="0.1.0",
        issued_at=NOW,
        supported_result_version=SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4,
    )
    selection = deepcopy(corpus["result"]["selection"])
    selection["immutable"].update({"byteLength": 401, "mediaType": MEDIA_TYPE, "format": FORMAT})
    return (
        query,
        selection,
        corpus["result"]["nextAction"],
        InstallationSigner.generate(),
        corpus["result"]["policy"]["policyDigest"],
    )


def _build(query: dict, selection: dict, next_action: dict, signer: InstallationSigner, policy: str) -> dict:
    return build_service_query_result(
        query=query,
        decision_ref="decision:artifact-1-4-conformance",
        authorized_scopes=["public"],
        policy_digest=policy,
        treatment="exact-component",
        selection=selection,
        next_action=next_action,
        index_generation=8,
        issued_at=NOW,
        signer=signer,
    )


def test_result_1_4_binds_and_advertises_exact_artifact_descriptor() -> None:
    query, selection, next_action, signer, policy = _fixture()

    result = _build(query, selection, next_action, signer, policy)
    checked = validate_service_query_result(
        result,
        public_keys={signer.key_id: signer.public_bytes()},
        expected_query=query,
        at=NOW,
    )

    assert checked["schemaVersion"] == SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4
    assert checked["selection"]["immutable"]["byteLength"] == 401
    assert SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4 in SERVICE_QUERY_RESULT_SCHEMA_VERSIONS

    for field, value in (
        ("byteLength", 402),
        ("mediaType", "application/octet-stream"),
        ("format", "unknown.bundle/1.0"),
    ):
        tampered = deepcopy(result)
        tampered["selection"]["immutable"][field] = value
        with pytest.raises(PublicServiceContractError):
            validate_service_query_result(
                tampered,
                public_keys={signer.key_id: signer.public_bytes()},
                expected_query=query,
                at=NOW,
            )


def test_static_result_1_4_vector_is_signed_and_cross_language_ready() -> None:
    corpus = load_json(ARTIFACT_CORPUS)
    assert corpus["corpusDigest"] == sha256_json({key: value for key, value in corpus.items() if key != "corpusDigest"})
    key = corpus["servicePublicKey"]
    public_key = urlsafe_b64decode(key["value"] + "=")
    at = datetime.fromisoformat(corpus["expected"]["validAt"]).astimezone(UTC)

    checked_query = validate_service_query(corpus["query"], at=at)
    checked_result = validate_service_query_result(
        corpus["result"],
        public_keys={key["keyId"]: public_key},
        expected_query=checked_query,
        at=at,
    )
    immutable = checked_result["selection"]["immutable"]
    for field in ("byteLength", "mediaType", "format"):
        assert immutable[field] == corpus["expected"][field]
    assert checked_result["resultDigest"] == corpus["expected"]["resultDigest"]

    for case in corpus["invalidCases"]:
        candidate = deepcopy(corpus[case["record"]])
        current = candidate
        for part in case["path"][:-1]:
            current = current[part]
        current[case["path"][-1]] = case["value"]
        with pytest.raises(PublicServiceContractError):
            if case["record"] == "query":
                validate_service_query(candidate, at=at)
            else:
                validate_service_query_result(
                    candidate,
                    public_keys={key["keyId"]: public_key},
                    expected_query=checked_query,
                    at=at,
                )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("byteLength", 0),
        ("byteLength", 64 * 1024 * 1024 + 1),
        ("mediaType", "application/octet-stream"),
        ("format", "unknown.bundle/1.0"),
    ],
)
def test_result_1_4_rejects_unbound_or_unsupported_artifact_descriptor(
    field: str,
    value: object,
) -> None:
    query, selection, next_action, signer, policy = _fixture()
    selection["immutable"][field] = value

    with pytest.raises(PublicServiceContractError):
        _build(query, selection, next_action, signer, policy)


@pytest.mark.parametrize("field", ["byteLength", "mediaType", "format"])
def test_result_1_4_requires_every_artifact_descriptor_field(field: str) -> None:
    query, selection, next_action, signer, policy = _fixture()
    del selection["immutable"][field]

    with pytest.raises(PublicServiceContractError, match="unsupported shape"):
        _build(query, selection, next_action, signer, policy)


def test_result_generations_cannot_be_mixed_or_smuggled_into_1_3() -> None:
    query, selection, next_action, signer, policy = _fixture()
    mixed = {key: value for key, value in query.items() if key != "queryDigest"}
    mixed["client"] = {
        **mixed["client"],
        "supportedResults": [
            SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_3,
            SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4,
        ],
    }
    with pytest.raises(PublicServiceContractError, match="mixed"):
        validate_service_query(
            {**mixed, "queryDigest": sha256_json(mixed)},
            at=NOW,
        )

    legacy = build_service_query(
        request_id="request:artifact-1-3-descriptor-smuggle",
        objective=query["objective"],
        receiver_context=query["receiverContext"],
        requested_audiences=query["requestedAudiences"],
        requested_treatments=["exact-component"],
        execution_mode="service",
        history_mode="local-only",
        client_name="limitless-library-conformance",
        client_version="0.1.0",
        issued_at=NOW,
        supported_result_version=SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_3,
    )
    with pytest.raises(PublicServiceContractError, match="unsupported shape"):
        _build(legacy, selection, next_action, signer, policy)
