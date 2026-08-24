from __future__ import annotations

from base64 import urlsafe_b64decode
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from email.message import Message
from hashlib import sha256
from importlib.resources import files
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from limitless_library.contracts import (
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_json,
    strict_json_loads,
)
from limitless_library.exact_file_bundle import build_exact_file_bundle
from limitless_library.public_admission_contracts import build_contribution_policy_acceptance
from limitless_library.public_submission_contracts import (
    build_content_transfer_grant,
    build_submission_intent,
    build_submission_plan,
)
from limitless_library.service_connector import (
    MAX_REMOTE_ARTIFACT_BYTES,
    MAX_REMOTE_STREAMED_ARTIFACT_BYTES,
    ServiceConnector,
    ServiceConnectorError,
    ServiceHttpResponse,
    ServiceProfile,
    ServiceStreamResponse,
    ServiceUnavailableError,
    ServiceUsageExceededError,
    UrllibServiceTransport,
    VerifiedService,
)
from limitless_library.service_contracts import (
    SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4,
    SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_5,
    build_service_discovery,
    build_service_query,
    build_service_query_result,
    validate_service_root_key_transition_set,
)
from limitless_library.service_identity import InstallationSigner

CORPUS = Path(str(files("limitless_library.conformance").joinpath("public-service-lifecycle-1.1.json")))
AT = datetime(2026, 8, 20, 22, 0, 30, tzinfo=UTC)


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


class MemoryTransport:
    def __init__(self, corpus: dict[str, Any]) -> None:
        self.corpus = corpus
        self.status = 200
        self.result = corpus["result"]
        self.response_headers = {"content-type": "application/json"}
        self.error_body: dict[str, Any] = {"error": "unavailable"}
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "maximumBytes": maximum_bytes,
                "timeoutSeconds": timeout_seconds,
            }
        )
        if self.status != 200:
            return ServiceHttpResponse(
                status=self.status,
                headers={"content-type": "application/json"},
                body=canonical_json_bytes(self.error_body),
            )
        if url.endswith("/.well-known/limitless-root-transitions"):
            value = {
                "schemaVersion": "limitless.service-root-key-transition-set/1.0",
                "serviceId": self.corpus["discovery"]["serviceId"],
                "transitions": [],
                "latestSequence": 0,
                "latestTransitionDigest": None,
            }
        elif url.endswith("/.well-known/limitless-service"):
            value = self.corpus["discovery"]
        elif url.endswith("/v1/queries"):
            assert body == canonical_json_bytes(self.corpus["query"])
            value = self.result
        else:
            raise AssertionError(f"unexpected URL: {url}")
        return ServiceHttpResponse(
            status=200,
            headers=self.response_headers,
            body=canonical_json_bytes(value),
        )


class ArtifactTransport:
    def __init__(self, uri: str, body: bytes, digest: str) -> None:
        self.uri = uri
        self.body = body
        self.status = 200
        self.headers = {
            "content-type": "application/octet-stream",
            "content-length": str(len(body)),
            "x-limitless-artifact-digest": digest,
        }
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse:
        assert url == self.uri
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "maximumBytes": maximum_bytes,
                "timeoutSeconds": timeout_seconds,
            }
        )
        return ServiceHttpResponse(
            status=self.status,
            headers=self.headers,
            body=self.body,
        )


class StreamingArtifactTransport:
    def __init__(self, uri: str, body: bytes, digest: str) -> None:
        self.uri = uri
        self.body = body
        self.status = 200
        self.headers = {
            "content-type": "application/vnd.limitless.exact-file-bundle+json",
            "content-length": str(len(body)),
            "x-limitless-artifact-digest": digest,
        }
        self.fail_after_first_chunk = False
        self.calls: list[dict[str, Any]] = []

    def download_file(
        self,
        url: str,
        *,
        headers: dict[str, str],
        destination: Any,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceStreamResponse:
        assert url == self.uri
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "maximumBytes": maximum_bytes,
                "timeoutSeconds": timeout_seconds,
            }
        )
        total = 0
        digest = sha256()
        for offset in range(0, len(self.body), 128 * 1024):
            chunk = self.body[offset : offset + 128 * 1024]
            destination.write(chunk)
            total += len(chunk)
            digest.update(chunk)
            if self.fail_after_first_chunk:
                raise ServiceUnavailableError("managed service is unavailable; continue locally")
        return ServiceStreamResponse(
            status=self.status,
            headers=self.headers,
            byte_length=total,
            content_digest="sha256:" + digest.hexdigest(),
        )


class PublicationTransport:
    def __init__(
        self,
        *,
        plan_signer: InstallationSigner,
        intent: dict[str, Any],
        policy_revision: str,
        policy_digest: str,
    ) -> None:
        self.plan_signer = plan_signer
        self.intent = intent
        self.policy_revision = policy_revision
        self.policy_digest = policy_digest
        self.plan: dict[str, Any] | None = None
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse:
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        if url.endswith("/v1/publication-policy/acceptances"):
            assert body is not None
            request = strict_json_loads(body.decode("utf-8"))
            assert request["policyDigest"] == self.policy_digest
            value = {
                "schemaVersion": "limitless.public-policy-acceptance-response/1.0",
                "acceptanceRef": "public-policy-acceptance:fixture",
                "policyRevision": self.policy_revision,
                "policyDigest": self.policy_digest,
                "acceptedAt": AT.replace(second=0).isoformat().replace("+00:00", "Z"),
            }
        elif url.endswith("/v1/submissions"):
            assert body == canonical_json_bytes(self.intent)
            self.plan = build_submission_plan(
                intent=self.intent,
                known_object_digests=(),
                review_stages=("compatibility", "quality", "rights", "security"),
                issued_at=AT.replace(second=0),
                signer=self.plan_signer,
            )
            value = self.plan
        elif url.endswith("/content-authorizations"):
            assert body is None and self.plan is not None
            value = build_content_transfer_grant(
                intent=self.intent,
                plan=self.plan,
                tenant_id=self.intent["publisher"]["authorityId"],
                publisher_id=self.intent["publisher"]["publisherId"],
                audience="public",
                objects=self.plan["requiredObjects"],
                issued_at=AT.replace(second=0),
                signer=self.plan_signer,
            )
        elif url.endswith("/admission-status"):
            assert body is None and self.plan is not None
            value = {
                "schemaVersion": "limitless.public-admission-status/1.0",
                "admissionRef": "public-admission:fixture",
                "submissionRef": self.plan["submissionRef"],
                "state": "observed",
                "releaseRef": None,
                "reasonCodes": [],
                "generation": 1,
                "updatedAt": AT.replace(second=0).isoformat().replace("+00:00", "Z"),
            }
        else:
            raise AssertionError(f"unexpected publication URL: {url}")
        encoded = canonical_json_bytes(value)
        assert len(encoded) <= maximum_bytes and timeout_seconds > 0
        return ServiceHttpResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=encoded,
        )

    def upload_file(
        self,
        url: str,
        *,
        headers: dict[str, str],
        source: Any,
        byte_length: int,
        expected_digest: str,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse:
        content = source.read()
        assert isinstance(content, bytes)
        assert len(content) == byte_length
        assert sha256_bytes(content) == expected_digest
        assert self.plan is not None
        descriptor = next(item for item in self.plan["requiredObjects"] if item["digest"] == expected_digest)
        self.calls.append({"method": "PUT", "url": url, "headers": dict(headers), "body": None})
        value = {
            "schemaVersion": "limitless.service-content-transfer-result/1.0",
            "grantId": "grant:" + "3" * 32,
            "submissionRef": self.plan["submissionRef"],
            "role": descriptor["role"],
            "digest": descriptor["digest"],
            "byteLength": descriptor["byteLength"],
            "disposition": "created",
        }
        encoded = canonical_json_bytes(value)
        assert len(encoded) <= maximum_bytes and timeout_seconds > 0
        return ServiceHttpResponse(
            status=201,
            headers={"content-type": "application/json"},
            body=encoded,
        )


class StaticResponse:
    def __init__(self, status: int, headers: Message, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.closed = False
        self.offset = 0
        self.read_sizes: list[int] = []

    def read(self, maximum_bytes: int) -> bytes:
        self.read_sizes.append(maximum_bytes)
        value = self.body[self.offset : self.offset + maximum_bytes]
        self.offset += len(value)
        return value

    def close(self) -> None:
        self.closed = True


class StaticOpener:
    def __init__(self, response: StaticResponse) -> None:
        self.response = response

    def open(self, _request: object, *, timeout: float) -> StaticResponse:
        assert timeout > 0
        return self.response


class UploadResponse:
    def __init__(self, body: bytes) -> None:
        self.status = 201
        self.body = body
        self.closed = False

    def getheaders(self) -> list[tuple[str, str]]:
        return [
            ("content-type", "application/json"),
            ("content-length", str(len(self.body))),
        ]

    def read(self, maximum_bytes: int) -> bytes:
        return self.body[:maximum_bytes]

    def close(self) -> None:
        self.closed = True


class UploadConnection:
    def __init__(self, response: UploadResponse) -> None:
        self.response = response
        self.method = ""
        self.path = ""
        self.headers: dict[str, str] = {}
        self.chunks: list[bytes] = []
        self.closed = False

    def putrequest(self, method: str, path: str, *, skip_accept_encoding: bool) -> None:
        assert skip_accept_encoding is True
        self.method = method
        self.path = path

    def putheader(self, name: str, value: str) -> None:
        self.headers[name] = value

    def endheaders(self) -> None:
        return None

    def send(self, value: bytes) -> None:
        self.chunks.append(value)

    def getresponse(self) -> UploadResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def _profile(corpus: dict[str, Any], *, token: str | None = None) -> ServiceProfile:
    root = corpus["rootPublicKey"]
    discovery = corpus["discovery"]
    return ServiceProfile(
        api_base_url=discovery["apiBaseUrl"],
        service_id=discovery["serviceId"],
        root_key_id=root["keyId"],
        root_public_key=_decode(root["publicKey"]),
        accepted_policy_digest=discovery["dataUsePolicy"]["digest"],
        requested_audiences=tuple(corpus["query"]["requestedAudiences"]),
        access_token=token,
    )


def _artifact_fixture(
    tmp_path: Path,
    *,
    token: str | None = "test-access-token-value",
    result_policy_digest: str | None = None,
) -> tuple[ServiceConnector, ArtifactTransport, dict[str, Any], dict[str, Any], bytes, Path]:
    corpus = load_json(CORPUS)
    artifact = b'{"schemaVersion":"example.bundle/1.0","files":[]}\n'
    digest = sha256_bytes(artifact)
    uri = "https://objects.limitlesslibrary.com/v1/public/deliveries/public-delivery-grant:sha256:" + "7" * 64
    selection = deepcopy(corpus["result"]["selection"])
    selection["immutable"] = {
        **selection["immutable"],
        "uri": uri,
        "digest": digest,
    }
    signer = InstallationSigner.generate()
    result = build_service_query_result(
        query=corpus["query"],
        decision_ref="decision:artifact-staging-test-001",
        authorized_scopes=corpus["result"]["authorizedAudiences"],
        policy_digest=result_policy_digest or corpus["discovery"]["dataUsePolicy"]["digest"],
        treatment="exact-component",
        selection=selection,
        next_action=corpus["result"]["nextAction"],
        index_generation=12,
        issued_at=AT.replace(second=0),
        signer=signer,
        ttl_seconds=120,
    )
    transport = ArtifactTransport(uri, artifact, digest)
    connector = ServiceConnector(
        _profile(corpus, token=token),
        transport=transport,
        clock=lambda: AT,
    )
    connector._cached = VerifiedService(
        discovery=corpus["discovery"],
        root_transitions={
            "schemaVersion": "limitless.service-root-key-transition-set/1.0",
            "serviceId": corpus["discovery"]["serviceId"],
            "transitions": [],
            "latestSequence": 0,
            "latestTransitionDigest": None,
        },
        result_keys={signer.key_id: signer.public_bytes()},
    )
    connector._cached_until = float("inf")
    return connector, transport, corpus["query"], result, artifact, tmp_path / "selected.bin"


def _streaming_artifact_fixture(
    tmp_path: Path,
) -> tuple[
    ServiceConnector,
    StreamingArtifactTransport,
    dict[str, Any],
    dict[str, Any],
    bytes,
    Path,
]:
    corpus = load_json(CORPUS)
    artifact = build_exact_file_bundle({"payload.bin": b"x" * (300 * 1024)})
    digest = sha256_bytes(artifact)
    uri = "https://objects.limitlesslibrary.com/v1/public/deliveries/public-delivery-grant:sha256:" + "8" * 64
    query = build_service_query(
        request_id="request:artifact-streaming-test-001",
        objective=corpus["query"]["objective"],
        receiver_context=corpus["query"]["receiverContext"],
        requested_audiences=corpus["query"]["requestedAudiences"],
        requested_treatments=["exact-component"],
        execution_mode="service",
        history_mode="local-only",
        client_name="limitless-library-streaming-test",
        client_version="0.1.0",
        issued_at=AT.replace(second=0),
        supported_result_version=SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4,
    )
    selection = deepcopy(corpus["result"]["selection"])
    selection["immutable"] = {
        **selection["immutable"],
        "uri": uri,
        "digest": digest,
        "byteLength": len(artifact),
        "mediaType": "application/vnd.limitless.exact-file-bundle+json",
        "format": "limitless.exact-file-bundle/1.0",
    }
    signer = InstallationSigner.generate()
    result = build_service_query_result(
        query=query,
        decision_ref="decision:artifact-streaming-test-001",
        authorized_scopes=corpus["result"]["authorizedAudiences"],
        policy_digest=corpus["discovery"]["dataUsePolicy"]["digest"],
        treatment="exact-component",
        selection=selection,
        next_action=corpus["result"]["nextAction"],
        index_generation=13,
        issued_at=AT.replace(second=0),
        signer=signer,
        ttl_seconds=120,
    )
    transport = StreamingArtifactTransport(uri, artifact, digest)
    connector = ServiceConnector(
        _profile(corpus, token="test-access-token-value"),
        transport=transport,
        clock=lambda: AT,
    )
    connector._cached = VerifiedService(
        discovery=corpus["discovery"],
        root_transitions={
            "schemaVersion": "limitless.service-root-key-transition-set/1.0",
            "serviceId": corpus["discovery"]["serviceId"],
            "transitions": [],
            "latestSequence": 0,
            "latestTransitionDigest": None,
        },
        result_keys={signer.key_id: signer.public_bytes()},
    )
    connector._cached_until = float("inf")
    return connector, transport, query, result, artifact, tmp_path / "streamed.bin"


def _delivery_1_5_fixture(
    tmp_path: Path,
    *,
    mode: str,
) -> tuple[ServiceConnector, StreamingArtifactTransport, dict[str, Any], dict[str, Any], Path]:
    corpus = load_json(CORPUS)
    artifact = build_exact_file_bundle({"payload.bin": b"delivery-1.5"})
    artifact_digest = sha256_bytes(artifact)
    hexadecimal = artifact_digest[7:]
    uri = (
        f"https://objects.limitlesslibrary.com/v1/sha256/{hexadecimal[:2]}/{hexadecimal}.bin"
        if mode == "public-edge"
        else "https://api.limitlesslibrary.com/v1/protected/deliveries/delivery:test"
    )
    query = build_service_query(
        request_id=f"request:artifact-delivery-{mode}",
        objective=corpus["query"]["objective"],
        receiver_context=corpus["query"]["receiverContext"],
        requested_audiences=corpus["query"]["requestedAudiences"],
        requested_treatments=["exact-component"],
        execution_mode="service",
        history_mode="local-only",
        client_name="limitless-library-delivery-test",
        client_version="0.1.0",
        issued_at=AT.replace(second=0),
        supported_result_version=SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_5,
    )
    delivery: dict[str, Any]
    if mode == "public-edge":
        delivery = {
            "mode": "public-edge",
            "objectRef": "public-edge-object:"
            + sha256_json({"authority": "limitless-public-edge/v1", "artifactDigest": artifact_digest})[7:39],
            "promotionRef": "public-edge-promotion:" + "4" * 32,
            "promotionReceiptDigest": "sha256:" + "5" * 64,
            "cacheControl": "public, max-age=31536000, immutable",
        }
    else:
        delivery = {
            "mode": "protected-capability",
            "authorization": {
                "header": "Limitless-Capability",
                "value": "A" * 43,
            },
        }
    selection = deepcopy(corpus["result"]["selection"])
    legacy = selection["immutable"]
    selection["immutable"] = {
        "kind": "artifact",
        "uri": uri,
        "revision": legacy["revision"],
        "digest": artifact_digest,
        "byteLength": len(artifact),
        "mediaType": "application/vnd.limitless.exact-file-bundle+json",
        "format": "limitless.exact-file-bundle/1.0",
        "delivery": delivery,
    }
    signer = InstallationSigner.generate()
    result = build_service_query_result(
        query=query,
        decision_ref=f"decision:artifact-delivery-{mode}",
        authorized_scopes=corpus["result"]["authorizedAudiences"],
        policy_digest=corpus["discovery"]["dataUsePolicy"]["digest"],
        treatment="exact-component",
        selection=selection,
        next_action=corpus["result"]["nextAction"],
        index_generation=14,
        issued_at=AT.replace(second=0),
        signer=signer,
        ttl_seconds=120,
    )
    transport = StreamingArtifactTransport(uri, artifact, artifact_digest)
    connector = ServiceConnector(
        _profile(corpus, token="test-access-token-value"),
        transport=transport,
        clock=lambda: AT,
    )
    connector._cached = VerifiedService(
        discovery={**corpus["discovery"], "resultVersions": [SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_5]},
        root_transitions={
            "schemaVersion": "limitless.service-root-key-transition-set/1.0",
            "serviceId": corpus["discovery"]["serviceId"],
            "transitions": [],
            "latestSequence": 0,
            "latestTransitionDigest": None,
        },
        result_keys={signer.key_id: signer.public_bytes()},
    )
    connector._cached_until = float("inf")
    return connector, transport, query, result, tmp_path / f"delivery-{mode}.bin"


def test_opted_in_query_verifies_discovery_request_and_signed_result() -> None:
    corpus = load_json(CORPUS)
    transport = MemoryTransport(corpus)
    connector = ServiceConnector(
        _profile(corpus, token="test-access-token-value"),
        transport=transport,
        clock=lambda: AT,
    )

    result = connector.query(corpus["query"])

    assert result == corpus["result"]
    assert [call["method"] for call in transport.calls] == ["GET", "GET", "POST"]
    assert all("authorization" not in call["headers"] for call in transport.calls[:2])
    assert transport.calls[2]["headers"]["authorization"] == "Bearer test-access-token-value"
    assert connector.profile.public_summary()["authenticated"] is True
    assert "test-access-token-value" not in repr(connector.profile)


def test_discovery_is_cached_but_a_tampered_result_still_fails_closed() -> None:
    corpus = load_json(CORPUS)
    transport = MemoryTransport(corpus)
    connector = ServiceConnector(
        _profile(corpus),
        transport=transport,
        clock=lambda: AT,
    )
    connector.inspect()
    connector.inspect()
    assert len(transport.calls) == 2

    changed = deepcopy(corpus["result"])
    changed["selection"]["immutable"]["uri"] = "https://attacker.example/object"
    transport.result = changed
    with pytest.raises(ServiceConnectorError, match="result"):
        connector.query(corpus["query"])


def test_policy_endpoint_and_scope_cannot_silently_drift() -> None:
    corpus = load_json(CORPUS)
    transport = MemoryTransport(corpus)
    profile = _profile(corpus)
    object.__setattr__(profile, "accepted_policy_digest", "sha256:" + "0" * 64)
    connector = ServiceConnector(profile, transport=transport, clock=lambda: AT)

    with pytest.raises(ServiceConnectorError, match="accepted profile"):
        connector.inspect()

    valid = ServiceConnector(
        _profile(corpus),
        transport=MemoryTransport(corpus),
        clock=lambda: AT,
    )
    broader = deepcopy(corpus["query"])
    broader["requestedAudiences"] = ["private", "public"]
    with pytest.raises(ServiceConnectorError, match="query"):
        valid.query(broader)


def test_signed_query_result_cannot_substitute_the_accepted_policy() -> None:
    corpus = load_json(CORPUS)
    signer = InstallationSigner.generate()
    result = build_service_query_result(
        query=corpus["query"],
        decision_ref="decision:substituted-policy-test-001",
        authorized_scopes=corpus["result"]["authorizedAudiences"],
        policy_digest="sha256:" + "8" * 64,
        treatment=corpus["result"]["treatment"],
        selection=corpus["result"]["selection"],
        next_action=corpus["result"]["nextAction"],
        index_generation=12,
        issued_at=AT.replace(second=0),
        signer=signer,
        ttl_seconds=120,
    )
    transport = MemoryTransport(corpus)
    transport.result = result
    connector = ServiceConnector(
        _profile(corpus, token="test-access-token-value"),
        transport=transport,
        clock=lambda: AT,
    )
    connector._cached = VerifiedService(
        discovery=corpus["discovery"],
        root_transitions={
            "schemaVersion": "limitless.service-root-key-transition-set/1.0",
            "serviceId": corpus["discovery"]["serviceId"],
            "transitions": [],
            "latestSequence": 0,
            "latestTransitionDigest": None,
        },
        result_keys={signer.key_id: signer.public_bytes()},
    )
    connector._cached_until = float("inf")

    with pytest.raises(ServiceConnectorError, match="opted-in profile"):
        connector.query(corpus["query"])


def test_remote_unavailability_explicitly_returns_control_to_local_reuse() -> None:
    corpus = load_json(CORPUS)
    transport = MemoryTransport(corpus)
    transport.status = 503
    connector = ServiceConnector(
        _profile(corpus),
        transport=transport,
        clock=lambda: AT,
    )

    with pytest.raises(ServiceUnavailableError, match="continue locally"):
        connector.inspect()


def test_free_usage_limit_is_distinct_from_service_unavailability() -> None:
    corpus = load_json(CORPUS)
    transport = MemoryTransport(corpus)
    transport.status = 429
    transport.error_body = {
        "error": "free-usage-exceeded",
        "resetAt": "2026-08-20T22:01:00Z",
        "upgradeUrl": "https://limitlesslibrary.com/#contact",
    }
    connector = ServiceConnector(
        _profile(corpus),
        transport=transport,
        clock=lambda: AT,
    )

    with pytest.raises(ServiceUsageExceededError) as raised:
        connector.inspect()

    assert raised.value.reset_at == "2026-08-20T22:01:00Z"
    assert raised.value.upgrade_url == "https://limitlesslibrary.com/#contact"


@pytest.mark.parametrize(
    "body",
    [
        {"error": "rate-limited"},
        {
            "error": "free-usage-exceeded",
            "resetAt": "2026-08-20T22:01:00Z",
            "upgradeUrl": "https://attacker.example/upgrade",
        },
    ],
)
def test_untrusted_429_details_remain_generic_unavailability(body: dict[str, Any]) -> None:
    corpus = load_json(CORPUS)
    transport = MemoryTransport(corpus)
    transport.status = 429
    transport.error_body = body
    connector = ServiceConnector(
        _profile(corpus),
        transport=transport,
        clock=lambda: AT,
    )

    with pytest.raises(ServiceUnavailableError, match="continue locally") as raised:
        connector.inspect()

    assert not isinstance(raised.value, ServiceUsageExceededError)


def test_json_endpoints_retain_their_strict_content_type_boundary() -> None:
    corpus = load_json(CORPUS)
    transport = MemoryTransport(corpus)
    transport.response_headers = {"Content-Type": "application/octet-stream"}
    connector = ServiceConnector(
        _profile(corpus),
        transport=transport,
        clock=lambda: AT,
    )

    with pytest.raises(ServiceConnectorError, match="content type"):
        connector.inspect()


def test_profile_json_is_exact_and_never_serializes_the_access_token() -> None:
    corpus = load_json(CORPUS)
    root = corpus["rootPublicKey"]
    discovery = corpus["discovery"]
    profile = ServiceProfile.from_json(
        {
            "schemaVersion": "limitless.service-profile/1.1",
            "apiBaseUrl": discovery["apiBaseUrl"],
            "serviceId": discovery["serviceId"],
            "rootKey": root,
            "acceptedPolicyDigest": discovery["dataUsePolicy"]["digest"],
            "executionMode": "service",
            "defaultAudience": "private",
            "historyMode": "local-only",
            "requestedAudiences": ["public"],
        },
        access_token="test-access-token-value",
    )

    summary = profile.public_summary()
    assert summary["defaultAudience"] == "private"
    assert summary["historyMode"] == "local-only"
    assert summary["requestedAudiences"] == ["public"]
    assert summary["rootKeyFingerprint"].startswith("sha256:")
    assert "access" not in "".join(summary).lower()

    invalid = {**summary, "schemaVersion": "limitless.service-profile/1.1"}
    with pytest.raises(ValueError, match="shape"):
        ServiceProfile.from_json(invalid)


def test_query_builder_emits_only_the_current_public_policy_vocabulary() -> None:
    corpus = load_json(CORPUS)
    connector = ServiceConnector(
        _profile(corpus),
        transport=MemoryTransport(corpus),
        clock=lambda: AT,
    )

    query = connector.build_query(
        request_id="request:current-client-vocabulary-001",
        objective="Find one compatible reviewed customization.",
        receiver_context=corpus["query"]["receiverContext"],
    )

    assert query["schemaVersion"] == "limitless.service-query/1.1"
    assert query["executionMode"] == "service"
    assert query["historyMode"] == "local-only"
    assert query["requestedAudiences"] == ["circle", "public"]
    assert query["client"]["supportedResults"] == ["limitless.service-query-result/1.3"]
    assert "dataUseMode" not in query
    assert "requestedScopes" not in query
    assert "exchange" not in canonical_json_bytes(query).decode("utf-8")


def test_query_builder_negotiates_current_result_from_current_discovery() -> None:
    corpus = load_json(CORPUS)
    root_signer = InstallationSigner.generate()
    result_signer = InstallationSigner.generate()
    policy_digest = sha256_json({"policy": "current-discovery"})
    discovery = build_service_discovery(
        service_id="service:current-discovery-test",
        api_base_url="https://api.limitlesslibrary.com",
        signing_keys=[
            (
                result_signer.key_id,
                result_signer.public_bytes(),
                AT - timedelta(days=1),
                AT + timedelta(days=1),
            )
        ],
        data_use_policy_url="https://limitlesslibrary.com/data-use",
        data_use_policy_digest=policy_digest,
        publication_policy_revision="policy:current-discovery-test",
        publication_policy_url="https://limitlesslibrary.com/publication-policy",
        publication_policy_digest=sha256_json({"policy": "publication"}),
        rate_limit_class="public-test",
        issued_at=AT.replace(second=0),
        root_signer=root_signer,
    )
    current = {**corpus, "discovery": discovery}
    connector = ServiceConnector(
        ServiceProfile(
            api_base_url=discovery["apiBaseUrl"],
            service_id=discovery["serviceId"],
            root_key_id=root_signer.key_id,
            root_public_key=root_signer.public_bytes(),
            accepted_policy_digest=policy_digest,
            requested_audiences=("public",),
        ),
        transport=MemoryTransport(current),
        clock=lambda: AT,
    )

    query = connector.build_query(
        request_id="request:current-result-negotiation-001",
        objective="Find one compatible reviewed customization.",
        receiver_context=corpus["query"]["receiverContext"],
    )

    assert query["client"]["supportedResults"] == ["limitless.service-query-result/1.5"]


def test_legacy_profile_is_mapped_without_re_emitting_deprecated_vocabulary() -> None:
    corpus = load_json(CORPUS)
    root = corpus["rootPublicKey"]
    discovery = corpus["discovery"]
    profile = ServiceProfile.from_json(
        {
            "schemaVersion": "limitless.service-profile/1.0",
            "apiBaseUrl": discovery["apiBaseUrl"],
            "serviceId": discovery["serviceId"],
            "rootKey": root,
            "acceptedPolicyDigest": discovery["dataUsePolicy"]["digest"],
            "dataUseMode": "confidential",
            "requestedScopes": ["exchange", "public"],
        }
    )
    connector = ServiceConnector(
        profile,
        transport=MemoryTransport(corpus),
        clock=lambda: AT,
    )

    encoded_profile = canonical_json_bytes(profile.public_summary()).decode("utf-8")
    query = connector.build_query(
        request_id="request:legacy-profile-mapping-001",
        objective="Find one compatible reviewed customization.",
        receiver_context=corpus["query"]["receiverContext"],
    )

    assert profile.default_audience == "private"
    assert profile.history_mode == "local-only"
    assert profile.requested_audiences == ("circle", "public")
    assert "confidential" not in encoded_profile
    assert "exchange" not in canonical_json_bytes(query).decode("utf-8")


def test_connector_selects_the_effective_root_without_accepting_a_future_one() -> None:
    corpus = load_json(
        Path(str(files("limitless_library.conformance").joinpath("public-service-root-transition-1.0.json")))
    )
    trusted = corpus["trustedRootKey"]
    roots = {trusted["keyId"]: _decode(trusted["publicKey"])}
    transitions = validate_service_root_key_transition_set(corpus["record"], trusted_root_keys=roots)
    effective = datetime.fromisoformat(corpus["expected"]["effectiveAt"])

    assert (
        ServiceConnector._current_roots(
            transitions,
            initial_roots=roots,
            at=effective - timedelta(seconds=1),
        )
        == roots
    )
    current = corpus["expected"]["currentRootKey"]
    assert ServiceConnector._current_roots(
        transitions,
        initial_roots=roots,
        at=effective,
    ) == {current["keyId"]: _decode(current["publicKey"])}


def test_default_transport_rejects_non_https_before_network_access() -> None:
    transport = UrllibServiceTransport()

    with pytest.raises(ServiceConnectorError, match="URL"):
        transport.request(
            "GET",
            "http://api.example/.well-known/limitless-service",
            headers={"accept": "application/json"},
            body=None,
            maximum_bytes=1024,
            timeout_seconds=1,
        )


def test_default_transport_preserves_availability_status_without_trusting_an_error_body() -> None:
    headers = Message()
    headers["content-type"] = "text/html"
    response = StaticResponse(503, headers, b"temporary intermediary failure")
    transport = UrllibServiceTransport()
    transport._opener = StaticOpener(response)

    result = transport.request(
        "GET",
        "https://api.example/.well-known/limitless-service",
        headers={"accept": "application/json"},
        body=None,
        maximum_bytes=1024,
        timeout_seconds=1,
    )

    assert result.status == 503
    assert response.closed is True


def test_default_transport_rejects_duplicate_success_headers() -> None:
    headers = Message()
    headers["content-type"] = "application/json"
    headers["content-type"] = "application/json"
    response = StaticResponse(200, headers, b"{}")
    transport = UrllibServiceTransport()
    transport._opener = StaticOpener(response)

    with pytest.raises(ServiceConnectorError, match="duplicate"):
        transport.request(
            "GET",
            "https://api.example/.well-known/limitless-service",
            headers={"accept": "application/json"},
            body=None,
            maximum_bytes=1024,
            timeout_seconds=1,
        )
    assert response.closed is True


def test_default_transport_preserves_a_bounded_octet_stream_for_artifact_validation() -> None:
    headers = Message()
    headers["content-type"] = "application/octet-stream"
    headers["content-length"] = "8"
    response = StaticResponse(200, headers, b"artifact")
    transport = UrllibServiceTransport()
    transport._opener = StaticOpener(response)

    result = transport.request(
        "GET",
        "https://objects.example/v1/delivery/example",
        headers={"accept": "application/octet-stream"},
        body=None,
        maximum_bytes=MAX_REMOTE_ARTIFACT_BYTES,
        timeout_seconds=1,
    )

    assert result.body == b"artifact"
    assert result.headers["content-type"] == "application/octet-stream"
    assert response.closed is True


def test_default_transport_streams_download_in_bounded_chunks() -> None:
    body = b"x" * (300 * 1024)
    digest = sha256_bytes(body)
    headers = Message()
    headers["content-type"] = "application/vnd.limitless.exact-file-bundle+json"
    headers["content-length"] = str(len(body))
    headers["x-limitless-artifact-digest"] = digest
    response = StaticResponse(200, headers, body)
    transport = UrllibServiceTransport()
    transport._opener = StaticOpener(response)
    destination = BytesIO()

    result = transport.download_file(
        "https://objects.example/v1/delivery/example",
        headers={"accept": "application/vnd.limitless.exact-file-bundle+json"},
        destination=destination,
        maximum_bytes=MAX_REMOTE_STREAMED_ARTIFACT_BYTES,
        timeout_seconds=5,
    )

    assert destination.getvalue() == body
    assert result.byte_length == len(body)
    assert result.content_digest == digest
    assert max(response.read_sizes) == 128 * 1024
    assert response.closed is True


def test_default_transport_streams_upload_and_rehashes_while_sending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result_body = canonical_json_bytes({"status": "created"})
    response = UploadResponse(result_body)
    connection = UploadConnection(response)
    transport = UrllibServiceTransport()
    monkeypatch.setattr(
        "limitless_library.service_connector.http.client.HTTPSConnection",
        lambda *_args, **_kwargs: connection,
    )
    content = b"x" * (300 * 1024)
    digest = sha256_bytes(content)

    result = transport.upload_file(
        "https://api.example/v1/submissions/submission:" + "1" * 32 + "/objects/artifact/" + digest,
        headers={
            "content-type": "application/octet-stream",
            "content-length": str(len(content)),
        },
        source=BytesIO(content),
        byte_length=len(content),
        expected_digest=digest,
        maximum_bytes=1024,
        timeout_seconds=5,
    )

    assert result.body == result_body
    assert connection.method == "PUT"
    assert b"".join(connection.chunks) == content
    assert max(map(len, connection.chunks)) == 128 * 1024
    assert connection.closed is True
    assert response.closed is True

    changed = bytearray(content)
    changed[-1] ^= 1
    with pytest.raises(ServiceConnectorError, match="bytes differ"):
        transport.upload_file(
            "https://api.example/v1/upload",
            headers={"content-length": str(len(changed))},
            source=BytesIO(bytes(changed)),
            byte_length=len(changed),
            expected_digest=digest,
            maximum_bytes=1024,
            timeout_seconds=5,
        )


def test_signed_artifact_is_fetched_with_header_authority_and_staged_without_secrets(
    tmp_path: Path,
) -> None:
    connector, transport, query, result, artifact, destination = _artifact_fixture(tmp_path)

    staged = connector.fetch_selected_artifact(
        query=query,
        result=result,
        destination=destination,
    )

    assert destination.read_bytes() == artifact
    assert destination.stat().st_mode & 0o777 == 0o600
    assert staged["digest"] == sha256_bytes(artifact)
    assert staged["byteLength"] == len(artifact)
    assert staged["path"] == str(destination)
    assert transport.calls == [
        {
            "method": "GET",
            "url": result["selection"]["immutable"]["uri"],
            "headers": {
                "accept": "application/octet-stream",
                "authorization": "Bearer test-access-token-value",
                "user-agent": "limitless-library/0.1.0a0",
                "Limitless-Capability": result["selection"]["immutable"]["authorization"]["value"],
            },
            "body": None,
            "maximumBytes": MAX_REMOTE_ARTIFACT_BYTES,
            "timeoutSeconds": 5.0,
        }
    ]
    public_output = canonical_json_bytes(staged).decode("utf-8")
    assert "test-access-token-value" not in public_output
    assert result["selection"]["immutable"]["authorization"]["value"] not in public_output


@pytest.mark.parametrize("mode", ["public-edge", "protected-capability"])
def test_result_1_5_enforces_delivery_lane_headers(tmp_path: Path, mode: str) -> None:
    connector, transport, query, result, destination = _delivery_1_5_fixture(tmp_path, mode=mode)
    if mode == "public-edge":
        transport.headers["content-type"] = "application/octet-stream"
        transport.headers.pop("x-limitless-artifact-digest")

    staged = connector.fetch_selected_artifact(query=query, result=result, destination=destination)

    assert destination.exists()
    assert staged["schemaVersion"] == "limitless.staged-service-artifact/1.1"
    sent = transport.calls[0]["headers"]
    if mode == "public-edge":
        assert "authorization" not in sent
        assert "Limitless-Capability" not in sent
    else:
        assert sent["authorization"] == "Bearer test-access-token-value"
        assert sent["Limitless-Capability"] == "A" * 43


def test_result_1_4_streams_large_exact_bundle_to_no_replace_staging(tmp_path: Path) -> None:
    connector, transport, query, result, artifact, destination = _streaming_artifact_fixture(tmp_path)

    staged = connector.fetch_selected_artifact(
        query=query,
        result=result,
        destination=destination,
    )

    assert len(artifact) > MAX_REMOTE_ARTIFACT_BYTES
    assert destination.read_bytes() == artifact
    assert destination.stat().st_mode & 0o777 == 0o600
    assert staged["schemaVersion"] == "limitless.staged-service-artifact/1.1"
    assert staged["format"] == "limitless.exact-file-bundle/1.0"
    assert staged["byteLength"] == len(artifact)
    assert transport.calls[0]["maximumBytes"] == MAX_REMOTE_STREAMED_ARTIFACT_BYTES
    assert transport.calls[0]["headers"]["accept"] == staged["mediaType"]
    public_output = canonical_json_bytes(staged).decode("utf-8")
    assert "test-access-token-value" not in public_output
    assert result["selection"]["immutable"]["authorization"]["value"] not in public_output


@pytest.mark.parametrize(
    ("header", "value", "message"),
    [
        ("content-type", "application/octet-stream", "content type"),
        ("content-length", "1", "content length"),
        ("x-limitless-artifact-digest", "sha256:" + "0" * 64, "digest header"),
    ],
)
def test_result_1_4_stream_metadata_drift_never_publishes(
    tmp_path: Path,
    header: str,
    value: str,
    message: str,
) -> None:
    connector, transport, query, result, _artifact, destination = _streaming_artifact_fixture(tmp_path)
    transport.headers[header] = value

    with pytest.raises(ServiceConnectorError, match=message):
        connector.fetch_selected_artifact(query=query, result=result, destination=destination)

    assert not destination.exists()
    assert list(tmp_path.glob(".streamed.bin.*.tmp")) == []


@pytest.mark.parametrize("change", ["short", "long", "digest"])
def test_result_1_4_stream_body_drift_never_publishes(
    tmp_path: Path,
    change: str,
) -> None:
    connector, transport, query, result, artifact, destination = _streaming_artifact_fixture(tmp_path)
    if change == "short":
        transport.body = artifact[:-1]
    elif change == "long":
        transport.body = artifact + b"x"
    else:
        changed = bytearray(artifact)
        changed[-1] ^= 1
        transport.body = bytes(changed)

    with pytest.raises(ServiceConnectorError, match="length differs|bytes differ"):
        connector.fetch_selected_artifact(query=query, result=result, destination=destination)

    assert not destination.exists()
    assert list(tmp_path.glob(".streamed.bin.*.tmp")) == []


def test_result_1_4_stream_failure_and_collision_preserve_receiver_state(
    tmp_path: Path,
) -> None:
    connector, transport, query, result, _artifact, destination = _streaming_artifact_fixture(tmp_path)
    transport.fail_after_first_chunk = True
    with pytest.raises(ServiceUnavailableError):
        connector.fetch_selected_artifact(query=query, result=result, destination=destination)
    assert not destination.exists()
    assert list(tmp_path.glob(".streamed.bin.*.tmp")) == []

    connector, transport, query, result, _artifact, destination = _streaming_artifact_fixture(tmp_path)
    destination.write_bytes(b"receiver-owned")
    with pytest.raises(ServiceConnectorError, match="without overwrite"):
        connector.fetch_selected_artifact(query=query, result=result, destination=destination)
    assert destination.read_bytes() == b"receiver-owned"
    assert transport.calls == []


def test_locally_bound_continuation_stages_without_retaining_query_text(tmp_path: Path) -> None:
    connector, transport, query, result, artifact, _destination = _artifact_fixture(tmp_path)
    destination = tmp_path / "continued.bin"

    staged = connector.fetch_selected_artifact_continuation(
        result=result,
        expected_request_digest=query["queryDigest"],
        destination=destination,
    )

    assert destination.read_bytes() == artifact
    assert staged["decisionRef"] == result["decisionRef"]
    assert len(transport.calls) == 1


def test_artifact_continuation_rejects_request_or_profile_substitution(tmp_path: Path) -> None:
    connector, transport, _query, result, _artifact, destination = _artifact_fixture(tmp_path)

    with pytest.raises(ServiceConnectorError, match="continuation is unbound"):
        connector.fetch_selected_artifact_continuation(
            result=result,
            expected_request_digest="sha256:" + "9" * 64,
            destination=destination,
        )

    assert transport.calls == []
    assert not destination.exists()

    connector, transport, query, result, _artifact, destination = _artifact_fixture(
        tmp_path,
        result_policy_digest="sha256:" + "8" * 64,
    )
    with pytest.raises(ServiceConnectorError, match="continuation is unbound"):
        connector.fetch_selected_artifact_continuation(
            result=result,
            expected_request_digest=query["queryDigest"],
            destination=destination,
        )

    assert transport.calls == []
    assert not destination.exists()


@pytest.mark.parametrize(
    ("header", "value", "message"),
    [
        ("content-type", "application/json", "content type"),
        ("content-length", "01", "content length"),
        ("content-length", "1", "content length"),
        ("x-limitless-artifact-digest", "sha256:" + "0" * 64, "digest header"),
    ],
)
def test_artifact_response_metadata_differences_fail_before_staging(
    tmp_path: Path,
    header: str,
    value: str,
    message: str,
) -> None:
    connector, transport, query, result, _artifact, destination = _artifact_fixture(tmp_path)
    transport.headers[header] = value

    with pytest.raises(ServiceConnectorError, match=message):
        connector.fetch_selected_artifact(query=query, result=result, destination=destination)

    assert not destination.exists()


def test_artifact_bytes_and_existing_destination_fail_closed(tmp_path: Path) -> None:
    connector, transport, query, result, _artifact, destination = _artifact_fixture(tmp_path)
    transport.body = b"changed"
    transport.headers["content-length"] = str(len(transport.body))

    with pytest.raises(ServiceConnectorError, match="bytes differ"):
        connector.fetch_selected_artifact(query=query, result=result, destination=destination)
    assert not destination.exists()

    connector, _transport, query, result, _artifact, destination = _artifact_fixture(tmp_path)
    destination.write_bytes(b"receiver-owned")
    with pytest.raises(ServiceConnectorError, match="without overwrite"):
        connector.fetch_selected_artifact(query=query, result=result, destination=destination)
    assert destination.read_bytes() == b"receiver-owned"


def test_artifact_fetch_requires_an_authenticated_exact_selection(tmp_path: Path) -> None:
    connector, transport, query, result, _artifact, destination = _artifact_fixture(
        tmp_path,
        token=None,
    )

    with pytest.raises(ServiceConnectorError, match="authorization is required"):
        connector.fetch_selected_artifact(query=query, result=result, destination=destination)
    assert transport.calls == []

    connector, transport, query, result, _artifact, destination = _artifact_fixture(tmp_path)
    changed = deepcopy(result)
    changed["treatment"] = "abstention"
    with pytest.raises(ServiceConnectorError, match="authority is invalid"):
        connector.fetch_selected_artifact(query=query, result=changed, destination=destination)
    assert transport.calls == []


def test_anonymous_publisher_can_accept_policy_negotiate_and_upload_exact_content(
    tmp_path: Path,
) -> None:
    publisher = InstallationSigner.generate()
    plan_signer = InstallationSigner.generate()
    root_signer = InstallationSigner.generate()
    service_id = "service:publication-connector-test"
    publisher_id = "installation:" + "1" * 32
    authority_id = "installation-space:" + "1" * 32
    data_policy_digest = sha256_json({"policy": "data-use"})
    publication_policy_digest = sha256_json({"policy": "publication"})
    discovery = build_service_discovery(
        service_id=service_id,
        api_base_url="https://api.limitlesslibrary.com",
        signing_keys=[
            (
                plan_signer.key_id,
                plan_signer.public_bytes(),
                AT - timedelta(days=1),
                AT + timedelta(days=30),
            )
        ],
        data_use_policy_url="https://limitlesslibrary.com/data-use",
        data_use_policy_digest=data_policy_digest,
        publication_policy_revision="policy:publication-connector-test",
        publication_policy_url="https://limitlesslibrary.com/publication-policy",
        publication_policy_digest=publication_policy_digest,
        rate_limit_class="public-test",
        issued_at=AT.replace(second=0),
        root_signer=root_signer,
    )
    intent = build_submission_intent(
        signer=publisher,
        requestId="request:publication-connector-test",
        publisher={
            "publisherId": publisher_id,
            "authorityId": authority_id,
            "keyId": publisher.key_id,
        },
        destination={"collectionId": "collection:public", "audience": "public"},
        candidate={
            "title": "Portable method",
            "summary": "A source-free method already verified by its publisher.",
            "treatment": "source-free-method",
            "capabilities": ["limitless.mcp/v1"],
        },
        lineage={
            "lineageId": "lineage:publication-connector-test",
            "version": "1.0.0",
            "releaseClass": "initial",
            "parents": [],
            "supersedes": None,
        },
        contentObjects=[
            {
                "role": "method",
                "digest": sha256_bytes(b"M" * 64),
                "byteLength": 64,
            }
        ],
        compatibility={
            "supportedTargets": [
                {
                    "platform": "linux",
                    "architecture": "x86_64",
                    "runtime": "python",
                    "versionRange": ">=3.11,<4",
                    "interfaces": ["limitless.mcp/v1"],
                }
            ],
            "verifiedTargets": [],
        },
        buildContext={
            "platform": "linux",
            "architecture": "x86_64",
            "runtime": "python",
            "version": "3.12.0",
            "interfaces": ["limitless.mcp/v1"],
        },
        evidenceDigests=[sha256_json({"evidence": "publisher-verification"})],
        rights={
            "license": "CC0-1.0",
            "grantedBy": publisher_id,
            "allowedUses": ["derive-method"],
            "hasAuthority": True,
            "policyDigest": publication_policy_digest,
        },
        submittedAt=AT.replace(second=0),
    )
    transport = PublicationTransport(
        plan_signer=plan_signer,
        intent=intent,
        policy_revision=discovery["publicationPolicy"]["revision"],
        policy_digest=publication_policy_digest,
    )
    profile = ServiceProfile(
        api_base_url=discovery["apiBaseUrl"],
        service_id=service_id,
        root_key_id=root_signer.key_id,
        root_public_key=root_signer.public_bytes(),
        accepted_policy_digest=data_policy_digest,
        requested_audiences=("public",),
        access_token="test-publication-token",
    )
    connector = ServiceConnector(profile, transport=transport, clock=lambda: AT)
    connector._cached = VerifiedService(
        discovery=discovery,
        root_transitions={},
        result_keys={plan_signer.key_id: plan_signer.public_bytes()},
    )
    connector._cached_until = float("inf")
    acceptance = build_contribution_policy_acceptance(
        signer=publisher,
        service_id=service_id,
        publisher_id=publisher_id,
        authority_id=authority_id,
        policy_revision=discovery["publicationPolicy"]["revision"],
        policy_digest=publication_policy_digest,
        request_id="request:publication-policy-test",
        issued_at=AT.replace(second=0),
    )

    accepted = connector.accept_publication_policy(
        acceptance,
        publisher_public_key=publisher.public_bytes(),
    )
    plan = connector.negotiate_submission(intent, publisher_public_key=publisher.public_bytes())
    grant = connector.authorize_submission_content(intent=intent, plan=plan)
    source = tmp_path / "method.bin"
    source.write_bytes(b"M" * 64)
    uploaded = connector.upload_submission_object(
        intent=intent,
        plan=plan,
        role="method",
        source=source.resolve(),
    )
    status = connector.submission_status(plan["submissionRef"])

    assert accepted["policyDigest"] == publication_policy_digest
    assert plan["state"] == "needs-content"
    assert grant["objects"] == plan["requiredObjects"]
    assert uploaded["digest"] == intent["contentObjects"][0]["digest"]
    assert uploaded["disposition"] == "created"
    assert status["state"] == "observed"
    assert all(call["headers"]["authorization"] == "Bearer test-publication-token" for call in transport.calls)

    changed = deepcopy(acceptance)
    changed["policyDigest"] = data_policy_digest
    with pytest.raises(ServiceConnectorError, match="acceptance is invalid"):
        connector.accept_publication_policy(changed, publisher_public_key=publisher.public_bytes())
