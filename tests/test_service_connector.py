from __future__ import annotations

from base64 import urlsafe_b64decode
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from email.message import Message
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from limitless_library.contracts import canonical_json_bytes, load_json, sha256_bytes
from limitless_library.service_connector import (
    MAX_REMOTE_ARTIFACT_BYTES,
    ServiceConnector,
    ServiceConnectorError,
    ServiceHttpResponse,
    ServiceProfile,
    ServiceUnavailableError,
    UrllibServiceTransport,
    VerifiedService,
)
from limitless_library.service_contracts import (
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
                body=canonical_json_bytes({"error": "unavailable"}),
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


class StaticResponse:
    def __init__(self, status: int, headers: Message, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.closed = False

    def read(self, maximum_bytes: int) -> bytes:
        return self.body[:maximum_bytes]

    def close(self) -> None:
        self.closed = True


class StaticOpener:
    def __init__(self, response: StaticResponse) -> None:
        self.response = response

    def open(self, _request: object, *, timeout: float) -> StaticResponse:
        assert timeout > 0
        return self.response


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
        policy_digest=corpus["discovery"]["dataUsePolicy"]["digest"],
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
    assert "dataUseMode" not in query
    assert "requestedScopes" not in query
    assert "exchange" not in canonical_json_bytes(query).decode("utf-8")


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
