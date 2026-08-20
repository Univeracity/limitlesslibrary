from __future__ import annotations

from base64 import urlsafe_b64decode
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from email.message import Message
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from limitless_library.contracts import canonical_json_bytes, load_json
from limitless_library.service_connector import (
    ServiceConnector,
    ServiceConnectorError,
    ServiceHttpResponse,
    ServiceProfile,
    ServiceUnavailableError,
    UrllibServiceTransport,
)
from limitless_library.service_contracts import validate_service_root_key_transition_set

CORPUS = Path(str(files("limitless_library.conformance").joinpath("public-service-lifecycle-1.0.json")))
AT = datetime(2026, 8, 20, 22, 0, 30, tzinfo=UTC)


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


class MemoryTransport:
    def __init__(self, corpus: dict[str, Any]) -> None:
        self.corpus = corpus
        self.status = 200
        self.result = corpus["result"]
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
            headers={"content-type": "application/json"},
            body=canonical_json_bytes(value),
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
        access_token=token,
    )


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
    broader["requestedScopes"] = ["private", "public"]
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


def test_profile_json_is_exact_and_never_serializes_the_access_token() -> None:
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
            "requestedScopes": ["public"],
        },
        access_token="test-access-token-value",
    )

    summary = profile.public_summary()
    assert summary["dataUseMode"] == "confidential"
    assert summary["rootKeyFingerprint"].startswith("sha256:")
    assert "access" not in "".join(summary).lower()

    invalid = {**summary, "schemaVersion": "limitless.service-profile/1.0"}
    with pytest.raises(ValueError, match="shape"):
        ServiceProfile.from_json(invalid)


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
