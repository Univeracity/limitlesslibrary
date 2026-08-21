"""Bounded, opt-in HTTPS connector for the managed Limitless service.

The connector verifies a configured trust root, the immutable root-transition
chain, current service discovery, the accepted data-use policy, and every
query result.  It does not upload local catalogs, workspace data, prompts,
source, adoption evidence, or credentials beyond an explicitly supplied
bearer token.
"""

from __future__ import annotations

import json
import re
import ssl
import threading
import time
from base64 import urlsafe_b64decode
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from ._service_support import decode_root_keys
from .contracts import canonical_json_bytes, sha256_bytes, strict_json_loads
from .service_contracts import (
    MAX_DISCOVERY_BYTES,
    MAX_QUERY_BYTES,
    MAX_RESULT_BYTES,
    MAX_ROOT_KEY_TRANSITION_SET_BYTES,
    SERVICE_PROTOCOL_VERSION,
    SERVICE_QUERY_RESULT_SCHEMA_VERSIONS,
    SERVICE_QUERY_SCHEMA_VERSION,
    active_result_keys,
    build_service_query,
    service_query_audiences,
    service_query_execution_mode,
    service_query_history_mode,
    validate_service_discovery,
    validate_service_profile,
    validate_service_query,
    validate_service_query_result,
    validate_service_root_key_transition_set,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,199}$")
_TOKEN = re.compile(r"^[\x21-\x7e]{16,4096}$")
_JSON_CONTENT_TYPE = re.compile(r"^application/json(?:\s*;\s*charset=(?:utf-8|UTF-8))?$")


class ServiceConnectorError(RuntimeError):
    """The remote service response is unsafe, malformed, or untrusted."""


class ServiceUnavailableError(ServiceConnectorError):
    """The opted-in service is unavailable; local reuse remains available."""


@dataclass(frozen=True)
class ServiceHttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class ServiceTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _base_url(value: Any, field_name: str = "service endpoint") -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError(f"{field_name} is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{field_name} is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is not None
        and not 1 <= port <= 65535
    ):
        raise ValueError(f"{field_name} is invalid")
    return value.rstrip("/")


def _request_url(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ServiceConnectorError("service request URL is invalid")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise ServiceConnectorError("service request URL is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
    ):
        raise ServiceConnectorError("service request URL is invalid")
    return value


def _identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field_name} is invalid")
    return value


def _digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field_name} is invalid")
    return value


def _decode_key(value: str) -> bytes:
    try:
        decoded = urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (TypeError, ValueError) as error:
        raise ValueError("service root public key is invalid") from error
    if len(decoded) != 32:
        raise ValueError("service root public key is invalid")
    return decoded


@dataclass(frozen=True)
class ServiceProfile:
    """Owner-approved remote endpoint and trust/data-use boundary."""

    api_base_url: str
    service_id: str
    root_key_id: str
    root_public_key: bytes
    accepted_policy_digest: str
    execution_mode: str = "service"
    default_audience: str = "private"
    history_mode: str = "local-only"
    requested_audiences: tuple[str, ...] = ("public",)
    access_token: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        endpoint = _base_url(self.api_base_url)
        service_id = _identifier(self.service_id, "service id")
        key_id = _identifier(self.root_key_id, "service root key id")
        root_keys = decode_root_keys({key_id: self.root_public_key})
        policy = _digest(self.accepted_policy_digest, "accepted policy digest")
        if self.execution_mode != "service":
            raise ValueError("service execution mode is invalid")
        if self.default_audience not in {"private", "circle", "organization", "public"}:
            raise ValueError("service default audience is invalid")
        if self.history_mode not in {"local-only", "service-persisted"}:
            raise ValueError("service history mode is invalid")
        audiences = tuple(sorted(set(self.requested_audiences)))
        if (
            not audiences
            or len(audiences) > 4
            or not set(audiences).issubset(
                {"private", "circle", "organization", "public"}
            )
        ):
            raise ValueError("service requested audiences are invalid")
        if self.access_token is not None and (
            not isinstance(self.access_token, str) or _TOKEN.fullmatch(self.access_token) is None
        ):
            raise ValueError("service access token is invalid")
        object.__setattr__(self, "api_base_url", endpoint)
        object.__setattr__(self, "service_id", service_id)
        object.__setattr__(self, "root_key_id", key_id)
        object.__setattr__(self, "root_public_key", root_keys[key_id])
        object.__setattr__(self, "accepted_policy_digest", policy)
        object.__setattr__(self, "requested_audiences", audiences)

    @property
    def legacy_data_use_mode(self) -> str:
        """Project the current boundary onto the compatibility wire protocol."""

        return "history" if self.history_mode == "service-persisted" else "standard"

    @property
    def legacy_requested_scopes(self) -> tuple[str, ...]:
        mapping = {
            "private": "private",
            "circle": "exchange",
            "organization": "organization",
            "public": "public",
        }
        return tuple(sorted(mapping[item] for item in self.requested_audiences))

    @classmethod
    def from_json(
        cls,
        value: Mapping[str, Any],
        *,
        access_token: str | None = None,
    ) -> ServiceProfile:
        checked = validate_service_profile(dict(value))
        root = checked["rootKey"]
        if checked["schemaVersion"] == "limitless.service-profile/1.0":
            mode = checked["dataUseMode"]
            requested_audiences = tuple(
                {
                    "private": "private",
                    "exchange": "circle",
                    "organization": "organization",
                    "public": "public",
                }[item]
                for item in checked["requestedScopes"]
            )
            history_mode = (
                "service-persisted"
                if mode in {"history", "organization"}
                else "local-only"
            )
            default_audience = "private"
        else:
            requested_audiences = tuple(checked["requestedAudiences"])
            history_mode = checked["historyMode"]
            default_audience = checked["defaultAudience"]
        return cls(
            api_base_url=checked["apiBaseUrl"],
            service_id=checked["serviceId"],
            root_key_id=root["keyId"],
            root_public_key=_decode_key(root["publicKey"]),
            accepted_policy_digest=checked["acceptedPolicyDigest"],
            execution_mode="service",
            default_audience=default_audience,
            history_mode=history_mode,
            requested_audiences=requested_audiences,
            access_token=access_token,
        )

    def public_summary(self) -> dict[str, Any]:
        return {
            "schemaVersion": "limitless.service-profile-summary/1.0",
            "apiBaseUrl": self.api_base_url,
            "serviceId": self.service_id,
            "rootKeyId": self.root_key_id,
            "rootKeyFingerprint": sha256_bytes(self.root_public_key),
            "acceptedPolicyDigest": self.accepted_policy_digest,
            "executionMode": self.execution_mode,
            "defaultAudience": self.default_audience,
            "historyMode": self.history_mode,
            "requestedAudiences": list(self.requested_audiences),
            "authenticated": self.access_token is not None,
        }


class UrllibServiceTransport:
    """Strict HTTPS/JSON transport with redirects and ambient proxies disabled."""

    def __init__(self, *, ssl_context: ssl.SSLContext | None = None) -> None:
        context = ssl_context or ssl.create_default_context()
        if not isinstance(context, ssl.SSLContext):
            raise TypeError("service SSL context is invalid")
        self._opener = build_opener(
            ProxyHandler({}),
            _NoRedirect(),
            HTTPSHandler(context=context),
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse:
        if method not in {"GET", "POST"}:
            raise ServiceConnectorError("service request is invalid")
        _request_url(url)
        if (
            isinstance(maximum_bytes, bool)
            or not isinstance(maximum_bytes, int)
            or not 1 <= maximum_bytes <= 1024 * 1024
            or timeout_seconds <= 0
            or timeout_seconds > 30
        ):
            raise ServiceConnectorError("service request limits are invalid")
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            response = self._opener.open(request, timeout=timeout_seconds)  # nosec B310
        except HTTPError as error:
            response = error
        except (OSError, TimeoutError, URLError) as error:
            raise ServiceUnavailableError("managed service is unavailable; continue locally") from error
        try:
            status = int(response.status)
            response_headers: dict[str, str] = {}
            for key in response.headers:
                normalized_key = str(key).lower()
                values = response.headers.get_all(key, [])
                if len(values) != 1 or normalized_key in response_headers:
                    raise ServiceConnectorError("duplicate service response header is invalid")
                response_headers[normalized_key] = str(values[0])
            encoding = response_headers.get("content-encoding")
            if encoding not in {None, "identity"}:
                raise ServiceConnectorError("compressed service responses are refused")
            declared = response_headers.get("content-length")
            if declared is not None:
                try:
                    length = int(declared)
                except ValueError as error:
                    raise ServiceConnectorError("service content length is invalid") from error
                if length < 0 or length > maximum_bytes:
                    raise ServiceConnectorError("service response exceeds its byte limit")
            content_type = response_headers.get("content-type", "")
            if status == 200 and _JSON_CONTENT_TYPE.fullmatch(content_type) is None:
                raise ServiceConnectorError("service response content type is invalid")
            content = response.read(maximum_bytes + 1)
        finally:
            response.close()
        if len(content) > maximum_bytes:
            raise ServiceConnectorError("service response exceeds its byte limit")
        return ServiceHttpResponse(status=status, headers=response_headers, body=content)


@dataclass(frozen=True)
class VerifiedService:
    discovery: dict[str, Any]
    root_transitions: dict[str, Any]
    result_keys: Mapping[str, bytes]


class ServiceConnector:
    """Verify service authority, then issue bounded signed queries."""

    def __init__(
        self,
        profile: ServiceProfile,
        *,
        transport: ServiceTransport | None = None,
        clock: Callable[[], datetime] | None = None,
        timeout_seconds: float = 5.0,
        cache_seconds: float = 60.0,
    ) -> None:
        if not isinstance(profile, ServiceProfile):
            raise TypeError("service profile is invalid")
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("service timeout is invalid")
        if cache_seconds < 0 or cache_seconds > 300:
            raise ValueError("service discovery cache duration is invalid")
        self.profile = profile
        self._transport = transport or UrllibServiceTransport()
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._timeout_seconds = timeout_seconds
        self._cache_seconds = cache_seconds
        self._lock = threading.Lock()
        self._cached: VerifiedService | None = None
        self._cached_until = 0.0

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ServiceConnectorError("service connector clock is invalid")
        return value.astimezone(UTC).replace(microsecond=0)

    def _headers(
        self,
        *,
        content: bool = False,
        authenticated: bool = False,
    ) -> dict[str, str]:
        headers = {
            "accept": "application/json",
            "user-agent": "limitless-library/0.1.0a0",
        }
        if content:
            headers["content-type"] = "application/json"
        if authenticated and self.profile.access_token is not None:
            headers["authorization"] = f"Bearer {self.profile.access_token}"
        return headers

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None,
        maximum_bytes: int,
        maximum_request_bytes: int | None = None,
        authenticated: bool = False,
    ) -> dict[str, Any]:
        encoded = None if body is None else canonical_json_bytes(body)
        request_limit = maximum_bytes if maximum_request_bytes is None else maximum_request_bytes
        if encoded is not None and len(encoded) > request_limit:
            raise ServiceConnectorError("service request exceeds its byte limit")
        response = self._transport.request(
            method,
            self.profile.api_base_url + path,
            headers=self._headers(
                content=encoded is not None,
                authenticated=authenticated,
            ),
            body=encoded,
            maximum_bytes=maximum_bytes,
            timeout_seconds=self._timeout_seconds,
        )
        if response.status in {401, 403}:
            raise ServiceConnectorError("managed service authorization failed")
        if response.status in {429, 502, 503, 504}:
            raise ServiceUnavailableError("managed service is unavailable; continue locally")
        if response.status != 200:
            raise ServiceConnectorError("managed service rejected the request")
        try:
            value = strict_json_loads(response.body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ServiceConnectorError("service response is not strict JSON") from error
        if not isinstance(value, dict):
            raise ServiceConnectorError("service response must be an object")
        return value

    @staticmethod
    def _current_roots(
        transitions: dict[str, Any],
        *,
        initial_roots: Mapping[str, bytes],
        at: datetime,
    ) -> dict[str, bytes]:
        roots = dict(initial_roots)
        current_valid_until: datetime | None = None
        for transition in transitions["transitions"]:
            effective = datetime.fromisoformat(transition["effectiveAt"]).astimezone(UTC)
            if at < effective:
                break
            next_key = transition["nextRootKey"]
            roots = {next_key["keyId"]: _decode_key(next_key["publicKey"])}
            current_valid_until = datetime.fromisoformat(next_key["validUntil"]).astimezone(UTC)
        if current_valid_until is not None and at > current_valid_until:
            raise ServiceConnectorError("current service root key has expired")
        return roots

    def inspect(self, *, refresh: bool = False) -> VerifiedService:
        with self._lock:
            if not refresh and self._cached is not None and time.monotonic() < self._cached_until:
                return self._cached
            now = self._now()
            initial_roots = {self.profile.root_key_id: self.profile.root_public_key}
            transition_value = self._request_json(
                "GET",
                "/.well-known/limitless-root-transitions",
                body=None,
                maximum_bytes=MAX_ROOT_KEY_TRANSITION_SET_BYTES,
            )
            try:
                transitions = validate_service_root_key_transition_set(
                    transition_value,
                    trusted_root_keys=initial_roots,
                )
            except ValueError as error:
                raise ServiceConnectorError("service root transition chain is invalid") from error
            if transitions["serviceId"] != self.profile.service_id:
                raise ServiceConnectorError("service root transition authority differs")
            current_roots = self._current_roots(
                transitions,
                initial_roots=initial_roots,
                at=now,
            )
            discovery_value = self._request_json(
                "GET",
                "/.well-known/limitless-service",
                body=None,
                maximum_bytes=MAX_DISCOVERY_BYTES,
            )
            try:
                discovery = validate_service_discovery(
                    discovery_value,
                    root_public_keys=current_roots,
                    at=now,
                )
                result_keys = active_result_keys(discovery, at=now)
            except ValueError as error:
                raise ServiceConnectorError("service discovery is invalid") from error
            if (
                discovery["serviceId"] != self.profile.service_id
                or discovery["apiBaseUrl"] != self.profile.api_base_url
                or discovery["protocolVersion"] != SERVICE_PROTOCOL_VERSION
                or SERVICE_QUERY_SCHEMA_VERSION not in discovery["queryVersions"]
                or not set(SERVICE_QUERY_RESULT_SCHEMA_VERSIONS).intersection(discovery["resultVersions"])
                or discovery["dataUsePolicy"]["digest"] != self.profile.accepted_policy_digest
                or discovery["rootTransitionState"]
                != {
                    "latestSequence": transitions["latestSequence"],
                    "latestTransitionDigest": transitions["latestTransitionDigest"],
                }
            ):
                raise ServiceConnectorError("service discovery differs from the accepted profile")
            verified = VerifiedService(
                discovery=discovery,
                root_transitions=transitions,
                result_keys=result_keys,
            )
            self._cached = verified
            expires_at = datetime.fromisoformat(discovery["expiresAt"]).astimezone(UTC)
            remaining = max(0.0, (expires_at - now).total_seconds())
            self._cached_until = time.monotonic() + min(
                self._cache_seconds,
                remaining,
            )
            return verified

    def query(self, query: dict[str, Any]) -> dict[str, Any]:
        verified = self.inspect()
        now = self._now()
        try:
            checked_query = validate_service_query(query, at=now)
        except ValueError as error:
            raise ServiceConnectorError("service query is invalid") from error
        if (
            service_query_execution_mode(checked_query) != self.profile.execution_mode
            or service_query_history_mode(checked_query) != self.profile.history_mode
            or not set(service_query_audiences(checked_query)).issubset(
                set(self.profile.requested_audiences)
            )
        ):
            raise ServiceConnectorError("service query exceeds the opted-in profile")
        maximum = min(
            MAX_RESULT_BYTES,
            verified.discovery["limits"]["maxResultBytes"],
        )
        request_maximum = min(
            MAX_QUERY_BYTES,
            verified.discovery["limits"]["maxQueryBytes"],
        )
        result_value = self._request_json(
            "POST",
            "/v1/queries",
            body=checked_query,
            maximum_bytes=maximum,
            maximum_request_bytes=request_maximum,
            authenticated=True,
        )
        try:
            return validate_service_query_result(
                result_value,
                public_keys=verified.result_keys,
                expected_query=checked_query,
                at=now,
            )
        except ValueError as error:
            raise ServiceConnectorError("service query result is invalid") from error

    def build_query(
        self,
        *,
        request_id: str,
        objective: str,
        receiver_context: dict[str, Any],
        requested_treatments: tuple[str, ...] = (
            "exact-component",
            "source-free-method",
        ),
        issued_at: datetime | None = None,
        ttl_seconds: int = 60,
    ) -> dict[str, Any]:
        return build_service_query(
            request_id=request_id,
            objective=objective,
            receiver_context=receiver_context,
            requested_audiences=self.profile.requested_audiences,
            requested_treatments=requested_treatments,
            execution_mode=self.profile.execution_mode,
            history_mode=self.profile.history_mode,
            client_name="limitless-library-python",
            client_version="0.1.0a0",
            issued_at=issued_at or self._now(),
            ttl_seconds=ttl_seconds,
        )
