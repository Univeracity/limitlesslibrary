"""Bounded, opt-in HTTPS connector for the managed Limitless service.

The connector verifies a configured trust root, the immutable root-transition
chain, current service discovery, the accepted data-use policy, and every
query result.  It does not upload local catalogs, workspace data, prompts,
source, adoption evidence, or credentials beyond an explicitly supplied
bearer token.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import ssl
import stat
import threading
import time
from base64 import urlsafe_b64decode
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from tempfile import mkstemp
from typing import Any, BinaryIO, Protocol
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
from .contracts import (
    ContractError,
    canonical_json_bytes,
    sha256_bytes,
    strict_json_loads,
    write_new_bytes,
)
from .installation_identity_contracts import (
    MAX_ATTESTATION_BYTES,
    MAX_SESSION_RESPONSE_BYTES,
)
from .installation_identity_contracts import (
    MAX_REQUEST_BYTES as MAX_INSTALLATION_REQUEST_BYTES,
)
from .public_admission_contracts import (
    MAX_SIGNED_REQUEST_BYTES,
    PublicAdmissionContractError,
    validate_contribution_policy_acceptance,
    validate_public_admission_status,
    validate_public_policy_acceptance_response,
    validate_public_release_revocation_request,
)
from .public_submission_contracts import (
    MAX_CONTENT_TRANSFER_GRANT_BYTES,
    MAX_CONTENT_TRANSFER_RESULT_BYTES,
    MAX_INTENT_BYTES,
    MAX_PLAN_BYTES,
    PublicSubmissionContractError,
    validate_content_transfer_grant,
    validate_content_transfer_result,
    validate_submission_intent,
    validate_submission_plan,
)
from .service_contracts import (
    MAX_DISCOVERY_BYTES,
    MAX_QUERY_BYTES,
    MAX_RESULT_BYTES,
    MAX_ROOT_KEY_TRANSITION_SET_BYTES,
    POLICY_BOUND_SERVICE_QUERY_RESULT_SCHEMA_VERSIONS,
    SERVICE_CONTENT_UPLOAD_SCHEMA_VERSION,
    SERVICE_PROTOCOL_VERSION,
    SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4,
    SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_5,
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
_CONTENT_LENGTH = re.compile(r"^(?:0|[1-9][0-9]{0,9})$")
_WHOLE_SECOND = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ARTIFACT_CONTENT_TYPE = "application/octet-stream"
_USAGE_UPGRADE_URL = "https://limitlesslibrary.com/#contact"
MAX_REMOTE_ARTIFACT_BYTES = 128 * 1024
MAX_REMOTE_STREAMED_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_PUBLICATION_STATUS_BYTES = 4 * 1024


class ServiceConnectorError(RuntimeError):
    """The remote service response is unsafe, malformed, or untrusted."""


class ServiceUnavailableError(ServiceConnectorError):
    """The opted-in service is unavailable; local reuse remains available."""


class ServiceUsageExceededError(ServiceUnavailableError):
    """The installation's free managed-service allowance is exhausted."""

    def __init__(self, *, reset_at: str, upgrade_url: str) -> None:
        super().__init__("free managed-service usage exceeded; continue locally")
        self.reset_at = reset_at
        self.upgrade_url = upgrade_url


@dataclass(frozen=True)
class ServiceHttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class ServiceStreamResponse:
    status: int
    headers: Mapping[str, str]
    byte_length: int
    content_digest: str


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

    def download_file(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        destination: BinaryIO,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceStreamResponse: ...

    def upload_file(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        source: BinaryIO,
        byte_length: int,
        expected_digest: str,
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
            or not set(audiences).issubset({"private", "circle", "organization", "public"})
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
            history_mode = "service-persisted" if mode in {"history", "organization"} else "local-only"
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
        self._ssl_context = context

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
            content = response.read(maximum_bytes + 1)
        finally:
            response.close()
        if len(content) > maximum_bytes:
            raise ServiceConnectorError("service response exceeds its byte limit")
        return ServiceHttpResponse(status=status, headers=response_headers, body=content)

    def upload_file(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        source: BinaryIO,
        byte_length: int,
        expected_digest: str,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse:
        """Stream one exact file over HTTPS without redirects or proxy state."""

        checked_url = _request_url(url)
        parsed = urlsplit(checked_url)
        if (
            not callable(getattr(source, "read", None))
            or isinstance(byte_length, bool)
            or not isinstance(byte_length, int)
            or not 1 <= byte_length <= 1024 * 1024 * 1024
            or not isinstance(expected_digest, str)
            or _DIGEST.fullmatch(expected_digest) is None
            or isinstance(maximum_bytes, bool)
            or not isinstance(maximum_bytes, int)
            or not 1 <= maximum_bytes <= 1024 * 1024
            or timeout_seconds <= 0
            or timeout_seconds > 300
        ):
            raise ServiceConnectorError("service upload limits are invalid")
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            port=parsed.port,
            timeout=timeout_seconds,
            context=self._ssl_context,
        )
        response: http.client.HTTPResponse | None = None
        try:
            connection.putrequest("PUT", parsed.path, skip_accept_encoding=True)
            for name, value in headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise ServiceConnectorError("service upload header is invalid")
                connection.putheader(name, value)
            connection.endheaders()
            hasher = sha256()
            total = 0
            while True:
                chunk = source.read(128 * 1024)
                if not isinstance(chunk, bytes) or len(chunk) > 128 * 1024:
                    raise ServiceConnectorError("service upload source is invalid")
                if not chunk:
                    break
                total += len(chunk)
                if total > byte_length:
                    raise ServiceConnectorError("service upload source length differs")
                hasher.update(chunk)
                connection.send(chunk)
            if total != byte_length or "sha256:" + hasher.hexdigest() != expected_digest:
                raise ServiceConnectorError("service upload source bytes differ")
            response = connection.getresponse()
            response_headers: dict[str, str] = {}
            for key, value in response.getheaders():
                normalized_key = key.lower()
                if normalized_key in response_headers:
                    raise ServiceConnectorError("duplicate service response header is invalid")
                response_headers[normalized_key] = value
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
            content = response.read(maximum_bytes + 1)
            if len(content) > maximum_bytes:
                raise ServiceConnectorError("service response exceeds its byte limit")
            return ServiceHttpResponse(
                status=int(response.status),
                headers=response_headers,
                body=content,
            )
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise ServiceUnavailableError("managed service is unavailable; continue locally") from error
        finally:
            if response is not None:
                response.close()
            connection.close()

    def download_file(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        destination: BinaryIO,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceStreamResponse:
        """Stream one bounded HTTPS response into an unpublished receiver file."""

        _request_url(url)
        if (
            not callable(getattr(destination, "write", None))
            or isinstance(maximum_bytes, bool)
            or not isinstance(maximum_bytes, int)
            or not 1 <= maximum_bytes <= MAX_REMOTE_STREAMED_ARTIFACT_BYTES
            or timeout_seconds <= 0
            or timeout_seconds > 300
        ):
            raise ServiceConnectorError("service download limits are invalid")
        request = Request(url, data=None, headers=dict(headers), method="GET")
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
            if status != 200:
                return ServiceStreamResponse(
                    status=status,
                    headers=response_headers,
                    byte_length=0,
                    content_digest="sha256:" + sha256(b"").hexdigest(),
                )
            hasher = sha256()
            total = 0
            while True:
                chunk = response.read(128 * 1024)
                if not isinstance(chunk, bytes) or len(chunk) > 128 * 1024:
                    raise ServiceConnectorError("service download response is invalid")
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_bytes:
                    raise ServiceConnectorError("service response exceeds its byte limit")
                try:
                    written = destination.write(chunk)
                except OSError as error:
                    raise ServiceConnectorError("service download destination write failed") from error
                if written != len(chunk):
                    raise ServiceConnectorError("service download destination write differs")
                hasher.update(chunk)
            return ServiceStreamResponse(
                status=status,
                headers=response_headers,
                byte_length=total,
                content_digest="sha256:" + hasher.hexdigest(),
            )
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise ServiceUnavailableError("managed service is unavailable; continue locally") from error
        finally:
            response.close()


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
        upload_timeout_seconds: float = 120.0,
        cache_seconds: float = 60.0,
    ) -> None:
        if not isinstance(profile, ServiceProfile):
            raise TypeError("service profile is invalid")
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("service timeout is invalid")
        if upload_timeout_seconds <= 0 or upload_timeout_seconds > 300:
            raise ValueError("service upload timeout is invalid")
        if cache_seconds < 0 or cache_seconds > 300:
            raise ValueError("service discovery cache duration is invalid")
        self.profile = profile
        self._transport = transport or UrllibServiceTransport()
        self._clock = clock or (lambda: datetime.now(tz=UTC))
        self._timeout_seconds = timeout_seconds
        self._upload_timeout_seconds = upload_timeout_seconds
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

    @staticmethod
    def _response_headers(headers: Mapping[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ServiceConnectorError("service response header is invalid")
            name = key.lower()
            if name in normalized:
                raise ServiceConnectorError("duplicate service response header is invalid")
            normalized[name] = value
        encoding = normalized.get("content-encoding")
        if encoding not in {None, "identity"}:
            raise ServiceConnectorError("compressed service responses are refused")
        return normalized

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
        if response.status == 429:
            try:
                response_headers = self._response_headers(response.headers)
                if _JSON_CONTENT_TYPE.fullmatch(response_headers.get("content-type", "")) is None:
                    raise ValueError("invalid content type")
                value = strict_json_loads(response.body.decode("utf-8"))
                if not isinstance(value, dict) or set(value) != {
                    "error",
                    "resetAt",
                    "upgradeUrl",
                }:
                    raise ValueError("invalid usage response")
                reset_at = value["resetAt"]
                upgrade_url = value["upgradeUrl"]
                if (
                    value["error"] != "free-usage-exceeded"
                    or not isinstance(reset_at, str)
                    or _WHOLE_SECOND.fullmatch(reset_at) is None
                    or upgrade_url != _USAGE_UPGRADE_URL
                ):
                    raise ValueError("invalid usage response")
                reset_time = datetime.fromisoformat(reset_at)
                now = self._now()
                if reset_time < now - timedelta(minutes=5) or reset_time > now + timedelta(days=366):
                    raise ValueError("invalid usage reset")
            except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                raise ServiceUnavailableError("managed service is unavailable; continue locally") from None
            raise ServiceUsageExceededError(reset_at=reset_at, upgrade_url=upgrade_url)
        if response.status in {500, 502, 503, 504}:
            raise ServiceUnavailableError("managed service is unavailable; continue locally")
        if response.status != 200:
            raise ServiceConnectorError("managed service rejected the request")
        response_headers = self._response_headers(response.headers)
        content_type = response_headers.get("content-type", "")
        if _JSON_CONTENT_TYPE.fullmatch(content_type) is None:
            raise ServiceConnectorError("service response content type is invalid")
        try:
            value = strict_json_loads(response.body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ServiceConnectorError("service response is not strict JSON") from error
        if not isinstance(value, dict):
            raise ServiceConnectorError("service response must be an object")
        return value

    def with_access_token(self, access_token: str) -> ServiceConnector:
        """Return an authorized connector while retaining verified discovery."""

        profile = replace(self.profile, access_token=access_token)
        connected = ServiceConnector(
            profile,
            transport=self._transport,
            clock=self._clock,
            timeout_seconds=self._timeout_seconds,
            upload_timeout_seconds=self._upload_timeout_seconds,
            cache_seconds=self._cache_seconds,
        )
        with self._lock:
            connected._cached = self._cached
            connected._cached_until = self._cached_until
        return connected

    def register_installation(self, request: dict[str, Any]) -> dict[str, Any]:
        """Submit one self-proved registration without ambient credentials."""

        return self._request_json(
            "POST",
            "/v1/installations",
            body=request,
            maximum_bytes=MAX_ATTESTATION_BYTES,
            maximum_request_bytes=MAX_INSTALLATION_REQUEST_BYTES,
        )

    def open_installation_session(self, request: dict[str, Any]) -> dict[str, Any]:
        """Exchange current-key proof for a short-lived anonymous bearer."""

        return self._request_json(
            "POST",
            "/v1/installations/sessions",
            body=request,
            maximum_bytes=MAX_SESSION_RESPONSE_BYTES,
            maximum_request_bytes=MAX_INSTALLATION_REQUEST_BYTES,
        )

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
            or not set(service_query_audiences(checked_query)).issubset(set(self.profile.requested_audiences))
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
            checked_result = validate_service_query_result(
                result_value,
                public_keys=verified.result_keys,
                expected_query=checked_query,
                at=now,
            )
        except ValueError as error:
            raise ServiceConnectorError("service query result is invalid") from error
        if not self._result_matches_profile(checked_result):
            raise ServiceConnectorError("service query result exceeds the opted-in profile")
        return checked_result

    def _result_matches_profile(self, checked_result: dict[str, Any]) -> bool:
        return (
            checked_result["schemaVersion"] in POLICY_BOUND_SERVICE_QUERY_RESULT_SCHEMA_VERSIONS
            and checked_result["policy"]["policyDigest"] == self.profile.accepted_policy_digest
            and checked_result["policy"]["executionMode"] == self.profile.execution_mode
            and checked_result["policy"]["historyMode"] == self.profile.history_mode
            and set(checked_result["authorizedAudiences"]).issubset(set(self.profile.requested_audiences))
        )

    def _stream_checked_artifact(
        self,
        *,
        checked_result: dict[str, Any],
        selection: dict[str, Any],
        immutable: dict[str, Any],
        authorization: dict[str, Any] | None,
        destination: str | Path,
    ) -> dict[str, Any]:
        download = getattr(self._transport, "download_file", None)
        if not callable(download):
            raise ServiceConnectorError("configured service transport cannot stream downloads")
        if not isinstance(destination, (str, Path)):
            raise ServiceConnectorError("service artifact destination is invalid")
        path = Path(destination)
        if not path.name:
            raise ServiceConnectorError("service artifact destination is invalid")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() or path.is_symlink():
                raise FileExistsError(path)
            descriptor, temporary_name = mkstemp(
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
            )
        except (OSError, ValueError) as error:
            raise ServiceConnectorError("service artifact could not be staged without overwrite") from error
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                headers = {
                    "accept": immutable["mediaType"],
                    "user-agent": "limitless-library/0.1.0a0",
                }
                if authorization is not None:
                    headers.update(
                        {
                            "authorization": f"Bearer {self.profile.access_token}",
                            authorization["header"]: authorization["value"],
                        }
                    )
                response = download(
                    _request_url(immutable["uri"]),
                    headers=headers,
                    destination=handle,
                    maximum_bytes=MAX_REMOTE_STREAMED_ARTIFACT_BYTES,
                    timeout_seconds=self._timeout_seconds,
                )
                if not isinstance(response, ServiceStreamResponse):
                    raise ServiceConnectorError("service artifact stream response is invalid")
                if response.status in {401, 403}:
                    raise ServiceConnectorError("managed service artifact authorization failed")
                if response.status in {429, 500, 502, 503, 504}:
                    raise ServiceUnavailableError("managed service is unavailable; continue locally")
                if response.status != 200:
                    raise ServiceConnectorError("managed service rejected the artifact request")
                headers = self._response_headers(response.headers)
                if headers.get("content-type") != immutable["mediaType"]:
                    raise ServiceConnectorError("service artifact content type is invalid")
                declared = headers.get("content-length")
                if declared is None or _CONTENT_LENGTH.fullmatch(declared) is None:
                    raise ServiceConnectorError("service artifact content length is invalid")
                declared_length = int(declared)
                if declared_length != immutable["byteLength"] or response.byte_length != immutable["byteLength"]:
                    raise ServiceConnectorError("service artifact content length differs")
                expected_digest = immutable["digest"]
                if headers.get("x-limitless-artifact-digest") != expected_digest:
                    raise ServiceConnectorError("service artifact digest header differs")
                if response.content_digest != expected_digest:
                    raise ServiceConnectorError("service artifact bytes differ from the signed result")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError as error:
                raise ServiceConnectorError("service artifact could not be staged without overwrite") from error
        except ServiceConnectorError:
            raise
        except (OSError, ValueError) as error:
            raise ServiceConnectorError("service artifact could not be staged without overwrite") from error
        finally:
            if descriptor != -1:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
        return {
            "schemaVersion": "limitless.staged-service-artifact/1.1",
            "decisionRef": checked_result["decisionRef"],
            "capabilityId": selection["capabilityId"],
            "revision": immutable["revision"],
            "digest": immutable["digest"],
            "byteLength": immutable["byteLength"],
            "mediaType": immutable["mediaType"],
            "format": immutable["format"],
            "path": str(path),
            "nextAction": checked_result["nextAction"],
        }

    def _fetch_checked_artifact(
        self,
        *,
        checked_result: dict[str, Any],
        destination: str | Path,
    ) -> dict[str, Any]:
        if self.profile.access_token is None:
            raise ServiceConnectorError("managed service authorization is required")
        if checked_result["treatment"] != "exact-component":
            raise ServiceConnectorError("service result does not select an exact component")
        selection = checked_result["selection"]
        immutable = selection.get("immutable")
        if not isinstance(immutable, dict) or immutable.get("kind") != "artifact":
            raise ServiceConnectorError("service result does not select a deliverable artifact")
        authorization = immutable.get("authorization")
        if checked_result["schemaVersion"] == SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_5:
            delivery = immutable.get("delivery")
            if not isinstance(delivery, dict):
                raise ServiceConnectorError("service artifact delivery is unavailable")
            authorization = delivery.get("authorization")
            if delivery.get("mode") == "public-edge":
                authorization = None
            elif delivery.get("mode") != "protected-capability" or not isinstance(authorization, dict):
                raise ServiceConnectorError("service artifact authorization is unavailable")
            return self._stream_checked_artifact(
                checked_result=checked_result,
                selection=selection,
                immutable=immutable,
                authorization=authorization,
                destination=destination,
            )
        if not isinstance(authorization, dict):
            raise ServiceConnectorError("service artifact authorization is unavailable")
        if checked_result["schemaVersion"] == SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_4:
            return self._stream_checked_artifact(
                checked_result=checked_result,
                selection=selection,
                immutable=immutable,
                authorization=authorization,
                destination=destination,
            )

        response = self._transport.request(
            "GET",
            _request_url(immutable["uri"]),
            headers={
                "accept": _ARTIFACT_CONTENT_TYPE,
                "authorization": f"Bearer {self.profile.access_token}",
                "user-agent": "limitless-library/0.1.0a0",
                authorization["header"]: authorization["value"],
            },
            body=None,
            maximum_bytes=MAX_REMOTE_ARTIFACT_BYTES,
            timeout_seconds=self._timeout_seconds,
        )
        if response.status in {401, 403}:
            raise ServiceConnectorError("managed service artifact authorization failed")
        if response.status in {429, 500, 502, 503, 504}:
            raise ServiceUnavailableError("managed service is unavailable; continue locally")
        if response.status != 200:
            raise ServiceConnectorError("managed service rejected the artifact request")

        headers = self._response_headers(response.headers)
        if headers.get("content-type") != _ARTIFACT_CONTENT_TYPE:
            raise ServiceConnectorError("service artifact content type is invalid")
        declared = headers.get("content-length")
        if declared is None or _CONTENT_LENGTH.fullmatch(declared) is None:
            raise ServiceConnectorError("service artifact content length is invalid")
        declared_length = int(declared)
        if declared_length > MAX_REMOTE_ARTIFACT_BYTES or declared_length != len(response.body):
            raise ServiceConnectorError("service artifact content length differs")
        expected_digest = immutable["digest"]
        if headers.get("x-limitless-artifact-digest") != expected_digest:
            raise ServiceConnectorError("service artifact digest header differs")
        if sha256_bytes(response.body) != expected_digest:
            raise ServiceConnectorError("service artifact bytes differ from the signed result")

        if not isinstance(destination, (str, Path)):
            raise ServiceConnectorError("service artifact destination is invalid")
        path = Path(destination)
        try:
            write_new_bytes(path, response.body)
        except (ContractError, OSError, ValueError) as error:
            raise ServiceConnectorError("service artifact could not be staged without overwrite") from error
        return {
            "schemaVersion": "limitless.staged-service-artifact/1.0",
            "decisionRef": checked_result["decisionRef"],
            "capabilityId": selection["capabilityId"],
            "revision": immutable["revision"],
            "digest": expected_digest,
            "byteLength": declared_length,
            "path": str(path),
            "nextAction": checked_result["nextAction"],
        }

    def fetch_selected_artifact(
        self,
        *,
        query: dict[str, Any],
        result: dict[str, Any],
        destination: str | Path,
    ) -> dict[str, Any]:
        """Fetch one signed exact artifact into a new receiver-owned file."""

        verified = self.inspect()
        now = self._now()
        try:
            checked_query = validate_service_query(query, at=now)
            checked_result = validate_service_query_result(
                result,
                public_keys=verified.result_keys,
                expected_query=checked_query,
                at=now,
            )
        except ValueError as error:
            raise ServiceConnectorError("service artifact authority is invalid") from error
        if (
            service_query_execution_mode(checked_query) != self.profile.execution_mode
            or service_query_history_mode(checked_query) != self.profile.history_mode
            or not set(service_query_audiences(checked_query)).issubset(set(self.profile.requested_audiences))
        ):
            raise ServiceConnectorError("service query exceeds the opted-in profile")
        if not self._result_matches_profile(checked_result):
            raise ServiceConnectorError("service artifact authority exceeds the opted-in profile")
        return self._fetch_checked_artifact(
            checked_result=checked_result,
            destination=destination,
        )

    def fetch_selected_artifact_continuation(
        self,
        *,
        result: dict[str, Any],
        expected_request_digest: str,
        destination: str | Path,
    ) -> dict[str, Any]:
        """Continue a locally bound, previously verified query without retaining its text."""

        verified = self.inspect()
        now = self._now()
        try:
            checked_result = validate_service_query_result(
                result,
                public_keys=verified.result_keys,
                at=now,
            )
        except ValueError as error:
            raise ServiceConnectorError("service artifact authority is invalid") from error
        if (
            not isinstance(expected_request_digest, str)
            or _DIGEST.fullmatch(expected_request_digest) is None
            or checked_result["requestDigest"] != expected_request_digest
            or not self._result_matches_profile(checked_result)
        ):
            raise ServiceConnectorError("service artifact continuation is unbound")
        return self._fetch_checked_artifact(
            checked_result=checked_result,
            destination=destination,
        )

    def accept_publication_policy(
        self,
        acceptance: dict[str, Any],
        *,
        publisher_public_key: bytes,
    ) -> dict[str, Any]:
        """Accept the exact publication policy advertised by discovery."""

        if self.profile.access_token is None:
            raise ServiceConnectorError("managed service authorization is required")
        verified = self.inspect()
        now = self._now()
        policy = verified.discovery.get("publicationPolicy")
        if not isinstance(policy, dict):
            raise ServiceConnectorError("service does not advertise a publication policy")
        try:
            key_id = acceptance["publisher"]["keyId"]
            checked = validate_contribution_policy_acceptance(
                acceptance,
                public_keys={key_id: publisher_public_key},
                at=now,
            )
        except (KeyError, PublicAdmissionContractError, TypeError, ValueError) as error:
            raise ServiceConnectorError("publication policy acceptance is invalid") from error
        if (
            checked["serviceId"] != self.profile.service_id
            or checked["policyRevision"] != policy["revision"]
            or checked["policyDigest"] != policy["digest"]
        ):
            raise ServiceConnectorError("publication policy acceptance differs from discovery")
        response = self._request_json(
            "POST",
            "/v1/publication-policy/acceptances",
            body=checked,
            maximum_bytes=MAX_PUBLICATION_STATUS_BYTES,
            maximum_request_bytes=MAX_SIGNED_REQUEST_BYTES,
            authenticated=True,
        )
        try:
            return validate_public_policy_acceptance_response(
                response,
                expected_policy_revision=policy["revision"],
                expected_policy_digest=policy["digest"],
            )
        except PublicAdmissionContractError as error:
            raise ServiceConnectorError("publication policy response is invalid") from error

    def negotiate_submission(
        self,
        intent: dict[str, Any],
        *,
        publisher_public_key: bytes,
    ) -> dict[str, Any]:
        """Submit one signed public intent and verify the service plan."""

        if self.profile.access_token is None:
            raise ServiceConnectorError("managed service authorization is required")
        verified = self.inspect()
        now = self._now()
        policy = verified.discovery.get("publicationPolicy")
        if not isinstance(policy, dict):
            raise ServiceConnectorError("service does not advertise public submission")
        try:
            key_id = intent["publisher"]["keyId"]
            checked_intent = validate_submission_intent(
                intent,
                public_keys={key_id: publisher_public_key},
            )
        except (KeyError, PublicSubmissionContractError, TypeError, ValueError) as error:
            raise ServiceConnectorError("public submission intent is invalid") from error
        if (
            checked_intent["schemaVersion"] not in verified.discovery["submissionIntentVersions"]
            or checked_intent["destination"] != {"collectionId": "collection:public", "audience": "public"}
            or checked_intent["rights"].get("policyDigest") != policy["digest"]
            or "public" not in self.profile.requested_audiences
        ):
            raise ServiceConnectorError("public submission intent exceeds the opted-in profile")
        maximum = min(MAX_PLAN_BYTES, verified.discovery["limits"]["maxSubmissionPlanBytes"])
        request_maximum = min(MAX_INTENT_BYTES, verified.discovery["limits"]["maxSubmissionIntentBytes"])
        plan_value = self._request_json(
            "POST",
            "/v1/submissions",
            body=checked_intent,
            maximum_bytes=maximum,
            maximum_request_bytes=request_maximum,
            authenticated=True,
        )
        try:
            return validate_submission_plan(
                plan_value,
                public_keys=verified.result_keys,
                expected_intent=checked_intent,
                at=now,
            )
        except PublicSubmissionContractError as error:
            raise ServiceConnectorError("public submission plan is invalid") from error

    def authorize_submission_content(
        self,
        *,
        intent: dict[str, Any],
        plan: dict[str, Any],
    ) -> dict[str, Any]:
        """Obtain signed authority for exactly the plan's missing objects."""

        if self.profile.access_token is None:
            raise ServiceConnectorError("managed service authorization is required")
        verified = self.inspect()
        now = self._now()
        try:
            checked_intent = validate_submission_intent(intent)
            checked_plan = validate_submission_plan(
                plan,
                public_keys=verified.result_keys,
                expected_intent=checked_intent,
                at=now,
            )
        except PublicSubmissionContractError as error:
            raise ServiceConnectorError("public content authorization input is invalid") from error
        if checked_plan["state"] != "needs-content":
            raise ServiceConnectorError("public submission does not require content")
        grant_value = self._request_json(
            "POST",
            f"/v1/submissions/{checked_plan['submissionRef']}/content-authorizations",
            body=None,
            maximum_bytes=MAX_CONTENT_TRANSFER_GRANT_BYTES,
            authenticated=True,
        )
        try:
            return validate_content_transfer_grant(
                grant_value,
                public_keys=verified.result_keys,
                expected_intent=checked_intent,
                expected_plan=checked_plan,
                at=now,
            )
        except PublicSubmissionContractError as error:
            raise ServiceConnectorError("public content transfer grant is invalid") from error

    def upload_submission_object(
        self,
        *,
        intent: dict[str, Any],
        plan: dict[str, Any],
        role: str,
        source: str | Path,
    ) -> dict[str, Any]:
        """Stream one plan-required object from an explicit absolute path."""

        if self.profile.access_token is None:
            raise ServiceConnectorError("managed service authorization is required")
        verified = self.inspect()
        now = self._now()
        try:
            checked_intent = validate_submission_intent(intent)
            checked_plan = validate_submission_plan(
                plan,
                public_keys=verified.result_keys,
                expected_intent=checked_intent,
                at=now,
            )
        except PublicSubmissionContractError as error:
            raise ServiceConnectorError("public content upload input is invalid") from error
        discovery = verified.discovery
        if (
            checked_plan["state"] != "needs-content"
            or SERVICE_CONTENT_UPLOAD_SCHEMA_VERSION not in discovery.get("contentUploadVersions", [])
            or not isinstance(role, str)
            or role not in {"artifact", "manifest", "method", "verification"}
        ):
            raise ServiceConnectorError("public content upload is unsupported")
        if not isinstance(source, (str, Path)):
            raise ServiceConnectorError("public content upload source is invalid")
        path = Path(source)
        if not path.is_absolute():
            raise ServiceConnectorError("public content upload source must be absolute")

        descriptor: dict[str, Any] | None = None
        opened: BinaryIO | None = None
        try:
            before = path.lstat()
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                raise ServiceConnectorError("public content upload source must be a regular file")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor_fd = os.open(path, flags)
            opened = os.fdopen(descriptor_fd, "rb", buffering=0)
            current = os.fstat(opened.fileno())
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_size != before.st_size
                or current.st_dev != before.st_dev
                or current.st_ino != before.st_ino
            ):
                raise ServiceConnectorError("public content upload source changed")
            maximum = discovery["limits"]["maxContentObjectBytes"]
            if not 1 <= current.st_size <= maximum:
                raise ServiceConnectorError("public content upload source exceeds the service limit")
            hasher = sha256()
            while True:
                chunk = opened.read(128 * 1024)
                if not isinstance(chunk, bytes) or len(chunk) > 128 * 1024:
                    raise ServiceConnectorError("public content upload source is invalid")
                if not chunk:
                    break
                hasher.update(chunk)
            digest = "sha256:" + hasher.hexdigest()
            descriptor = next(
                (
                    item
                    for item in checked_plan["requiredObjects"]
                    if item["role"] == role and item["digest"] == digest and item["byteLength"] == current.st_size
                ),
                None,
            )
            if descriptor is None:
                raise ServiceConnectorError("public content upload source is outside the signed plan")
            opened.seek(0)
            upload = getattr(self._transport, "upload_file", None)
            if not callable(upload):
                raise ServiceConnectorError("configured service transport cannot stream uploads")
            response = upload(
                self.profile.api_base_url + f"/v1/submissions/{checked_plan['submissionRef']}/objects/{role}/{digest}",
                headers={
                    "accept": "application/json",
                    "authorization": f"Bearer {self.profile.access_token}",
                    "content-type": _ARTIFACT_CONTENT_TYPE,
                    "content-length": str(current.st_size),
                    "x-limitless-content-digest": digest,
                    "user-agent": "limitless-library/0.1.0a0",
                },
                source=opened,
                byte_length=current.st_size,
                expected_digest=digest,
                maximum_bytes=MAX_CONTENT_TRANSFER_RESULT_BYTES,
                timeout_seconds=self._upload_timeout_seconds,
            )
            after = os.fstat(opened.fileno())
            if after.st_size != current.st_size or after.st_dev != current.st_dev or after.st_ino != current.st_ino:
                raise ServiceConnectorError("public content upload source changed")
        except ServiceConnectorError:
            raise
        except OSError as error:
            raise ServiceConnectorError("public content upload source is unavailable") from error
        finally:
            if opened is not None:
                opened.close()

        if response.status in {401, 403}:
            raise ServiceConnectorError("managed service upload authorization failed")
        if response.status in {429, 500, 502, 503, 504}:
            raise ServiceUnavailableError("managed service is unavailable; continue locally")
        if response.status == 428:
            raise ServiceConnectorError("current publication policy acceptance is required")
        if response.status not in {200, 201}:
            raise ServiceConnectorError("managed service rejected the content upload")
        headers = self._response_headers(response.headers)
        if _JSON_CONTENT_TYPE.fullmatch(headers.get("content-type", "")) is None:
            raise ServiceConnectorError("service upload response content type is invalid")
        try:
            value = strict_json_loads(response.body.decode("utf-8"))
            result = validate_content_transfer_result(
                value,
                expected_plan=checked_plan,
            )
        except (
            UnicodeError,
            json.JSONDecodeError,
            PublicSubmissionContractError,
            TypeError,
            ValueError,
        ) as error:
            raise ServiceConnectorError("service content upload result is invalid") from error
        if descriptor is None or (result["role"], result["digest"], result["byteLength"]) != (
            descriptor["role"],
            descriptor["digest"],
            descriptor["byteLength"],
        ):
            raise ServiceConnectorError("service content upload result is unbound")
        return result

    def submission_status(self, submission_ref: str) -> dict[str, Any]:
        """Return one publisher-visible admission status without candidate leakage."""

        if self.profile.access_token is None:
            raise ServiceConnectorError("managed service authorization is required")
        if not isinstance(submission_ref, str) or re.fullmatch(r"submission:[0-9a-f]{32}", submission_ref) is None:
            raise ServiceConnectorError("public submission reference is invalid")
        response = self._request_json(
            "POST",
            f"/v1/submissions/{submission_ref}/admission-status",
            body=None,
            maximum_bytes=MAX_PUBLICATION_STATUS_BYTES,
            authenticated=True,
        )
        try:
            return validate_public_admission_status(
                response,
                expected_submission_ref=submission_ref,
            )
        except PublicAdmissionContractError as error:
            raise ServiceConnectorError("public admission status is invalid") from error

    def revoke_submission_release(
        self,
        request: dict[str, Any],
        *,
        publisher_public_key: bytes,
    ) -> dict[str, Any]:
        """Withdraw one exact publisher-owned release through a signed request."""

        if self.profile.access_token is None:
            raise ServiceConnectorError("managed service authorization is required")
        now = self._now()
        try:
            key_id = request["publisher"]["keyId"]
            checked = validate_public_release_revocation_request(
                request,
                public_keys={key_id: publisher_public_key},
                at=now,
            )
        except (KeyError, PublicAdmissionContractError, TypeError, ValueError) as error:
            raise ServiceConnectorError("public release revocation is invalid") from error
        if checked["serviceId"] != self.profile.service_id:
            raise ServiceConnectorError("public release revocation names another service")
        response = self._request_json(
            "POST",
            f"/v1/submissions/{checked['submissionRef']}/revocations",
            body=checked,
            maximum_bytes=MAX_PUBLICATION_STATUS_BYTES,
            maximum_request_bytes=MAX_SIGNED_REQUEST_BYTES,
            authenticated=True,
        )
        try:
            status = validate_public_admission_status(
                response,
                expected_submission_ref=checked["submissionRef"],
            )
        except PublicAdmissionContractError as error:
            raise ServiceConnectorError("public release revocation response is invalid") from error
        if (
            status["state"] != "revoked"
            or status["releaseRef"] is None
            or status["releaseRef"]["releaseId"] != checked["releaseId"]
        ):
            raise ServiceConnectorError("public release revocation response is unbound")
        return status

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
        verified = self.inspect()
        compatible_results = [
            version
            for version in SERVICE_QUERY_RESULT_SCHEMA_VERSIONS
            if version in POLICY_BOUND_SERVICE_QUERY_RESULT_SCHEMA_VERSIONS
            and version in verified.discovery["resultVersions"]
        ]
        if not compatible_results:
            raise ServiceConnectorError("service does not advertise a policy-bound result generation")
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
            supported_result_version=compatible_results[-1],
        )
