"""One-action activation for the release-pinned official Limitless service.

Local reuse remains the default.  An official release may bundle one immutable
locator containing the service identity, original root key, profile URL, and
exact profile digest.  Activation fetches that profile, verifies the complete
root-transition and discovery chain through :class:`ServiceConnector`, and
only then stores credential-free local state.

This source release deliberately contains no live locator.  Publishing that
trust anchor is a separate owner-controlled release step, not a client default.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from .contracts import (
    ContractError,
    canonical_json_bytes,
    load_json,
    sha256_json,
    strict_json_loads,
    write_new_json,
)
from .service_connector import (
    ServiceConnector,
    ServiceConnectorError,
    ServiceProfile,
    ServiceTransport,
    ServiceUnavailableError,
    UrllibServiceTransport,
)
from .service_contracts import (
    MAX_SERVICE_PROFILE_BYTES,
    PublicServiceContractError,
    validate_official_service_locator,
    validate_service_profile,
)
from .service_identity import (
    ServiceIdentityError,
    ServiceIdentityUnavailableError,
    ensure_installation_session,
)

ACTIVATION_STATE_SCHEMA_VERSION = "limitless.official-service-activation/1.0"
ACTIVATION_DETAILS_SCHEMA_VERSION = "limitless.official-service-details/1.0"
MAX_ACTIVATION_STATE_BYTES = 16 * 1024
_BUNDLED_LOCATOR_NAME = "official-service-locator.json"


class OfficialServiceActivationError(ServiceConnectorError):
    """Bundled trust, fetched authority, or local activation state is invalid."""


class OfficialServiceNotConfiguredError(OfficialServiceActivationError):
    """This client release does not bundle an official-service trust anchor."""


class OfficialServiceUnavailableError(OfficialServiceActivationError):
    """The optional official service is unavailable; local use remains valid."""


def _whole_second(value: datetime | None) -> datetime:
    selected = datetime.now(tz=UTC) if value is None else value
    if not isinstance(selected, datetime) or selected.tzinfo is None or selected.utcoffset() is None:
        raise OfficialServiceActivationError("official service activation time must be timezone-aware")
    return selected.astimezone(UTC).replace(microsecond=0)


def _isoformat(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def default_activation_state_path(
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Return the per-user activation state without creating it."""

    environment = os.environ if environ is None else environ
    configured = environment.get("XDG_CONFIG_HOME")
    if configured:
        root = Path(configured)
    else:
        home = environment.get("HOME")
        if not home:
            raise OfficialServiceActivationError("a per-user configuration directory is unavailable")
        root = Path(home) / ".config"
    if not root.is_absolute() or any(part == ".." for part in root.parts):
        raise OfficialServiceActivationError("the per-user configuration directory is invalid")
    return root / "limitless-library" / "official-service.json"


def _installation_path(
    activation_path: Path,
    installation_path: Path | None,
) -> Path:
    if installation_path is not None:
        return Path(installation_path)
    return Path(activation_path).with_name("official-service-identity.json")


def load_bundled_official_locator() -> dict[str, Any]:
    """Load the release-pinned locator, or preserve the local-only build."""

    resource = files("limitless_library").joinpath(_BUNDLED_LOCATOR_NAME)
    try:
        raw = resource.read_bytes()
    except FileNotFoundError as error:
        raise OfficialServiceNotConfiguredError(
            "the official service is not configured in this client release; continue locally"
        ) from error
    except OSError as error:
        raise OfficialServiceActivationError("the bundled official service locator is unreadable") from error
    if not raw or len(raw) > 4 * 1024:
        raise OfficialServiceActivationError("the bundled official service locator is invalid")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
        return validate_official_service_locator(value)
    except (UnicodeError, json.JSONDecodeError, PublicServiceContractError) as error:
        raise OfficialServiceActivationError("the bundled official service locator is invalid") from error


def _profile_record(value: Any) -> dict[str, Any]:
    try:
        return validate_service_profile(value)
    except PublicServiceContractError as error:
        raise OfficialServiceActivationError("the official service profile is invalid") from error


def validate_activation_state(value: Any) -> dict[str, Any]:
    expected = {
        "schemaVersion",
        "enabled",
        "locatorDigest",
        "profileDigest",
        "profile",
        "activatedAt",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise OfficialServiceActivationError("official service activation state has an unsupported shape")
    if value["schemaVersion"] != ACTIVATION_STATE_SCHEMA_VERSION or value["enabled"] is not True:
        raise OfficialServiceActivationError("official service activation state is invalid")
    profile = _profile_record(value["profile"])
    for field in ("locatorDigest", "profileDigest"):
        digest = value[field]
        if (
            not isinstance(digest, str)
            or len(digest) != 71
            or not digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in digest[7:])
        ):
            raise OfficialServiceActivationError(f"official service activation {field} is invalid")
    if value["profileDigest"] != sha256_json(profile):
        raise OfficialServiceActivationError("official service activation profile digest is invalid")
    try:
        activated = datetime.fromisoformat(str(value["activatedAt"]))
    except ValueError as error:
        raise OfficialServiceActivationError("official service activation time is invalid") from error
    if (
        activated.tzinfo is None
        or activated.microsecond
        or _isoformat(activated.astimezone(UTC)) != value["activatedAt"]
    ):
        raise OfficialServiceActivationError("official service activation time is invalid")
    checked = {
        "schemaVersion": ACTIVATION_STATE_SCHEMA_VERSION,
        "enabled": True,
        "locatorDigest": value["locatorDigest"],
        "profileDigest": value["profileDigest"],
        "profile": profile,
        "activatedAt": value["activatedAt"],
    }
    if len(canonical_json_bytes(checked)) > MAX_ACTIVATION_STATE_BYTES:
        raise OfficialServiceActivationError("official service activation state exceeds its byte limit")
    return checked


def load_activation_state(path: Path | None = None) -> dict[str, Any] | None:
    selected = default_activation_state_path() if path is None else Path(path)
    if selected.is_symlink():
        raise OfficialServiceActivationError("official service activation state path is unsafe")
    if not selected.exists():
        return None
    if not selected.is_file():
        raise OfficialServiceActivationError("official service activation state path is unsafe")
    try:
        return validate_activation_state(load_json(selected))
    except OfficialServiceActivationError:
        raise
    except (ContractError, OSError, ValueError) as error:
        raise OfficialServiceActivationError("official service activation state is unreadable") from error


def activation_details(path: Path | None = None) -> dict[str, Any]:
    state = load_activation_state(path)
    if state is None:
        return {
            "schemaVersion": ACTIVATION_DETAILS_SCHEMA_VERSION,
            "enabled": False,
            "executionMode": "local",
            "historyMode": "local-only",
        }
    profile = ServiceProfile.from_json(state["profile"])
    return {
        "schemaVersion": ACTIVATION_DETAILS_SCHEMA_VERSION,
        "enabled": True,
        **{
            key: value
            for key, value in profile.public_summary().items()
            if key not in {"schemaVersion", "authenticated"}
        },
        "activatedAt": state["activatedAt"],
    }


def _fetch_profile(
    *,
    url: str,
    transport: ServiceTransport,
) -> dict[str, Any]:
    try:
        response = transport.request(
            "GET",
            url,
            headers={
                "accept": "application/json",
                "accept-encoding": "identity",
                "user-agent": "limitless-library-official-activation/1",
            },
            body=None,
            maximum_bytes=MAX_SERVICE_PROFILE_BYTES,
            timeout_seconds=5.0,
        )
    except ServiceUnavailableError as error:
        raise OfficialServiceUnavailableError("the official service is unavailable; continue locally") from error
    except ServiceConnectorError as error:
        raise OfficialServiceActivationError("the official service profile could not be verified") from error
    if response.status in {429, 500, 502, 503, 504}:
        raise OfficialServiceUnavailableError("the official service is unavailable; continue locally")
    if response.status != 200:
        raise OfficialServiceActivationError("the official service profile was rejected")
    try:
        value = strict_json_loads(response.body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise OfficialServiceActivationError("the official service profile is not strict JSON") from error
    return _profile_record(value)


def activate_service_from_locator(
    locator_value: Mapping[str, Any],
    *,
    state_path: Path,
    installation_state_path: Path | None = None,
    at: datetime | None = None,
    transport: ServiceTransport | None = None,
) -> dict[str, Any]:
    """Verify and persist a locator supplied by release/conformance tooling."""

    try:
        locator = validate_official_service_locator(dict(locator_value))
    except (PublicServiceContractError, TypeError, ValueError) as error:
        raise OfficialServiceActivationError("the bundled official service locator is invalid") from error
    locator_digest = sha256_json(locator)
    existing = load_activation_state(state_path)
    if existing is not None and not (
        existing["locatorDigest"] == locator_digest
        and existing["profileDigest"] == locator["profileDigest"]
        and existing["profile"]["serviceId"] == locator["serviceId"]
        and existing["profile"]["rootKey"] == locator["rootKey"]
    ):
        raise OfficialServiceActivationError(
            "official service authority changed; explicit replacement acceptance is required"
        )
    current = _whole_second(at)
    selected_transport = transport or UrllibServiceTransport()
    profile_record = _fetch_profile(
        url=locator["profileUrl"],
        transport=selected_transport,
    )
    if (
        sha256_json(profile_record) != locator["profileDigest"]
        or profile_record["serviceId"] != locator["serviceId"]
        or profile_record["rootKey"] != locator["rootKey"]
    ):
        raise OfficialServiceActivationError("the official service profile differs from bundled trust")
    profile = ServiceProfile.from_json(profile_record)
    connector = ServiceConnector(
        profile,
        transport=selected_transport,
        clock=lambda: current,
    )
    try:
        connector.inspect(refresh=True)
    except ServiceUnavailableError as error:
        raise OfficialServiceUnavailableError("the official service is unavailable; continue locally") from error
    except ServiceConnectorError as error:
        raise OfficialServiceActivationError("official service authority verification failed") from error
    selected_installation_path = _installation_path(Path(state_path), installation_state_path)
    try:
        ensure_installation_session(
            connector,
            state_path=selected_installation_path,
            at=current,
        )
    except ServiceIdentityUnavailableError as error:
        raise OfficialServiceUnavailableError(
            "the official service identity is unavailable; continue locally"
        ) from error
    except ServiceIdentityError as error:
        raise OfficialServiceActivationError("the official service identity could not be verified") from error
    if existing is not None:
        return existing
    state = validate_activation_state(
        {
            "schemaVersion": ACTIVATION_STATE_SCHEMA_VERSION,
            "enabled": True,
            "locatorDigest": locator_digest,
            "profileDigest": locator["profileDigest"],
            "profile": profile_record,
            "activatedAt": _isoformat(current),
        }
    )
    try:
        write_new_json(Path(state_path), state)
    except (ContractError, OSError, ValueError) as error:
        replay = load_activation_state(state_path)
        if replay == state:
            return replay
        raise OfficialServiceActivationError("official service activation could not be persisted") from error
    return state


def activate_official_service(
    *,
    state_path: Path | None = None,
    installation_state_path: Path | None = None,
    at: datetime | None = None,
    transport: ServiceTransport | None = None,
) -> dict[str, Any]:
    """Enable the release-pinned service after one explicit user action."""

    selected_path = default_activation_state_path() if state_path is None else state_path
    return activate_service_from_locator(
        load_bundled_official_locator(),
        state_path=selected_path,
        installation_state_path=installation_state_path,
        at=at,
        transport=transport,
    )


def activated_service_profile(
    *,
    state_path: Path | None = None,
    access_token: str | None = None,
) -> ServiceProfile:
    state = load_activation_state(state_path)
    if state is None:
        raise OfficialServiceNotConfiguredError("the official service is not enabled; activate it or continue locally")
    return ServiceProfile.from_json(state["profile"], access_token=access_token)


def activated_service_connector(
    *,
    state_path: Path | None = None,
    installation_state_path: Path | None = None,
    access_token: str | None = None,
    at: datetime | None = None,
    transport: ServiceTransport | None = None,
) -> ServiceConnector:
    """Return a usable official connector with automatic anonymous authority."""

    selected_state_path = default_activation_state_path() if state_path is None else Path(state_path)
    profile = activated_service_profile(state_path=selected_state_path, access_token=access_token)
    connector = ServiceConnector(
        profile,
        transport=transport,
        clock=None if at is None else lambda: _whole_second(at),
    )
    if access_token is not None:
        return connector
    connected, _details = ensure_installation_session(
        connector,
        state_path=_installation_path(selected_state_path, installation_state_path),
        at=at,
    )
    return connected


__all__ = [
    "ACTIVATION_DETAILS_SCHEMA_VERSION",
    "ACTIVATION_STATE_SCHEMA_VERSION",
    "OfficialServiceActivationError",
    "OfficialServiceNotConfiguredError",
    "OfficialServiceUnavailableError",
    "activate_official_service",
    "activate_service_from_locator",
    "activated_service_connector",
    "activated_service_profile",
    "activation_details",
    "default_activation_state_path",
    "load_activation_state",
    "load_bundled_official_locator",
    "validate_activation_state",
]
