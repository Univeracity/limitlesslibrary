"""Local custody and anonymous-session bootstrap for the official service.

The ordinary activation record stays credential-free.  A separate mode-0600
state file holds one service-specific Ed25519 key and a short-lived anonymous
session.  The private key never leaves the client; only signed public records
are sent to the service.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_hex
from tempfile import mkstemp
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import canonical_json_bytes, sha256_json, strict_json_loads
from .installation_identity_contracts import (
    INSTALLATION_SESSION_CAPABILITIES,
    InstallationIdentityContractError,
    build_installation_registration_request,
    build_installation_session_request,
    installation_id,
    installation_key_id,
    validate_installation_attestation,
    validate_installation_session_response,
)
from .service_connector import (
    ServiceConnector,
    ServiceConnectorError,
    ServiceUnavailableError,
)

INSTALLATION_STATE_SCHEMA_VERSION = "limitless.installation-client-state/1.0"
MAX_INSTALLATION_STATE_BYTES = 32 * 1024
SESSION_REFRESH_MARGIN = timedelta(seconds=30)

_process_lock = threading.Lock()


class ServiceIdentityError(ServiceConnectorError):
    """Local identity state or remote anonymous authority is invalid."""


class ServiceIdentityUnavailableError(ServiceUnavailableError):
    """Anonymous authority is temporarily unavailable; local use remains valid."""


class InstallationSigner:
    """Minimal service-specific Ed25519 signing authority."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ServiceIdentityError("installation private key is invalid")
        self._private_key = private_key
        self.key_id = installation_key_id(self.public_bytes())

    @classmethod
    def generate(cls) -> InstallationSigner:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_encoded(cls, value: Any) -> InstallationSigner:
        if not isinstance(value, str) or len(value) != 43:
            raise ServiceIdentityError("installation private key is invalid")
        try:
            material = urlsafe_b64decode(value + "=")
            signer = cls(Ed25519PrivateKey.from_private_bytes(material))
        except (TypeError, ValueError) as error:
            raise ServiceIdentityError("installation private key is invalid") from error
        if signer.encoded_private_key() != value:
            raise ServiceIdentityError("installation private key is invalid")
        return signer

    def encoded_private_key(self) -> str:
        material = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return urlsafe_b64encode(material).rstrip(b"=").decode("ascii")

    def public_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload: bytes) -> str:
        if not isinstance(payload, bytes):
            raise ServiceIdentityError("installation signing payload is invalid")
        return urlsafe_b64encode(self._private_key.sign(payload)).rstrip(b"=").decode("ascii")


def default_installation_state_path(
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    environment = os.environ if environ is None else environ
    configured = environment.get("XDG_CONFIG_HOME")
    if configured:
        root = Path(configured)
    else:
        home = environment.get("HOME")
        if not home:
            raise ServiceIdentityError("a per-user configuration directory is unavailable")
        root = Path(home) / ".config"
    if not root.is_absolute() or any(part == ".." for part in root.parts):
        raise ServiceIdentityError("the per-user configuration directory is invalid")
    return root / "limitless-library" / "official-service-identity.json"


def _whole_second(value: datetime | None) -> datetime:
    selected = datetime.now(tz=UTC) if value is None else value
    if not isinstance(selected, datetime) or selected.tzinfo is None:
        raise ServiceIdentityError("installation identity time is invalid")
    return selected.astimezone(UTC).replace(microsecond=0)


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ServiceIdentityError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ServiceIdentityError(f"{field} is invalid") from error
    if (
        parsed.tzinfo is None
        or parsed.microsecond
        or parsed.astimezone(UTC).isoformat().replace("+00:00", "Z") != value
    ):
        raise ServiceIdentityError(f"{field} is invalid")
    return parsed.astimezone(UTC)


def _pending_state(*, service_id: str, signer: InstallationSigner) -> dict[str, Any]:
    identifier = installation_id(service_id, signer.public_bytes())
    return {
        "schemaVersion": INSTALLATION_STATE_SCHEMA_VERSION,
        "serviceId": service_id,
        "installationId": identifier,
        "generation": 1,
        "privateKey": signer.encoded_private_key(),
        "attestation": None,
        "session": None,
    }


def validate_installation_state(value: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion",
        "serviceId",
        "installationId",
        "generation",
        "privateKey",
        "attestation",
        "session",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schemaVersion") != INSTALLATION_STATE_SCHEMA_VERSION
    ):
        raise ServiceIdentityError("installation identity state has an unsupported shape")
    service_id = value["serviceId"]
    if not isinstance(service_id, str) or not service_id.startswith("service:"):
        raise ServiceIdentityError("installation identity service is invalid")
    signer = InstallationSigner.from_encoded(value["privateKey"])
    identifier = installation_id(service_id, signer.public_bytes())
    generation = value["generation"]
    if (
        value["installationId"] != identifier
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= 16
    ):
        raise ServiceIdentityError("installation identity key binding is invalid")
    attestation = value["attestation"]
    if attestation is not None:
        try:
            attestation = validate_installation_attestation(attestation)
        except InstallationIdentityContractError as error:
            raise ServiceIdentityError("installation attestation is invalid") from error
        if (
            attestation["serviceId"] != service_id
            or attestation["installationId"] != identifier
            or attestation["generation"] != generation
            or attestation["currentKey"]["keyId"] != signer.key_id
            or attestation["currentKey"]["value"]
            != urlsafe_b64encode(signer.public_bytes()).rstrip(b"=").decode("ascii")
            or attestation["status"] != "active"
        ):
            raise ServiceIdentityError("installation attestation is unbound")
    elif generation != 1:
        raise ServiceIdentityError("pending installation generation is invalid")
    session = value["session"]
    if session is not None:
        if not isinstance(session, dict) or set(session) != {"request", "response"}:
            raise ServiceIdentityError("cached installation session is invalid")
        try:
            response = validate_installation_session_response(
                session["response"],
                expected_request=session["request"],
                current_public_key=signer.public_bytes(),
            )
        except InstallationIdentityContractError as error:
            raise ServiceIdentityError("cached installation session is invalid") from error
        request = dict(session["request"])
        if (
            request["serviceId"] != service_id
            or request["installationId"] != identifier
            or request["generation"] != generation
            or request["currentKeyId"] != signer.key_id
            or attestation is None
        ):
            raise ServiceIdentityError("cached installation session is unbound")
        session = {"request": request, "response": response}
    normalized = {
        "schemaVersion": INSTALLATION_STATE_SCHEMA_VERSION,
        "serviceId": service_id,
        "installationId": identifier,
        "generation": generation,
        "privateKey": signer.encoded_private_key(),
        "attestation": attestation,
        "session": session,
    }
    if len(canonical_json_bytes(normalized)) > MAX_INSTALLATION_STATE_BYTES:
        raise ServiceIdentityError("installation identity state exceeds its byte limit")
    return normalized


def _secure_parent(path: Path) -> None:
    parent = path.parent
    try:
        if parent.is_symlink():
            raise ServiceIdentityError("installation identity directory is unsafe")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or not parent.is_dir():
            raise ServiceIdentityError("installation identity directory is unsafe")
        if os.name == "posix":
            info = parent.stat()
            if info.st_uid != os.geteuid():
                raise ServiceIdentityError("installation identity directory is not owned by this user")
            os.chmod(parent, 0o700)
    except ServiceIdentityError:
        raise
    except OSError as error:
        raise ServiceIdentityError("installation identity directory is unavailable") from error


def _read_state(path: Path) -> dict[str, Any] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ServiceIdentityError("installation identity state is unreadable") from error
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ServiceIdentityError("installation identity state path is unsafe")
    if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
        raise ServiceIdentityError("installation identity state permissions are unsafe")
    try:
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_INSTALLATION_STATE_BYTES:
            raise ServiceIdentityError("installation identity state is invalid")
        value = strict_json_loads(raw.decode("utf-8"))
        return validate_installation_state(value)
    except ServiceIdentityError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ServiceIdentityError("installation identity state is unreadable") from error


def _replace_state(path: Path, value: dict[str, Any]) -> None:
    checked = validate_installation_state(value)
    encoded = canonical_json_bytes(checked) + b"\n"
    _secure_parent(path)
    if path.is_symlink():
        raise ServiceIdentityError("installation identity state path is unsafe")
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, name = mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as error:
        raise ServiceIdentityError("installation identity state could not be persisted") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def _state_lock(path: Path) -> Iterator[None]:
    _secure_parent(path)
    lock_path = path.with_suffix(path.suffix + ".lock")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
        lock_info = os.fstat(descriptor)
        if not stat.S_ISREG(lock_info.st_mode):
            raise ServiceIdentityError("installation identity lock is unsafe")
        if os.name == "posix" and lock_info.st_uid != os.geteuid():
            raise ServiceIdentityError("installation identity lock is unsafe")
        os.fchmod(descriptor, 0o600)
    except ServiceIdentityError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except OSError as error:
        raise ServiceIdentityError("installation identity lock is unavailable") from error
    try:
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        elif os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        with _process_lock:
            yield
    finally:
        if os.name == "posix":
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        elif os.name == "nt":
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        os.close(descriptor)


def _request_id(kind: str) -> str:
    return f"request:{kind}-{token_hex(16)}"


def _cached_token(
    state: dict[str, Any],
    *,
    policy_digest: str,
    now: datetime,
) -> str | None:
    session = state["session"]
    if session is None:
        return None
    response = session["response"]
    request = session["request"]
    if (
        response["acceptedPolicyDigest"] != policy_digest
        or request["acceptedPolicyDigest"] != policy_digest
        or request["capabilities"] != list(INSTALLATION_SESSION_CAPABILITIES)
        or _parse_time(response["expiresAt"], "installation session expiresAt") <= now + SESSION_REFRESH_MARGIN
    ):
        return None
    return response["accessToken"]


def ensure_installation_session(
    connector: ServiceConnector,
    *,
    state_path: Path | None = None,
    at: datetime | None = None,
) -> tuple[ServiceConnector, dict[str, Any]]:
    """Register once, reuse a live bearer, and otherwise renew it in one POST."""

    if not isinstance(connector, ServiceConnector):
        raise ServiceIdentityError("service connector is invalid")
    selected_path = default_installation_state_path() if state_path is None else Path(state_path)
    if not selected_path.is_absolute() or any(part == ".." for part in selected_path.parts):
        raise ServiceIdentityError("installation identity state path is invalid")
    now = _whole_second(at)
    try:
        verified = connector.inspect()
    except ServiceUnavailableError as error:
        raise ServiceIdentityUnavailableError("anonymous service identity is unavailable; continue locally") from error
    with _state_lock(selected_path):
        state = _read_state(selected_path)
        if state is None:
            state = _pending_state(
                service_id=connector.profile.service_id,
                signer=InstallationSigner.generate(),
            )
            _replace_state(selected_path, state)
        if state["serviceId"] != connector.profile.service_id:
            raise ServiceIdentityError("installation identity belongs to another service")
        signer = InstallationSigner.from_encoded(state["privateKey"])
        if state["attestation"] is None:
            registration = build_installation_registration_request(
                signer=signer,
                service_id=state["serviceId"],
                request_id=_request_id("registration"),
                issued_at=now,
            )
            try:
                attestation_value = connector.register_installation(registration)
                attestation = validate_installation_attestation(
                    attestation_value,
                    service_public_keys=verified.result_keys,
                )
            except ServiceUnavailableError as error:
                raise ServiceIdentityUnavailableError(
                    "anonymous service registration is unavailable; continue locally"
                ) from error
            except (ServiceConnectorError, InstallationIdentityContractError) as error:
                raise ServiceIdentityError("anonymous service registration could not be verified") from error
            if (
                attestation["serviceId"] != state["serviceId"]
                or attestation["installationId"] != state["installationId"]
                or attestation["generation"] != state["generation"]
                or attestation["currentKey"]["keyId"] != signer.key_id
                or attestation["status"] != "active"
            ):
                raise ServiceIdentityError("anonymous service registration returned another identity")
            state = validate_installation_state({**state, "attestation": attestation, "session": None})
            _replace_state(selected_path, state)
        token = _cached_token(
            state,
            policy_digest=connector.profile.accepted_policy_digest,
            now=now,
        )
        if token is None:
            request = build_installation_session_request(
                service_id=state["serviceId"],
                installation_id_value=state["installationId"],
                generation=state["generation"],
                request_id=_request_id("session"),
                current_signer=signer,
                issued_at=now,
                accepted_policy_digest=connector.profile.accepted_policy_digest,
            )
            try:
                response_value = connector.open_installation_session(request)
                response = validate_installation_session_response(
                    response_value,
                    expected_request=request,
                    current_public_key=signer.public_bytes(),
                    at=now,
                )
            except ServiceUnavailableError as error:
                raise ServiceIdentityUnavailableError(
                    "anonymous service session is unavailable; continue locally"
                ) from error
            except (ServiceConnectorError, InstallationIdentityContractError) as error:
                raise ServiceIdentityError("anonymous service session could not be verified") from error
            state = validate_installation_state({**state, "session": {"request": request, "response": response}})
            _replace_state(selected_path, state)
            token = response["accessToken"]
    return connector.with_access_token(token), {
        "schemaVersion": "limitless.installation-session-details/1.0",
        "serviceId": state["serviceId"],
        "installationId": state["installationId"],
        "generation": state["generation"],
        "sessionId": state["session"]["response"]["sessionId"],
        "expiresAt": state["session"]["response"]["expiresAt"],
        "capabilities": state["session"]["response"]["capabilities"],
    }


def installation_state_fingerprint(path: Path | None = None) -> str | None:
    """Return non-secret state identity for diagnostics without exposing a token."""

    selected = default_installation_state_path() if path is None else Path(path)
    state = _read_state(selected)
    if state is None:
        return None
    return sha256_json(
        {
            "serviceId": state["serviceId"],
            "installationId": state["installationId"],
            "generation": state["generation"],
            "attestationDigest": (None if state["attestation"] is None else state["attestation"]["attestationDigest"]),
        }
    )


__all__ = [
    "INSTALLATION_STATE_SCHEMA_VERSION",
    "InstallationSigner",
    "ServiceIdentityError",
    "ServiceIdentityUnavailableError",
    "default_installation_state_path",
    "ensure_installation_session",
    "installation_state_fingerprint",
    "validate_installation_state",
]
