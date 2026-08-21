"""Client-side contracts for anonymous installation identity and sessions.

The managed service owns identity persistence and authorization.  This module
contains only the language-neutral records an inspectable client must build or
verify before it accepts anonymous service authority.
"""

from __future__ import annotations

import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature

from ._service_support import (
    DecisionSigningAuthority,
    isoformat_utc,
    public_key_from_bytes,
)
from .contracts import (
    ContractError,
    canonical_json_bytes,
    parse_utc,
    sha256_bytes,
    sha256_json,
)

INSTALLATION_REGISTRATION_SCHEMA_VERSION = "limitless.installation-registration-request/1.0"
INSTALLATION_ATTESTATION_SCHEMA_VERSION = "limitless.installation-attestation/1.0"
INSTALLATION_SESSION_REQUEST_SCHEMA_VERSION = "limitless.installation-session-request/1.0"
INSTALLATION_SESSION_RESPONSE_SCHEMA_VERSION = "limitless.installation-session-response/1.0"
SIGNATURE_ALGORITHM = "ed25519"
MAX_REQUEST_TTL = timedelta(minutes=5)
MAX_REQUEST_BYTES = 8 * 1024
MAX_ATTESTATION_BYTES = 8 * 1024
MAX_SESSION_RESPONSE_BYTES = 8 * 1024
MAX_SESSION_TTL_SECONDS = 3600
INSTALLATION_SESSION_CAPABILITIES = (
    "circles",
    "deliveries",
    "queries",
    "submissions",
)

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,199}$")
_REQUEST = re.compile(r"^request:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_INSTALLATION = re.compile(r"^installation:[0-9a-f]{32}$")
_INSTALLATION_SESSION = re.compile(r"^installation-session:[0-9a-f]{32}$")
_INSTALLATION_SPACE = re.compile(r"^installation-space:[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BASE64URL_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_SESSION_TOKEN = re.compile(r"^lst_[A-Za-z0-9_-]{43}$")


class InstallationIdentityContractError(ValueError):
    """An installation identity or session envelope is malformed."""


def _exact(value: Any, fields: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise InstallationIdentityContractError(f"{field} has an unsupported shape")
    return value


def _text(
    value: Any,
    field: str,
    *,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or pattern is not None
        and pattern.fullmatch(value) is None
    ):
        raise InstallationIdentityContractError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    return _text(value, field, maximum=71, pattern=_DIGEST)


def _encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: Any, field: str) -> bytes:
    encoded = _text(value, field, maximum=43, pattern=_BASE64URL_32)
    try:
        decoded = urlsafe_b64decode(encoded + "=")
    except (TypeError, ValueError) as error:
        raise InstallationIdentityContractError(f"{field} is invalid") from error
    if len(decoded) != 32 or _encode(decoded) != encoded:
        raise InstallationIdentityContractError(f"{field} is invalid")
    return decoded


def _timestamp(value: Any, field: str) -> datetime:
    try:
        parsed = parse_utc(value, field)
    except ContractError as error:
        raise InstallationIdentityContractError(f"{field} is invalid") from error
    if parsed.microsecond:
        raise InstallationIdentityContractError(f"{field} must use whole seconds")
    return parsed


def _lifetime(
    issued_value: Any,
    expires_value: Any,
    *,
    at: datetime | None,
    field: str,
) -> tuple[str, str]:
    issued = _timestamp(issued_value, f"{field} issuedAt")
    expires = _timestamp(expires_value, f"{field} expiresAt")
    if not issued < expires <= issued + MAX_REQUEST_TTL:
        raise InstallationIdentityContractError(f"{field} lifetime is invalid")
    if at is not None:
        if not isinstance(at, datetime) or at.tzinfo is None:
            raise InstallationIdentityContractError("validation time is invalid")
        current = at.astimezone(UTC).replace(microsecond=0)
        if current < issued or current > expires:
            raise InstallationIdentityContractError(f"{field} is not current")
    return isoformat_utc(issued), isoformat_utc(expires)


def installation_key_id(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise InstallationIdentityContractError("installation public key is invalid")
    return "key:installation:" + sha256_bytes(public_key)[7:39]


def installation_id(service_id: str, public_key: bytes) -> str:
    service = _text(service_id, "serviceId", maximum=200, pattern=_IDENTIFIER)
    return "installation:" + sha256_json({"serviceId": service, "publicKeyDigest": sha256_bytes(public_key)})[7:39]


def installation_tenant_id(installation_id_value: str) -> str:
    installation = _text(
        installation_id_value,
        "installationId",
        maximum=45,
        pattern=_INSTALLATION,
    )
    return "installation-space:" + installation.removeprefix("installation:")


def _public_key(value: Any, field: str) -> tuple[dict[str, str], bytes]:
    item = _exact(value, {"keyId", "algorithm", "value"}, field)
    material = _decode(item["value"], f"{field} value")
    normalized = {
        "keyId": _text(item["keyId"], f"{field} keyId", maximum=200, pattern=_IDENTIFIER),
        "algorithm": _text(item["algorithm"], f"{field} algorithm", maximum=20),
        "value": _encode(material),
    }
    if normalized["algorithm"] != SIGNATURE_ALGORITHM:
        raise InstallationIdentityContractError(f"{field} algorithm is invalid")
    if normalized["keyId"] != installation_key_id(material):
        raise InstallationIdentityContractError(f"{field} keyId is not derived from its key")
    return normalized, material


def _signature(value: Any, field: str) -> dict[str, str]:
    item = _exact(value, {"keyId", "algorithm", "value"}, field)
    signature = {
        "keyId": _text(item["keyId"], f"{field} keyId", maximum=200, pattern=_IDENTIFIER),
        "algorithm": _text(item["algorithm"], f"{field} algorithm", maximum=20),
        "value": _text(item["value"], f"{field} value", maximum=86, pattern=_SIGNATURE),
    }
    if signature["algorithm"] != SIGNATURE_ALGORITHM:
        raise InstallationIdentityContractError(f"{field} algorithm is invalid")
    return signature


def _verify(payload: dict[str, Any], signature: dict[str, str], key: bytes) -> None:
    try:
        encoded = signature["value"]
        decoded = urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        if len(decoded) != 64:
            raise ValueError("invalid signature length")
        public_key_from_bytes(key).verify(decoded, canonical_json_bytes(payload))
    except (ContractError, InvalidSignature, TypeError, ValueError) as error:
        raise InstallationIdentityContractError("signature is invalid") from error


def _sign(
    payload: dict[str, Any],
    *,
    signer: DecisionSigningAuthority,
    key_id: str,
) -> dict[str, str]:
    try:
        return {
            "keyId": key_id,
            "algorithm": SIGNATURE_ALGORITHM,
            "value": signer.sign(canonical_json_bytes(payload)),
        }
    except Exception as error:
        raise InstallationIdentityContractError("signature creation failed") from error


def validate_installation_registration_request(
    value: Any,
    *,
    at: datetime | None = None,
) -> dict[str, Any]:
    request = _exact(
        value,
        {
            "schemaVersion",
            "requestId",
            "serviceId",
            "publicKey",
            "issuedAt",
            "expiresAt",
            "requestDigest",
            "proof",
        },
        "installation registration request",
    )
    if request["schemaVersion"] != INSTALLATION_REGISTRATION_SCHEMA_VERSION:
        raise InstallationIdentityContractError("installation registration schemaVersion is invalid")
    key, material = _public_key(request["publicKey"], "installation registration publicKey")
    issued, expires = _lifetime(
        request["issuedAt"],
        request["expiresAt"],
        at=at,
        field="installation registration request",
    )
    unsigned = {
        "schemaVersion": INSTALLATION_REGISTRATION_SCHEMA_VERSION,
        "requestId": _text(
            request["requestId"],
            "installation registration requestId",
            maximum=128,
            pattern=_REQUEST,
        ),
        "serviceId": _text(
            request["serviceId"],
            "installation registration serviceId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "publicKey": key,
        "issuedAt": issued,
        "expiresAt": expires,
    }
    digest = _digest(request["requestDigest"], "installation registration requestDigest")
    if digest != sha256_json(unsigned):
        raise InstallationIdentityContractError("installation registration digest does not bind its exact content")
    signed = {**unsigned, "requestDigest": digest}
    proof = _signature(request["proof"], "installation registration proof")
    if proof["keyId"] != key["keyId"]:
        raise InstallationIdentityContractError("installation registration proof uses the wrong key")
    _verify(signed, proof, material)
    result = {**signed, "proof": proof}
    if len(canonical_json_bytes(result)) > MAX_REQUEST_BYTES:
        raise InstallationIdentityContractError("installation registration request exceeds its byte limit")
    return result


def build_installation_registration_request(
    *,
    signer: DecisionSigningAuthority,
    service_id: str,
    request_id: str,
    issued_at: datetime,
    ttl_seconds: int = 120,
) -> dict[str, Any]:
    if (
        not isinstance(issued_at, datetime)
        or issued_at.tzinfo is None
        or isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 1 <= ttl_seconds <= int(MAX_REQUEST_TTL.total_seconds())
    ):
        raise InstallationIdentityContractError("installation registration lifetime is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    material = signer.public_bytes()
    key_id = installation_key_id(material)
    unsigned = {
        "schemaVersion": INSTALLATION_REGISTRATION_SCHEMA_VERSION,
        "requestId": request_id,
        "serviceId": service_id,
        "publicKey": {
            "keyId": key_id,
            "algorithm": SIGNATURE_ALGORITHM,
            "value": _encode(material),
        },
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    digest = sha256_json(unsigned)
    signed = {**unsigned, "requestDigest": digest}
    return validate_installation_registration_request({**signed, "proof": _sign(signed, signer=signer, key_id=key_id)})


def validate_installation_attestation(
    value: Any,
    *,
    service_public_keys: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    attestation = _exact(
        value,
        {
            "schemaVersion",
            "serviceId",
            "installationId",
            "currentKey",
            "generation",
            "accountId",
            "status",
            "issuedAt",
            "attestationDigest",
            "signature",
        },
        "installation attestation",
    )
    if attestation["schemaVersion"] != INSTALLATION_ATTESTATION_SCHEMA_VERSION:
        raise InstallationIdentityContractError("installation attestation schemaVersion is invalid")
    key, material = _public_key(attestation["currentKey"], "installation attestation currentKey")
    generation = attestation["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= 16:
        raise InstallationIdentityContractError("installation attestation generation is invalid")
    account_id = attestation["accountId"]
    if account_id is not None:
        account_id = _text(
            account_id,
            "installation attestation accountId",
            maximum=200,
            pattern=_IDENTIFIER,
        )
    status = _text(attestation["status"], "installation attestation status", maximum=16)
    if status not in {"active", "disabled"}:
        raise InstallationIdentityContractError("installation attestation status is invalid")
    unsigned = {
        "schemaVersion": INSTALLATION_ATTESTATION_SCHEMA_VERSION,
        "serviceId": _text(
            attestation["serviceId"],
            "installation attestation serviceId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "installationId": _text(
            attestation["installationId"],
            "installation attestation installationId",
            maximum=45,
            pattern=_INSTALLATION,
        ),
        "currentKey": key,
        "generation": generation,
        "accountId": account_id,
        "status": status,
        "issuedAt": isoformat_utc(_timestamp(attestation["issuedAt"], "installation attestation issuedAt")),
    }
    if generation == 1 and unsigned["installationId"] != installation_id(unsigned["serviceId"], material):
        raise InstallationIdentityContractError(
            "installation attestation identity is not derived from its original key"
        )
    digest = _digest(
        attestation["attestationDigest"],
        "installation attestation attestationDigest",
    )
    if digest != sha256_json(unsigned):
        raise InstallationIdentityContractError("installation attestation digest does not bind its exact content")
    signed = {**unsigned, "attestationDigest": digest}
    signature = _signature(attestation["signature"], "installation attestation signature")
    if service_public_keys is not None:
        key_material = service_public_keys.get(signature["keyId"])
        if key_material is None:
            raise InstallationIdentityContractError("installation attestation signing key is unknown")
        _verify(signed, signature, key_material)
    result = {**signed, "signature": signature}
    if len(canonical_json_bytes(result)) > MAX_ATTESTATION_BYTES:
        raise InstallationIdentityContractError("installation attestation exceeds its byte limit")
    return result


def build_installation_attestation(
    *,
    service_id: str,
    installation_id_value: str,
    current_public_key: bytes,
    generation: int,
    account_id: str | None,
    status: str,
    issued_at: datetime,
    signer: DecisionSigningAuthority,
) -> dict[str, Any]:
    """Build the service response for conformance and alternate implementations."""

    key_id = installation_key_id(current_public_key)
    unsigned = {
        "schemaVersion": INSTALLATION_ATTESTATION_SCHEMA_VERSION,
        "serviceId": service_id,
        "installationId": installation_id_value,
        "currentKey": {
            "keyId": key_id,
            "algorithm": SIGNATURE_ALGORITHM,
            "value": _encode(current_public_key),
        },
        "generation": generation,
        "accountId": account_id,
        "status": status,
        "issuedAt": isoformat_utc(issued_at.astimezone(UTC).replace(microsecond=0)),
    }
    digest = sha256_json(unsigned)
    signed = {**unsigned, "attestationDigest": digest}
    return validate_installation_attestation(
        {
            **signed,
            "signature": _sign(signed, signer=signer, key_id=signer.key_id),
        },
        service_public_keys={signer.key_id: signer.public_bytes()},
    )


def validate_installation_session_request(
    value: Any,
    *,
    current_public_key: bytes,
    at: datetime | None = None,
) -> dict[str, Any]:
    request = _exact(
        value,
        {
            "schemaVersion",
            "requestId",
            "serviceId",
            "installationId",
            "generation",
            "currentKeyId",
            "acceptedPolicyDigest",
            "capabilities",
            "sessionTtlSeconds",
            "issuedAt",
            "expiresAt",
            "requestDigest",
            "proof",
        },
        "installation session request",
    )
    if request["schemaVersion"] != INSTALLATION_SESSION_REQUEST_SCHEMA_VERSION:
        raise InstallationIdentityContractError("installation session schemaVersion is invalid")
    generation = request["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= 16:
        raise InstallationIdentityContractError("installation session generation is invalid")
    capabilities = request["capabilities"]
    if (
        not isinstance(capabilities, list)
        or capabilities != sorted(set(capabilities))
        or not capabilities
        or not set(capabilities).issubset(INSTALLATION_SESSION_CAPABILITIES)
    ):
        raise InstallationIdentityContractError("installation session capabilities are invalid")
    session_ttl = request["sessionTtlSeconds"]
    if (
        isinstance(session_ttl, bool)
        or not isinstance(session_ttl, int)
        or not 60 <= session_ttl <= MAX_SESSION_TTL_SECONDS
    ):
        raise InstallationIdentityContractError("installation session lifetime is invalid")
    issued, expires = _lifetime(
        request["issuedAt"],
        request["expiresAt"],
        at=at,
        field="installation session request",
    )
    unsigned = {
        "schemaVersion": INSTALLATION_SESSION_REQUEST_SCHEMA_VERSION,
        "requestId": _text(
            request["requestId"],
            "installation session requestId",
            maximum=128,
            pattern=_REQUEST,
        ),
        "serviceId": _text(
            request["serviceId"],
            "installation session serviceId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "installationId": _text(
            request["installationId"],
            "installation session installationId",
            maximum=45,
            pattern=_INSTALLATION,
        ),
        "generation": generation,
        "currentKeyId": _text(
            request["currentKeyId"],
            "installation session currentKeyId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "acceptedPolicyDigest": _digest(
            request["acceptedPolicyDigest"],
            "installation session acceptedPolicyDigest",
        ),
        "capabilities": capabilities,
        "sessionTtlSeconds": session_ttl,
        "issuedAt": issued,
        "expiresAt": expires,
    }
    digest = _digest(request["requestDigest"], "installation session requestDigest")
    if digest != sha256_json(unsigned):
        raise InstallationIdentityContractError("installation session digest does not bind its exact content")
    signed = {**unsigned, "requestDigest": digest}
    proof = _signature(request["proof"], "installation session proof")
    current_key_id = installation_key_id(current_public_key)
    if signed["currentKeyId"] != current_key_id or proof["keyId"] != current_key_id:
        raise InstallationIdentityContractError("installation session key binding is invalid")
    _verify(signed, proof, current_public_key)
    result = {**signed, "proof": proof}
    if len(canonical_json_bytes(result)) > MAX_REQUEST_BYTES:
        raise InstallationIdentityContractError("installation session request exceeds its byte limit")
    return result


def build_installation_session_request(
    *,
    service_id: str,
    installation_id_value: str,
    generation: int,
    request_id: str,
    current_signer: DecisionSigningAuthority,
    issued_at: datetime,
    accepted_policy_digest: str,
    capabilities: tuple[str, ...] = INSTALLATION_SESSION_CAPABILITIES,
    request_ttl_seconds: int = 120,
    session_ttl_seconds: int = 900,
) -> dict[str, Any]:
    if (
        not isinstance(issued_at, datetime)
        or issued_at.tzinfo is None
        or isinstance(request_ttl_seconds, bool)
        or not isinstance(request_ttl_seconds, int)
        or not 1 <= request_ttl_seconds <= int(MAX_REQUEST_TTL.total_seconds())
    ):
        raise InstallationIdentityContractError("installation session request lifetime is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    current_key_id = installation_key_id(current_signer.public_bytes())
    unsigned = {
        "schemaVersion": INSTALLATION_SESSION_REQUEST_SCHEMA_VERSION,
        "requestId": request_id,
        "serviceId": service_id,
        "installationId": installation_id_value,
        "generation": generation,
        "currentKeyId": current_key_id,
        "acceptedPolicyDigest": accepted_policy_digest,
        "capabilities": list(capabilities),
        "sessionTtlSeconds": session_ttl_seconds,
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=request_ttl_seconds)),
    }
    digest = sha256_json(unsigned)
    signed = {**unsigned, "requestDigest": digest}
    return validate_installation_session_request(
        {
            **signed,
            "proof": _sign(signed, signer=current_signer, key_id=current_key_id),
        },
        current_public_key=current_signer.public_bytes(),
    )


def validate_installation_session_response(
    value: Any,
    *,
    expected_request: Mapping[str, Any],
    current_public_key: bytes,
    at: datetime | None = None,
) -> dict[str, Any]:
    """Validate the bounded TLS response and bind it to the signed request."""

    response = _exact(
        value,
        {
            "schemaVersion",
            "accessToken",
            "tokenType",
            "sessionId",
            "installationId",
            "tenantId",
            "acceptedPolicyDigest",
            "capabilities",
            "issuedAt",
            "expiresAt",
        },
        "installation session response",
    )
    checked_request = validate_installation_session_request(
        dict(expected_request),
        current_public_key=current_public_key,
    )
    token = _text(
        response["accessToken"],
        "installation session accessToken",
        maximum=47,
        pattern=_SESSION_TOKEN,
    )
    session_id_value = _text(
        response["sessionId"],
        "installation session sessionId",
        maximum=53,
        pattern=_INSTALLATION_SESSION,
    )
    if session_id_value != "installation-session:" + sha256_bytes(token.encode("ascii"))[7:39]:
        raise InstallationIdentityContractError("installation session token is unbound")
    installation_id_value = _text(
        response["installationId"],
        "installation session installationId",
        maximum=45,
        pattern=_INSTALLATION,
    )
    tenant_id = _text(
        response["tenantId"],
        "installation session tenantId",
        maximum=51,
        pattern=_INSTALLATION_SPACE,
    )
    capabilities = response["capabilities"]
    if (
        not isinstance(capabilities, list)
        or capabilities != sorted(set(capabilities))
        or not capabilities
        or not set(capabilities).issubset(INSTALLATION_SESSION_CAPABILITIES)
    ):
        raise InstallationIdentityContractError("installation session capabilities are invalid")
    issued = _timestamp(response["issuedAt"], "installation session issuedAt")
    expires = _timestamp(response["expiresAt"], "installation session expiresAt")
    request_issued = _timestamp(checked_request["issuedAt"], "installation session request issuedAt")
    request_expires = _timestamp(checked_request["expiresAt"], "installation session request expiresAt")
    if not request_issued <= issued <= request_expires or not issued < expires <= issued + timedelta(
        seconds=checked_request["sessionTtlSeconds"]
    ):
        raise InstallationIdentityContractError("installation session response lifetime is invalid")
    if at is not None:
        if not isinstance(at, datetime) or at.tzinfo is None:
            raise InstallationIdentityContractError("validation time is invalid")
        current = at.astimezone(UTC).replace(microsecond=0)
        if current < issued or current >= expires:
            raise InstallationIdentityContractError("installation session response is not current")
    if (
        response["schemaVersion"] != INSTALLATION_SESSION_RESPONSE_SCHEMA_VERSION
        or response["tokenType"] != "Bearer"
        or installation_id_value != checked_request.get("installationId")
        or tenant_id != installation_tenant_id(installation_id_value)
        or response["acceptedPolicyDigest"] != checked_request.get("acceptedPolicyDigest")
        or capabilities != checked_request.get("capabilities")
    ):
        raise InstallationIdentityContractError("installation session response differs from its request")
    normalized = {
        "schemaVersion": INSTALLATION_SESSION_RESPONSE_SCHEMA_VERSION,
        "accessToken": token,
        "tokenType": "Bearer",
        "sessionId": session_id_value,
        "installationId": installation_id_value,
        "tenantId": tenant_id,
        "acceptedPolicyDigest": _digest(
            response["acceptedPolicyDigest"],
            "installation session acceptedPolicyDigest",
        ),
        "capabilities": capabilities,
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(expires),
    }
    if len(canonical_json_bytes(normalized)) > MAX_SESSION_RESPONSE_BYTES:
        raise InstallationIdentityContractError("installation session response exceeds its byte limit")
    return normalized


__all__ = [
    "INSTALLATION_ATTESTATION_SCHEMA_VERSION",
    "INSTALLATION_REGISTRATION_SCHEMA_VERSION",
    "INSTALLATION_SESSION_CAPABILITIES",
    "INSTALLATION_SESSION_REQUEST_SCHEMA_VERSION",
    "INSTALLATION_SESSION_RESPONSE_SCHEMA_VERSION",
    "InstallationIdentityContractError",
    "build_installation_attestation",
    "build_installation_registration_request",
    "build_installation_session_request",
    "installation_id",
    "installation_key_id",
    "installation_tenant_id",
    "validate_installation_attestation",
    "validate_installation_registration_request",
    "validate_installation_session_request",
    "validate_installation_session_response",
]
