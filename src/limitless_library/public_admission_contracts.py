"""Signed publication-policy and source-neutral admission contracts.

These contracts deliberately keep publisher authorization, service-side
assessment, and release revocation separate.  An account is not required:
an installation key can accept the current publication policy, sign an
immutable submission, and later withdraw its exact release.
"""

from __future__ import annotations

import re
from base64 import urlsafe_b64decode
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature

from ._service_support import (
    DecisionSigningAuthority,
    isoformat_utc,
    public_key_from_bytes,
)
from .contracts import ContractError as ControlPlaneContractError
from .contracts import canonical_json_bytes, parse_utc, sha256_json

CONTRIBUTION_POLICY_ACCEPTANCE_SCHEMA_VERSION = "limitless.contribution-policy-acceptance/1.0"
PUBLIC_ADMISSION_ASSESSMENT_SCHEMA_VERSION = "limitless.public-admission-assessment/1.0"
PUBLIC_RELEASE_REVOCATION_SCHEMA_VERSION = "limitless.public-release-revocation-request/1.0"
PUBLIC_ADMISSION_STATUS_SCHEMA_VERSION = "limitless.public-admission-status/1.0"
SIGNATURE_ALGORITHM = "ed25519"
MAX_SIGNED_REQUEST_BYTES = 8 * 1024
MAX_ASSESSMENT_BYTES = 32 * 1024
MAX_REQUEST_TTL = timedelta(minutes=5)

POLICY_ASSERTIONS = ("acceptable-use", "publication-rights")
ADMISSION_CHECK_IDS = (
    "abuse",
    "capabilities",
    "compatibility",
    "dependencies",
    "malware",
    "privacy",
    "prompt-injection",
    "provenance",
    "quality",
    "rights",
    "secrets",
    "verification",
)
CHECK_DISPOSITIONS = ("fail", "pass", "review")

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,199}$")
_REQUEST = re.compile(r"^request:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_SUBMISSION = re.compile(r"^submission:[0-9a-f]{32}$")
_RELEASE = re.compile(r"^release:[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,79}$")


class PublicAdmissionContractError(ValueError):
    """A publication-policy or admission envelope is invalid."""


def _exact(value: Any, fields: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise PublicAdmissionContractError(f"{field} has an unsupported shape")
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
        raise PublicAdmissionContractError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    return _text(value, field, maximum=71, pattern=_DIGEST)


def _timestamp(value: Any, field: str) -> datetime:
    try:
        parsed = parse_utc(value, field)
    except ControlPlaneContractError as error:
        raise PublicAdmissionContractError(f"{field} is invalid") from error
    if parsed.microsecond:
        raise PublicAdmissionContractError(f"{field} must use whole seconds")
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
        raise PublicAdmissionContractError(f"{field} lifetime is invalid")
    if at is not None:
        if not isinstance(at, datetime) or at.tzinfo is None:
            raise PublicAdmissionContractError("validation time is invalid")
        current = at.astimezone(UTC).replace(microsecond=0)
        if current < issued or current > expires:
            raise PublicAdmissionContractError(f"{field} is not current")
    return isoformat_utc(issued), isoformat_utc(expires)


def _sorted_texts(
    value: Any,
    field: str,
    *,
    maximum_items: int,
    maximum_length: int,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items or not allow_empty and not value:
        raise PublicAdmissionContractError(f"{field} is invalid")
    result = [_text(item, field, maximum=maximum_length, pattern=pattern) for item in value]
    if result != sorted(set(result)):
        raise PublicAdmissionContractError(f"{field} must be sorted and unique")
    return result


def _signature(value: Any, field: str) -> dict[str, str]:
    item = _exact(value, {"keyId", "algorithm", "value"}, field)
    signature = {
        "keyId": _text(item["keyId"], f"{field} keyId", maximum=200, pattern=_IDENTIFIER),
        "algorithm": _text(item["algorithm"], f"{field} algorithm", maximum=20),
        "value": _text(item["value"], f"{field} value", maximum=86, pattern=_SIGNATURE),
    }
    if signature["algorithm"] != SIGNATURE_ALGORITHM:
        raise PublicAdmissionContractError(f"{field} algorithm is invalid")
    return signature


def _verify(
    payload: dict[str, Any],
    signature: dict[str, str],
    public_keys: Mapping[str, bytes],
) -> None:
    key = public_keys.get(signature["keyId"])
    if key is None:
        raise PublicAdmissionContractError("signature key is unknown")
    try:
        encoded = signature["value"]
        decoded = urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        if len(decoded) != 64:
            raise ValueError("invalid signature length")
        public_key_from_bytes(key).verify(decoded, canonical_json_bytes(payload))
    except (ControlPlaneContractError, InvalidSignature, TypeError, ValueError) as error:
        raise PublicAdmissionContractError("signature is invalid") from error


def _sign(payload: dict[str, Any], signer: DecisionSigningAuthority) -> dict[str, str]:
    try:
        signer.assert_ready()
        signer.public_bytes()
        return {
            "keyId": signer.key_id,
            "algorithm": SIGNATURE_ALGORITHM,
            "value": signer.sign(canonical_json_bytes(payload)),
        }
    except Exception as error:
        raise PublicAdmissionContractError("signature creation failed") from error


def _publisher(value: Any, field: str) -> dict[str, str]:
    publisher = _exact(value, {"publisherId", "authorityId", "keyId"}, field)
    return {
        "publisherId": _text(
            publisher["publisherId"],
            f"{field} publisherId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "authorityId": _text(
            publisher["authorityId"],
            f"{field} authorityId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "keyId": _text(
            publisher["keyId"],
            f"{field} keyId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
    }


def validate_contribution_policy_acceptance(
    value: Any,
    *,
    public_keys: Mapping[str, bytes],
    at: datetime | None = None,
) -> dict[str, Any]:
    """Validate a publisher's explicit acceptance of one exact policy revision."""

    request = _exact(
        value,
        {
            "schemaVersion",
            "requestId",
            "serviceId",
            "publisher",
            "policyRevision",
            "policyDigest",
            "assertions",
            "issuedAt",
            "expiresAt",
            "acceptanceDigest",
            "signature",
        },
        "contribution policy acceptance",
    )
    if request["schemaVersion"] != CONTRIBUTION_POLICY_ACCEPTANCE_SCHEMA_VERSION:
        raise PublicAdmissionContractError("contribution policy acceptance schemaVersion is invalid")
    issued, expires = _lifetime(
        request["issuedAt"],
        request["expiresAt"],
        at=at,
        field="contribution policy acceptance",
    )
    unsigned = {
        "schemaVersion": CONTRIBUTION_POLICY_ACCEPTANCE_SCHEMA_VERSION,
        "requestId": _text(
            request["requestId"],
            "contribution policy acceptance requestId",
            maximum=128,
            pattern=_REQUEST,
        ),
        "serviceId": _text(
            request["serviceId"],
            "contribution policy acceptance serviceId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "publisher": _publisher(request["publisher"], "contribution policy acceptance publisher"),
        "policyRevision": _text(
            request["policyRevision"],
            "contribution policy acceptance policyRevision",
            maximum=120,
            pattern=_IDENTIFIER,
        ),
        "policyDigest": _digest(
            request["policyDigest"],
            "contribution policy acceptance policyDigest",
        ),
        "assertions": _sorted_texts(
            request["assertions"],
            "contribution policy acceptance assertions",
            maximum_items=len(POLICY_ASSERTIONS),
            maximum_length=40,
            pattern=_TOKEN,
        ),
        "issuedAt": issued,
        "expiresAt": expires,
    }
    if tuple(unsigned["assertions"]) != POLICY_ASSERTIONS:
        raise PublicAdmissionContractError("contribution policy acceptance assertions are incomplete")
    digest = _digest(
        request["acceptanceDigest"],
        "contribution policy acceptance digest",
    )
    if digest != sha256_json(unsigned):
        raise PublicAdmissionContractError("contribution policy acceptance digest is unbound")
    signed = {**unsigned, "acceptanceDigest": digest}
    signature = _signature(request["signature"], "contribution policy acceptance signature")
    if signature["keyId"] != unsigned["publisher"]["keyId"]:
        raise PublicAdmissionContractError("contribution policy acceptance signer is unbound")
    _verify(signed, signature, public_keys)
    result = {**signed, "signature": signature}
    if len(canonical_json_bytes(result)) > MAX_SIGNED_REQUEST_BYTES:
        raise PublicAdmissionContractError("contribution policy acceptance exceeds its byte limit")
    return result


def build_contribution_policy_acceptance(
    *,
    signer: DecisionSigningAuthority,
    service_id: str,
    publisher_id: str,
    authority_id: str,
    policy_revision: str,
    policy_digest: str,
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
        raise PublicAdmissionContractError("contribution policy acceptance lifetime is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    unsigned = {
        "schemaVersion": CONTRIBUTION_POLICY_ACCEPTANCE_SCHEMA_VERSION,
        "requestId": request_id,
        "serviceId": service_id,
        "publisher": {
            "publisherId": publisher_id,
            "authorityId": authority_id,
            "keyId": signer.key_id,
        },
        "policyRevision": policy_revision,
        "policyDigest": policy_digest,
        "assertions": list(POLICY_ASSERTIONS),
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    signed = {**unsigned, "acceptanceDigest": sha256_json(unsigned)}
    return validate_contribution_policy_acceptance(
        {**signed, "signature": _sign(signed, signer)},
        public_keys={signer.key_id: signer.public_bytes()},
    )


def validate_public_admission_assessment(value: Any) -> dict[str, Any]:
    """Validate complete service-generated evidence for one submission."""

    assessment = _exact(
        value,
        {
            "schemaVersion",
            "submissionRef",
            "intentDigest",
            "publisherId",
            "engine",
            "checks",
            "assessedAt",
            "assessmentDigest",
        },
        "public admission assessment",
    )
    if assessment["schemaVersion"] != PUBLIC_ADMISSION_ASSESSMENT_SCHEMA_VERSION:
        raise PublicAdmissionContractError("public admission assessment schemaVersion is invalid")
    engine = _exact(assessment["engine"], {"engineId", "version"}, "admission engine")
    raw_checks = assessment["checks"]
    if not isinstance(raw_checks, list) or len(raw_checks) != len(ADMISSION_CHECK_IDS):
        raise PublicAdmissionContractError("public admission assessment checks are incomplete")
    checks: list[dict[str, Any]] = []
    for raw in raw_checks:
        check = _exact(
            raw,
            {"id", "disposition", "evidenceDigests", "reasonCodes"},
            "public admission check",
        )
        disposition = _text(
            check["disposition"],
            "public admission check disposition",
            maximum=12,
        )
        reasons = _sorted_texts(
            check["reasonCodes"],
            "public admission check reasonCodes",
            maximum_items=16,
            maximum_length=80,
            pattern=_TOKEN,
            allow_empty=True,
        )
        if (
            disposition not in CHECK_DISPOSITIONS
            or (disposition == "pass" and reasons)
            or (disposition != "pass" and not reasons)
        ):
            raise PublicAdmissionContractError("public admission check disposition is unbound")
        checks.append(
            {
                "id": _text(
                    check["id"],
                    "public admission check id",
                    maximum=40,
                    pattern=_TOKEN,
                ),
                "disposition": disposition,
                "evidenceDigests": _sorted_texts(
                    check["evidenceDigests"],
                    "public admission check evidenceDigests",
                    maximum_items=16,
                    maximum_length=71,
                    pattern=_DIGEST,
                ),
                "reasonCodes": reasons,
            }
        )
    if tuple(item["id"] for item in checks) != ADMISSION_CHECK_IDS:
        raise PublicAdmissionContractError("public admission assessment checks are incomplete")
    unsigned = {
        "schemaVersion": PUBLIC_ADMISSION_ASSESSMENT_SCHEMA_VERSION,
        "submissionRef": _text(
            assessment["submissionRef"],
            "public admission assessment submissionRef",
            maximum=43,
            pattern=_SUBMISSION,
        ),
        "intentDigest": _digest(
            assessment["intentDigest"],
            "public admission assessment intentDigest",
        ),
        "publisherId": _text(
            assessment["publisherId"],
            "public admission assessment publisherId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "engine": {
            "engineId": _text(
                engine["engineId"],
                "public admission engineId",
                maximum=200,
                pattern=_IDENTIFIER,
            ),
            "version": _text(engine["version"], "public admission engine version", maximum=80),
        },
        "checks": checks,
        "assessedAt": isoformat_utc(_timestamp(assessment["assessedAt"], "public admission assessment assessedAt")),
    }
    digest = _digest(
        assessment["assessmentDigest"],
        "public admission assessment digest",
    )
    if digest != sha256_json(unsigned):
        raise PublicAdmissionContractError("public admission assessment digest is unbound")
    result = {**unsigned, "assessmentDigest": digest}
    if len(canonical_json_bytes(result)) > MAX_ASSESSMENT_BYTES:
        raise PublicAdmissionContractError("public admission assessment exceeds its byte limit")
    return result


def build_public_admission_assessment(
    *,
    submission_ref: str,
    intent_digest: str,
    publisher_id: str,
    engine_id: str,
    engine_version: str,
    checks: Iterable[dict[str, Any]],
    assessed_at: datetime,
) -> dict[str, Any]:
    if not isinstance(assessed_at, datetime) or assessed_at.tzinfo is None:
        raise PublicAdmissionContractError("public admission assessment time is invalid")
    unsigned = {
        "schemaVersion": PUBLIC_ADMISSION_ASSESSMENT_SCHEMA_VERSION,
        "submissionRef": submission_ref,
        "intentDigest": intent_digest,
        "publisherId": publisher_id,
        "engine": {"engineId": engine_id, "version": engine_version},
        "checks": list(checks),
        "assessedAt": isoformat_utc(assessed_at.astimezone(UTC).replace(microsecond=0)),
    }
    return validate_public_admission_assessment({**unsigned, "assessmentDigest": sha256_json(unsigned)})


def assessment_state(assessment: dict[str, Any]) -> str:
    checked = validate_public_admission_assessment(assessment)
    dispositions = {item["disposition"] for item in checked["checks"]}
    if "fail" in dispositions:
        return "rejected"
    if "review" in dispositions:
        return "quarantined"
    return "active"


def assessment_reason_codes(assessment: dict[str, Any]) -> list[str]:
    checked = validate_public_admission_assessment(assessment)
    return sorted({reason for item in checked["checks"] for reason in item["reasonCodes"]})


def validate_public_release_revocation_request(
    value: Any,
    *,
    public_keys: Mapping[str, bytes],
    at: datetime | None = None,
) -> dict[str, Any]:
    request = _exact(
        value,
        {
            "schemaVersion",
            "requestId",
            "serviceId",
            "publisher",
            "submissionRef",
            "releaseId",
            "reasonCode",
            "issuedAt",
            "expiresAt",
            "revocationDigest",
            "signature",
        },
        "public release revocation request",
    )
    if request["schemaVersion"] != PUBLIC_RELEASE_REVOCATION_SCHEMA_VERSION:
        raise PublicAdmissionContractError("public release revocation schemaVersion is invalid")
    issued, expires = _lifetime(
        request["issuedAt"],
        request["expiresAt"],
        at=at,
        field="public release revocation request",
    )
    unsigned = {
        "schemaVersion": PUBLIC_RELEASE_REVOCATION_SCHEMA_VERSION,
        "requestId": _text(
            request["requestId"],
            "public release revocation requestId",
            maximum=128,
            pattern=_REQUEST,
        ),
        "serviceId": _text(
            request["serviceId"],
            "public release revocation serviceId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "publisher": _publisher(request["publisher"], "public release revocation publisher"),
        "submissionRef": _text(
            request["submissionRef"],
            "public release revocation submissionRef",
            maximum=43,
            pattern=_SUBMISSION,
        ),
        "releaseId": _text(
            request["releaseId"],
            "public release revocation releaseId",
            maximum=40,
            pattern=_RELEASE,
        ),
        "reasonCode": _text(
            request["reasonCode"],
            "public release revocation reasonCode",
            maximum=80,
            pattern=_TOKEN,
        ),
        "issuedAt": issued,
        "expiresAt": expires,
    }
    digest = _digest(request["revocationDigest"], "public release revocation digest")
    if digest != sha256_json(unsigned):
        raise PublicAdmissionContractError("public release revocation digest is unbound")
    signed = {**unsigned, "revocationDigest": digest}
    signature = _signature(request["signature"], "public release revocation signature")
    if signature["keyId"] != unsigned["publisher"]["keyId"]:
        raise PublicAdmissionContractError("public release revocation signer is unbound")
    _verify(signed, signature, public_keys)
    result = {**signed, "signature": signature}
    if len(canonical_json_bytes(result)) > MAX_SIGNED_REQUEST_BYTES:
        raise PublicAdmissionContractError("public release revocation exceeds its byte limit")
    return result


def build_public_release_revocation_request(
    *,
    signer: DecisionSigningAuthority,
    service_id: str,
    publisher_id: str,
    authority_id: str,
    submission_ref: str,
    release_id: str,
    reason_code: str,
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
        raise PublicAdmissionContractError("public release revocation lifetime is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    unsigned = {
        "schemaVersion": PUBLIC_RELEASE_REVOCATION_SCHEMA_VERSION,
        "requestId": request_id,
        "serviceId": service_id,
        "publisher": {
            "publisherId": publisher_id,
            "authorityId": authority_id,
            "keyId": signer.key_id,
        },
        "submissionRef": submission_ref,
        "releaseId": release_id,
        "reasonCode": reason_code,
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    signed = {**unsigned, "revocationDigest": sha256_json(unsigned)}
    return validate_public_release_revocation_request(
        {**signed, "signature": _sign(signed, signer)},
        public_keys={signer.key_id: signer.public_bytes()},
    )


def validate_public_policy_acceptance_response(
    value: Any,
    *,
    expected_policy_revision: str | None = None,
    expected_policy_digest: str | None = None,
) -> dict[str, Any]:
    response = _exact(
        value,
        {
            "schemaVersion",
            "acceptanceRef",
            "policyRevision",
            "policyDigest",
            "acceptedAt",
        },
        "public policy acceptance response",
    )
    if response["schemaVersion"] != "limitless.public-policy-acceptance-response/1.0":
        raise PublicAdmissionContractError("public policy acceptance response schemaVersion is invalid")
    checked = {
        "schemaVersion": response["schemaVersion"],
        "acceptanceRef": _text(
            response["acceptanceRef"],
            "public policy acceptance response acceptanceRef",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "policyRevision": _text(
            response["policyRevision"],
            "public policy acceptance response policyRevision",
            maximum=120,
            pattern=_IDENTIFIER,
        ),
        "policyDigest": _digest(
            response["policyDigest"],
            "public policy acceptance response policyDigest",
        ),
        "acceptedAt": isoformat_utc(
            _timestamp(
                response["acceptedAt"],
                "public policy acceptance response acceptedAt",
            )
        ),
    }
    if (expected_policy_revision is None) != (expected_policy_digest is None):
        raise PublicAdmissionContractError("public policy acceptance expectation is invalid")
    if expected_policy_revision is not None and (
        checked["policyRevision"] != expected_policy_revision or checked["policyDigest"] != expected_policy_digest
    ):
        raise PublicAdmissionContractError("public policy acceptance response is unbound")
    return checked


def validate_public_admission_status(
    value: Any,
    *,
    expected_submission_ref: str | None = None,
) -> dict[str, Any]:
    status = _exact(
        value,
        {
            "schemaVersion",
            "admissionRef",
            "submissionRef",
            "state",
            "releaseRef",
            "reasonCodes",
            "generation",
            "updatedAt",
        },
        "public admission status",
    )
    if status["schemaVersion"] != PUBLIC_ADMISSION_STATUS_SCHEMA_VERSION:
        raise PublicAdmissionContractError("public admission status schemaVersion is invalid")
    state = _text(status["state"], "public admission status state", maximum=20)
    if state not in {
        "active",
        "observed",
        "pending",
        "quarantined",
        "rejected",
        "retired",
        "revoked",
    }:
        raise PublicAdmissionContractError("public admission status state is invalid")
    generation = status["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= 2_147_483_647:
        raise PublicAdmissionContractError("public admission status generation is invalid")
    release = status["releaseRef"]
    if release is not None:
        item = _exact(release, {"releaseId", "releaseDigest"}, "public admission status releaseRef")
        release = {
            "releaseId": _text(
                item["releaseId"],
                "public admission status releaseId",
                maximum=40,
                pattern=_RELEASE,
            ),
            "releaseDigest": _digest(
                item["releaseDigest"],
                "public admission status releaseDigest",
            ),
        }
    if state in {"active", "revoked", "retired"} and release is None:
        raise PublicAdmissionContractError("public admission status release evidence is incomplete")
    if state in {"observed", "pending"} and release is not None:
        raise PublicAdmissionContractError("public admission status release evidence is invalid")
    checked = {
        "schemaVersion": status["schemaVersion"],
        "admissionRef": _text(
            status["admissionRef"],
            "public admission status admissionRef",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "submissionRef": _text(
            status["submissionRef"],
            "public admission status submissionRef",
            maximum=43,
            pattern=_SUBMISSION,
        ),
        "state": state,
        "releaseRef": release,
        "reasonCodes": _sorted_texts(
            status["reasonCodes"],
            "public admission status reasonCodes",
            maximum_items=32,
            maximum_length=80,
            pattern=_TOKEN,
            allow_empty=True,
        ),
        "generation": generation,
        "updatedAt": isoformat_utc(_timestamp(status["updatedAt"], "public admission status updatedAt")),
    }
    if expected_submission_ref is not None and checked["submissionRef"] != expected_submission_ref:
        raise PublicAdmissionContractError("public admission status is unbound")
    return checked


__all__ = [
    "ADMISSION_CHECK_IDS",
    "CONTRIBUTION_POLICY_ACCEPTANCE_SCHEMA_VERSION",
    "PUBLIC_ADMISSION_ASSESSMENT_SCHEMA_VERSION",
    "PUBLIC_RELEASE_REVOCATION_SCHEMA_VERSION",
    "PublicAdmissionContractError",
    "assessment_reason_codes",
    "assessment_state",
    "build_contribution_policy_acceptance",
    "build_public_admission_assessment",
    "build_public_release_revocation_request",
    "validate_contribution_policy_acceptance",
    "validate_public_admission_assessment",
    "validate_public_admission_status",
    "validate_public_policy_acceptance_response",
    "validate_public_release_revocation_request",
]
