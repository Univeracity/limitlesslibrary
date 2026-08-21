"""Cheap public submission and immutable release-lineage contracts.

The agent-facing operation is intentionally tiny: a client can assemble an
intent from already-captured local outcome evidence and send digests first.
Content transfer is negotiated only for objects the service does not already
have. Build context is provenance, never compatibility evidence.
"""

from __future__ import annotations

import re
from base64 import urlsafe_b64decode
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature

from ._service_support import (
    TREATMENT_CLASSES,
    DecisionSigningAuthority,
    isoformat_utc,
    public_key_from_bytes,
)
from .contracts import ContractError as ControlPlaneContractError
from .contracts import canonical_json_bytes, parse_utc, sha256_json

SUBMISSION_INTENT_SCHEMA_VERSION_1_0 = "limitless.service-submission-intent/1.0"
SUBMISSION_INTENT_SCHEMA_VERSION_1_1 = "limitless.service-submission-intent/1.1"
SUBMISSION_INTENT_SCHEMA_VERSION_1_2 = "limitless.service-submission-intent/1.2"
SUBMISSION_INTENT_SCHEMA_VERSION = SUBMISSION_INTENT_SCHEMA_VERSION_1_2
SUBMISSION_INTENT_SCHEMA_VERSIONS = (
    SUBMISSION_INTENT_SCHEMA_VERSION_1_0,
    SUBMISSION_INTENT_SCHEMA_VERSION_1_1,
    SUBMISSION_INTENT_SCHEMA_VERSION_1_2,
)
SUBMISSION_INTENT_VALIDATION_VERSIONS = SUBMISSION_INTENT_SCHEMA_VERSIONS
PUBLISHER_SIGNED_SUBMISSION_INTENT_SCHEMA_VERSIONS = frozenset(
    {
        SUBMISSION_INTENT_SCHEMA_VERSION_1_1,
        SUBMISSION_INTENT_SCHEMA_VERSION_1_2,
    }
)
SUBMISSION_PLAN_SCHEMA_VERSION = "limitless.service-submission-plan/1.0"
CONTENT_TRANSFER_GRANT_SCHEMA_VERSION = "limitless.service-content-transfer-grant/1.0"
CONTENT_TRANSFER_RESULT_SCHEMA_VERSION = "limitless.service-content-transfer-result/1.0"
IMMUTABLE_RELEASE_SCHEMA_VERSION_1_0 = "limitless.service-release/1.0"
IMMUTABLE_RELEASE_SCHEMA_VERSION_1_1 = "limitless.service-release/1.1"
IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2 = "limitless.service-release/1.2"
IMMUTABLE_RELEASE_SCHEMA_VERSION = IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2
IMMUTABLE_RELEASE_SCHEMA_VERSIONS = (
    IMMUTABLE_RELEASE_SCHEMA_VERSION_1_0,
    IMMUTABLE_RELEASE_SCHEMA_VERSION_1_1,
    IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2,
)
IMMUTABLE_RELEASE_VALIDATION_VERSIONS = IMMUTABLE_RELEASE_SCHEMA_VERSIONS
SIGNATURE_ALGORITHM = "ed25519"

MAX_INTENT_BYTES = 16 * 1024
MAX_PLAN_BYTES = 16 * 1024
MAX_CONTENT_TRANSFER_GRANT_BYTES = 16 * 1024
MAX_CONTENT_TRANSFER_RESULT_BYTES = 1024
MAX_RELEASE_BYTES = 32 * 1024
MAX_PLAN_TTL = timedelta(minutes=10)
MAX_CONTENT_TRANSFER_GRANT_TTL = timedelta(minutes=10)
MAX_EXACT_ARTIFACT_BYTES = 64 * 1024 * 1024

RELEASE_CLASSES = ("initial", "revision", "upgrade", "fork")
VISIBILITIES = ("private", "organization", "exchange", "public")
AUDIENCES = ("private", "circle", "organization", "public")
OBJECT_ROLES = ("artifact", "manifest", "method", "verification")
PLAN_STATES = ("accepted", "needs-content", "rejected")
REVIEW_GATES = ("rights", "provenance", "compatibility", "security", "quality")
_CURRENT_INTENT_VERSIONS = PUBLISHER_SIGNED_SUBMISSION_INTENT_SCHEMA_VERSIONS
_CURRENT_RELEASE_VERSIONS = frozenset(
    {IMMUTABLE_RELEASE_SCHEMA_VERSION_1_1, IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2}
)
_EXACT_ARTIFACT_FORMAT = "limitless.exact-file-bundle/1.0"
_EXACT_ARTIFACT_MEDIA_TYPE = "application/vnd.limitless.exact-file-bundle+json"

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,199}$")
_REQUEST = re.compile(r"^request:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_LINEAGE = re.compile(r"^lineage:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_RELEASE = re.compile(r"^release:[0-9a-f]{32}$")
_SUBMISSION = re.compile(r"^submission:[0-9a-f]{32}$")
_GRANT = re.compile(r"^grant:[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$")
_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9._:/+<>=,-]{0,127}$")


class PublicSubmissionContractError(ValueError):
    """A public submission, plan, or release is unsafe or unbound."""


def _exact(value: Any, fields: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise PublicSubmissionContractError(f"{field} has an unsupported shape")
    return value


def _text(value: Any, field: str, *, maximum: int, pattern: re.Pattern[str] | None = None) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise PublicSubmissionContractError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    return _text(value, field, maximum=71, pattern=_DIGEST)


def _timestamp(value: Any, field: str) -> datetime:
    try:
        parsed = parse_utc(value, field)
    except ControlPlaneContractError as error:
        raise PublicSubmissionContractError(f"{field} is invalid") from error
    if parsed.microsecond:
        raise PublicSubmissionContractError(f"{field} must use whole seconds")
    return parsed


def _sorted_texts(
    value: Any,
    field: str,
    *,
    maximum_items: int,
    maximum_length: int,
    pattern: re.Pattern[str] | None = None,
    allowed: Iterable[str] | None = None,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items or (not value and not allow_empty):
        raise PublicSubmissionContractError(f"{field} is invalid")
    result = [_text(item, field, maximum=maximum_length, pattern=pattern) for item in value]
    if result != sorted(set(result)):
        raise PublicSubmissionContractError(f"{field} must be sorted and unique")
    if allowed is not None and not set(result).issubset(set(allowed)):
        raise PublicSubmissionContractError(f"{field} is invalid")
    return result


def _environment(value: Any, field: str, *, version_field: str) -> dict[str, Any]:
    item = _exact(value, {"platform", "architecture", "runtime", version_field, "interfaces"}, field)
    return {
        "platform": _text(item["platform"], f"{field} platform", maximum=64, pattern=_TOKEN),
        "architecture": _text(item["architecture"], f"{field} architecture", maximum=64, pattern=_TOKEN),
        "runtime": _text(item["runtime"], f"{field} runtime", maximum=64, pattern=_TOKEN),
        version_field: _text(item[version_field], f"{field} {version_field}", maximum=128),
        "interfaces": _sorted_texts(
            item["interfaces"], f"{field} interfaces", maximum_items=32, maximum_length=128, pattern=_TOKEN
        ),
    }


def _compatibility(value: Any) -> dict[str, Any]:
    item = _exact(value, {"supportedTargets", "verifiedTargets"}, "compatibility")
    raw_supported = item["supportedTargets"]
    if not isinstance(raw_supported, list) or not 1 <= len(raw_supported) <= 16:
        raise PublicSubmissionContractError("compatibility supportedTargets are invalid")
    supported = [_environment(target, "supported target", version_field="versionRange") for target in raw_supported]
    supported = sorted(supported, key=sha256_json)
    if len({sha256_json(target) for target in supported}) != len(supported):
        raise PublicSubmissionContractError("compatibility supportedTargets must be unique")
    raw_verified = item["verifiedTargets"]
    if not isinstance(raw_verified, list) or len(raw_verified) > 16:
        raise PublicSubmissionContractError("compatibility verifiedTargets are invalid")
    verified: list[dict[str, Any]] = []
    supported_digests = {sha256_json(target) for target in supported}
    for raw in raw_verified:
        proof = _exact(raw, {"target", "evidenceDigests"}, "verified target")
        target = _environment(proof["target"], "verified target target", version_field="versionRange")
        if sha256_json(target) not in supported_digests:
            raise PublicSubmissionContractError("verified target is not an exact supported target")
        verified.append(
            {
                "target": target,
                "evidenceDigests": _sorted_texts(
                    proof["evidenceDigests"],
                    "verified target evidenceDigests",
                    maximum_items=16,
                    maximum_length=71,
                    pattern=_DIGEST,
                ),
            }
        )
    verified = sorted(verified, key=lambda proof: sha256_json(proof["target"]))
    if len({sha256_json(proof["target"]) for proof in verified}) != len(verified):
        raise PublicSubmissionContractError("compatibility verifiedTargets must be unique")
    return {"supportedTargets": supported, "verifiedTargets": verified}


def _release_reference(value: Any, field: str) -> dict[str, str]:
    item = _exact(value, {"releaseId", "releaseDigest", "lineageId", "version"}, field)
    return {
        "releaseId": _text(item["releaseId"], f"{field} releaseId", maximum=40, pattern=_RELEASE),
        "releaseDigest": _digest(item["releaseDigest"], f"{field} releaseDigest"),
        "lineageId": _text(item["lineageId"], f"{field} lineageId", maximum=128, pattern=_LINEAGE),
        "version": _text(item["version"], f"{field} version", maximum=80, pattern=_SEMVER),
    }


def _semver(value: str) -> tuple[int, int, int]:
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise PublicSubmissionContractError("release version is invalid")
    return tuple(int(match.group(index)) for index in range(1, 4))


def _lineage(value: Any) -> dict[str, Any]:
    item = _exact(value, {"lineageId", "version", "releaseClass", "parents", "supersedes"}, "lineage")
    lineage_id = _text(item["lineageId"], "lineage lineageId", maximum=128, pattern=_LINEAGE)
    version = _text(item["version"], "lineage version", maximum=80, pattern=_SEMVER)
    release_class = _text(item["releaseClass"], "lineage releaseClass", maximum=16)
    if release_class not in RELEASE_CLASSES:
        raise PublicSubmissionContractError("lineage releaseClass is invalid")
    if not isinstance(item["parents"], list) or len(item["parents"]) > 8:
        raise PublicSubmissionContractError("lineage parents are invalid")
    parents = sorted(
        (_release_reference(parent, "lineage parent") for parent in item["parents"]),
        key=lambda parent: parent["releaseId"],
    )
    if len({parent["releaseId"] for parent in parents}) != len(parents):
        raise PublicSubmissionContractError("lineage parents must be unique")
    supersedes = item["supersedes"]
    supersedes = None if supersedes is None else _release_reference(supersedes, "lineage supersedes")
    if release_class == "initial":
        if parents or supersedes is not None:
            raise PublicSubmissionContractError("initial lineage cannot have ancestors")
    elif release_class in {"revision", "upgrade"}:
        if (
            supersedes is None
            or not parents
            or supersedes["releaseId"] not in {parent["releaseId"] for parent in parents}
        ):
            raise PublicSubmissionContractError("revision or upgrade must preserve its superseded release as a parent")
        if supersedes["lineageId"] != lineage_id or _semver(version) <= _semver(supersedes["version"]):
            raise PublicSubmissionContractError("revision or upgrade lineage/version is invalid")
        if release_class == "revision" and _semver(version)[0] != _semver(supersedes["version"])[0]:
            raise PublicSubmissionContractError("revision must remain within the superseded major version")
        if release_class == "upgrade" and _semver(version)[0] <= _semver(supersedes["version"])[0]:
            raise PublicSubmissionContractError("upgrade must advance the superseded major version")
    elif not parents or supersedes is not None or any(parent["lineageId"] == lineage_id for parent in parents):
        raise PublicSubmissionContractError("fork must name ancestors from another lineage and cannot supersede them")
    return {
        "lineageId": lineage_id,
        "version": version,
        "releaseClass": release_class,
        "parents": parents,
        "supersedes": supersedes,
    }


def _objects(value: Any, *, format_aware: bool = False) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise PublicSubmissionContractError("contentObjects are invalid")
    objects: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, dict):
            raise PublicSubmissionContractError("content object has an unsupported shape")
        role = _text(raw.get("role"), "content object role", maximum=20)
        fields = {"role", "digest", "byteLength"}
        if format_aware and role == "artifact":
            fields.update({"format", "mediaType"})
        item = _exact(raw, fields, "content object")
        length = item["byteLength"]
        if (
            role not in OBJECT_ROLES
            or isinstance(length, bool)
            or not isinstance(length, int)
            or not 1 <= length <= 1_073_741_824
        ):
            raise PublicSubmissionContractError("content object is invalid")
        checked = {
            "role": role,
            "digest": _digest(item["digest"], "content object digest"),
            "byteLength": length,
        }
        if format_aware and role == "artifact":
            artifact_format = _text(
                item["format"], "content object format", maximum=96
            )
            media_type = _text(
                item["mediaType"], "content object mediaType", maximum=96
            )
            if (
                length > MAX_EXACT_ARTIFACT_BYTES
                or artifact_format != _EXACT_ARTIFACT_FORMAT
                or media_type != _EXACT_ARTIFACT_MEDIA_TYPE
            ):
                raise PublicSubmissionContractError(
                    "content object artifact format is unsupported"
                )
            checked.update({"format": artifact_format, "mediaType": media_type})
        objects.append(checked)
    objects = sorted(objects, key=lambda item: (item["digest"], item["role"]))
    if len({(item["digest"], item["role"]) for item in objects}) != len(objects):
        raise PublicSubmissionContractError("contentObjects must be unique")
    lengths_by_digest: dict[str, int] = {}
    for item in objects:
        prior = lengths_by_digest.setdefault(item["digest"], item["byteLength"])
        if prior != item["byteLength"]:
            raise PublicSubmissionContractError("one content digest cannot declare multiple byte lengths")
    return objects


def _signature(value: Any) -> dict[str, str]:
    item = _exact(value, {"keyId", "algorithm", "value"}, "signature")
    result = {
        "keyId": _text(item["keyId"], "signature keyId", maximum=200, pattern=_IDENTIFIER),
        "algorithm": _text(item["algorithm"], "signature algorithm", maximum=20),
        "value": _text(item["value"], "signature value", maximum=86, pattern=_SIGNATURE),
    }
    if result["algorithm"] != SIGNATURE_ALGORITHM:
        raise PublicSubmissionContractError("signature algorithm is invalid")
    return result


def _verify(payload: dict[str, Any], signature: dict[str, str], public_keys: Mapping[str, bytes] | None) -> None:
    if public_keys is None:
        return
    key = public_keys.get(signature["keyId"])
    if key is None:
        raise PublicSubmissionContractError("signature key is unknown")
    try:
        encoded = signature["value"]
        decoded = urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        if len(decoded) != 64:
            raise ValueError("invalid length")
        public_key_from_bytes(key).verify(decoded, canonical_json_bytes(payload))
    except (ControlPlaneContractError, InvalidSignature, ValueError) as error:
        raise PublicSubmissionContractError("signature is invalid") from error


def validate_submission_intent(
    value: Any,
    *,
    public_keys: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PublicSubmissionContractError("submission intent has an unsupported shape")
    version = value.get("schemaVersion")
    if version not in SUBMISSION_INTENT_VALIDATION_VERSIONS:
        raise PublicSubmissionContractError("submission intent schemaVersion is invalid")
    common_fields = {
        "schemaVersion",
        "requestId",
        "publisher",
        "destination",
        "candidate",
        "lineage",
        "contentObjects",
        "compatibility",
        "buildContext",
        "evidenceDigests",
        "rights",
        "submittedAt",
        "intentDigest",
    }
    intent = _exact(
        value,
        common_fields | ({"signature"} if version in _CURRENT_INTENT_VERSIONS else set()),
        "submission intent",
    )
    publisher = _exact(
        intent["publisher"],
        {"publisherId", "authorityId", "keyId"}
        if version in _CURRENT_INTENT_VERSIONS
        else {"publisherId", "authorityId"},
        "submission publisher",
    )
    destination = _exact(
        intent["destination"],
        {
            "collectionId",
            "audience" if version in _CURRENT_INTENT_VERSIONS else "visibility",
        },
        "submission destination",
    )
    candidate = _exact(intent["candidate"], {"title", "summary", "treatment", "capabilities"}, "submission candidate")
    rights_fields = {"license", "grantedBy", "allowedUses", "hasAuthority"}
    if version in _CURRENT_INTENT_VERSIONS:
        rights_fields.add("policyDigest")
    rights = _exact(intent["rights"], rights_fields, "submission rights")
    treatment = _text(candidate["treatment"], "submission candidate treatment", maximum=32)
    destination_field = "audience" if version in _CURRENT_INTENT_VERSIONS else "visibility"
    destination_value = _text(
        destination[destination_field],
        f"submission destination {destination_field}",
        maximum=20,
    )
    allowed_destinations = AUDIENCES if version in _CURRENT_INTENT_VERSIONS else VISIBILITIES
    if (
        treatment not in TREATMENT_CLASSES
        or destination_value not in allowed_destinations
        or rights["hasAuthority"] is not True
    ):
        raise PublicSubmissionContractError("submission treatment, audience, or authority is invalid")
    build_context = _environment(intent["buildContext"], "buildContext", version_field="version")
    unsigned = {
        "schemaVersion": version,
        "requestId": _text(intent["requestId"], "submission requestId", maximum=128, pattern=_REQUEST),
        "publisher": {
            "publisherId": _text(publisher["publisherId"], "submission publisherId", maximum=200, pattern=_IDENTIFIER),
            "authorityId": _text(publisher["authorityId"], "submission authorityId", maximum=200, pattern=_IDENTIFIER),
            **(
                {
                    "keyId": _text(
                        publisher["keyId"],
                        "submission publisher keyId",
                        maximum=200,
                        pattern=_IDENTIFIER,
                    )
                }
                if version in _CURRENT_INTENT_VERSIONS
                else {}
            ),
        },
        "destination": {
            "collectionId": _text(
                destination["collectionId"], "submission collectionId", maximum=200, pattern=_IDENTIFIER
            ),
            destination_field: destination_value,
        },
        "candidate": {
            "title": _text(candidate["title"], "submission candidate title", maximum=120),
            "summary": _text(candidate["summary"], "submission candidate summary", maximum=480),
            "treatment": treatment,
            "capabilities": _sorted_texts(
                candidate["capabilities"],
                "submission candidate capabilities",
                maximum_items=32,
                maximum_length=128,
                pattern=_TOKEN,
            ),
        },
        "lineage": _lineage(intent["lineage"]),
        "contentObjects": _objects(
            intent["contentObjects"],
            format_aware=version == SUBMISSION_INTENT_SCHEMA_VERSION_1_2,
        ),
        "compatibility": _compatibility(intent["compatibility"]),
        "buildContext": build_context,
        "evidenceDigests": _sorted_texts(
            intent["evidenceDigests"],
            "submission evidenceDigests",
            maximum_items=32,
            maximum_length=71,
            pattern=_DIGEST,
        ),
        "rights": {
            "license": _text(rights["license"], "submission rights license", maximum=80),
            "grantedBy": _text(rights["grantedBy"], "submission rights grantedBy", maximum=200, pattern=_IDENTIFIER),
            "allowedUses": _sorted_texts(
                rights["allowedUses"],
                "submission rights allowedUses",
                maximum_items=32,
                maximum_length=128,
                pattern=_TOKEN,
            ),
            "hasAuthority": True,
            **(
                {
                    "policyDigest": _digest(
                        rights["policyDigest"],
                        "submission rights policyDigest",
                    )
                }
                if version in _CURRENT_INTENT_VERSIONS
                else {}
            ),
        },
        "submittedAt": isoformat_utc(_timestamp(intent["submittedAt"], "submission submittedAt")),
    }
    if unsigned["rights"]["grantedBy"] != unsigned["publisher"]["publisherId"]:
        raise PublicSubmissionContractError("submission rights are not bound to the publisher")
    digest = _digest(intent["intentDigest"], "submission intentDigest")
    if digest != sha256_json(unsigned):
        raise PublicSubmissionContractError("submission intent digest does not bind its exact content")
    signed = {**unsigned, "intentDigest": digest}
    if version in _CURRENT_INTENT_VERSIONS:
        signature = _signature(intent["signature"])
        if signature["keyId"] != unsigned["publisher"]["keyId"]:
            raise PublicSubmissionContractError("submission signature is not bound to the publisher")
        _verify(signed, signature, public_keys)
        result = {**signed, "signature": signature}
    else:
        result = signed
    if len(canonical_json_bytes(result)) > MAX_INTENT_BYTES:
        raise PublicSubmissionContractError("submission intent exceeds its byte limit")
    return result


def build_submission_intent(
    *,
    signer: DecisionSigningAuthority,
    schema_version: str = SUBMISSION_INTENT_SCHEMA_VERSION,
    **fields: Any,
) -> dict[str, Any]:
    """Build one current, publisher-signed submission intent."""

    body = {"schemaVersion": schema_version, **fields}
    submitted_at = body.get("submittedAt")
    if isinstance(submitted_at, datetime) and submitted_at.tzinfo is not None:
        body["submittedAt"] = isoformat_utc(submitted_at.astimezone(UTC).replace(microsecond=0))
    digest = sha256_json(body)
    signed = {**body, "intentDigest": digest}
    try:
        signature = signer.sign(canonical_json_bytes(signed))
        return validate_submission_intent(
            {
                **signed,
                "signature": {
                    "keyId": signer.key_id,
                    "algorithm": SIGNATURE_ALGORITHM,
                    "value": signature,
                },
            },
            public_keys={signer.key_id: signer.public_bytes()},
        )
    except PublicSubmissionContractError:
        raise
    except (ControlPlaneContractError, ValueError) as error:
        raise PublicSubmissionContractError("submission intent signing failed") from error


def build_legacy_submission_intent(**fields: Any) -> dict[str, Any]:
    """Build an unsigned 1.0 intent solely for compatibility fixtures."""

    body = {"schemaVersion": SUBMISSION_INTENT_SCHEMA_VERSION_1_0, **fields}
    submitted_at = body.get("submittedAt")
    if isinstance(submitted_at, datetime) and submitted_at.tzinfo is not None:
        body["submittedAt"] = isoformat_utc(submitted_at.astimezone(UTC).replace(microsecond=0))
    body["intentDigest"] = sha256_json(body)
    return validate_submission_intent(body)


def validate_submission_plan(
    value: Any,
    *,
    public_keys: Mapping[str, bytes] | None = None,
    expected_intent: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    plan = _exact(
        value,
        {
            "schemaVersion",
            "requestId",
            "intentDigest",
            "submissionRef",
            "state",
            "requiredObjects",
            "reviewStages",
            "reasonCodes",
            "issuedAt",
            "expiresAt",
            "planDigest",
            "signature",
        },
        "submission plan",
    )
    if plan["schemaVersion"] != SUBMISSION_PLAN_SCHEMA_VERSION:
        raise PublicSubmissionContractError("submission plan schemaVersion is invalid")
    raw_required = plan["requiredObjects"]
    if not isinstance(raw_required, list) or len(raw_required) > 32:
        raise PublicSubmissionContractError("submission plan requiredObjects are invalid")
    required: list[dict[str, Any]] = []
    for raw in raw_required:
        item = _exact(raw, {"role", "digest", "byteLength"}, "required object")
        required.append(
            {
                "role": _text(item["role"], "required object role", maximum=20),
                "digest": _digest(item["digest"], "required object digest"),
                "byteLength": item["byteLength"],
            }
        )
    required = _objects(required) if required else []
    state = _text(plan["state"], "submission plan state", maximum=20)
    reasons = _sorted_texts(
        plan["reasonCodes"],
        "submission plan reasonCodes",
        maximum_items=16,
        maximum_length=80,
        pattern=_TOKEN,
        allow_empty=True,
    )
    if state not in PLAN_STATES:
        raise PublicSubmissionContractError("submission plan state is invalid")
    if state == "needs-content" and not required:
        raise PublicSubmissionContractError("needs-content plan must name missing objects")
    if state == "accepted" and (required or reasons):
        raise PublicSubmissionContractError("accepted plan cannot require objects or carry rejection reasons")
    if state == "rejected" and (required or not reasons):
        raise PublicSubmissionContractError("rejected plan must carry only bounded reasons")
    issued = _timestamp(plan["issuedAt"], "submission plan issuedAt")
    expires = _timestamp(plan["expiresAt"], "submission plan expiresAt")
    if not issued < expires <= issued + MAX_PLAN_TTL:
        raise PublicSubmissionContractError("submission plan lifetime is invalid")
    unsigned = {
        "schemaVersion": SUBMISSION_PLAN_SCHEMA_VERSION,
        "requestId": _text(plan["requestId"], "submission plan requestId", maximum=128, pattern=_REQUEST),
        "intentDigest": _digest(plan["intentDigest"], "submission plan intentDigest"),
        "submissionRef": _text(plan["submissionRef"], "submission plan submissionRef", maximum=43, pattern=_SUBMISSION),
        "state": state,
        "requiredObjects": required,
        "reviewStages": _sorted_texts(
            plan["reviewStages"],
            "submission plan reviewStages",
            maximum_items=5,
            maximum_length=20,
            allowed=REVIEW_GATES,
        ),
        "reasonCodes": reasons,
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(expires),
    }
    digest = _digest(plan["planDigest"], "submission plan planDigest")
    if digest != sha256_json(unsigned):
        raise PublicSubmissionContractError("submission plan digest does not bind its exact content")
    signed = {**unsigned, "planDigest": digest}
    signature = _signature(plan["signature"])
    _verify(signed, signature, public_keys)
    result = {**signed, "signature": signature}
    if len(canonical_json_bytes(result)) > MAX_PLAN_BYTES:
        raise PublicSubmissionContractError("submission plan exceeds its byte limit")
    if expected_intent is not None:
        intent = validate_submission_intent(expected_intent)
        if result["requestId"] != intent["requestId"] or result["intentDigest"] != intent["intentDigest"]:
            raise PublicSubmissionContractError("submission plan is not bound to the expected intent")
        known = {(item["role"], item["digest"], item["byteLength"]) for item in intent["contentObjects"]}
        if any((item["role"], item["digest"], item["byteLength"]) not in known for item in required):
            raise PublicSubmissionContractError("submission plan requested an object outside the intent")
    if at is not None:
        current = at.astimezone(UTC).replace(microsecond=0)
        if current < issued or current > expires:
            raise PublicSubmissionContractError("submission plan is not current")
    return result


def build_submission_plan(
    *,
    intent: dict[str, Any],
    known_object_digests: Iterable[str],
    review_stages: Iterable[str],
    issued_at: datetime,
    signer: DecisionSigningAuthority,
    reject_reasons: Iterable[str] = (),
    ttl_seconds: int = 300,
    submission_ref: str | None = None,
) -> dict[str, Any]:
    checked = validate_submission_intent(intent)
    if (
        not isinstance(issued_at, datetime)
        or issued_at.tzinfo is None
        or isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 1 <= ttl_seconds <= int(MAX_PLAN_TTL.total_seconds())
    ):
        raise PublicSubmissionContractError("submission plan timing is invalid")
    try:
        signer.assert_ready()
        signer.public_bytes()
    except Exception as error:
        raise PublicSubmissionContractError("submission plan signer is unavailable") from error
    known = set(known_object_digests)
    missing = [
        {key: item[key] for key in ("role", "digest", "byteLength")}
        for item in checked["contentObjects"]
        if item["digest"] not in known
    ]
    reasons = sorted(set(reject_reasons))
    state = "rejected" if reasons else ("needs-content" if missing else "accepted")
    if reasons:
        missing = []
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    unsigned = {
        "schemaVersion": SUBMISSION_PLAN_SCHEMA_VERSION,
        "requestId": checked["requestId"],
        "intentDigest": checked["intentDigest"],
        "submissionRef": submission_ref or "submission:" + checked["intentDigest"][7:39],
        "state": state,
        "requiredObjects": missing,
        "reviewStages": sorted(set(review_stages)),
        "reasonCodes": reasons,
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    digest = sha256_json(unsigned)
    signed = {**unsigned, "planDigest": digest}
    return validate_submission_plan(
        {
            **signed,
            "signature": {
                "keyId": signer.key_id,
                "algorithm": SIGNATURE_ALGORITHM,
                "value": signer.sign(canonical_json_bytes(signed)),
            },
        },
        public_keys={signer.key_id: signer.public_bytes()},
        expected_intent=checked,
    )


def public_submission_ref(
    *,
    tenant_id: str,
    publisher_id: str,
    request_id: str,
) -> str:
    """Derive the service-neutral identity for one publisher request."""

    binding = {
        "tenantId": _text(
            tenant_id,
            "public submission tenantId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "publisherId": _text(
            publisher_id,
            "public submission publisherId",
            maximum=200,
            pattern=_IDENTIFIER,
        ),
        "requestId": _text(
            request_id,
            "public submission requestId",
            maximum=128,
            pattern=_REQUEST,
        ),
    }
    return "submission:" + sha256_json(binding)[7:39]


def validate_content_transfer_grant(
    value: Any,
    *,
    public_keys: Mapping[str, bytes] | None = None,
    expected_intent: dict[str, Any] | None = None,
    expected_plan: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    """Validate authority to put exact, already-declared objects into a data plane."""

    grant = _exact(
        value,
        {
            "schemaVersion",
            "grantId",
            "submissionRef",
            "requestId",
            "intentDigest",
            "planDigest",
            "tenantId",
            "publisherId",
            "audience",
            "operation",
            "objects",
            "issuedAt",
            "expiresAt",
            "grantDigest",
            "signature",
        },
        "content transfer grant",
    )
    if grant["schemaVersion"] != CONTENT_TRANSFER_GRANT_SCHEMA_VERSION:
        raise PublicSubmissionContractError("content transfer grant schemaVersion is invalid")
    operation = _text(grant["operation"], "content transfer grant operation", maximum=24)
    if operation != "put-if-absent":
        raise PublicSubmissionContractError("content transfer grant operation is invalid")
    issued = _timestamp(grant["issuedAt"], "content transfer grant issuedAt")
    expires = _timestamp(grant["expiresAt"], "content transfer grant expiresAt")
    if not issued < expires <= issued + MAX_CONTENT_TRANSFER_GRANT_TTL:
        raise PublicSubmissionContractError("content transfer grant lifetime is invalid")
    unsigned = {
        "schemaVersion": CONTENT_TRANSFER_GRANT_SCHEMA_VERSION,
        "submissionRef": _text(
            grant["submissionRef"], "content transfer grant submissionRef", maximum=43, pattern=_SUBMISSION
        ),
        "requestId": _text(grant["requestId"], "content transfer grant requestId", maximum=128, pattern=_REQUEST),
        "intentDigest": _digest(grant["intentDigest"], "content transfer grant intentDigest"),
        "planDigest": _digest(grant["planDigest"], "content transfer grant planDigest"),
        "tenantId": _text(grant["tenantId"], "content transfer grant tenantId", maximum=200, pattern=_IDENTIFIER),
        "publisherId": _text(
            grant["publisherId"], "content transfer grant publisherId", maximum=200, pattern=_IDENTIFIER
        ),
        "audience": _text(grant["audience"], "content transfer grant audience", maximum=200, pattern=_IDENTIFIER),
        "operation": operation,
        "objects": _objects(grant["objects"]),
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(expires),
    }
    digest = _digest(grant["grantDigest"], "content transfer grant grantDigest")
    identifier = _text(grant["grantId"], "content transfer grant grantId", maximum=38, pattern=_GRANT)
    if digest != sha256_json(unsigned) or identifier != "grant:" + digest[7:39]:
        raise PublicSubmissionContractError("content transfer grant identity does not bind its exact authority")
    signed = {**unsigned, "grantId": identifier, "grantDigest": digest}
    signature = _signature(grant["signature"])
    _verify(signed, signature, public_keys)
    result = {**signed, "signature": signature}
    if len(canonical_json_bytes(result)) > MAX_CONTENT_TRANSFER_GRANT_BYTES:
        raise PublicSubmissionContractError("content transfer grant exceeds its byte limit")

    intent = validate_submission_intent(expected_intent) if expected_intent is not None else None
    plan = (
        validate_submission_plan(expected_plan, public_keys=public_keys, expected_intent=intent)
        if expected_plan is not None
        else None
    )
    if intent is not None and (
        result["requestId"] != intent["requestId"]
        or result["intentDigest"] != intent["intentDigest"]
        or result["tenantId"] != intent["publisher"]["authorityId"]
        or result["publisherId"] != intent["publisher"]["publisherId"]
    ):
        raise PublicSubmissionContractError("content transfer grant is not bound to the expected intent")
    if plan is not None:
        if plan["state"] != "needs-content" or (
            result["submissionRef"] != plan["submissionRef"]
            or result["requestId"] != plan["requestId"]
            or result["intentDigest"] != plan["intentDigest"]
            or result["planDigest"] != plan["planDigest"]
        ):
            raise PublicSubmissionContractError("content transfer grant is not bound to the missing-content plan")
        required = {(item["role"], item["digest"], item["byteLength"]) for item in plan["requiredObjects"]}
        if any((item["role"], item["digest"], item["byteLength"]) not in required for item in result["objects"]):
            raise PublicSubmissionContractError("content transfer grant exceeds the missing-content plan")
    if at is not None:
        current = at.astimezone(UTC).replace(microsecond=0)
        if current < issued or current > expires:
            raise PublicSubmissionContractError("content transfer grant is not current")
    return result


def build_content_transfer_grant(
    *,
    intent: dict[str, Any],
    plan: dict[str, Any],
    tenant_id: str,
    publisher_id: str,
    audience: str,
    objects: Iterable[dict[str, Any]],
    issued_at: datetime,
    signer: DecisionSigningAuthority,
    ttl_seconds: int = 300,
) -> dict[str, Any]:
    checked_intent = validate_submission_intent(intent)
    checked_plan = validate_submission_plan(plan, expected_intent=checked_intent)
    if checked_plan["state"] != "needs-content":
        raise PublicSubmissionContractError("content transfer requires a missing-content plan")
    if (
        not isinstance(issued_at, datetime)
        or issued_at.tzinfo is None
        or isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 1 <= ttl_seconds <= int(MAX_CONTENT_TRANSFER_GRANT_TTL.total_seconds())
    ):
        raise PublicSubmissionContractError("content transfer grant timing is invalid")
    try:
        signer.assert_ready()
        public_key = signer.public_bytes()
    except Exception as error:
        raise PublicSubmissionContractError("content transfer grant signer is unavailable") from error
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    unsigned = {
        "schemaVersion": CONTENT_TRANSFER_GRANT_SCHEMA_VERSION,
        "submissionRef": checked_plan["submissionRef"],
        "requestId": checked_intent["requestId"],
        "intentDigest": checked_intent["intentDigest"],
        "planDigest": checked_plan["planDigest"],
        "tenantId": tenant_id,
        "publisherId": publisher_id,
        "audience": audience,
        "operation": "put-if-absent",
        "objects": list(objects),
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    digest = sha256_json(unsigned)
    signed = {**unsigned, "grantId": "grant:" + digest[7:39], "grantDigest": digest}
    return validate_content_transfer_grant(
        {
            **signed,
            "signature": {
                "keyId": signer.key_id,
                "algorithm": SIGNATURE_ALGORITHM,
                "value": signer.sign(canonical_json_bytes(signed)),
            },
        },
        public_keys={signer.key_id: public_key},
        expected_intent=checked_intent,
        expected_plan=checked_plan,
    )


def validate_content_transfer_result(
    value: Any,
    *,
    expected_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate one non-authoritative exact-object upload result."""

    result = _exact(
        value,
        {
            "schemaVersion",
            "grantId",
            "submissionRef",
            "role",
            "digest",
            "byteLength",
            "disposition",
        },
        "content transfer result",
    )
    byte_length = result["byteLength"]
    checked = {
        "schemaVersion": result["schemaVersion"],
        "grantId": _text(
            result["grantId"],
            "content transfer result grantId",
            maximum=38,
            pattern=_GRANT,
        ),
        "submissionRef": _text(
            result["submissionRef"],
            "content transfer result submissionRef",
            maximum=43,
            pattern=_SUBMISSION,
        ),
        "role": _text(result["role"], "content transfer result role", maximum=20),
        "digest": _digest(result["digest"], "content transfer result digest"),
        "byteLength": byte_length,
        "disposition": _text(
            result["disposition"],
            "content transfer result disposition",
            maximum=24,
        ),
    }
    if (
        checked["schemaVersion"] != CONTENT_TRANSFER_RESULT_SCHEMA_VERSION
        or checked["role"] not in OBJECT_ROLES
        or isinstance(byte_length, bool)
        or not isinstance(byte_length, int)
        or not 1 <= byte_length <= 1_073_741_824
        or checked["disposition"] not in {"created", "already-present"}
        or len(canonical_json_bytes(checked)) > MAX_CONTENT_TRANSFER_RESULT_BYTES
    ):
        raise PublicSubmissionContractError("content transfer result is invalid")
    if expected_plan is not None:
        plan = validate_submission_plan(expected_plan)
        required = {(item["role"], item["digest"], item["byteLength"]) for item in plan["requiredObjects"]}
        if (
            plan["state"] != "needs-content"
            or checked["submissionRef"] != plan["submissionRef"]
            or (
                checked["role"],
                checked["digest"],
                checked["byteLength"],
            )
            not in required
        ):
            raise PublicSubmissionContractError("content transfer result is not bound to the missing-content plan")
    return checked


def validate_immutable_release(
    value: Any,
    *,
    public_keys: Mapping[str, bytes] | None = None,
    expected_intent: dict[str, Any] | None = None,
    expected_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    release = _exact(
        value,
        {
            "schemaVersion",
            "releaseId",
            "submissionIntentDigest",
            "submissionPlanDigest",
            "publisherId",
            "reviewerId",
            "candidate",
            "lineage",
            "contentObjects",
            "compatibility",
            "buildContext",
            "evidenceDigests",
            "rights",
            "reviewEvidenceDigests",
            "createdAt",
            "releaseDigest",
            "signature",
        },
        "immutable release",
    )
    version = release["schemaVersion"]
    if version not in IMMUTABLE_RELEASE_VALIDATION_VERSIONS:
        raise PublicSubmissionContractError("immutable release schemaVersion is invalid")
    candidate = _exact(release["candidate"], {"title", "summary", "treatment", "capabilities"}, "release candidate")
    rights_fields = {"license", "grantedBy", "allowedUses", "hasAuthority"}
    if version in _CURRENT_RELEASE_VERSIONS:
        rights_fields.add("policyDigest")
    rights = _exact(release["rights"], rights_fields, "release rights")
    treatment = _text(candidate["treatment"], "release treatment", maximum=32)
    if treatment not in TREATMENT_CLASSES or rights["hasAuthority"] is not True:
        raise PublicSubmissionContractError("immutable release treatment or authority is invalid")
    publisher = _text(release["publisherId"], "release publisherId", maximum=200, pattern=_IDENTIFIER)
    reviewer = _text(release["reviewerId"], "release reviewerId", maximum=200, pattern=_IDENTIFIER)
    if publisher == reviewer:
        raise PublicSubmissionContractError("immutable release requires independent review")
    body = {
        "schemaVersion": version,
        "submissionIntentDigest": _digest(release["submissionIntentDigest"], "release submissionIntentDigest"),
        "submissionPlanDigest": _digest(release["submissionPlanDigest"], "release submissionPlanDigest"),
        "publisherId": publisher,
        "reviewerId": reviewer,
        "candidate": {
            "title": _text(candidate["title"], "release title", maximum=120),
            "summary": _text(candidate["summary"], "release summary", maximum=480),
            "treatment": treatment,
            "capabilities": _sorted_texts(
                candidate["capabilities"], "release capabilities", maximum_items=32, maximum_length=128, pattern=_TOKEN
            ),
        },
        "lineage": _lineage(release["lineage"]),
        "contentObjects": _objects(
            release["contentObjects"],
            format_aware=version == IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2,
        ),
        "compatibility": _compatibility(release["compatibility"]),
        "buildContext": _environment(release["buildContext"], "release buildContext", version_field="version"),
        "evidenceDigests": _sorted_texts(
            release["evidenceDigests"], "release evidenceDigests", maximum_items=32, maximum_length=71, pattern=_DIGEST
        ),
        "rights": {
            "license": _text(rights["license"], "release license", maximum=80),
            "grantedBy": _text(rights["grantedBy"], "release grantedBy", maximum=200, pattern=_IDENTIFIER),
            "allowedUses": _sorted_texts(
                rights["allowedUses"], "release allowedUses", maximum_items=32, maximum_length=128, pattern=_TOKEN
            ),
            "hasAuthority": True,
            **(
                {"policyDigest": _digest(rights["policyDigest"], "release policyDigest")}
                if version in _CURRENT_RELEASE_VERSIONS
                else {}
            ),
        },
        "reviewEvidenceDigests": _sorted_texts(
            release["reviewEvidenceDigests"],
            "release reviewEvidenceDigests",
            maximum_items=32,
            maximum_length=71,
            pattern=_DIGEST,
        ),
        "createdAt": isoformat_utc(_timestamp(release["createdAt"], "release createdAt")),
    }
    if body["rights"]["grantedBy"] != publisher:
        raise PublicSubmissionContractError("immutable release rights are not bound to the publisher")
    digest = _digest(release["releaseDigest"], "release releaseDigest")
    identifier = _text(release["releaseId"], "release releaseId", maximum=40, pattern=_RELEASE)
    if digest != sha256_json(body) or identifier != "release:" + digest[7:39]:
        raise PublicSubmissionContractError("immutable release identity does not bind its exact content")
    signed = {**body, "releaseId": identifier, "releaseDigest": digest}
    signature = _signature(release["signature"])
    _verify(signed, signature, public_keys)
    result = {**signed, "signature": signature}
    if len(canonical_json_bytes(result)) > MAX_RELEASE_BYTES:
        raise PublicSubmissionContractError("immutable release exceeds its byte limit")
    intent = validate_submission_intent(expected_intent) if expected_intent is not None else None
    plan = (
        validate_submission_plan(expected_plan, public_keys=public_keys, expected_intent=intent)
        if expected_plan is not None
        else None
    )
    if intent is not None and (
        result["submissionIntentDigest"] != intent["intentDigest"]
        or result["publisherId"] != intent["publisher"]["publisherId"]
        or any(
            result[field] != intent[field]
            for field in (
                "candidate",
                "lineage",
                "contentObjects",
                "compatibility",
                "buildContext",
                "evidenceDigests",
                "rights",
            )
        )
    ):
        raise PublicSubmissionContractError("immutable release is not bound to the expected intent")
    if plan is not None and (
        plan["state"] != "accepted"
        or result["submissionPlanDigest"] != plan["planDigest"]
        or result["submissionIntentDigest"] != plan["intentDigest"]
        or _timestamp(result["createdAt"], "release createdAt")
        < _timestamp(plan["issuedAt"], "submission plan issuedAt")
    ):
        raise PublicSubmissionContractError("immutable release is not bound to the accepted plan")
    return result


def build_immutable_release(
    *,
    intent: dict[str, Any],
    plan: dict[str, Any],
    publisher_id: str,
    reviewer_id: str,
    review_evidence_digests: Iterable[str],
    created_at: datetime,
    signer: DecisionSigningAuthority,
) -> dict[str, Any]:
    checked_intent = validate_submission_intent(intent)
    if not isinstance(created_at, datetime) or created_at.tzinfo is None:
        raise PublicSubmissionContractError("immutable release createdAt is invalid")
    try:
        signer.assert_ready()
        public_key = signer.public_bytes()
    except Exception as error:
        raise PublicSubmissionContractError("immutable release signer is unavailable") from error
    checked_plan = validate_submission_plan(
        plan,
        public_keys={signer.key_id: public_key},
        expected_intent=checked_intent,
    )
    if checked_plan["state"] != "accepted":
        raise PublicSubmissionContractError("only a content-complete submission can become a release")
    release_version = {
        SUBMISSION_INTENT_SCHEMA_VERSION_1_0: IMMUTABLE_RELEASE_SCHEMA_VERSION_1_0,
        SUBMISSION_INTENT_SCHEMA_VERSION_1_1: IMMUTABLE_RELEASE_SCHEMA_VERSION_1_1,
        SUBMISSION_INTENT_SCHEMA_VERSION_1_2: IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2,
    }[checked_intent["schemaVersion"]]
    body = {
        "schemaVersion": release_version,
        "submissionIntentDigest": checked_intent["intentDigest"],
        "submissionPlanDigest": checked_plan["planDigest"],
        "publisherId": publisher_id,
        "reviewerId": reviewer_id,
        "candidate": checked_intent["candidate"],
        "lineage": checked_intent["lineage"],
        "contentObjects": checked_intent["contentObjects"],
        "compatibility": checked_intent["compatibility"],
        "buildContext": checked_intent["buildContext"],
        "evidenceDigests": checked_intent["evidenceDigests"],
        "rights": checked_intent["rights"],
        "reviewEvidenceDigests": sorted(set(review_evidence_digests)),
        "createdAt": isoformat_utc(created_at.astimezone(UTC).replace(microsecond=0)),
    }
    digest = sha256_json(body)
    signed = {**body, "releaseId": "release:" + digest[7:39], "releaseDigest": digest}
    return validate_immutable_release(
        {
            **signed,
            "signature": {
                "keyId": signer.key_id,
                "algorithm": SIGNATURE_ALGORITHM,
                "value": signer.sign(canonical_json_bytes(signed)),
            },
        },
        public_keys={signer.key_id: public_key},
        expected_intent=checked_intent,
        expected_plan=checked_plan,
    )
