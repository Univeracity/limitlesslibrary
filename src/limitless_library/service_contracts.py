"""Public, language-neutral contracts for the Limitless service facade.

These envelopes intentionally hide private control-plane identity, policy,
ranking, and persistence records.  A public client can verify one bounded
decision without becoming coupled to the managed implementation.
"""

from __future__ import annotations

import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature

from ._service_support import (
    CONTENT_TRANSFER_GRANT_SCHEMA_VERSION,
    DATA_USE_MODES,
    IMMUTABLE_RELEASE_SCHEMA_VERSION,
    MAX_CONTENT_TRANSFER_GRANT_BYTES,
    MAX_INTENT_BYTES,
    MAX_PLAN_BYTES,
    MAX_RELEASE_BYTES,
    QUERY_SCOPES,
    SUBMISSION_INTENT_SCHEMA_VERSION,
    SUBMISSION_PLAN_SCHEMA_VERSION,
    TREATMENT_CLASSES,
    DecisionSigningAuthority,
    isoformat_utc,
    public_key_from_bytes,
    validate_next_action,
    version_range_covers,
)
from .contracts import (
    ContractError as ControlPlaneContractError,
)
from .contracts import (
    canonical_json_bytes,
    parse_utc,
    sha256_json,
)

SERVICE_DISCOVERY_SCHEMA_VERSION = "limitless.service-discovery/1.0"
SERVICE_QUERY_SCHEMA_VERSION = "limitless.service-query/1.0"
SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_0 = "limitless.service-query-result/1.0"
SERVICE_QUERY_RESULT_SCHEMA_VERSION = "limitless.service-query-result/1.1"
SERVICE_QUERY_RESULT_SCHEMA_VERSIONS = (
    SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_0,
    SERVICE_QUERY_RESULT_SCHEMA_VERSION,
)
SERVICE_OUTCOME_ATTEMPT_SCHEMA_VERSION = "limitless.service-outcome-attempt/1.0"
SERVICE_OUTCOME_RECEIPT_SCHEMA_VERSION = "limitless.service-outcome-receipt/1.0"
SERVICE_ROOT_KEY_TRANSITION_SCHEMA_VERSION = "limitless.service-root-key-transition/1.0"
SERVICE_ROOT_KEY_TRANSITION_SET_SCHEMA_VERSION = "limitless.service-root-key-transition-set/1.0"
SERVICE_PROTOCOL_VERSION = "limitless.service/1.0"
SIGNATURE_ALGORITHM = "ed25519"

MAX_QUERY_BYTES = 8 * 1024
MAX_RESULT_BYTES = 32 * 1024
MAX_OUTCOME_ATTEMPT_BYTES = 4 * 1024
MAX_OUTCOME_RECEIPT_BYTES = 8 * 1024
MAX_DISCOVERY_BYTES = 32 * 1024
MAX_ROOT_KEY_TRANSITION_BYTES = 8 * 1024
MAX_ROOT_KEY_TRANSITION_SET_BYTES = 32 * 1024
MAX_QUERY_TTL = timedelta(minutes=5)
MAX_RESULT_TTL = timedelta(minutes=5)
MAX_DISCOVERY_TTL = timedelta(days=7)
MAX_ROOT_KEY_LIFETIME = timedelta(days=3660)
MAX_ROOT_KEY_TRANSITION_LEAD = timedelta(days=90)
MAX_ROOT_KEY_TRANSITIONS = 16

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,199}$")
_REQUEST = re.compile(r"^request:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_DECISION = re.compile(r"^decision:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_CAPABILITY = re.compile(r"^capability:[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_BASE64URL_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_SEMVERISH = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_RECEIVER = re.compile(r"^receiver:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_TARGET = re.compile(r"^target:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_ATTEMPT = re.compile(r"^attempt:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$")
_OUTCOME = re.compile(r"^outcome:[0-9a-f]{32}$")
_UNSET = object()

OUTCOME_STATUSES = frozenset({"verified", "failed", "abstained-in-use"})
OUTCOME_CHECK_CLASSES = frozenset(
    {
        "artifact-integrity",
        "compatibility",
        "containment",
        "method-evaluation",
        "observed-invocation",
        "receiver-tests",
        "rights-policy",
    }
)


class PublicServiceContractError(ValueError):
    """A public service record is malformed, stale, or cryptographically unbound."""


def _exact(value: Any, fields: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise PublicServiceContractError(f"{field} has an unsupported shape")
    return value


def _text(value: Any, field: str, *, maximum: int, pattern: re.Pattern[str] | None = None) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise PublicServiceContractError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    return _text(value, field, maximum=71, pattern=_DIGEST)


def _timestamp(value: Any, field: str) -> datetime:
    try:
        parsed = parse_utc(value, field)
    except ControlPlaneContractError as error:
        raise PublicServiceContractError(f"{field} is invalid") from error
    if parsed.microsecond != 0:
        raise PublicServiceContractError(f"{field} must use whole seconds")
    return parsed


def _lifetime(issued: Any, expires: Any, *, maximum: timedelta, field: str) -> tuple[str, str]:
    issued_at = _timestamp(issued, f"{field} issuedAt")
    expires_at = _timestamp(expires, f"{field} expiresAt")
    if not issued_at < expires_at <= issued_at + maximum:
        raise PublicServiceContractError(f"{field} lifetime is invalid")
    return isoformat_utc(issued_at), isoformat_utc(expires_at)


def _sorted_texts(
    value: Any,
    field: str,
    *,
    maximum_items: int,
    maximum_length: int,
    allowed: Iterable[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum_items:
        raise PublicServiceContractError(f"{field} is invalid")
    result = [_text(item, field, maximum=maximum_length) for item in value]
    if result != sorted(set(result)):
        raise PublicServiceContractError(f"{field} must be sorted and unique")
    if allowed is not None and not set(result).issubset(set(allowed)):
        raise PublicServiceContractError(f"{field} is invalid")
    return result


def _positive_int(value: Any, field: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise PublicServiceContractError(f"{field} is invalid")
    return value


def _https_url(value: Any, field: str, *, maximum: int = 2048, allow_path: bool = True) -> str:
    selected = _text(value, field, maximum=maximum)
    try:
        parsed = urlsplit(selected)
        _ = parsed.port
    except ValueError as error:
        raise PublicServiceContractError(f"{field} is invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (not allow_path and (parsed.path not in {"", "/"} or parsed.query))
    ):
        raise PublicServiceContractError(f"{field} is invalid")
    return selected.rstrip("/") if not allow_path else selected


def _base64url_encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str, *, expected_bytes: int, field: str) -> bytes:
    try:
        decoded = urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (TypeError, ValueError) as error:
        raise PublicServiceContractError(f"{field} is invalid") from error
    if len(decoded) != expected_bytes or _base64url_encode(decoded) != value:
        raise PublicServiceContractError(f"{field} is invalid")
    return decoded


def _signature(value: Any, field: str) -> dict[str, str]:
    item = _exact(value, {"keyId", "algorithm", "value"}, field)
    normalized = {
        "keyId": _text(item["keyId"], f"{field} keyId", maximum=200, pattern=_IDENTIFIER),
        "algorithm": _text(item["algorithm"], f"{field} algorithm", maximum=20),
        "value": _text(item["value"], f"{field} value", maximum=86, pattern=_SIGNATURE),
    }
    if normalized["algorithm"] != SIGNATURE_ALGORITHM:
        raise PublicServiceContractError(f"{field} algorithm is invalid")
    _base64url_decode(normalized["value"], expected_bytes=64, field=f"{field} value")
    return normalized


def _verify(payload: dict[str, Any], signature: dict[str, str], public_key: bytes | None) -> None:
    if public_key is None:
        return
    try:
        public_key_from_bytes(public_key).verify(
            _base64url_decode(signature["value"], expected_bytes=64, field="signature value"),
            canonical_json_bytes(payload),
        )
    except (ControlPlaneContractError, InvalidSignature, ValueError) as error:
        raise PublicServiceContractError("signature is invalid") from error


def _at(value: dict[str, Any], *, at: datetime | None, field: str) -> None:
    if at is None:
        return
    if not isinstance(at, datetime) or at.tzinfo is None:
        raise PublicServiceContractError("validation time is invalid")
    current = at.astimezone(UTC).replace(microsecond=0)
    issued = _timestamp(value["issuedAt"], f"{field} issuedAt")
    expires = _timestamp(value["expiresAt"], f"{field} expiresAt")
    if current < issued or current > expires:
        raise PublicServiceContractError(f"{field} is not current")


def _receiver_context(value: Any) -> dict[str, Any]:
    context = _exact(
        value,
        {"receiverId", "allowedUse", "interfaces", "execution", "targets", "compatibilityMode", "selectedTarget"},
        "receiverContext",
    )
    execution = _exact(
        context["execution"], {"platform", "architecture", "runtime", "version"}, "receiverContext execution"
    )
    targets = context["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 8:
        raise PublicServiceContractError("receiverContext targets are invalid")
    checked_targets: list[dict[str, Any]] = []
    for value_target in targets:
        target = _exact(
            value_target,
            {"id", "platform", "architecture", "runtime", "versionRange", "interfaces"},
            "receiverContext target",
        )
        checked_targets.append(
            {
                "id": _text(target["id"], "receiverContext target id", maximum=128, pattern=_TARGET),
                "platform": _text(target["platform"], "receiverContext target platform", maximum=64),
                "architecture": _text(target["architecture"], "receiverContext target architecture", maximum=64),
                "runtime": _text(target["runtime"], "receiverContext target runtime", maximum=64),
                "versionRange": _text(target["versionRange"], "receiverContext target versionRange", maximum=120),
                "interfaces": _sorted_texts(
                    target["interfaces"], "receiverContext target interfaces", maximum_items=32, maximum_length=128
                ),
            }
        )
    if checked_targets != sorted(checked_targets, key=lambda item: item["id"]) or len(
        {item["id"] for item in checked_targets}
    ) != len(checked_targets):
        raise PublicServiceContractError("receiverContext targets must be sorted and unique")
    mode = _text(context["compatibilityMode"], "receiverContext compatibilityMode", maximum=20)
    if mode not in {"all-targets", "one-target"}:
        raise PublicServiceContractError("receiverContext compatibilityMode is invalid")
    selected = context["selectedTarget"]
    target_ids = {item["id"] for item in checked_targets}
    if mode == "all-targets":
        if selected is not None:
            raise PublicServiceContractError("all-targets receiverContext cannot select one target")
    else:
        selected = _text(selected, "receiverContext selectedTarget", maximum=128, pattern=_TARGET)
        if selected not in target_ids:
            raise PublicServiceContractError("receiverContext selectedTarget is unavailable")
    interfaces = _sorted_texts(
        context["interfaces"], "receiverContext interfaces", maximum_items=32, maximum_length=128
    )
    applicable = (
        checked_targets if mode == "all-targets" else [item for item in checked_targets if item["id"] == selected]
    )
    if any(not set(interfaces).issubset(set(item["interfaces"])) for item in applicable):
        raise PublicServiceContractError("receiverContext target interfaces do not cover the receiver")
    return {
        "receiverId": _text(context["receiverId"], "receiverContext receiverId", maximum=128, pattern=_RECEIVER),
        "allowedUse": _text(context["allowedUse"], "receiverContext allowedUse", maximum=128),
        "interfaces": interfaces,
        "execution": {
            "platform": _text(execution["platform"], "receiverContext execution platform", maximum=64),
            "architecture": _text(execution["architecture"], "receiverContext execution architecture", maximum=64),
            "runtime": _text(execution["runtime"], "receiverContext execution runtime", maximum=64),
            "version": _text(execution["version"], "receiverContext execution version", maximum=80),
        },
        "targets": checked_targets,
        "compatibilityMode": mode,
        "selectedTarget": selected,
    }


def validate_service_query(value: Any, *, at: datetime | None = None) -> dict[str, Any]:
    query = _exact(
        value,
        {
            "schemaVersion",
            "requestId",
            "objective",
            "receiverContext",
            "requestedScopes",
            "requestedTreatments",
            "dataUseMode",
            "client",
            "issuedAt",
            "expiresAt",
            "queryDigest",
        },
        "service query",
    )
    if query["schemaVersion"] != SERVICE_QUERY_SCHEMA_VERSION:
        raise PublicServiceContractError("service query schemaVersion is invalid")
    client = _exact(query["client"], {"name", "version", "supportedResults"}, "service query client")
    context = _receiver_context(query["receiverContext"])
    issued_at, expires_at = _lifetime(
        query["issuedAt"], query["expiresAt"], maximum=MAX_QUERY_TTL, field="service query"
    )
    unsigned = {
        "schemaVersion": SERVICE_QUERY_SCHEMA_VERSION,
        "requestId": _text(query["requestId"], "service query requestId", maximum=128, pattern=_REQUEST),
        "objective": _text(query["objective"], "service query objective", maximum=480),
        "receiverContext": context,
        "requestedScopes": _sorted_texts(
            query["requestedScopes"],
            "service query requestedScopes",
            maximum_items=4,
            maximum_length=20,
            allowed=QUERY_SCOPES,
        ),
        "requestedTreatments": _sorted_texts(
            query["requestedTreatments"],
            "service query requestedTreatments",
            maximum_items=2,
            maximum_length=32,
            allowed=TREATMENT_CLASSES,
        ),
        "dataUseMode": _text(query["dataUseMode"], "service query dataUseMode", maximum=20),
        "client": {
            "name": _text(client["name"], "service query client name", maximum=80, pattern=_IDENTIFIER),
            "version": _text(client["version"], "service query client version", maximum=64, pattern=_SEMVERISH),
            "supportedResults": _sorted_texts(
                client["supportedResults"],
                "service query client supportedResults",
                maximum_items=4,
                maximum_length=80,
            ),
        },
        "issuedAt": issued_at,
        "expiresAt": expires_at,
    }
    if unsigned["dataUseMode"] not in DATA_USE_MODES:
        raise PublicServiceContractError("service query dataUseMode is invalid")
    if not set(unsigned["client"]["supportedResults"]).intersection(SERVICE_QUERY_RESULT_SCHEMA_VERSIONS):
        raise PublicServiceContractError("service query client cannot accept this service result")
    digest = _digest(query["queryDigest"], "service query queryDigest")
    if digest != sha256_json(unsigned):
        raise PublicServiceContractError("service query digest does not bind its exact content")
    normalized = {**unsigned, "queryDigest": digest}
    if len(canonical_json_bytes(normalized)) > MAX_QUERY_BYTES:
        raise PublicServiceContractError("service query exceeds its byte limit")
    _at(normalized, at=at, field="service query")
    return normalized


def build_service_query(
    *,
    request_id: str,
    objective: str,
    receiver_context: dict[str, Any],
    requested_scopes: Iterable[str],
    requested_treatments: Iterable[str],
    data_use_mode: str,
    client_name: str,
    client_version: str,
    issued_at: datetime,
    ttl_seconds: int = 60,
) -> dict[str, Any]:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 300:
        raise PublicServiceContractError("service query ttl is invalid")
    if not isinstance(issued_at, datetime) or issued_at.tzinfo is None:
        raise PublicServiceContractError("service query issuedAt is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    unsigned = {
        "schemaVersion": SERVICE_QUERY_SCHEMA_VERSION,
        "requestId": request_id,
        "objective": objective,
        "receiverContext": receiver_context,
        "requestedScopes": sorted(set(requested_scopes)),
        "requestedTreatments": sorted(set(requested_treatments)),
        "dataUseMode": data_use_mode,
        "client": {
            "name": client_name,
            "version": client_version,
            "supportedResults": list(SERVICE_QUERY_RESULT_SCHEMA_VERSIONS),
        },
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    return validate_service_query({**unsigned, "queryDigest": sha256_json(unsigned)})


def _compatibility(value: Any) -> dict[str, Any]:
    item = _exact(
        value,
        {"runtime", "versionRange", "interfaces", "platforms", "architectures"},
        "selection compatibility",
    )
    interfaces = _sorted_texts(
        item["interfaces"], "selection compatibility interfaces", maximum_items=32, maximum_length=128
    )
    platforms = _sorted_texts(
        item["platforms"], "selection compatibility platforms", maximum_items=16, maximum_length=64
    )
    architectures = _sorted_texts(
        item["architectures"], "selection compatibility architectures", maximum_items=16, maximum_length=64
    )
    return {
        "runtime": _text(item["runtime"], "selection compatibility runtime", maximum=64),
        "versionRange": _text(item["versionRange"], "selection compatibility versionRange", maximum=120),
        "interfaces": interfaces,
        "platforms": platforms,
        "architectures": architectures,
    }


def _provenance(value: Any) -> dict[str, Any]:
    item = _exact(
        value,
        {"source", "publisher", "license", "reviewState", "reviewEvidence"},
        "selection provenance",
    )
    state = _text(item["reviewState"], "selection provenance reviewState", maximum=20)
    if state not in {"active", "reviewed", "source-validated"}:
        raise PublicServiceContractError("selection provenance reviewState is invalid")
    evidence = item["reviewEvidence"]
    if not isinstance(evidence, list) or len(evidence) > 16:
        raise PublicServiceContractError("selection provenance reviewEvidence is invalid")
    checked_evidence: list[dict[str, str]] = []
    for entry in evidence:
        current = _exact(entry, {"kind", "status", "source"}, "selection review evidence")
        status = _text(current["status"], "selection review evidence status", maximum=20)
        if status not in {"passed", "failed", "unknown", "not-applicable"}:
            raise PublicServiceContractError("selection review evidence status is invalid")
        checked_evidence.append(
            {
                "kind": _text(current["kind"], "selection review evidence kind", maximum=80),
                "status": status,
                "source": _text(current["source"], "selection review evidence source", maximum=160),
            }
        )
    if checked_evidence != sorted(checked_evidence, key=lambda entry: (entry["kind"], entry["source"])):
        raise PublicServiceContractError("selection review evidence must be sorted")
    return {
        "source": _https_url(item["source"], "selection provenance source"),
        "publisher": _text(item["publisher"], "selection provenance publisher", maximum=160),
        "license": _text(item["license"], "selection provenance license", maximum=80),
        "reviewState": state,
        "reviewEvidence": checked_evidence,
    }


def _method(value: Any) -> dict[str, Any]:
    item = _exact(value, {"summary", "steps", "constraints", "evaluation", "limitations"}, "source-free method")
    steps = item["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 16:
        raise PublicServiceContractError("source-free method steps are invalid")
    checked_steps: list[dict[str, str]] = []
    for index, step in enumerate(steps, start=1):
        current = _exact(step, {"index", "instruction", "check", "expected"}, "source-free method step")
        if current["index"] != index:
            raise PublicServiceContractError("source-free method step indexes are invalid")
        checked_steps.append(
            {
                "index": index,
                "instruction": _text(current["instruction"], "source-free method instruction", maximum=400),
                "check": _text(current["check"], "source-free method check", maximum=80),
                "expected": _text(current["expected"], "source-free method expected", maximum=240),
            }
        )
    return {
        "summary": _text(item["summary"], "source-free method summary", maximum=400),
        "steps": checked_steps,
        "constraints": _sorted_texts(
            item["constraints"], "source-free method constraints", maximum_items=16, maximum_length=240
        ),
        "evaluation": _sorted_texts(
            item["evaluation"], "source-free method evaluation", maximum_items=16, maximum_length=240
        ),
        "limitations": _sorted_texts(
            item["limitations"], "source-free method limitations", maximum_items=16, maximum_length=240
        ),
    }


def _selection(
    value: Any,
    *,
    treatment: str,
    require_supply_authority: bool = False,
) -> dict[str, Any]:
    if treatment == "abstention":
        item = _exact(value, {"reason", "uncertainty", "missingFact"}, "abstention selection")
        return {
            "reason": _text(item["reason"], "abstention reason", maximum=80),
            "uncertainty": _text(item["uncertainty"], "abstention uncertainty", maximum=120),
            "missingFact": _text(item["missingFact"], "abstention missingFact", maximum=128),
        }
    common = {
        "capabilityId",
        "title",
        "summary",
        "cardDigest",
        "compatibility",
        "allowedUses",
        "provenance",
        "confidence",
        "rationale",
    }
    if require_supply_authority:
        common.add("supplyAuthorityId")
    expected = common | ({"immutable"} if treatment == "exact-component" else {"method"})
    item = _exact(value, expected, f"{treatment} selection")
    confidence = _text(item["confidence"], "selection confidence", maximum=12)
    if confidence not in {"high", "medium", "low"}:
        raise PublicServiceContractError("selection confidence is invalid")
    normalized: dict[str, Any] = {
        "capabilityId": _text(item["capabilityId"], "selection capabilityId", maximum=171, pattern=_CAPABILITY),
        "title": _text(item["title"], "selection title", maximum=160),
        "summary": _text(item["summary"], "selection summary", maximum=400),
        "cardDigest": _digest(item["cardDigest"], "selection cardDigest"),
        "compatibility": _compatibility(item["compatibility"]),
        "allowedUses": _sorted_texts(
            item["allowedUses"], "selection allowedUses", maximum_items=32, maximum_length=128
        ),
        "provenance": _provenance(item["provenance"]),
        "confidence": confidence,
        "rationale": _text(item["rationale"], "selection rationale", maximum=280),
    }
    if require_supply_authority:
        normalized["supplyAuthorityId"] = _text(
            item["supplyAuthorityId"],
            "selection supplyAuthorityId",
            maximum=200,
            pattern=_IDENTIFIER,
        )
    if treatment == "source-free-method":
        normalized["method"] = _method(item["method"])
        return normalized
    immutable = _exact(item["immutable"], {"kind", "uri", "revision", "digest"}, "selection immutable")
    kind = _text(immutable["kind"], "selection immutable kind", maximum=24)
    if kind not in {"artifact", "git-commit"}:
        raise PublicServiceContractError("selection immutable kind is invalid")
    revision = _text(immutable["revision"], "selection immutable revision", maximum=80)
    if kind == "git-commit" and _COMMIT.fullmatch(revision) is None:
        raise PublicServiceContractError("selection immutable Git revision is invalid")
    normalized["immutable"] = {
        "kind": kind,
        "uri": _https_url(immutable["uri"], "selection immutable uri"),
        "revision": revision,
        "digest": _digest(immutable["digest"], "selection immutable digest"),
    }
    return normalized


def validate_service_query_result(
    value: Any,
    *,
    public_keys: Mapping[str, bytes] | None = None,
    expected_query: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    result = _exact(
        value,
        {
            "schemaVersion",
            "requestDigest",
            "decisionRef",
            "authorizedScopes",
            "dataUse",
            "treatment",
            "selection",
            "nextAction",
            "indexGeneration",
            "issuedAt",
            "expiresAt",
            "resultDigest",
            "signature",
        },
        "service query result",
    )
    if result["schemaVersion"] not in SERVICE_QUERY_RESULT_SCHEMA_VERSIONS:
        raise PublicServiceContractError("service query result schemaVersion is invalid")
    result_version = result["schemaVersion"]
    treatment = _text(result["treatment"], "service query result treatment", maximum=32)
    if treatment not in {*TREATMENT_CLASSES, "abstention"}:
        raise PublicServiceContractError("service query result treatment is invalid")
    data_use = _exact(result["dataUse"], {"effectiveMode", "policyDigest"}, "service query result dataUse")
    mode = _text(data_use["effectiveMode"], "service query result effectiveMode", maximum=20)
    if mode not in DATA_USE_MODES:
        raise PublicServiceContractError("service query result effectiveMode is invalid")
    issued_at, expires_at = _lifetime(
        result["issuedAt"], result["expiresAt"], maximum=MAX_RESULT_TTL, field="service query result"
    )
    try:
        next_action = validate_next_action(result["nextAction"])
    except ValueError as error:
        raise PublicServiceContractError("service query result nextAction is invalid") from error
    normalized = {
        "schemaVersion": result_version,
        "requestDigest": _digest(result["requestDigest"], "service query result requestDigest"),
        "decisionRef": _text(result["decisionRef"], "service query result decisionRef", maximum=128, pattern=_DECISION),
        "authorizedScopes": _sorted_texts(
            result["authorizedScopes"],
            "service query result authorizedScopes",
            maximum_items=4,
            maximum_length=20,
            allowed=QUERY_SCOPES,
        ),
        "dataUse": {
            "effectiveMode": mode,
            "policyDigest": _digest(data_use["policyDigest"], "service query result policyDigest"),
        },
        "treatment": treatment,
        "selection": _selection(
            result["selection"],
            treatment=treatment,
            require_supply_authority=(result_version == SERVICE_QUERY_RESULT_SCHEMA_VERSION),
        ),
        "nextAction": next_action,
        "indexGeneration": _positive_int(
            result["indexGeneration"], "service query result indexGeneration", maximum=2**31 - 1
        ),
        "issuedAt": issued_at,
        "expiresAt": expires_at,
    }
    if treatment == "abstention" and normalized["nextAction"]["kind"] != "supply-missing-fact":
        raise PublicServiceContractError("abstention nextAction is invalid")
    digest = _digest(result["resultDigest"], "service query result resultDigest")
    if digest != sha256_json(normalized):
        raise PublicServiceContractError("service query result digest does not bind its exact content")
    signature = _signature(result["signature"], "service query result signature")
    bound = {**normalized, "resultDigest": digest, "signature": signature}
    if public_keys is not None:
        public_key = public_keys.get(signature["keyId"])
        if public_key is None:
            raise PublicServiceContractError("service query result signing key is unknown")
        _verify({**normalized, "resultDigest": digest}, signature, public_key)
    if expected_query is not None:
        query = validate_service_query(expected_query)
        if result_version not in query["client"]["supportedResults"]:
            raise PublicServiceContractError("service query result version was not accepted by this client")
        if normalized["requestDigest"] != query["queryDigest"]:
            raise PublicServiceContractError("service query result is not bound to this query")
        if normalized["dataUse"]["effectiveMode"] != query["dataUseMode"]:
            raise PublicServiceContractError("service query result changed the requested data-use mode")
        if not set(normalized["authorizedScopes"]).issubset(set(query["requestedScopes"])):
            raise PublicServiceContractError("service query result scope was not requested")
        if treatment != "abstention" and treatment not in query["requestedTreatments"]:
            raise PublicServiceContractError("service query result treatment was not requested")
        if treatment != "abstention":
            receiver = query["receiverContext"]
            targets = receiver["targets"]
            if receiver["compatibilityMode"] == "one-target":
                targets = [item for item in targets if item["id"] == receiver["selectedTarget"]]
            compatibility = normalized["selection"]["compatibility"]
            for target in targets:
                if (
                    compatibility["runtime"] not in {"any", target["runtime"]}
                    or not version_range_covers(compatibility["versionRange"], target["versionRange"])
                    or target["platform"] not in {*compatibility["platforms"], "any"}
                    or target["architecture"] not in {*compatibility["architectures"], "any"}
                    or not set(receiver["interfaces"]).issubset(set(compatibility["interfaces"]))
                ):
                    raise PublicServiceContractError("service query result is incompatible with a receiver target")
    if len(canonical_json_bytes(bound)) > MAX_RESULT_BYTES:
        raise PublicServiceContractError("service query result exceeds its byte limit")
    _at(bound, at=at, field="service query result")
    return bound


def build_service_query_result(
    *,
    query: dict[str, Any],
    decision_ref: str,
    authorized_scopes: Iterable[str],
    policy_digest: str,
    treatment: str,
    selection: dict[str, Any],
    next_action: dict[str, Any],
    index_generation: int,
    issued_at: datetime,
    signer: DecisionSigningAuthority,
    ttl_seconds: int = 120,
) -> dict[str, Any]:
    checked_query = validate_service_query(query)
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 300:
        raise PublicServiceContractError("service query result ttl is invalid")
    if not isinstance(issued_at, datetime) or issued_at.tzinfo is None:
        raise PublicServiceContractError("service query result issuedAt is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    mutually_supported = [
        version
        for version in SERVICE_QUERY_RESULT_SCHEMA_VERSIONS
        if version in checked_query["client"]["supportedResults"]
    ]
    if not mutually_supported:
        raise PublicServiceContractError("service query has no mutually supported result version")
    result_version = mutually_supported[-1]
    versioned_selection = dict(selection)
    if result_version == SERVICE_QUERY_RESULT_SCHEMA_VERSION_1_0:
        versioned_selection.pop("supplyAuthorityId", None)
    unsigned = {
        "schemaVersion": result_version,
        "requestDigest": checked_query["queryDigest"],
        "decisionRef": decision_ref,
        "authorizedScopes": sorted(set(authorized_scopes)),
        "dataUse": {"effectiveMode": checked_query["dataUseMode"], "policyDigest": policy_digest},
        "treatment": treatment,
        "selection": versioned_selection,
        "nextAction": next_action,
        "indexGeneration": index_generation,
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    digest = sha256_json(unsigned)
    try:
        signature = signer.sign(canonical_json_bytes({**unsigned, "resultDigest": digest}))
        return validate_service_query_result(
            {
                **unsigned,
                "resultDigest": digest,
                "signature": {"keyId": signer.key_id, "algorithm": SIGNATURE_ALGORITHM, "value": signature},
            },
            public_keys={signer.key_id: signer.public_bytes()},
            expected_query=checked_query,
        )
    except PublicServiceContractError:
        raise
    except (ControlPlaneContractError, ValueError) as error:
        raise PublicServiceContractError("service query result signing failed") from error


def _outcome_check_classes(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 8:
        raise PublicServiceContractError("service outcome checkClasses are invalid")
    checked = [_text(item, "service outcome checkClass", maximum=40) for item in value]
    if checked != sorted(set(checked)) or not set(checked).issubset(OUTCOME_CHECK_CLASSES):
        raise PublicServiceContractError("service outcome checkClasses are invalid")
    return checked


def validate_service_outcome_attempt(
    value: Any,
    *,
    at: datetime | None = None,
) -> dict[str, Any]:
    attempt = _exact(
        value,
        {
            "schemaVersion",
            "attemptId",
            "status",
            "evidenceDigest",
            "checkClasses",
            "issuedAt",
            "expiresAt",
            "attemptDigest",
        },
        "service outcome attempt",
    )
    if attempt["schemaVersion"] != SERVICE_OUTCOME_ATTEMPT_SCHEMA_VERSION:
        raise PublicServiceContractError("service outcome attempt schemaVersion is invalid")
    status = _text(attempt["status"], "service outcome attempt status", maximum=24)
    if status not in OUTCOME_STATUSES:
        raise PublicServiceContractError("service outcome attempt status is invalid")
    issued_at, expires_at = _lifetime(
        attempt["issuedAt"],
        attempt["expiresAt"],
        maximum=MAX_QUERY_TTL,
        field="service outcome attempt",
    )
    normalized = {
        "schemaVersion": SERVICE_OUTCOME_ATTEMPT_SCHEMA_VERSION,
        "attemptId": _text(attempt["attemptId"], "service outcome attempt attemptId", maximum=128, pattern=_ATTEMPT),
        "status": status,
        "evidenceDigest": _digest(attempt["evidenceDigest"], "service outcome attempt evidenceDigest"),
        "checkClasses": _outcome_check_classes(attempt["checkClasses"]),
        "issuedAt": issued_at,
        "expiresAt": expires_at,
    }
    digest = _digest(attempt["attemptDigest"], "service outcome attempt attemptDigest")
    if digest != sha256_json(normalized):
        raise PublicServiceContractError("service outcome attempt digest does not bind its exact content")
    bound = {**normalized, "attemptDigest": digest}
    if len(canonical_json_bytes(bound)) > MAX_OUTCOME_ATTEMPT_BYTES:
        raise PublicServiceContractError("service outcome attempt exceeds its byte limit")
    _at(bound, at=at, field="service outcome attempt")
    return bound


def build_service_outcome_attempt(
    *,
    attempt_id: str,
    status: str,
    evidence_digest: str,
    check_classes: Iterable[str],
    issued_at: datetime,
    ttl_seconds: int = 120,
) -> dict[str, Any]:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 300:
        raise PublicServiceContractError("service outcome attempt ttl is invalid")
    if not isinstance(issued_at, datetime) or issued_at.tzinfo is None:
        raise PublicServiceContractError("service outcome attempt issuedAt is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    unsigned = {
        "schemaVersion": SERVICE_OUTCOME_ATTEMPT_SCHEMA_VERSION,
        "attemptId": attempt_id,
        "status": status,
        "evidenceDigest": evidence_digest,
        "checkClasses": sorted(set(check_classes)),
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    return validate_service_outcome_attempt({**unsigned, "attemptDigest": sha256_json(unsigned)})


def validate_service_outcome_receipt(
    value: Any,
    *,
    public_keys: Mapping[str, bytes] | None = None,
    expected_attempt: dict[str, Any] | None = None,
    expected_decision_ref: str | None = None,
) -> dict[str, Any]:
    receipt = _exact(
        value,
        {
            "schemaVersion",
            "outcomeRef",
            "decisionRef",
            "resultDigest",
            "attemptId",
            "attemptDigest",
            "status",
            "evidenceDigest",
            "checkClasses",
            "dataUse",
            "rankingEligible",
            "acceptedAt",
            "receiptDigest",
            "signature",
        },
        "service outcome receipt",
    )
    if receipt["schemaVersion"] != SERVICE_OUTCOME_RECEIPT_SCHEMA_VERSION:
        raise PublicServiceContractError("service outcome receipt schemaVersion is invalid")
    status = _text(receipt["status"], "service outcome receipt status", maximum=24)
    if status not in OUTCOME_STATUSES:
        raise PublicServiceContractError("service outcome receipt status is invalid")
    data_use = _exact(receipt["dataUse"], {"effectiveMode", "policyDigest"}, "service outcome receipt dataUse")
    mode = _text(data_use["effectiveMode"], "service outcome receipt effectiveMode", maximum=20)
    if mode not in DATA_USE_MODES:
        raise PublicServiceContractError("service outcome receipt effectiveMode is invalid")
    if not isinstance(receipt["rankingEligible"], bool):
        raise PublicServiceContractError("service outcome receipt rankingEligible is invalid")
    if mode == "confidential" and receipt["rankingEligible"]:
        raise PublicServiceContractError("confidential service outcomes cannot be ranking eligible")
    accepted = isoformat_utc(_timestamp(receipt["acceptedAt"], "service outcome receipt acceptedAt"))
    normalized = {
        "schemaVersion": SERVICE_OUTCOME_RECEIPT_SCHEMA_VERSION,
        "outcomeRef": _text(receipt["outcomeRef"], "service outcome receipt outcomeRef", maximum=40, pattern=_OUTCOME),
        "decisionRef": _text(
            receipt["decisionRef"], "service outcome receipt decisionRef", maximum=128, pattern=_DECISION
        ),
        "resultDigest": _digest(receipt["resultDigest"], "service outcome receipt resultDigest"),
        "attemptId": _text(receipt["attemptId"], "service outcome receipt attemptId", maximum=128, pattern=_ATTEMPT),
        "attemptDigest": _digest(receipt["attemptDigest"], "service outcome receipt attemptDigest"),
        "status": status,
        "evidenceDigest": _digest(receipt["evidenceDigest"], "service outcome receipt evidenceDigest"),
        "checkClasses": _outcome_check_classes(receipt["checkClasses"]),
        "dataUse": {
            "effectiveMode": mode,
            "policyDigest": _digest(data_use["policyDigest"], "service outcome receipt policyDigest"),
        },
        "rankingEligible": receipt["rankingEligible"],
        "acceptedAt": accepted,
    }
    digest = _digest(receipt["receiptDigest"], "service outcome receipt receiptDigest")
    if digest != sha256_json(normalized):
        raise PublicServiceContractError("service outcome receipt digest does not bind its exact content")
    signature = _signature(receipt["signature"], "service outcome receipt signature")
    bound = {**normalized, "receiptDigest": digest, "signature": signature}
    if public_keys is not None:
        public_key = public_keys.get(signature["keyId"])
        if public_key is None:
            raise PublicServiceContractError("service outcome receipt signing key is unknown")
        _verify({**normalized, "receiptDigest": digest}, signature, public_key)
    if expected_attempt is not None:
        attempt = validate_service_outcome_attempt(expected_attempt)
        for field in ("attemptId", "attemptDigest", "status", "evidenceDigest", "checkClasses"):
            if normalized[field] != attempt[field]:
                raise PublicServiceContractError("service outcome receipt is not bound to this attempt")
    if expected_decision_ref is not None and normalized["decisionRef"] != _text(
        expected_decision_ref, "expected decisionRef", maximum=128, pattern=_DECISION
    ):
        raise PublicServiceContractError("service outcome receipt is not bound to this decision")
    if len(canonical_json_bytes(bound)) > MAX_OUTCOME_RECEIPT_BYTES:
        raise PublicServiceContractError("service outcome receipt exceeds its byte limit")
    return bound


def build_service_outcome_receipt(
    *,
    outcome_ref: str,
    decision_ref: str,
    result_digest: str,
    attempt: dict[str, Any],
    effective_data_use_mode: str,
    policy_digest: str,
    ranking_eligible: bool,
    accepted_at: datetime,
    signer: DecisionSigningAuthority,
) -> dict[str, Any]:
    checked_attempt = validate_service_outcome_attempt(attempt)
    if not isinstance(accepted_at, datetime) or accepted_at.tzinfo is None:
        raise PublicServiceContractError("service outcome receipt acceptedAt is invalid")
    unsigned = {
        "schemaVersion": SERVICE_OUTCOME_RECEIPT_SCHEMA_VERSION,
        "outcomeRef": outcome_ref,
        "decisionRef": decision_ref,
        "resultDigest": result_digest,
        "attemptId": checked_attempt["attemptId"],
        "attemptDigest": checked_attempt["attemptDigest"],
        "status": checked_attempt["status"],
        "evidenceDigest": checked_attempt["evidenceDigest"],
        "checkClasses": checked_attempt["checkClasses"],
        "dataUse": {"effectiveMode": effective_data_use_mode, "policyDigest": policy_digest},
        "rankingEligible": ranking_eligible,
        "acceptedAt": isoformat_utc(accepted_at.astimezone(UTC).replace(microsecond=0)),
    }
    digest = sha256_json(unsigned)
    try:
        signature = signer.sign(canonical_json_bytes({**unsigned, "receiptDigest": digest}))
        return validate_service_outcome_receipt(
            {
                **unsigned,
                "receiptDigest": digest,
                "signature": {"keyId": signer.key_id, "algorithm": SIGNATURE_ALGORITHM, "value": signature},
            },
            public_keys={signer.key_id: signer.public_bytes()},
            expected_attempt=checked_attempt,
            expected_decision_ref=decision_ref,
        )
    except PublicServiceContractError:
        raise
    except (ControlPlaneContractError, ValueError) as error:
        raise PublicServiceContractError("service outcome receipt signing failed") from error


def _root_key(value: Any, field: str) -> dict[str, Any]:
    item = _exact(value, {"keyId", "algorithm", "publicKey", "validFrom", "validUntil"}, field)
    valid_from = _timestamp(item["validFrom"], f"{field} validFrom")
    valid_until = _timestamp(item["validUntil"], f"{field} validUntil")
    if not valid_from < valid_until <= valid_from + MAX_ROOT_KEY_LIFETIME:
        raise PublicServiceContractError(f"{field} lifetime is invalid")
    public = _text(item["publicKey"], f"{field} publicKey", maximum=43, pattern=_BASE64URL_32)
    _base64url_decode(public, expected_bytes=32, field=f"{field} publicKey")
    algorithm = _text(item["algorithm"], f"{field} algorithm", maximum=20)
    if algorithm != SIGNATURE_ALGORITHM:
        raise PublicServiceContractError(f"{field} algorithm is invalid")
    return {
        "keyId": _text(item["keyId"], f"{field} keyId", maximum=200, pattern=_IDENTIFIER),
        "algorithm": algorithm,
        "publicKey": public,
        "validFrom": isoformat_utc(valid_from),
        "validUntil": isoformat_utc(valid_until),
    }


def validate_service_root_key_transition(
    value: Any,
    *,
    trusted_root_keys: Mapping[str, bytes] | None = None,
    expected_service_id: str | None = None,
    expected_sequence: int | None = None,
    expected_previous_transition_digest: Any = _UNSET,
) -> dict[str, Any]:
    """Validate one scheduled, dual-signed service root transition.

    Structural validation without ``trusted_root_keys`` proves internal
    consistency only. Trust advancement must use
    :func:`advance_service_root_trust`, which requires an already-pinned
    predecessor and an exact sequence/digest expectation.
    """

    transition = _exact(
        value,
        {
            "schemaVersion",
            "serviceId",
            "sequence",
            "previousTransitionDigest",
            "previousRootKey",
            "nextRootKey",
            "effectiveAt",
            "issuedAt",
            "transitionDigest",
            "signatures",
        },
        "service root key transition",
    )
    if transition["schemaVersion"] != SERVICE_ROOT_KEY_TRANSITION_SCHEMA_VERSION:
        raise PublicServiceContractError("service root key transition schemaVersion is invalid")
    service_id = _text(
        transition["serviceId"], "service root key transition serviceId", maximum=200, pattern=_IDENTIFIER
    )
    sequence = transition["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence <= 2_147_483_647:
        raise PublicServiceContractError("service root key transition sequence is invalid")
    previous_digest = transition["previousTransitionDigest"]
    if sequence == 1:
        if previous_digest is not None:
            raise PublicServiceContractError("first service root key transition cannot name a predecessor")
    else:
        previous_digest = _digest(previous_digest, "service root key transition previousTransitionDigest")

    previous_key = _root_key(transition["previousRootKey"], "service root key transition previousRootKey")
    next_key = _root_key(transition["nextRootKey"], "service root key transition nextRootKey")
    if previous_key["keyId"] == next_key["keyId"] or previous_key["publicKey"] == next_key["publicKey"]:
        raise PublicServiceContractError("service root key transition does not change the root")

    issued_at = _timestamp(transition["issuedAt"], "service root key transition issuedAt")
    effective_at = _timestamp(transition["effectiveAt"], "service root key transition effectiveAt")
    previous_from = _timestamp(previous_key["validFrom"], "service root key transition previousRootKey validFrom")
    previous_until = _timestamp(previous_key["validUntil"], "service root key transition previousRootKey validUntil")
    next_from = _timestamp(next_key["validFrom"], "service root key transition nextRootKey validFrom")
    next_until = _timestamp(next_key["validUntil"], "service root key transition nextRootKey validUntil")
    if not previous_from <= issued_at < effective_at <= previous_until:
        raise PublicServiceContractError("service root key transition timing is invalid")
    if (
        effective_at - issued_at > MAX_ROOT_KEY_TRANSITION_LEAD
        or next_from != effective_at
        or next_until <= effective_at
    ):
        raise PublicServiceContractError("service root key transition timing is invalid")

    unsigned = {
        "schemaVersion": SERVICE_ROOT_KEY_TRANSITION_SCHEMA_VERSION,
        "serviceId": service_id,
        "sequence": sequence,
        "previousTransitionDigest": previous_digest,
        "previousRootKey": previous_key,
        "nextRootKey": next_key,
        "effectiveAt": isoformat_utc(effective_at),
        "issuedAt": isoformat_utc(issued_at),
    }
    digest = _digest(transition["transitionDigest"], "service root key transition transitionDigest")
    if digest != sha256_json(unsigned):
        raise PublicServiceContractError("service root key transition digest does not bind its exact content")
    signatures = _exact(
        transition["signatures"], {"authorization", "acceptance"}, "service root key transition signatures"
    )
    authorization = _signature(signatures["authorization"], "service root key transition authorization")
    acceptance = _signature(signatures["acceptance"], "service root key transition acceptance")
    if authorization["keyId"] != previous_key["keyId"] or acceptance["keyId"] != next_key["keyId"]:
        raise PublicServiceContractError("service root key transition signatures use the wrong keys")

    previous_public = _base64url_decode(
        previous_key["publicKey"], expected_bytes=32, field="service root key transition previousRootKey publicKey"
    )
    next_public = _base64url_decode(
        next_key["publicKey"], expected_bytes=32, field="service root key transition nextRootKey publicKey"
    )
    if trusted_root_keys is not None:
        trusted = trusted_root_keys.get(previous_key["keyId"])
        if trusted is None:
            raise PublicServiceContractError("service root key transition predecessor is not trusted")
        if trusted != previous_public:
            raise PublicServiceContractError("service root key transition predecessor material differs")
    signed = {**unsigned, "transitionDigest": digest}
    _verify(signed, authorization, previous_public)
    _verify(signed, acceptance, next_public)

    checked = {
        **unsigned,
        "transitionDigest": digest,
        "signatures": {"authorization": authorization, "acceptance": acceptance},
    }
    if expected_service_id is not None and checked["serviceId"] != expected_service_id:
        raise PublicServiceContractError("service root key transition service differs")
    if expected_sequence is not None and checked["sequence"] != expected_sequence:
        raise PublicServiceContractError("service root key transition sequence differs")
    if (
        expected_previous_transition_digest is not _UNSET
        and checked["previousTransitionDigest"] != expected_previous_transition_digest
    ):
        raise PublicServiceContractError("service root key transition predecessor differs")
    if len(canonical_json_bytes(checked)) > MAX_ROOT_KEY_TRANSITION_BYTES:
        raise PublicServiceContractError("service root key transition exceeds its byte limit")
    return checked


def build_service_root_key_transition(
    *,
    service_id: str,
    sequence: int,
    previous_transition_digest: str | None,
    previous_root_signer: DecisionSigningAuthority,
    previous_root_valid_from: datetime,
    previous_root_valid_until: datetime,
    next_root_signer: DecisionSigningAuthority,
    next_root_valid_until: datetime,
    issued_at: datetime,
    effective_at: datetime,
) -> dict[str, Any]:
    if any(
        not isinstance(item, datetime) or item.tzinfo is None
        for item in (
            previous_root_valid_from,
            previous_root_valid_until,
            next_root_valid_until,
            issued_at,
            effective_at,
        )
    ):
        raise PublicServiceContractError("service root key transition time is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    effective = effective_at.astimezone(UTC).replace(microsecond=0)
    unsigned = {
        "schemaVersion": SERVICE_ROOT_KEY_TRANSITION_SCHEMA_VERSION,
        "serviceId": service_id,
        "sequence": sequence,
        "previousTransitionDigest": previous_transition_digest,
        "previousRootKey": {
            "keyId": previous_root_signer.key_id,
            "algorithm": SIGNATURE_ALGORITHM,
            "publicKey": _base64url_encode(previous_root_signer.public_bytes()),
            "validFrom": isoformat_utc(previous_root_valid_from.astimezone(UTC).replace(microsecond=0)),
            "validUntil": isoformat_utc(previous_root_valid_until.astimezone(UTC).replace(microsecond=0)),
        },
        "nextRootKey": {
            "keyId": next_root_signer.key_id,
            "algorithm": SIGNATURE_ALGORITHM,
            "publicKey": _base64url_encode(next_root_signer.public_bytes()),
            "validFrom": isoformat_utc(effective),
            "validUntil": isoformat_utc(next_root_valid_until.astimezone(UTC).replace(microsecond=0)),
        },
        "effectiveAt": isoformat_utc(effective),
        "issuedAt": isoformat_utc(issued),
    }
    digest = sha256_json(unsigned)
    signed = {**unsigned, "transitionDigest": digest}
    try:
        value = {
            **signed,
            "signatures": {
                "authorization": {
                    "keyId": previous_root_signer.key_id,
                    "algorithm": SIGNATURE_ALGORITHM,
                    "value": previous_root_signer.sign(canonical_json_bytes(signed)),
                },
                "acceptance": {
                    "keyId": next_root_signer.key_id,
                    "algorithm": SIGNATURE_ALGORITHM,
                    "value": next_root_signer.sign(canonical_json_bytes(signed)),
                },
            },
        }
        return validate_service_root_key_transition(
            value,
            trusted_root_keys={previous_root_signer.key_id: previous_root_signer.public_bytes()},
            expected_service_id=service_id,
            expected_sequence=sequence,
            expected_previous_transition_digest=previous_transition_digest,
        )
    except PublicServiceContractError:
        raise
    except (ControlPlaneContractError, ValueError) as error:
        raise PublicServiceContractError("service root key transition signing failed") from error


def advance_service_root_trust(
    transition: dict[str, Any],
    *,
    trusted_root_keys: Mapping[str, bytes],
    expected_service_id: str,
    expected_sequence: int,
    expected_previous_transition_digest: str | None,
    at: datetime,
) -> tuple[dict[str, bytes], int, str]:
    """Advance a pinned root exactly once after a scheduled transition.

    The returned trust set intentionally drops the predecessor. Persisting the
    returned sequence and digest makes a subsequently replayed older chain
    fail closed. Emergency recovery from a compromised predecessor is an
    out-of-band trust reset, not a weaker form of this operation.
    """

    checked = validate_service_root_key_transition(
        transition,
        trusted_root_keys=trusted_root_keys,
        expected_service_id=expected_service_id,
        expected_sequence=expected_sequence,
        expected_previous_transition_digest=expected_previous_transition_digest,
    )
    if not isinstance(at, datetime) or at.tzinfo is None:
        raise PublicServiceContractError("root trust advancement time is invalid")
    current = at.astimezone(UTC).replace(microsecond=0)
    effective = _timestamp(checked["effectiveAt"], "service root key transition effectiveAt")
    next_key = checked["nextRootKey"]
    next_until = _timestamp(next_key["validUntil"], "service root key transition nextRootKey validUntil")
    if current < effective:
        raise PublicServiceContractError("service root key transition is not yet effective")
    if current > next_until:
        raise PublicServiceContractError("service root key transition successor has expired")
    next_public = _base64url_decode(
        next_key["publicKey"], expected_bytes=32, field="service root key transition nextRootKey publicKey"
    )
    return {next_key["keyId"]: next_public}, checked["sequence"], checked["transitionDigest"]


def validate_service_root_key_transition_set(
    value: Any,
    *,
    trusted_root_keys: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Validate the bounded append-only chain published beside discovery.

    Supplying the client's pinned initial roots validates the entire chain as
    an authority path. Omitting them validates exact shape, signatures, and
    link continuity but does not establish an external trust anchor.
    """

    document = _exact(
        value,
        {"schemaVersion", "serviceId", "transitions", "latestSequence", "latestTransitionDigest"},
        "service root key transition set",
    )
    if document["schemaVersion"] != SERVICE_ROOT_KEY_TRANSITION_SET_SCHEMA_VERSION:
        raise PublicServiceContractError("service root key transition set schemaVersion is invalid")
    service_id = _text(
        document["serviceId"], "service root key transition set serviceId", maximum=200, pattern=_IDENTIFIER
    )
    transitions = document["transitions"]
    if not isinstance(transitions, list) or len(transitions) > MAX_ROOT_KEY_TRANSITIONS:
        raise PublicServiceContractError("service root key transition set transitions are invalid")
    latest_sequence = document["latestSequence"]
    if (
        isinstance(latest_sequence, bool)
        or not isinstance(latest_sequence, int)
        or not 0 <= latest_sequence <= MAX_ROOT_KEY_TRANSITIONS
    ):
        raise PublicServiceContractError("service root key transition set latestSequence is invalid")
    latest_digest = document["latestTransitionDigest"]
    if latest_sequence == 0:
        if latest_digest is not None or transitions:
            raise PublicServiceContractError("empty service root key transition set state is invalid")
    else:
        latest_digest = _digest(latest_digest, "service root key transition set latestTransitionDigest")
        if len(transitions) != latest_sequence:
            raise PublicServiceContractError("service root key transition set is incomplete")

    checked_transitions: list[dict[str, Any]] = []
    expected_previous: str | None = None
    current_roots = trusted_root_keys
    for sequence, transition in enumerate(transitions, start=1):
        checked = validate_service_root_key_transition(
            transition,
            trusted_root_keys=current_roots,
            expected_service_id=service_id,
            expected_sequence=sequence,
            expected_previous_transition_digest=expected_previous,
        )
        checked_transitions.append(checked)
        next_key = checked["nextRootKey"]
        current_roots = {
            next_key["keyId"]: _base64url_decode(
                next_key["publicKey"],
                expected_bytes=32,
                field="service root key transition set successor publicKey",
            )
        }
        expected_previous = checked["transitionDigest"]
    if checked_transitions and latest_digest != checked_transitions[-1]["transitionDigest"]:
        raise PublicServiceContractError("service root key transition set latest digest differs")
    checked_document = {
        "schemaVersion": SERVICE_ROOT_KEY_TRANSITION_SET_SCHEMA_VERSION,
        "serviceId": service_id,
        "transitions": checked_transitions,
        "latestSequence": latest_sequence,
        "latestTransitionDigest": latest_digest,
    }
    if len(canonical_json_bytes(checked_document)) > MAX_ROOT_KEY_TRANSITION_SET_BYTES:
        raise PublicServiceContractError("service root key transition set exceeds its byte limit")
    return checked_document


def build_service_root_key_transition_set(
    *,
    service_id: str,
    transitions: Iterable[dict[str, Any]],
    trusted_root_keys: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    items = list(transitions)
    latest_digest = items[-1].get("transitionDigest") if items and isinstance(items[-1], dict) else None
    value = {
        "schemaVersion": SERVICE_ROOT_KEY_TRANSITION_SET_SCHEMA_VERSION,
        "serviceId": service_id,
        "transitions": items,
        "latestSequence": len(items),
        "latestTransitionDigest": latest_digest,
    }
    return validate_service_root_key_transition_set(value, trusted_root_keys=trusted_root_keys)


def latest_service_root_keys(transition_set: dict[str, Any]) -> dict[str, bytes]:
    checked = validate_service_root_key_transition_set(transition_set)
    if not checked["transitions"]:
        return {}
    next_key = checked["transitions"][-1]["nextRootKey"]
    return {
        next_key["keyId"]: _base64url_decode(
            next_key["publicKey"], expected_bytes=32, field="service root key transition set successor publicKey"
        )
    }


def _signing_key(value: Any) -> dict[str, Any]:
    item = _exact(value, {"keyId", "algorithm", "publicKey", "validFrom", "validUntil"}, "service signing key")
    valid_from, valid_until = _lifetime(
        item["validFrom"], item["validUntil"], maximum=timedelta(days=366), field="service signing key"
    )
    public = _text(item["publicKey"], "service signing key publicKey", maximum=43, pattern=_BASE64URL_32)
    _base64url_decode(public, expected_bytes=32, field="service signing key publicKey")
    algorithm = _text(item["algorithm"], "service signing key algorithm", maximum=20)
    if algorithm != SIGNATURE_ALGORITHM:
        raise PublicServiceContractError("service signing key algorithm is invalid")
    return {
        "keyId": _text(item["keyId"], "service signing key keyId", maximum=200, pattern=_IDENTIFIER),
        "algorithm": algorithm,
        "publicKey": public,
        "validFrom": valid_from,
        "validUntil": valid_until,
    }


def validate_service_discovery(
    value: Any,
    *,
    root_public_keys: Mapping[str, bytes] | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    discovery = _exact(
        value,
        {
            "schemaVersion",
            "serviceId",
            "protocolVersion",
            "apiBaseUrl",
            "queryVersions",
            "resultVersions",
            "outcomeAttemptVersions",
            "outcomeReceiptVersions",
            "submissionIntentVersions",
            "submissionPlanVersions",
            "contentTransferGrantVersions",
            "releaseVersions",
            "rootTransitionVersions",
            "rootTransitionState",
            "signingKeys",
            "dataUsePolicy",
            "limits",
            "issuedAt",
            "expiresAt",
            "documentDigest",
            "signature",
        },
        "service discovery",
    )
    if discovery["schemaVersion"] != SERVICE_DISCOVERY_SCHEMA_VERSION:
        raise PublicServiceContractError("service discovery schemaVersion is invalid")
    policy = _exact(discovery["dataUsePolicy"], {"url", "digest"}, "service discovery dataUsePolicy")
    transition_state = _exact(
        discovery["rootTransitionState"],
        {"latestSequence", "latestTransitionDigest"},
        "service discovery rootTransitionState",
    )
    transition_sequence = transition_state["latestSequence"]
    if (
        isinstance(transition_sequence, bool)
        or not isinstance(transition_sequence, int)
        or not 0 <= transition_sequence <= MAX_ROOT_KEY_TRANSITIONS
    ):
        raise PublicServiceContractError("service discovery rootTransitionState latestSequence is invalid")
    transition_digest = transition_state["latestTransitionDigest"]
    if transition_sequence == 0:
        if transition_digest is not None:
            raise PublicServiceContractError("service discovery rootTransitionState is invalid")
    else:
        transition_digest = _digest(transition_digest, "service discovery rootTransitionState latestTransitionDigest")
    limits = _exact(
        discovery["limits"],
        {
            "maxQueryBytes",
            "maxResultBytes",
            "maxOutcomeAttemptBytes",
            "maxOutcomeReceiptBytes",
            "maxSubmissionIntentBytes",
            "maxSubmissionPlanBytes",
            "maxContentTransferGrantBytes",
            "maxReleaseBytes",
            "rateLimitClass",
        },
        "service discovery limits",
    )
    keys = discovery["signingKeys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= 8:
        raise PublicServiceContractError("service discovery signingKeys are invalid")
    checked_keys = [_signing_key(item) for item in keys]
    if checked_keys != sorted(checked_keys, key=lambda item: item["keyId"]) or len(
        {item["keyId"] for item in checked_keys}
    ) != len(checked_keys):
        raise PublicServiceContractError("service discovery signingKeys must be sorted and unique")
    issued_at, expires_at = _lifetime(
        discovery["issuedAt"], discovery["expiresAt"], maximum=MAX_DISCOVERY_TTL, field="service discovery"
    )
    unsigned = {
        "schemaVersion": SERVICE_DISCOVERY_SCHEMA_VERSION,
        "serviceId": _text(discovery["serviceId"], "service discovery serviceId", maximum=200, pattern=_IDENTIFIER),
        "protocolVersion": _text(discovery["protocolVersion"], "service discovery protocolVersion", maximum=80),
        "apiBaseUrl": _https_url(discovery["apiBaseUrl"], "service discovery apiBaseUrl", allow_path=False),
        "queryVersions": _sorted_texts(
            discovery["queryVersions"], "service discovery queryVersions", maximum_items=4, maximum_length=80
        ),
        "resultVersions": _sorted_texts(
            discovery["resultVersions"], "service discovery resultVersions", maximum_items=4, maximum_length=80
        ),
        "outcomeAttemptVersions": _sorted_texts(
            discovery["outcomeAttemptVersions"],
            "service discovery outcomeAttemptVersions",
            maximum_items=4,
            maximum_length=80,
        ),
        "outcomeReceiptVersions": _sorted_texts(
            discovery["outcomeReceiptVersions"],
            "service discovery outcomeReceiptVersions",
            maximum_items=4,
            maximum_length=80,
        ),
        "submissionIntentVersions": _sorted_texts(
            discovery["submissionIntentVersions"],
            "service discovery submissionIntentVersions",
            maximum_items=4,
            maximum_length=80,
        ),
        "submissionPlanVersions": _sorted_texts(
            discovery["submissionPlanVersions"],
            "service discovery submissionPlanVersions",
            maximum_items=4,
            maximum_length=80,
        ),
        "contentTransferGrantVersions": _sorted_texts(
            discovery["contentTransferGrantVersions"],
            "service discovery contentTransferGrantVersions",
            maximum_items=4,
            maximum_length=80,
        ),
        "releaseVersions": _sorted_texts(
            discovery["releaseVersions"],
            "service discovery releaseVersions",
            maximum_items=4,
            maximum_length=80,
        ),
        "rootTransitionVersions": _sorted_texts(
            discovery["rootTransitionVersions"],
            "service discovery rootTransitionVersions",
            maximum_items=4,
            maximum_length=80,
        ),
        "rootTransitionState": {
            "latestSequence": transition_sequence,
            "latestTransitionDigest": transition_digest,
        },
        "signingKeys": checked_keys,
        "dataUsePolicy": {
            "url": _https_url(policy["url"], "service discovery dataUsePolicy url"),
            "digest": _digest(policy["digest"], "service discovery dataUsePolicy digest"),
        },
        "limits": {
            "maxQueryBytes": _positive_int(
                limits["maxQueryBytes"], "service discovery maxQueryBytes", maximum=MAX_QUERY_BYTES
            ),
            "maxResultBytes": _positive_int(
                limits["maxResultBytes"], "service discovery maxResultBytes", maximum=MAX_RESULT_BYTES
            ),
            "maxOutcomeAttemptBytes": _positive_int(
                limits["maxOutcomeAttemptBytes"],
                "service discovery maxOutcomeAttemptBytes",
                maximum=MAX_OUTCOME_ATTEMPT_BYTES,
            ),
            "maxOutcomeReceiptBytes": _positive_int(
                limits["maxOutcomeReceiptBytes"],
                "service discovery maxOutcomeReceiptBytes",
                maximum=MAX_OUTCOME_RECEIPT_BYTES,
            ),
            "maxSubmissionIntentBytes": _positive_int(
                limits["maxSubmissionIntentBytes"],
                "service discovery maxSubmissionIntentBytes",
                maximum=MAX_INTENT_BYTES,
            ),
            "maxSubmissionPlanBytes": _positive_int(
                limits["maxSubmissionPlanBytes"],
                "service discovery maxSubmissionPlanBytes",
                maximum=MAX_PLAN_BYTES,
            ),
            "maxContentTransferGrantBytes": _positive_int(
                limits["maxContentTransferGrantBytes"],
                "service discovery maxContentTransferGrantBytes",
                maximum=MAX_CONTENT_TRANSFER_GRANT_BYTES,
            ),
            "maxReleaseBytes": _positive_int(
                limits["maxReleaseBytes"],
                "service discovery maxReleaseBytes",
                maximum=MAX_RELEASE_BYTES,
            ),
            "rateLimitClass": _text(limits["rateLimitClass"], "service discovery rateLimitClass", maximum=80),
        },
        "issuedAt": issued_at,
        "expiresAt": expires_at,
    }
    if unsigned["protocolVersion"] != SERVICE_PROTOCOL_VERSION:
        raise PublicServiceContractError("service discovery protocolVersion is invalid")
    if (
        SERVICE_QUERY_SCHEMA_VERSION not in unsigned["queryVersions"]
        or not set(unsigned["resultVersions"]).intersection(SERVICE_QUERY_RESULT_SCHEMA_VERSIONS)
        or SERVICE_OUTCOME_ATTEMPT_SCHEMA_VERSION not in unsigned["outcomeAttemptVersions"]
        or SERVICE_OUTCOME_RECEIPT_SCHEMA_VERSION not in unsigned["outcomeReceiptVersions"]
        or SUBMISSION_INTENT_SCHEMA_VERSION not in unsigned["submissionIntentVersions"]
        or SUBMISSION_PLAN_SCHEMA_VERSION not in unsigned["submissionPlanVersions"]
        or CONTENT_TRANSFER_GRANT_SCHEMA_VERSION not in unsigned["contentTransferGrantVersions"]
        or IMMUTABLE_RELEASE_SCHEMA_VERSION not in unsigned["releaseVersions"]
        or SERVICE_ROOT_KEY_TRANSITION_SCHEMA_VERSION not in unsigned["rootTransitionVersions"]
    ):
        raise PublicServiceContractError("service discovery omits the required protocol versions")
    digest = _digest(discovery["documentDigest"], "service discovery documentDigest")
    if digest != sha256_json(unsigned):
        raise PublicServiceContractError("service discovery digest does not bind its exact content")
    signature = _signature(discovery["signature"], "service discovery signature")
    bound = {**unsigned, "documentDigest": digest, "signature": signature}
    if root_public_keys is not None:
        root_key = root_public_keys.get(signature["keyId"])
        if root_key is None:
            raise PublicServiceContractError("service discovery root key is unknown")
        _verify({**unsigned, "documentDigest": digest}, signature, root_key)
    if len(canonical_json_bytes(bound)) > MAX_DISCOVERY_BYTES:
        raise PublicServiceContractError("service discovery exceeds its byte limit")
    _at(bound, at=at, field="service discovery")
    return bound


def build_service_discovery(
    *,
    service_id: str,
    api_base_url: str,
    signing_keys: Iterable[tuple[str, bytes, datetime, datetime]],
    data_use_policy_url: str,
    data_use_policy_digest: str,
    rate_limit_class: str,
    issued_at: datetime,
    root_signer: DecisionSigningAuthority,
    root_transition_sequence: int = 0,
    root_transition_digest: str | None = None,
    ttl_seconds: int = 24 * 60 * 60,
) -> dict[str, Any]:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 7 * 24 * 60 * 60:
        raise PublicServiceContractError("service discovery ttl is invalid")
    if not isinstance(issued_at, datetime) or issued_at.tzinfo is None:
        raise PublicServiceContractError("service discovery issuedAt is invalid")
    issued = issued_at.astimezone(UTC).replace(microsecond=0)
    keys = []
    for key_id, public_key, valid_from, valid_until in signing_keys:
        keys.append(
            {
                "keyId": key_id,
                "algorithm": SIGNATURE_ALGORITHM,
                "publicKey": _base64url_encode(public_key),
                "validFrom": isoformat_utc(valid_from.astimezone(UTC).replace(microsecond=0)),
                "validUntil": isoformat_utc(valid_until.astimezone(UTC).replace(microsecond=0)),
            }
        )
    unsigned = {
        "schemaVersion": SERVICE_DISCOVERY_SCHEMA_VERSION,
        "serviceId": service_id,
        "protocolVersion": SERVICE_PROTOCOL_VERSION,
        "apiBaseUrl": api_base_url,
        "queryVersions": [SERVICE_QUERY_SCHEMA_VERSION],
        "resultVersions": list(SERVICE_QUERY_RESULT_SCHEMA_VERSIONS),
        "outcomeAttemptVersions": [SERVICE_OUTCOME_ATTEMPT_SCHEMA_VERSION],
        "outcomeReceiptVersions": [SERVICE_OUTCOME_RECEIPT_SCHEMA_VERSION],
        "submissionIntentVersions": [SUBMISSION_INTENT_SCHEMA_VERSION],
        "submissionPlanVersions": [SUBMISSION_PLAN_SCHEMA_VERSION],
        "contentTransferGrantVersions": [CONTENT_TRANSFER_GRANT_SCHEMA_VERSION],
        "releaseVersions": [IMMUTABLE_RELEASE_SCHEMA_VERSION],
        "rootTransitionVersions": [SERVICE_ROOT_KEY_TRANSITION_SCHEMA_VERSION],
        "rootTransitionState": {
            "latestSequence": root_transition_sequence,
            "latestTransitionDigest": root_transition_digest,
        },
        "signingKeys": sorted(keys, key=lambda item: item["keyId"]),
        "dataUsePolicy": {"url": data_use_policy_url, "digest": data_use_policy_digest},
        "limits": {
            "maxQueryBytes": MAX_QUERY_BYTES,
            "maxResultBytes": MAX_RESULT_BYTES,
            "maxOutcomeAttemptBytes": MAX_OUTCOME_ATTEMPT_BYTES,
            "maxOutcomeReceiptBytes": MAX_OUTCOME_RECEIPT_BYTES,
            "maxSubmissionIntentBytes": MAX_INTENT_BYTES,
            "maxSubmissionPlanBytes": MAX_PLAN_BYTES,
            "maxContentTransferGrantBytes": MAX_CONTENT_TRANSFER_GRANT_BYTES,
            "maxReleaseBytes": MAX_RELEASE_BYTES,
            "rateLimitClass": rate_limit_class,
        },
        "issuedAt": isoformat_utc(issued),
        "expiresAt": isoformat_utc(issued + timedelta(seconds=ttl_seconds)),
    }
    digest = sha256_json(unsigned)
    try:
        signature = root_signer.sign(canonical_json_bytes({**unsigned, "documentDigest": digest}))
        return validate_service_discovery(
            {
                **unsigned,
                "documentDigest": digest,
                "signature": {"keyId": root_signer.key_id, "algorithm": SIGNATURE_ALGORITHM, "value": signature},
            },
            root_public_keys={root_signer.key_id: root_signer.public_bytes()},
        )
    except PublicServiceContractError:
        raise
    except (ControlPlaneContractError, ValueError) as error:
        raise PublicServiceContractError("service discovery signing failed") from error


def active_result_keys(discovery: dict[str, Any], *, at: datetime) -> dict[str, bytes]:
    checked = validate_service_discovery(discovery, at=at)
    now = at.astimezone(UTC).replace(microsecond=0)
    result: dict[str, bytes] = {}
    for item in checked["signingKeys"]:
        if (
            _timestamp(item["validFrom"], "signing key validFrom")
            <= now
            <= _timestamp(item["validUntil"], "signing key validUntil")
        ):
            result[item["keyId"]] = _base64url_decode(
                item["publicKey"], expected_bytes=32, field="signing key publicKey"
            )
    if not result:
        raise PublicServiceContractError("service discovery has no active result key")
    return result
