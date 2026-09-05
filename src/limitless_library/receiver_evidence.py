"""Composite evidence bound to the environment that established each claim."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from .contracts import ContractError, parse_utc, sha256_json, utc_now
from .receiver_environment import (
    ReceiverEnvironmentError,
    receiver_environment_digest,
    validate_receiver_environment_profile,
)

RECEIVER_EVIDENCE_SCHEMA_VERSION = "limitless.receiver-evidence/1.0"
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,199}$")
_DECISION = re.compile(
    r"^(?:decision:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}|(?:managed-query-decision|control-decision):[0-9a-f]{16})$"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_KINDS = {"deterministic", "receiver-observation", "human-witness"}
_STATUSES = {"passed", "failed", "blocked", "not-applicable"}


class ReceiverEvidenceError(ValueError):
    """Composite receiver evidence is incomplete, altered, or overclaims."""


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReceiverEvidenceError(f"{label} must be a SHA-256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ReceiverEvidenceError(f"{label} must be a bounded identifier")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ReceiverEvidenceError(f"{label} is invalid")
    try:
        parse_utc(value, label)
    except ContractError as error:
        raise ReceiverEvidenceError(f"{label} is invalid") from error
    return value


def _recorded_at(value: datetime | None) -> str:
    if value is None:
        return utc_now()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ReceiverEvidenceError("recordedAt requires a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _receipt_digest(value: dict[str, Any]) -> str:
    return sha256_json({key: item for key, item in value.items() if key not in {"id", "receiptDigest"}})


def _normalize_checks(checks: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for value in checks:
        if not isinstance(value, dict) or set(value) != {
            "id",
            "kind",
            "environmentId",
            "status",
            "reasonCode",
            "observedAt",
            "evidenceDigest",
        }:
            raise ReceiverEvidenceError("receiver evidence check has unsupported or missing fields")
        if value["kind"] not in _KINDS or value["status"] not in _STATUSES:
            raise ReceiverEvidenceError("receiver evidence check kind or status is unsupported")
        normalized.append(
            {
                "id": _identifier(value["id"], "receiver evidence check id"),
                "kind": value["kind"],
                "environmentId": _identifier(value["environmentId"], "receiver evidence environment id"),
                "status": value["status"],
                "reasonCode": _identifier(value["reasonCode"], "receiver evidence reasonCode"),
                "observedAt": _timestamp(value["observedAt"], "receiver evidence observedAt"),
                "evidenceDigest": _digest(value["evidenceDigest"], "receiver evidence check evidenceDigest"),
            }
        )
    if not 1 <= len(normalized) <= 64:
        raise ReceiverEvidenceError("receiver evidence requires one through sixty-four checks")
    if normalized != sorted(normalized, key=lambda item: item["id"]) or len(
        {item["id"] for item in normalized}
    ) != len(normalized):
        raise ReceiverEvidenceError("receiver evidence checks must be sorted by unique id")
    return normalized


def _outcome(checks: list[dict[str, Any]], required_ids: list[str]) -> str:
    required = [item for item in checks if item["id"] in required_ids]
    if any(item["status"] == "failed" for item in required):
        return "failed"
    if any(item["status"] in {"blocked", "not-applicable"} for item in required):
        return "blocked"
    if all(item["status"] == "passed" for item in required):
        return "verified"
    raise ReceiverEvidenceError("receiver evidence required checks have no honest outcome")


def build_receiver_evidence(
    *,
    profile: dict[str, Any],
    decision_ref: str,
    checks: Iterable[dict[str, Any]],
    required_check_ids: Iterable[str],
    recorded_at: datetime | None = None,
) -> dict[str, Any]:
    """Build evidence without turning absent capabilities into passing checks."""

    checked_profile = validate_receiver_environment_profile(profile)
    normalized_checks = _normalize_checks(checks)
    raw_required = list(required_check_ids)
    if not raw_required or any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in raw_required):
        raise ReceiverEvidenceError("requiredCheckIds must contain bounded identifiers")
    required = sorted(set(raw_required))
    if not set(required).issubset({item["id"] for item in normalized_checks}):
        raise ReceiverEvidenceError("requiredCheckIds name absent checks")
    receipt: dict[str, Any] = {
        "schemaVersion": RECEIVER_EVIDENCE_SCHEMA_VERSION,
        "decisionRef": decision_ref,
        "receiverProfileDigest": receiver_environment_digest(checked_profile),
        "requiredCheckIds": required,
        "checks": normalized_checks,
        "outcome": _outcome(normalized_checks, required),
        "recordedAt": _recorded_at(recorded_at),
    }
    receipt["receiptDigest"] = _receipt_digest(receipt)
    receipt["id"] = f"receiver-evidence:{receipt['receiptDigest'][7:23]}"
    validate_receiver_evidence(receipt, profile=checked_profile, expected_decision_ref=decision_ref)
    return receipt


def validate_receiver_evidence(
    value: Any,
    *,
    profile: dict[str, Any] | None = None,
    expected_decision_ref: str | None = None,
) -> dict[str, Any]:
    """Validate composite evidence and its optional exact receiver binding."""

    expected_fields = {
        "schemaVersion",
        "id",
        "decisionRef",
        "receiverProfileDigest",
        "requiredCheckIds",
        "checks",
        "outcome",
        "recordedAt",
        "receiptDigest",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ReceiverEvidenceError("receiver evidence has unsupported or missing fields")
    if value["schemaVersion"] != RECEIVER_EVIDENCE_SCHEMA_VERSION:
        raise ReceiverEvidenceError("receiver evidence schemaVersion is unsupported")
    decision_ref = value["decisionRef"]
    if not isinstance(decision_ref, str) or _DECISION.fullmatch(decision_ref) is None:
        raise ReceiverEvidenceError("receiver evidence decisionRef is invalid")
    if expected_decision_ref is not None and decision_ref != expected_decision_ref:
        raise ReceiverEvidenceError("receiver evidence is bound to another decision")
    checks = _normalize_checks(value["checks"])
    required = value["requiredCheckIds"]
    if not isinstance(required, list) or not required or required != sorted(set(required)):
        raise ReceiverEvidenceError("receiver evidence requiredCheckIds must be sorted and unique")
    if any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in required):
        raise ReceiverEvidenceError("receiver evidence requiredCheckIds are invalid")
    if not set(required).issubset({item["id"] for item in checks}):
        raise ReceiverEvidenceError("receiver evidence requiredCheckIds name absent checks")
    if value["outcome"] != _outcome(checks, required):
        raise ReceiverEvidenceError("receiver evidence outcome overclaims its required checks")
    _timestamp(value["recordedAt"], "receiver evidence recordedAt")
    profile_digest = _digest(value["receiverProfileDigest"], "receiverProfileDigest")
    if profile is not None:
        try:
            checked_profile = validate_receiver_environment_profile(profile)
        except ReceiverEnvironmentError as error:
            raise ReceiverEvidenceError(f"receiver evidence profile is invalid: {error}") from error
        if profile_digest != receiver_environment_digest(checked_profile):
            raise ReceiverEvidenceError("receiver evidence is bound to another receiver profile")
        by_id = {item["id"]: item for item in checked_profile["environments"]}
        verification_ids = set(checked_profile["bindings"]["verificationReceivers"])
        for check in checks:
            environment = by_id.get(check["environmentId"])
            if environment is None:
                raise ReceiverEvidenceError("receiver evidence check names an unknown environment")
            if check["environmentId"] not in verification_ids:
                raise ReceiverEvidenceError("receiver evidence must come from a verificationReceiver")
            if check["kind"] == "human-witness" and environment["kind"] != "human-observer":
                raise ReceiverEvidenceError("human-witness evidence must bind a human-observer environment")
    digest = _digest(value["receiptDigest"], "receiver evidence receiptDigest")
    if digest != _receipt_digest(value):
        raise ReceiverEvidenceError("receiver evidence digest does not bind its contents")
    if value["id"] != f"receiver-evidence:{digest[7:23]}":
        raise ReceiverEvidenceError("receiver evidence id does not derive from its digest")
    return value
