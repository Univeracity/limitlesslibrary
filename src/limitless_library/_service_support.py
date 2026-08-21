"""Small public helpers shared by the hosted-service wire contracts.

This module intentionally contains no service implementation, identity logic,
ranking policy, persistence adapter, or deployment configuration.  It only
supports validation of language-neutral records returned to an opted-in
client.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import ContractError

DATA_USE_MODES = ("standard", "history", "organization", "private")
QUERY_SCOPES = ("public", "organization", "exchange", "private")
TREATMENT_CLASSES = ("exact-component", "source-free-method")

SUBMISSION_INTENT_SCHEMA_VERSION = "limitless.service-submission-intent/1.0"
SUBMISSION_PLAN_SCHEMA_VERSION = "limitless.service-submission-plan/1.0"
CONTENT_TRANSFER_GRANT_SCHEMA_VERSION = "limitless.service-content-transfer-grant/1.0"
IMMUTABLE_RELEASE_SCHEMA_VERSION = "limitless.service-release/1.0"
MAX_INTENT_BYTES = 16 * 1024
MAX_PLAN_BYTES = 16 * 1024
MAX_CONTENT_TRANSFER_GRANT_BYTES = 16 * 1024
MAX_RELEASE_BYTES = 32 * 1024

NEXT_ACTION_KINDS = (
    "install-and-verify",
    "handoff-native-add",
    "apply-method-step",
    "supply-missing-fact",
    "use-local-catalog",
    "re-query",
)
PREDICATES = (
    "digest-equals",
    "symbol-exists",
    "file-exists",
    "interface-subset",
    "fact-present",
    "generation-current",
)
MISSING_FACTS = (
    "receiverFacts.runtime",
    "receiverFacts.versionRange",
    "receiverFacts.interfaces",
    "receiverFacts.allowedUse",
    "receiverFacts.platform",
    "receiverContext.targets",
    "requestedScopes",
    "disambiguating-constraint",
    "eligible-authorized-supply",
    "decision-budget",
    "rate-limited",
    "local-catalog",
)
SIGNED_MISSING_FACTS = frozenset(MISSING_FACTS) - {"rate-limited", "local-catalog"}

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHECK_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_LOCATOR = re.compile(
    r"^(none|[A-Za-z][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_.]*|"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,158})$"
)
_CLAUSE = re.compile(r"^(?P<operator>>=|<=|>|<|==|=)?(?P<version>[0-9]+(?:\.[0-9]+){0,3})$")


class DecisionSigningAuthority(Protocol):
    key_id: str

    def sign(self, payload: bytes) -> str: ...

    def public_bytes(self) -> bytes: ...


def isoformat_utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ContractError("timestamp must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def public_key_from_bytes(value: bytes) -> Ed25519PublicKey:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ContractError("Ed25519 public key must contain exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(value)


def _exact(value: Any, fields: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{field} has an unsupported shape")
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
        raise ValueError(f"{field} is invalid")
    return value


def _checks(
    value: Any,
    *,
    minimum: int = 1,
    maximum: int = 8,
) -> list[dict[str, str]]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError("checks are invalid")
    result: list[dict[str, str]] = []
    for value_item in value:
        item = _exact(value_item, {"id", "predicate", "expected"}, "check")
        predicate = _text(item["predicate"], "check predicate", maximum=32)
        expected = _text(item["expected"], "check expected", maximum=160)
        if predicate not in PREDICATES:
            raise ValueError("check predicate is invalid")
        if predicate == "digest-equals" and _DIGEST.fullmatch(expected) is None:
            raise ValueError("digest-equals expected is invalid")
        result.append(
            {
                "id": _text(item["id"], "check id", maximum=32, pattern=_CHECK_ID),
                "predicate": predicate,
                "expected": expected,
            }
        )
    return result


def _locator(value: Any, field: str) -> str:
    selected = _text(value, field, maximum=160)
    if ".." in selected or _LOCATOR.fullmatch(selected) is None:
        raise ValueError(f"{field} is invalid")
    return selected


def validate_next_action(
    value: Any,
    *,
    allow_unsigned_facts: bool = False,
) -> dict[str, Any]:
    """Validate the bounded action that follows a signed service result."""

    if not isinstance(value, dict) or "kind" not in value:
        raise ValueError("nextAction has an unsupported shape")
    kind = _text(value["kind"], "nextAction kind", maximum=40)
    if kind not in NEXT_ACTION_KINDS:
        raise ValueError("nextAction kind is invalid")
    if kind == "install-and-verify":
        action = _exact(
            value,
            {
                "kind",
                "instruction",
                "checks",
                "localReuseAvailable",
                "handoff",
                "artifactDigest",
            },
            "nextAction",
        )
        digest = _text(
            action["artifactDigest"],
            "nextAction artifactDigest",
            maximum=71,
            pattern=_DIGEST,
        )
        checks = _checks(action["checks"])
        if not any(item["predicate"] == "digest-equals" and item["expected"] == digest for item in checks):
            raise ValueError("install-and-verify requires the artifact digest")
        if action["handoff"] != "library-install" or action["localReuseAvailable"] is not True:
            raise ValueError("install-and-verify action is invalid")
        return {
            "kind": kind,
            "instruction": _text(action["instruction"], "nextAction instruction", maximum=280),
            "checks": checks,
            "localReuseAvailable": True,
            "handoff": "library-install",
            "artifactDigest": digest,
        }
    if kind == "handoff-native-add":
        action = _exact(
            value,
            {"kind", "instruction", "checks", "localReuseAvailable", "handoff"},
            "nextAction",
        )
        handoff = _text(action["handoff"], "nextAction handoff", maximum=40)
        checks = _checks(action["checks"])
        if (
            handoff not in {"library-install", "provider-native-add"}
            or any(item["predicate"] == "digest-equals" for item in checks)
            or action["localReuseAvailable"] is not True
        ):
            raise ValueError("handoff-native-add action is invalid")
        return {
            "kind": kind,
            "instruction": _text(action["instruction"], "nextAction instruction", maximum=280),
            "checks": checks,
            "localReuseAvailable": True,
            "handoff": handoff,
        }
    if kind == "apply-method-step":
        action = _exact(
            value,
            {
                "kind",
                "instruction",
                "checks",
                "localReuseAvailable",
                "stepIndex",
                "steps",
                "locator",
            },
            "nextAction",
        )
        steps = action["steps"]
        if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
            raise ValueError("method steps are invalid")
        normalized_steps: list[dict[str, Any]] = []
        for value_step in steps:
            step = _exact(
                value_step,
                {"instruction", "check", "expected", "locator", "inRepo"},
                "method step",
            )
            check = _text(step["check"], "method step check", maximum=32)
            if check not in PREDICATES or not isinstance(step["inRepo"], bool):
                raise ValueError("method step is invalid")
            normalized_steps.append(
                {
                    "instruction": _text(step["instruction"], "method step instruction", maximum=280),
                    "check": check,
                    "expected": _text(step["expected"], "method step expected", maximum=160),
                    "locator": _locator(step["locator"], "method step locator"),
                    "inRepo": step["inRepo"],
                }
            )
        index = action["stepIndex"]
        if isinstance(index, bool) or not isinstance(index, int) or not 1 <= index <= len(normalized_steps):
            raise ValueError("nextAction stepIndex is invalid")
        first = normalized_steps[0]
        checks = _checks(action["checks"], minimum=1, maximum=1)
        if (
            action["instruction"] != first["instruction"]
            or _locator(action["locator"], "nextAction locator") != first["locator"]
            or checks[0]["predicate"] != first["check"]
            or checks[0]["expected"] != first["expected"]
            or action["localReuseAvailable"] is not True
        ):
            raise ValueError("apply-method-step action is inconsistent")
        return {
            "kind": kind,
            "instruction": first["instruction"],
            "checks": checks,
            "localReuseAvailable": True,
            "stepIndex": index,
            "steps": normalized_steps,
            "locator": first["locator"],
        }
    if kind == "supply-missing-fact":
        action = _exact(
            value,
            {"kind", "instruction", "checks", "localReuseAvailable", "missingFact"},
            "nextAction",
        )
        missing = _text(action["missingFact"], "nextAction missingFact", maximum=40)
        allowed = MISSING_FACTS if allow_unsigned_facts else SIGNED_MISSING_FACTS
        checks = _checks(action["checks"], minimum=1, maximum=1)
        if (
            missing not in allowed
            or checks[0]["predicate"] != "fact-present"
            or checks[0]["expected"] != missing
            or action["localReuseAvailable"] is not True
        ):
            raise ValueError("supply-missing-fact action is inconsistent")
        return {
            "kind": kind,
            "instruction": _text(action["instruction"], "nextAction instruction", maximum=280),
            "checks": checks,
            "localReuseAvailable": True,
            "missingFact": missing,
        }
    action = _exact(
        value,
        {"kind", "instruction", "checks", "localReuseAvailable"},
        "nextAction",
    )
    checks = _checks(action["checks"], minimum=1, maximum=1)
    expected = "local-catalog" if kind == "use-local-catalog" else None
    predicate = "fact-present" if kind == "use-local-catalog" else "generation-current"
    if (
        checks[0]["predicate"] != predicate
        or expected is not None
        and checks[0]["expected"] != expected
        or action["localReuseAvailable"] is not True
    ):
        raise ValueError(f"{kind} action is inconsistent")
    return {
        "kind": kind,
        "instruction": _text(action["instruction"], "nextAction instruction", maximum=280),
        "checks": checks,
        "localReuseAvailable": True,
    }


@dataclass(frozen=True)
class _Bound:
    value: tuple[int, int, int, int]
    inclusive: bool


@dataclass(frozen=True)
class _Interval:
    lower: _Bound | None
    upper: _Bound | None


def _version(value: str) -> tuple[int, int, int, int]:
    parts = [int(part) for part in value.split(".")]
    return (*parts, *([0] * (4 - len(parts))))  # type: ignore[return-value]


def _parse_range(value: str) -> _Interval | None:
    if value in {"*", "any"}:
        return _Interval(None, None)
    if not isinstance(value, str) or not value or len(value) > 120:
        return None
    lower: _Bound | None = None
    upper: _Bound | None = None
    for raw in value.split(","):
        clause = _CLAUSE.fullmatch(raw.strip())
        if clause is None:
            return None
        selected = _version(clause["version"])
        operator = clause["operator"] or "=="
        if operator in {"==", "="}:
            lower_candidate = _Bound(selected, True)
            upper_candidate = _Bound(selected, True)
        elif operator in {">", ">="}:
            lower_candidate = _Bound(selected, operator == ">=")
            upper_candidate = None
        else:
            lower_candidate = None
            upper_candidate = _Bound(selected, operator == "<=")
        if lower_candidate is not None and (
            lower is None
            or lower_candidate.value > lower.value
            or lower_candidate.value == lower.value
            and not lower_candidate.inclusive
        ):
            lower = lower_candidate
        if upper_candidate is not None and (
            upper is None
            or upper_candidate.value < upper.value
            or upper_candidate.value == upper.value
            and not upper_candidate.inclusive
        ):
            upper = upper_candidate
    if (
        lower is not None
        and upper is not None
        and (lower.value > upper.value or lower.value == upper.value and not (lower.inclusive and upper.inclusive))
    ):
        return None
    return _Interval(lower, upper)


def version_range_covers(supported: str, required: str) -> bool:
    if not isinstance(supported, str) or not isinstance(required, str):
        return False
    if supported == required or supported in {"*", "any"}:
        return True
    supported_interval = _parse_range(supported)
    required_interval = _parse_range(required)
    if supported_interval is None or required_interval is None:
        return False
    if required_interval.lower is None:
        if supported_interval.lower is not None:
            return False
    elif supported_interval.lower is not None and (
        supported_interval.lower.value > required_interval.lower.value
        or supported_interval.lower.value == required_interval.lower.value
        and required_interval.lower.inclusive
        and not supported_interval.lower.inclusive
    ):
        return False
    if required_interval.upper is None:
        if supported_interval.upper is not None:
            return False
    elif supported_interval.upper is not None and (
        supported_interval.upper.value < required_interval.upper.value
        or supported_interval.upper.value == required_interval.upper.value
        and required_interval.upper.inclusive
        and not supported_interval.upper.inclusive
    ):
        return False
    return True


def decode_root_keys(value: Mapping[str, bytes]) -> dict[str, bytes]:
    """Defensively copy a configured root-key mapping."""

    if not value or any(
        not isinstance(key, str) or not key or not isinstance(material, bytes) or len(material) != 32
        for key, material in value.items()
    ):
        raise ContractError("service root keys are invalid")
    return dict(value)
