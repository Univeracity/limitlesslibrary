"""Deterministically redact named fields from structured audit events.

This intentionally narrow component protects fields by name. It is not a
general secret scanner and does not attempt to find secrets embedded in free
text.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TypeAlias

JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]

DEFAULT_SENSITIVE_FIELDS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "password",
        "refresh_token",
        "secret",
        "token",
    }
)
REDACTED = "[REDACTED]"


def redact_event(
    event: Mapping[str, JsonValue],
    *,
    sensitive_fields: Iterable[str] = DEFAULT_SENSITIVE_FIELDS,
) -> dict[str, JsonValue]:
    """Return a redacted copy of a JSON-like event without mutating input."""

    if not isinstance(event, Mapping):
        raise TypeError("event must be a mapping")
    normalized_fields = frozenset(field.casefold() for field in sensitive_fields)

    def redact(value: JsonValue) -> JsonValue:
        if isinstance(value, Mapping):
            output: dict[str, JsonValue] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("event keys must be strings")
                output[key] = REDACTED if key.casefold() in normalized_fields else redact(item)
            return output
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return redact(event)
