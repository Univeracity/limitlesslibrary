"""Bundled JSON Schema access."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError


class SchemaError(ValueError):
    """A public protocol record does not satisfy its schema."""


def load_schema(name: str) -> dict[str, Any]:
    resource = files(__package__).joinpath(name)
    return json.loads(resource.read_text(encoding="utf-8"))


def validate(value: dict[str, Any], name: str, label: str) -> None:
    try:
        Draft202012Validator(load_schema(name), format_checker=FormatChecker()).validate(value)
    except ValidationError as error:
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise SchemaError(f"{label} is invalid at {location}: {error.message}") from error
