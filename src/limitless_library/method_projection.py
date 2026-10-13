"""Shared projection of source-free methods into the local query contract."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .catalog import seal_capsule
from .service_contracts import validate_source_free_method


def local_method(method: dict[str, Any]) -> dict[str, Any]:
    """Keep legacy local methods intact; retain every canonical check and limit."""
    if set(method) == {"summary", "steps", "verification"}:
        return copy.deepcopy(method)
    checked = validate_source_free_method(method)
    return {
        "summary": checked["summary"],
        "steps": [f"{step['instruction']}\nCheck ({step['check']}): {step['expected']}" for step in checked["steps"]],
        "verification": (
            [f"Applicability: {constraint}" for constraint in checked["constraints"]]
            + list(checked["evaluation"])
            + [f"Limitation: {limitation}" for limitation in checked["limitations"]]
        ),
    }


def project_method_capsule(
    *,
    capsule_id: str,
    offer_id: str,
    version: str,
    title: str,
    task_kind: str,
    method: dict[str, Any],
    compatibility: dict[str, Any],
    priority: int = 500,
) -> dict[str, Any]:
    """Create a private-only, non-executable projection, not a publication grant."""
    return seal_capsule(
        {
            "schemaVersion": "limitless.capsule/0.1",
            "id": capsule_id,
            "version": version,
            "title": title,
            "license": "LicenseRef-Limitless-Source-Free-Method",
            "offers": [
                {
                    "id": offer_id,
                    "kind": "method",
                    "priority": priority,
                    "taskKind": task_kind,
                    "compatibility": copy.deepcopy(compatibility),
                    "policy": {"allowedUses": ["adopt", "instantiate"], "tenantScopes": ["private"], "state": "active"},
                    "files": None,
                    "method": local_method(method),
                }
            ],
        },
        Path("."),
    )
