"""Role-separated receiver environments and minimal service projection.

The process running an agent may differ from the environment where files are
edited, the target where work must operate, and the receiver capable of
observing success. This local contract keeps those roles and their provenance
intact. Its service projection deliberately excludes work-environment,
observation, attribute, and verification-receiver details.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .contracts import ContractError, parse_utc, sha256_json
from .service_contracts import PublicServiceContractError, validate_service_receiver_context

RECEIVER_ENVIRONMENT_SCHEMA_VERSION = "limitless.receiver-environment-profile/1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,199}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_INTERFACE = re.compile(r"^[A-Za-z][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_KINDS = {"compute", "physical-device", "human-observer"}
_SOURCES = {
    "host-detected",
    "user-declared",
    "remote-observed",
    "receiver-observed",
    "physical-witness",
}


class ReceiverEnvironmentError(ValueError):
    """A receiver environment profile is ambiguous, incomplete, or unsafe."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ReceiverEnvironmentError(f"{label} has unsupported or missing fields")
    return value


def _text(value: Any, label: str, *, maximum: int, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReceiverEnvironmentError(f"{label} must be a bounded non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ReceiverEnvironmentError(f"{label} has an invalid format")
    return value


def _optional_token(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label, maximum=64, pattern=_TOKEN)


def _timestamp(value: Any, label: str) -> str:
    selected = _text(value, label, maximum=40)
    try:
        parse_utc(selected, label)
    except ContractError as error:
        raise ReceiverEnvironmentError(f"{label} is invalid") from error
    return selected


def _sorted_texts(
    value: Any,
    label: str,
    *,
    maximum_items: int,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items or (not allow_empty and not value):
        raise ReceiverEnvironmentError(f"{label} must be a bounded list")
    checked = [_text(item, label, maximum=128, pattern=pattern) for item in value]
    if checked != sorted(set(checked)):
        raise ReceiverEnvironmentError(f"{label} must be sorted and unique")
    return checked


def validate_receiver_environment_profile(value: Any) -> dict[str, Any]:
    """Return one canonical role-separated profile or fail closed."""

    profile = _exact(value, {"schemaVersion", "environments", "bindings"}, "receiver environment profile")
    if profile["schemaVersion"] != RECEIVER_ENVIRONMENT_SCHEMA_VERSION:
        raise ReceiverEnvironmentError("receiver environment profile schemaVersion is unsupported")
    environments = profile["environments"]
    if not isinstance(environments, list) or not 1 <= len(environments) <= 16:
        raise ReceiverEnvironmentError("receiver environments must contain one through sixteen entries")
    checked_environments: list[dict[str, Any]] = []
    for item in environments:
        environment = _exact(item, {"id", "kind", "facts", "observation"}, "receiver environment")
        identifier = _text(environment["id"], "receiver environment id", maximum=200, pattern=_IDENTIFIER)
        kind = environment["kind"]
        if kind not in _KINDS:
            raise ReceiverEnvironmentError("receiver environment kind is unsupported")
        facts = _exact(
            environment["facts"],
            {"platform", "architecture", "runtime", "version", "versionRange", "interfaces", "attributes"},
            "receiver environment facts",
        )
        version = facts["version"]
        if version is not None:
            version = _text(version, "receiver environment version", maximum=80)
        version_range = facts["versionRange"]
        if version_range is not None:
            version_range = _text(version_range, "receiver environment versionRange", maximum=120)
        interfaces = _sorted_texts(
            facts["interfaces"],
            "receiver environment interfaces",
            maximum_items=32,
            pattern=_INTERFACE,
            allow_empty=True,
        )
        attributes = facts["attributes"]
        if not isinstance(attributes, list) or len(attributes) > 64:
            raise ReceiverEnvironmentError("receiver environment attributes must be a bounded list")
        checked_attributes: list[dict[str, str]] = []
        for attribute_value in attributes:
            attribute = _exact(attribute_value, {"name", "value"}, "receiver environment attribute")
            checked_attributes.append(
                {
                    "name": _text(
                        attribute["name"],
                        "receiver environment attribute name",
                        maximum=128,
                        pattern=_INTERFACE,
                    ),
                    "value": _text(attribute["value"], "receiver environment attribute value", maximum=256),
                }
            )
        if checked_attributes != sorted(checked_attributes, key=lambda entry: entry["name"]) or len(
            {entry["name"] for entry in checked_attributes}
        ) != len(checked_attributes):
            raise ReceiverEnvironmentError("receiver environment attributes must be sorted by unique name")
        observation = _exact(
            environment["observation"],
            {"source", "authority", "observedAt", "evidenceDigest"},
            "receiver environment observation",
        )
        source = observation["source"]
        if source not in _SOURCES:
            raise ReceiverEnvironmentError("receiver environment observation source is unsupported")
        checked_environments.append(
            {
                "id": identifier,
                "kind": kind,
                "facts": {
                    "platform": _optional_token(facts["platform"], "receiver environment platform"),
                    "architecture": _optional_token(facts["architecture"], "receiver environment architecture"),
                    "runtime": _optional_token(facts["runtime"], "receiver environment runtime"),
                    "version": version,
                    "versionRange": version_range,
                    "interfaces": interfaces,
                    "attributes": checked_attributes,
                },
                "observation": {
                    "source": source,
                    "authority": _text(
                        observation["authority"],
                        "receiver environment observation authority",
                        maximum=200,
                        pattern=_IDENTIFIER,
                    ),
                    "observedAt": _timestamp(observation["observedAt"], "receiver environment observedAt"),
                    "evidenceDigest": _text(
                        observation["evidenceDigest"],
                        "receiver environment evidenceDigest",
                        maximum=71,
                        pattern=_DIGEST,
                    ),
                },
            }
        )
    if checked_environments != sorted(checked_environments, key=lambda entry: entry["id"]) or len(
        {entry["id"] for entry in checked_environments}
    ) != len(checked_environments):
        raise ReceiverEnvironmentError("receiver environments must be sorted by unique id")

    bindings = _exact(
        profile["bindings"],
        {"agentHost", "workEnvironment", "targetEnvironments", "verificationReceivers"},
        "receiver environment bindings",
    )
    agent_host = _text(bindings["agentHost"], "agentHost binding", maximum=200, pattern=_IDENTIFIER)
    work_environment = _text(
        bindings["workEnvironment"], "workEnvironment binding", maximum=200, pattern=_IDENTIFIER
    )
    target_environments = _sorted_texts(
        bindings["targetEnvironments"], "targetEnvironments bindings", maximum_items=8, pattern=_IDENTIFIER
    )
    verification_receivers = _sorted_texts(
        bindings["verificationReceivers"], "verificationReceivers bindings", maximum_items=8, pattern=_IDENTIFIER
    )
    by_id: dict[str, dict[str, Any]] = {item["id"]: item for item in checked_environments}
    referenced = {agent_host, work_environment, *target_environments, *verification_receivers}
    unknown = referenced - set(by_id)
    if unknown:
        raise ReceiverEnvironmentError(f"receiver environment bindings name unknown ids: {', '.join(sorted(unknown))}")
    if by_id[agent_host]["kind"] != "compute":
        raise ReceiverEnvironmentError("agentHost must bind a compute environment")
    agent_facts = by_id[agent_host]["facts"]
    if any(agent_facts[field] is None for field in ("platform", "architecture", "runtime", "version")):
        raise ReceiverEnvironmentError("agentHost requires complete execution facts")
    if by_id[work_environment]["kind"] not in {"compute", "physical-device"}:
        raise ReceiverEnvironmentError("workEnvironment must bind a compute or physical-device environment")
    for target_id in target_environments:
        target = by_id[target_id]
        if target["kind"] not in {"compute", "physical-device"}:
            raise ReceiverEnvironmentError("targetEnvironments must bind compute or physical-device environments")
        target_facts = target["facts"]
        if any(
            target_facts[field] is None for field in ("platform", "architecture", "runtime", "versionRange")
        ) or not target_facts["interfaces"]:
            raise ReceiverEnvironmentError("each targetEnvironment requires complete compatibility facts")
    return {
        "schemaVersion": RECEIVER_ENVIRONMENT_SCHEMA_VERSION,
        "environments": checked_environments,
        "bindings": {
            "agentHost": agent_host,
            "workEnvironment": work_environment,
            "targetEnvironments": target_environments,
            "verificationReceivers": verification_receivers,
        },
    }


def receiver_environment_digest(value: Any) -> str:
    """Digest the canonical validated role-separated profile."""

    return sha256_json(validate_receiver_environment_profile(value))


def _target_id(environment_id: str) -> str:
    suffix = environment_id.split(":", 1)[1] if ":" in environment_id else environment_id
    return f"target:{suffix}"


def project_service_receiver_context(
    value: Any,
    *,
    receiver_id: str,
    allowed_use: str,
    compatibility_mode: str = "one-target",
    selected_target: str | None = None,
    required_interfaces: Iterable[str] = (),
) -> dict[str, Any]:
    """Project only agent-host execution and target compatibility to the service.

    The richer local profile remains authoritative. Work locations, fact
    provenance, target attributes, and verification receivers never enter the
    returned service record.
    """

    profile = validate_receiver_environment_profile(value)
    by_id = {item["id"]: item for item in profile["environments"]}
    target_environment_ids = profile["bindings"]["targetEnvironments"]
    if compatibility_mode not in {"all-targets", "one-target"}:
        raise ReceiverEnvironmentError("compatibilityMode is unsupported")
    if compatibility_mode == "one-target":
        if selected_target is None:
            if len(target_environment_ids) != 1:
                raise ReceiverEnvironmentError("multiple targets require an explicit selectedTarget")
            selected_target = target_environment_ids[0]
        if selected_target not in target_environment_ids:
            raise ReceiverEnvironmentError("selectedTarget is not an authorized target binding")
    elif selected_target is not None:
        raise ReceiverEnvironmentError("all-targets compatibility cannot select one target")

    raw_interfaces = list(required_interfaces)
    if any(not isinstance(item, str) or _INTERFACE.fullmatch(item) is None for item in raw_interfaces):
        raise ReceiverEnvironmentError("required receiver interfaces are invalid")
    requested_interfaces = sorted(set(raw_interfaces))
    applicable_ids = target_environment_ids if compatibility_mode == "all-targets" else [selected_target]
    available_sets = [set(by_id[target_id]["facts"]["interfaces"]) for target_id in applicable_ids]
    common_interfaces = sorted(set.intersection(*available_sets))
    interfaces = requested_interfaces or common_interfaces
    if not interfaces or any(not set(interfaces).issubset(available) for available in available_sets):
        raise ReceiverEnvironmentError("applicable targets do not share every required receiver interface")

    projected_targets: list[dict[str, Any]] = []
    target_id_map: dict[str, str] = {}
    for environment_id in target_environment_ids:
        target = by_id[environment_id]
        service_id = _target_id(environment_id)
        target_id_map[environment_id] = service_id
        projected_targets.append(
            {
                "id": service_id,
                "platform": target["facts"]["platform"],
                "architecture": target["facts"]["architecture"],
                "runtime": target["facts"]["runtime"],
                "versionRange": target["facts"]["versionRange"],
                "interfaces": target["facts"]["interfaces"],
            }
        )
    projected_targets.sort(key=lambda item: item["id"])
    if len({item["id"] for item in projected_targets}) != len(projected_targets):
        raise ReceiverEnvironmentError("receiver environment ids collide after service projection")
    host = by_id[profile["bindings"]["agentHost"]]["facts"]
    context = {
        "receiverId": receiver_id,
        "allowedUse": allowed_use,
        "interfaces": interfaces,
        "execution": {
            "platform": host["platform"],
            "architecture": host["architecture"],
            "runtime": host["runtime"],
            "version": host["version"],
        },
        "targets": projected_targets,
        "compatibilityMode": compatibility_mode,
        "selectedTarget": target_id_map[selected_target] if selected_target is not None else None,
    }
    try:
        return validate_service_receiver_context(context)
    except PublicServiceContractError as error:
        raise ReceiverEnvironmentError(f"service receiver projection is invalid: {error}") from error
