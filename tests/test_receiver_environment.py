from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest

from limitless_library.contracts import load_json
from limitless_library.receiver_environment import (
    ReceiverEnvironmentError,
    project_service_receiver_context,
    receiver_environment_digest,
    validate_receiver_environment_profile,
)
from limitless_library.receiver_evidence import (
    ReceiverEvidenceError,
    build_receiver_evidence,
    validate_receiver_evidence,
)
from limitless_library.schemas import validate as validate_schema
from limitless_library.service_contracts import build_service_query

NOW = datetime(2026, 9, 4, 15, 0, tzinfo=UTC)
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
TWO = "sha256:" + "2" * 64
ROOT = Path(__file__).parents[1]


def _profile() -> dict:
    return {
        "schemaVersion": "limitless.receiver-environment-profile/1.0",
        "environments": [
            {
                "id": "environment:agent-host",
                "kind": "compute",
                "facts": {
                    "platform": "linux", "architecture": "x86_64", "runtime": "python",
                    "version": "3.13.7", "versionRange": ">=3.11,<3.14", "interfaces": ["mcp/v1"],
                    "attributes": [],
                },
                "observation": {
                    "source": "host-detected", "authority": "host:agent",
                    "observedAt": "2026-09-04T14:55:00Z", "evidenceDigest": ZERO,
                },
            },
            {
                "id": "environment:listener",
                "kind": "human-observer",
                "facts": {
                    "platform": None, "architecture": None, "runtime": None, "version": None, "versionRange": None,
                    "interfaces": [],
                    "attributes": [{"name": "observation.mode", "value": "physical-audible-witness"}],
                },
                "observation": {
                    "source": "user-declared", "authority": "user:owner",
                    "observedAt": "2026-09-04T14:56:00Z", "evidenceDigest": ONE,
                },
            },
            {
                "id": "environment:macbook10.1",
                "kind": "physical-device",
                "facts": {
                    "platform": "linux", "architecture": "x86_64", "runtime": "linux-kernel",
                    "version": "7.1.9", "versionRange": ">=7.1,<7.2",
                    "interfaces": ["alsa.hda/v1", "hardware-audio/v1"],
                    "attributes": [
                        {"name": "hardware.codec", "value": "CS4208"},
                        {"name": "hardware.model", "value": "MacBook10,1"},
                    ],
                },
                "observation": {
                    "source": "remote-observed", "authority": "receiver:macbook10.1",
                    "observedAt": "2026-09-04T14:57:00Z", "evidenceDigest": TWO,
                },
            },
        ],
        "bindings": {
            "agentHost": "environment:agent-host",
            "workEnvironment": "environment:macbook10.1",
            "targetEnvironments": ["environment:macbook10.1"],
            "verificationReceivers": ["environment:listener", "environment:macbook10.1"],
        },
    }


def _checks() -> list[dict]:
    return [
        {
            "id": "check:alsa-stack", "kind": "receiver-observation",
            "environmentId": "environment:macbook10.1", "status": "passed",
            "reasonCode": "pcm-control-mapped", "observedAt": "2026-09-04T15:01:00Z",
            "evidenceDigest": ZERO,
        },
        {
            "id": "check:audible-output", "kind": "human-witness",
            "environmentId": "environment:listener", "status": "passed",
            "reasonCode": "stepped-tones-heard", "observedAt": "2026-09-04T15:02:00Z",
            "evidenceDigest": ONE,
        },
    ]


def test_profile_projects_only_bounded_service_facts() -> None:
    profile = validate_receiver_environment_profile(_profile())
    context = project_service_receiver_context(
        profile,
        receiver_id="receiver:macbook-audio",
        allowed_use="repair-hardware-audio",
        required_interfaces=["alsa.hda/v1"],
    )
    assert context == {
        "receiverId": "receiver:macbook-audio",
        "allowedUse": "repair-hardware-audio",
        "interfaces": ["alsa.hda/v1"],
        "execution": {"platform": "linux", "architecture": "x86_64", "runtime": "python", "version": "3.13.7"},
        "targets": [{
            "id": "target:macbook10.1", "platform": "linux", "architecture": "x86_64",
            "runtime": "linux-kernel", "versionRange": ">=7.1,<7.2",
            "interfaces": ["alsa.hda/v1", "hardware-audio/v1"],
        }],
        "compatibilityMode": "one-target",
        "selectedTarget": "target:macbook10.1",
    }
    query = build_service_query(
        request_id="request:remote-hardware-001",
        objective="Restore reliable audio on the intended receiver.",
        receiver_context=context,
        requested_audiences=["public"],
        requested_treatments=["source-free-method"],
        execution_mode="service",
        history_mode="local-only",
        client_name="limitless-library",
        client_version="0.1.0a0",
        issued_at=NOW,
    )
    serialized = repr(query["receiverContext"])
    assert "hardware.model" not in serialized
    assert "physical-audible-witness" not in serialized
    assert "environment:listener" not in serialized
    assert receiver_environment_digest(profile).startswith("sha256:")


def test_multiple_targets_require_selection_or_shared_all_target_interface() -> None:
    profile = _profile()
    second = deepcopy(profile["environments"][2])
    second["id"] = "environment:second-target"
    second["facts"]["platform"] = "windows"
    profile["environments"].append(second)
    profile["bindings"]["targetEnvironments"] = ["environment:macbook10.1", "environment:second-target"]
    with pytest.raises(ReceiverEnvironmentError, match="explicit selectedTarget"):
        project_service_receiver_context(profile, receiver_id="receiver:multi", allowed_use="repair-hardware-audio")
    context = project_service_receiver_context(
        profile,
        receiver_id="receiver:multi",
        allowed_use="repair-hardware-audio",
        compatibility_mode="all-targets",
        required_interfaces=["hardware-audio/v1"],
    )
    assert context["selectedTarget"] is None
    assert [target["id"] for target in context["targets"]] == ["target:macbook10.1", "target:second-target"]


def test_profile_and_composite_evidence_match_bundled_schemas() -> None:
    profile = validate_receiver_environment_profile(_profile())
    validate_schema(profile, "receiver-environment-profile-1.0.schema.json", "receiver environment profile")
    receipt = build_receiver_evidence(
        profile=profile,
        decision_ref="decision:hardware-audio-001",
        checks=_checks(),
        required_check_ids=["check:alsa-stack", "check:audible-output"],
        recorded_at=NOW,
    )
    assert receipt["outcome"] == "verified"
    assert validate_receiver_evidence(receipt, profile=profile) == receipt
    validate_schema(receipt, "receiver-evidence-1.0.schema.json", "receiver evidence")


def test_counterevidence_and_missing_physical_observation_fail_honestly() -> None:
    failed = _checks()
    failed[0]["status"] = "failed"
    failed[0]["reasonCode"] = "stale-driver"
    receipt = build_receiver_evidence(
        profile=_profile(), decision_ref="decision:hardware-audio-001", checks=failed,
        required_check_ids=["check:alsa-stack", "check:audible-output"], recorded_at=NOW,
    )
    assert receipt["outcome"] == "failed"
    receipt["outcome"] = "verified"
    with pytest.raises(ReceiverEvidenceError, match="overclaims"):
        validate_receiver_evidence(receipt, profile=_profile())

    blocked = _checks()
    blocked[1]["status"] = "blocked"
    blocked[1]["reasonCode"] = "physical-witness-unavailable"
    receipt = build_receiver_evidence(
        profile=_profile(), decision_ref="decision:hardware-audio-001", checks=blocked,
        required_check_ids=["check:alsa-stack", "check:audible-output"], recorded_at=NOW,
    )
    assert receipt["outcome"] == "blocked"


def test_every_check_requires_an_explicit_verification_receiver() -> None:
    profile = _profile()
    profile["bindings"]["verificationReceivers"] = ["environment:listener"]
    with pytest.raises(ReceiverEvidenceError, match="verificationReceiver"):
        build_receiver_evidence(
            profile=profile,
            decision_ref="decision:hardware-audio-001",
            checks=_checks(),
            required_check_ids=["check:alsa-stack", "check:audible-output"],
            recorded_at=NOW,
        )


def test_bundled_cross_environment_example_is_valid_and_projectable() -> None:
    profile = load_json(ROOT / "examples" / "receiver" / "environment-profile.json")
    validate_schema(profile, "receiver-environment-profile-1.0.schema.json", "receiver environment profile")
    context = project_service_receiver_context(
        profile,
        receiver_id="receiver:windows-application",
        allowed_use="develop-application",
    )
    assert context["execution"]["platform"] == "linux"
    assert context["targets"][0]["platform"] == "windows"
