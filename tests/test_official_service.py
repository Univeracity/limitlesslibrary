from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from limitless_library.contracts import canonical_json_bytes, load_json, sha256_json
from limitless_library.official_service import (
    OfficialServiceActivationError,
    OfficialServiceNotConfiguredError,
    OfficialServiceUnavailableError,
    activate_service_from_locator,
    activation_details,
    default_activation_state_path,
    load_bundled_official_locator,
)
from limitless_library.service_connector import ServiceHttpResponse, ServiceUnavailableError

AT = datetime(2026, 8, 20, 22, 0, 30, tzinfo=UTC)
CORPUS = Path(
    str(
        files("limitless_library.conformance").joinpath(
            "public-service-lifecycle-1.0.json"
        )
    )
)
OFFICIAL_CORPUS = Path(
    str(
        files("limitless_library.conformance").joinpath(
            "official-service-activation-1.0.json"
        )
    )
)


def _records() -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    corpus = load_json(CORPUS)
    discovery = corpus["discovery"]
    root = corpus["rootPublicKey"]
    profile = {
        "schemaVersion": "limitless.service-profile/1.1",
        "apiBaseUrl": discovery["apiBaseUrl"],
        "serviceId": discovery["serviceId"],
        "rootKey": root,
        "acceptedPolicyDigest": discovery["dataUsePolicy"]["digest"],
        "executionMode": "service",
        "defaultAudience": "private",
        "historyMode": "local-only",
        "requestedAudiences": ["public"],
    }
    profile_url = "https://profiles.example/releases/official-fixture-1.json"
    locator = {
        "schemaVersion": "limitless.official-service-locator/1.0",
        "profileUrl": profile_url,
        "profileDigest": sha256_json(profile),
        "serviceId": discovery["serviceId"],
        "rootKey": root,
    }
    transitions = {
        "schemaVersion": "limitless.service-root-key-transition-set/1.0",
        "serviceId": discovery["serviceId"],
        "transitions": [],
        "latestSequence": 0,
        "latestTransitionDigest": None,
    }
    resources = {
        profile_url: profile,
        discovery["apiBaseUrl"] + "/.well-known/limitless-root-transitions": transitions,
        discovery["apiBaseUrl"] + "/.well-known/limitless-service": discovery,
    }
    return locator, profile, resources


def _official_resources(corpus: dict[str, Any]) -> dict[str, dict[str, Any]]:
    api = corpus["profile"]["apiBaseUrl"]
    return {
        corpus["locator"]["profileUrl"]: corpus["profile"],
        api + "/.well-known/limitless-root-transitions": corpus["rootTransitions"],
        api + "/.well-known/limitless-service": corpus["discovery"],
    }


def _replace(value: dict[str, Any], path: list[str], replacement: Any) -> None:
    cursor = value
    for segment in path[:-1]:
        cursor = cursor[segment]
    cursor[path[-1]] = replacement


class MemoryTransport:
    def __init__(self, resources: dict[str, dict[str, Any]]) -> None:
        self.resources = resources
        self.calls: list[str] = []
        self.status = 200
        self.raise_unavailable = False

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse:
        assert method == "GET"
        assert body is None
        assert timeout_seconds > 0
        self.calls.append(url)
        if self.raise_unavailable:
            raise ServiceUnavailableError("network unavailable")
        if self.status != 200:
            return ServiceHttpResponse(
                status=self.status,
                headers={"content-type": "application/json"},
                body=b"{}",
            )
        encoded = canonical_json_bytes(self.resources[url])
        assert len(encoded) <= maximum_bytes
        return ServiceHttpResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=encoded,
        )


def test_one_action_verifies_authority_and_persists_credential_free_state(
    tmp_path: Path,
) -> None:
    locator, profile, resources = _records()
    transport = MemoryTransport(resources)
    state_path = tmp_path / "official-service.json"

    state = activate_service_from_locator(
        locator,
        state_path=state_path,
        at=AT,
        transport=transport,
    )

    assert state["profile"] == profile
    assert transport.calls == [
        locator["profileUrl"],
        profile["apiBaseUrl"] + "/.well-known/limitless-root-transitions",
        profile["apiBaseUrl"] + "/.well-known/limitless-service",
    ]
    assert activation_details(state_path)["defaultAudience"] == "private"
    assert activation_details(state_path)["historyMode"] == "local-only"
    assert "token" not in state_path.read_text(encoding="utf-8").lower()

    previous_calls = list(transport.calls)
    assert (
        activate_service_from_locator(
            locator,
            state_path=state_path,
            at=AT,
            transport=transport,
        )
        == state
    )
    assert transport.calls == previous_calls


def test_private_and_public_implementations_share_the_exact_activation_corpus(
    tmp_path: Path,
) -> None:
    corpus = load_json(OFFICIAL_CORPUS)
    digest = corpus.pop("corpusDigest")
    assert digest == sha256_json(corpus)
    corpus["corpusDigest"] = digest
    at = datetime.fromisoformat(corpus["expected"]["validAt"])

    state = activate_service_from_locator(
        corpus["locator"],
        state_path=tmp_path / "official-corpus.json",
        at=at,
        transport=MemoryTransport(_official_resources(corpus)),
    )

    assert state["profile"] == corpus["profile"]
    details = activation_details(tmp_path / "official-corpus.json")
    for field in (
        "executionMode",
        "defaultAudience",
        "historyMode",
        "requestedAudiences",
    ):
        assert details[field] == corpus["expected"][field]

    for index, case in enumerate(corpus["invalidCases"]):
        changed = deepcopy(corpus)
        _replace(changed[case["target"]], case["path"], case["replacement"])
        with pytest.raises(OfficialServiceActivationError):
            activate_service_from_locator(
                changed["locator"],
                state_path=tmp_path / f"invalid-{index}.json",
                at=at,
                transport=MemoryTransport(_official_resources(changed)),
            )


def test_substituted_profile_and_authority_fail_closed(tmp_path: Path) -> None:
    locator, _profile, resources = _records()
    substituted = deepcopy(resources)
    substituted[locator["profileUrl"]]["defaultAudience"] = "public"
    with pytest.raises(OfficialServiceActivationError, match="bundled trust"):
        activate_service_from_locator(
            locator,
            state_path=tmp_path / "substituted.json",
            at=AT,
            transport=MemoryTransport(substituted),
        )

    drifted = deepcopy(resources)
    discovery_url = (
        resources[locator["profileUrl"]]["apiBaseUrl"]
        + "/.well-known/limitless-service"
    )
    drifted[discovery_url]["dataUsePolicy"]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(OfficialServiceActivationError, match="authority verification"):
        activate_service_from_locator(
            locator,
            state_path=tmp_path / "drifted.json",
            at=AT,
            transport=MemoryTransport(drifted),
        )


def test_unavailability_preserves_local_default(tmp_path: Path) -> None:
    locator, _profile, resources = _records()
    transport = MemoryTransport(resources)
    transport.status = 503
    state_path = tmp_path / "official-service.json"

    with pytest.raises(OfficialServiceUnavailableError, match="continue locally"):
        activate_service_from_locator(
            locator,
            state_path=state_path,
            at=AT,
            transport=transport,
        )

    assert not state_path.exists()
    assert activation_details(state_path)["executionMode"] == "local"

    transport.status = 200
    transport.raise_unavailable = True
    with pytest.raises(OfficialServiceUnavailableError, match="continue locally"):
        activate_service_from_locator(
            locator,
            state_path=state_path,
            at=AT,
            transport=transport,
        )


def test_unconfigured_source_build_does_not_invent_official_identity() -> None:
    with pytest.raises(OfficialServiceNotConfiguredError, match="continue locally"):
        load_bundled_official_locator()


def test_default_state_path_is_per_user_and_requires_absolute_configuration() -> None:
    assert default_activation_state_path(
        environ={"XDG_CONFIG_HOME": "/tmp/limitless-config"}
    ) == Path("/tmp/limitless-config/limitless-library/official-service.json")
    with pytest.raises(OfficialServiceActivationError, match="invalid"):
        default_activation_state_path(environ={"XDG_CONFIG_HOME": "relative"})
