from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from limitless_library.contracts import (
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_json,
    strict_json_loads,
)
from limitless_library.installation_identity_contracts import (
    build_installation_attestation,
    installation_id,
    validate_installation_registration_request,
    validate_installation_session_request,
)
from limitless_library.official_service import (
    OfficialServiceActivationError,
    OfficialServiceUnavailableError,
    activate_service_from_locator,
    activation_details,
    default_activation_state_path,
    load_bundled_official_locator,
)
from limitless_library.service_connector import ServiceHttpResponse, ServiceUnavailableError
from limitless_library.service_contracts import (
    build_official_service_locator,
    build_service_discovery,
    build_service_profile,
)
from limitless_library.service_identity import (
    InstallationSigner,
    installation_publisher_authority,
)

AT = datetime(2026, 8, 20, 22, 0, 30, tzinfo=UTC)
CORPUS = Path(str(files("limitless_library.conformance").joinpath("public-service-lifecycle-1.1.json")))
OFFICIAL_CORPUS = Path(str(files("limitless_library.conformance").joinpath("official-service-activation-1.0.json")))


def _records() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, dict[str, Any]],
    InstallationSigner,
]:
    root_signer = InstallationSigner.generate()
    service_signer = InstallationSigner.generate()
    service_id = "service:limitless-activation-test"
    api_base_url = "https://api.activation.example"
    policy_digest = "sha256:" + "a" * 64
    discovery = build_service_discovery(
        service_id=service_id,
        api_base_url=api_base_url,
        signing_keys=[
            (
                service_signer.key_id,
                service_signer.public_bytes(),
                AT - timedelta(days=1),
                AT + timedelta(days=30),
            )
        ],
        data_use_policy_url="https://activation.example/data-use",
        data_use_policy_digest=policy_digest,
        publication_policy_revision="policy:activation-publication",
        publication_policy_url="https://activation.example/publication-policy",
        publication_policy_digest=policy_digest,
        rate_limit_class="public-test",
        issued_at=AT - timedelta(seconds=30),
        root_signer=root_signer,
    )
    profile = build_service_profile(
        api_base_url=api_base_url,
        service_id=service_id,
        root_key_id=root_signer.key_id,
        root_public_key=root_signer.public_bytes(),
        accepted_policy_digest=policy_digest,
        execution_mode="service",
        default_audience="private",
        history_mode="local-only",
        requested_audiences=("public",),
    )
    profile_url = "https://profiles.example/releases/official-fixture-1.json"
    locator = build_official_service_locator(profile_url=profile_url, profile=profile)
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
    return locator, profile, resources, service_signer


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
    def __init__(
        self,
        resources: dict[str, dict[str, Any]],
        *,
        service_signer: InstallationSigner | None = None,
    ) -> None:
        self.resources = resources
        self.calls: list[str] = []
        self.status = 200
        self.raise_unavailable = False
        self.unavailable_suffix: str | None = None
        self.service_signer = service_signer
        self.installation_keys: dict[str, bytes] = {}

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
        assert timeout_seconds > 0
        self.calls.append(url)
        if self.raise_unavailable or (self.unavailable_suffix is not None and url.endswith(self.unavailable_suffix)):
            raise ServiceUnavailableError("network unavailable")
        if self.status != 200:
            return ServiceHttpResponse(
                status=self.status,
                headers={"content-type": "application/json"},
                body=b"{}",
            )
        if method == "GET":
            assert body is None
            value = self.resources[url]
        elif method == "POST" and url.endswith("/v1/installations"):
            assert body is not None and self.service_signer is not None
            request = validate_installation_registration_request(strict_json_loads(body.decode("utf-8")), at=AT)
            public_key = urlsafe_b64decode(request["publicKey"]["value"] + "=")
            identifier = installation_id(request["serviceId"], public_key)
            self.installation_keys[identifier] = public_key
            value = build_installation_attestation(
                service_id=request["serviceId"],
                installation_id_value=identifier,
                current_public_key=public_key,
                generation=1,
                account_id=None,
                status="active",
                issued_at=AT,
                signer=self.service_signer,
            )
        elif method == "POST" and url.endswith("/v1/installations/sessions"):
            assert body is not None
            raw = strict_json_loads(body.decode("utf-8"))
            public_key = self.installation_keys[raw["installationId"]]
            request = validate_installation_session_request(raw, current_public_key=public_key, at=AT)
            token = "lst_" + urlsafe_b64encode(b"S" * 32).rstrip(b"=").decode("ascii")
            value = {
                "schemaVersion": "limitless.installation-session-response/1.0",
                "accessToken": token,
                "tokenType": "Bearer",
                "sessionId": "installation-session:" + sha256_bytes(token.encode("ascii"))[7:39],
                "installationId": request["installationId"],
                "tenantId": "installation-space:" + request["installationId"].removeprefix("installation:"),
                "acceptedPolicyDigest": request["acceptedPolicyDigest"],
                "capabilities": request["capabilities"],
                "issuedAt": AT.isoformat().replace("+00:00", "Z"),
                "expiresAt": (AT + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
            }
        else:
            raise AssertionError(f"unexpected transport call: {method} {url}")
        encoded = canonical_json_bytes(value)
        assert len(encoded) <= maximum_bytes
        return ServiceHttpResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=encoded,
        )


def test_one_action_verifies_authority_and_persists_credential_free_state(
    tmp_path: Path,
) -> None:
    locator, profile, resources, service_signer = _records()
    transport = MemoryTransport(resources, service_signer=service_signer)
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
        profile["apiBaseUrl"] + "/v1/installations",
        profile["apiBaseUrl"] + "/v1/installations/sessions",
    ]
    assert activation_details(state_path)["defaultAudience"] == "private"
    assert activation_details(state_path)["historyMode"] == "local-only"
    assert "token" not in state_path.read_text(encoding="utf-8").lower()
    identity_path = tmp_path / "official-service-identity.json"
    assert identity_path.exists()
    assert identity_path.stat().st_mode & 0o777 == 0o600
    assert "accessToken" in identity_path.read_text(encoding="utf-8")
    publisher_signer, publisher = installation_publisher_authority(
        service_id=profile["serviceId"],
        path=identity_path,
    )
    publisher_id = next(iter(transport.installation_keys))
    assert publisher == {
        "schemaVersion": "limitless.installation-publisher-authority/1.0",
        "serviceId": profile["serviceId"],
        "publisherId": publisher_id,
        "authorityId": "installation-space:" + publisher_id.removeprefix("installation:"),
        "keyId": publisher_signer.key_id,
        "generation": 1,
    }

    previous_count = len(transport.calls)
    assert (
        activate_service_from_locator(
            locator,
            state_path=state_path,
            at=AT,
            transport=transport,
        )
        == state
    )
    assert transport.calls[previous_count:] == [
        locator["profileUrl"],
        profile["apiBaseUrl"] + "/.well-known/limitless-root-transitions",
        profile["apiBaseUrl"] + "/.well-known/limitless-service",
    ]


def test_private_and_public_implementations_share_the_exact_activation_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus = load_json(OFFICIAL_CORPUS)
    digest = corpus.pop("corpusDigest")
    assert digest == sha256_json(corpus)
    corpus["corpusDigest"] = digest
    at = datetime.fromisoformat(corpus["expected"]["validAt"])
    monkeypatch.setattr(
        "limitless_library.official_service.ensure_installation_session",
        lambda connector, **_kwargs: (connector, {}),
    )

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
    locator, _profile, resources, service_signer = _records()
    substituted = deepcopy(resources)
    substituted[locator["profileUrl"]]["defaultAudience"] = "public"
    with pytest.raises(OfficialServiceActivationError, match="bundled trust"):
        activate_service_from_locator(
            locator,
            state_path=tmp_path / "substituted.json",
            at=AT,
            transport=MemoryTransport(substituted, service_signer=service_signer),
        )

    drifted = deepcopy(resources)
    discovery_url = resources[locator["profileUrl"]]["apiBaseUrl"] + "/.well-known/limitless-service"
    drifted[discovery_url]["dataUsePolicy"]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(OfficialServiceActivationError, match="authority verification"):
        activate_service_from_locator(
            locator,
            state_path=tmp_path / "drifted.json",
            at=AT,
            transport=MemoryTransport(drifted, service_signer=service_signer),
        )


def test_unavailability_preserves_local_default(tmp_path: Path) -> None:
    locator, _profile, resources, service_signer = _records()
    transport = MemoryTransport(resources, service_signer=service_signer)
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


def test_unsafe_identity_permissions_fail_closed_without_touching_activation(
    tmp_path: Path,
) -> None:
    locator, _profile, resources, service_signer = _records()
    transport = MemoryTransport(resources, service_signer=service_signer)
    state_path = tmp_path / "official-service.json"
    activate_service_from_locator(
        locator,
        state_path=state_path,
        at=AT,
        transport=transport,
    )
    identity_path = tmp_path / "official-service-identity.json"
    identity_path.chmod(0o644)

    with pytest.raises(OfficialServiceActivationError, match="identity"):
        activate_service_from_locator(
            locator,
            state_path=state_path,
            at=AT,
            transport=transport,
        )

    assert state_path.exists()
    assert identity_path.stat().st_mode & 0o777 == 0o644


def test_interrupted_session_preserves_identity_and_retries_without_reregistering(
    tmp_path: Path,
) -> None:
    locator, _profile, resources, service_signer = _records()
    transport = MemoryTransport(resources, service_signer=service_signer)
    transport.unavailable_suffix = "/v1/installations/sessions"
    state_path = tmp_path / "official-service.json"

    with pytest.raises(OfficialServiceUnavailableError, match="continue locally"):
        activate_service_from_locator(
            locator,
            state_path=state_path,
            at=AT,
            transport=transport,
        )

    identity_path = tmp_path / "official-service-identity.json"
    retained = load_json(identity_path)
    assert retained["attestation"] is not None
    assert retained["session"] is None
    assert not state_path.exists()

    transport.unavailable_suffix = None
    previous_calls = len(transport.calls)
    activate_service_from_locator(
        locator,
        state_path=state_path,
        at=AT,
        transport=transport,
    )
    retry_calls = transport.calls[previous_calls:]
    assert retry_calls.count(resources[locator["profileUrl"]]["apiBaseUrl"] + "/v1/installations") == 0
    assert retry_calls[-1].endswith("/v1/installations/sessions")
    assert load_json(identity_path)["installationId"] == retained["installationId"]


def test_release_bundles_the_content_addressed_official_identity() -> None:
    locator = load_bundled_official_locator()

    assert locator["serviceId"] == "service:limitless-library"
    assert locator["profileUrl"] == (
        "https://api.limitlesslibrary.com/.well-known/limitless-service-profile/1.0.json"
    )
    assert locator["profileDigest"] == (
        "sha256:6ea3ab4baa7a4f0fff6304d3ea352400f9c08af5bb8aaa3eed35d9f5a2ba33b8"
    )
    assert locator["rootKey"]["keyId"] == "key:limitless-root-2026-01"


def test_default_state_path_is_per_user_and_requires_absolute_configuration() -> None:
    assert default_activation_state_path(environ={"XDG_CONFIG_HOME": "/tmp/limitless-config"}) == Path(
        "/tmp/limitless-config/limitless-library/official-service.json"
    )
    with pytest.raises(OfficialServiceActivationError, match="invalid"):
        default_activation_state_path(environ={"XDG_CONFIG_HOME": "relative"})
