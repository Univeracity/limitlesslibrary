from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Callable
from copy import deepcopy
from datetime import datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from limitless_library.contracts import load_json, sha256_bytes, sha256_json
from limitless_library.installation_identity_contracts import (
    InstallationIdentityContractError,
    validate_installation_attestation,
    validate_installation_registration_request,
    validate_installation_session_request,
    validate_installation_session_response,
)

CORPUS = Path(str(files("limitless_library.conformance").joinpath("installation-identity-lifecycle-1.0.json")))


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _replace(value: dict[str, Any], path: list[str], replacement: Any) -> None:
    cursor = value
    for segment in path[:-1]:
        cursor = cursor[segment]
    cursor[path[-1]] = replacement


def test_private_and_public_installation_records_share_exact_canonical_bytes() -> None:
    corpus = load_json(CORPUS)
    digest = corpus.pop("corpusDigest")
    assert digest == sha256_json(corpus)
    corpus["corpusDigest"] = digest
    at = datetime.fromisoformat(corpus["expected"]["validAt"])
    current_key = _decode(corpus["registration"]["publicKey"]["value"])
    service_key = _decode(corpus["servicePublicKey"]["value"])

    registration = validate_installation_registration_request(corpus["registration"], at=at)
    attestation = validate_installation_attestation(
        corpus["attestation"],
        service_public_keys={corpus["servicePublicKey"]["keyId"]: service_key},
    )
    session = validate_installation_session_request(corpus["sessionRequest"], current_public_key=current_key, at=at)

    assert registration["publicKey"]["keyId"] == session["currentKeyId"]
    assert attestation["installationId"] == corpus["expected"]["installationId"]
    assert session["capabilities"] == corpus["expected"]["sessionCapabilities"]
    assert "privateKey" not in str(corpus)


def test_declared_registration_and_session_mutations_fail_closed() -> None:
    corpus = load_json(CORPUS)
    at = datetime.fromisoformat(corpus["expected"]["validAt"])
    current_key = _decode(corpus["registration"]["publicKey"]["value"])
    validators: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
        "registration": lambda value: validate_installation_registration_request(value, at=at),
        "sessionRequest": lambda value: validate_installation_session_request(
            value, current_public_key=current_key, at=at
        ),
    }
    selected = [case for case in corpus["invalidCases"] if case["record"] in validators]
    assert selected
    for case in selected:
        changed = deepcopy(corpus[case["record"]])
        _replace(changed, case["path"], case["replacement"])
        with pytest.raises(InstallationIdentityContractError, match=case["error"]):
            validators[case["record"]](changed)


def test_session_response_is_bounded_to_token_request_policy_and_lifetime() -> None:
    corpus = load_json(CORPUS)
    request = corpus["sessionRequest"]
    current_key = _decode(corpus["registration"]["publicKey"]["value"])
    at = datetime.fromisoformat(corpus["expected"]["validAt"])
    token = "lst_" + urlsafe_b64encode(b"R" * 32).rstrip(b"=").decode("ascii")
    response = {
        "schemaVersion": "limitless.installation-session-response/1.0",
        "accessToken": token,
        "tokenType": "Bearer",
        "sessionId": "installation-session:" + sha256_bytes(token.encode("ascii"))[7:39],
        "installationId": request["installationId"],
        "tenantId": corpus["expected"]["tenantId"],
        "acceptedPolicyDigest": request["acceptedPolicyDigest"],
        "capabilities": request["capabilities"],
        "issuedAt": at.isoformat().replace("+00:00", "Z"),
        "expiresAt": (at + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
    }

    assert (
        validate_installation_session_response(
            response,
            expected_request=request,
            current_public_key=current_key,
            at=at,
        )["accessToken"]
        == token
    )
    changed = deepcopy(response)
    changed["capabilities"] = ["queries"]
    with pytest.raises(InstallationIdentityContractError, match="differs"):
        validate_installation_session_response(
            changed,
            expected_request=request,
            current_public_key=current_key,
            at=at,
        )
