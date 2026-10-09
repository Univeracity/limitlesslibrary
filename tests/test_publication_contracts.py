from __future__ import annotations

from base64 import urlsafe_b64decode
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from limitless_library.contracts import canonical_json_bytes, load_json, sha256_json
from limitless_library.public_admission_contracts import (
    PublicAdmissionContractError,
    assessment_state,
    validate_contribution_policy_acceptance,
    validate_public_admission_assessment,
    validate_public_release_revocation_request,
)
from limitless_library.public_submission_contracts import (
    PublicSubmissionContractError,
    build_submission_intent,
    validate_content_transfer_grant,
    validate_content_transfer_result,
    validate_immutable_release,
    validate_submission_intent,
    validate_submission_plan,
)
from limitless_library.service_identity import InstallationSigner


def test_new_target_order_is_canonical_and_legacy_signatures_are_preserved() -> None:
    fixture = load_json(Path(str(files("limitless_library.conformance").joinpath("multi-target-submission-1.2.json"))))
    key = _decode(fixture["publicKey"])
    intent = fixture["intent"]
    keys = {intent["publisher"]["keyId"]: key}
    assert validate_submission_intent(intent, public_keys=keys) == intent
    targets = intent["compatibility"]["supportedTargets"]
    assert targets == sorted(targets, key=canonical_json_bytes)
    assert [target["interfaces"][0] for target in targets] == fixture["expectedInterfaces"]
    assert [proof["target"] for proof in intent["compatibility"]["verifiedTargets"]] == targets
    legacy = fixture["oldDigestOrderedIntent"]
    assert validate_submission_intent(legacy, public_keys=keys) == legacy

    signer = InstallationSigner.generate()
    fields = deepcopy({k: v for k, v in intent.items() if k not in {"schemaVersion", "signature", "intentDigest"}})
    fields["publisher"]["keyId"] = signer.key_id
    fields["compatibility"]["supportedTargets"].reverse()
    fields["compatibility"]["verifiedTargets"].reverse()
    built = build_submission_intent(signer=signer, **fields)
    assert built["compatibility"] == intent["compatibility"]


@pytest.mark.parametrize("field", ["supportedTargets", "verifiedTargets"])
def test_signed_target_order_cannot_change_without_a_new_signature(field: str) -> None:
    fixture = load_json(Path(str(files("limitless_library.conformance").joinpath("multi-target-submission-1.2.json"))))
    changed = deepcopy(fixture["oldDigestOrderedIntent"])
    keys = {changed["publisher"]["keyId"]: _decode(fixture["publicKey"])}
    changed["compatibility"][field].reverse()
    with pytest.raises(PublicSubmissionContractError, match="digest"):
        validate_submission_intent(changed, public_keys=keys)
    changed["intentDigest"] = sha256_json({k: v for k, v in changed.items() if k not in {"intentDigest", "signature"}})
    with pytest.raises(PublicSubmissionContractError, match="signature"):
        validate_submission_intent(changed, public_keys=keys)


@pytest.mark.parametrize("mutation", ["duplicate-target", "duplicate-proof", "unclaimed-proof", "over-limit"])
def test_legacy_order_does_not_bypass_target_validation(mutation: str) -> None:
    fixture = load_json(Path(str(files("limitless_library.conformance").joinpath("multi-target-submission-1.2.json"))))
    changed = deepcopy(fixture["oldDigestOrderedIntent"])
    compatibility = changed["compatibility"]
    if mutation == "duplicate-target":
        compatibility["supportedTargets"].append(compatibility["supportedTargets"][0])
    elif mutation == "duplicate-proof":
        compatibility["verifiedTargets"].append(compatibility["verifiedTargets"][0])
    elif mutation == "unclaimed-proof":
        compatibility["verifiedTargets"][0]["target"]["interfaces"] = ["repo.unclaimed/v1"]
    else:
        compatibility["supportedTargets"] *= 5
    with pytest.raises(PublicSubmissionContractError, match="compatibility|unique|exact supported"):
        validate_submission_intent(changed, public_keys={changed["publisher"]["keyId"]: _decode(fixture["publicKey"])})


def test_legacy_release_preserves_signed_intent_and_plan_identity() -> None:
    fixture = load_json(Path(str(files("limitless_library.conformance").joinpath("multi-target-submission-1.2.json"))))
    legacy = fixture["oldDigestOrderedIntent"]
    key = fixture["releasePublicKey"]
    keys = {key["keyId"]: _decode(key["publicKey"])}
    plan = validate_submission_plan(fixture["legacyAcceptedPlan"], public_keys=keys, expected_intent=legacy)
    release = validate_immutable_release(
        fixture["legacyRelease"], public_keys=keys, expected_intent=legacy, expected_plan=plan
    )
    assert release == fixture["legacyRelease"]
    assert release["compatibility"] == legacy["compatibility"]
    changed = deepcopy(release)
    changed["compatibility"]["verifiedTargets"].reverse()
    with pytest.raises(PublicSubmissionContractError, match="identity"):
        validate_immutable_release(changed, public_keys=keys)
    body = {k: v for k, v in changed.items() if k not in {"releaseId", "releaseDigest", "signature"}}
    changed["releaseDigest"] = sha256_json(body)
    changed["releaseId"] = "release:" + changed["releaseDigest"][7:39]
    with pytest.raises(PublicSubmissionContractError, match="signature"):
        validate_immutable_release(changed, public_keys=keys)


def _corpus(name: str) -> dict[str, Any]:
    path = Path(str(files("limitless_library.conformance").joinpath(name)))
    value = load_json(path)
    digest = value["corpusDigest"]
    assert digest == sha256_json({key: item for key, item in value.items() if key != "corpusDigest"})
    return value


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _replace_pointer(value: dict[str, Any], pointer: str, replacement: Any) -> dict[str, Any]:
    changed = deepcopy(value)
    parts = pointer.removeprefix("/").split("/")
    current: Any = changed
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    final = parts[-1]
    if isinstance(current, list):
        current[int(final)] = replacement
    else:
        current[final] = replacement
    return changed


def _replace_path(value: dict[str, Any], path: list[Any], replacement: Any) -> dict[str, Any]:
    changed = deepcopy(value)
    current: Any = changed
    for segment in path[:-1]:
        current = current[segment]
    current[path[-1]] = replacement
    return changed


def test_submission_release_corpus_is_signed_bound_and_mutation_complete() -> None:
    corpus = _corpus("public-submission-release-1.0.json")
    key = corpus["publicKey"]
    keys = {key["keyId"]: _decode(key["publicKey"])}
    at = datetime.fromisoformat(corpus["expected"]["validAt"]).astimezone(UTC)
    intent = validate_submission_intent(corpus["intent"])
    plan = validate_submission_plan(
        corpus["acceptedPlan"],
        public_keys=keys,
        expected_intent=intent,
        at=at,
    )
    release = validate_immutable_release(
        corpus["release"],
        public_keys=keys,
        expected_intent=intent,
        expected_plan=plan,
    )
    assert release["releaseId"] == corpus["expected"]["releaseId"]

    for case in corpus["invalidCases"]:
        candidate = _replace_pointer(corpus[case["record"]], case["path"], case["value"])
        with pytest.raises(PublicSubmissionContractError):
            if case["record"] == "intent":
                validate_submission_intent(candidate)
            elif case["record"] == "acceptedPlan":
                validate_submission_plan(candidate, public_keys=keys, expected_intent=intent)
            else:
                validate_immutable_release(
                    candidate,
                    public_keys=keys,
                    expected_intent=intent,
                    expected_plan=plan,
                )


def test_content_transfer_corpus_is_current_exact_and_mutation_complete() -> None:
    corpus = _corpus("public-content-transfer-grant-1.0.json")
    key = corpus["publicKey"]
    keys = {key["keyId"]: _decode(key["publicKey"])}
    at = datetime.fromisoformat(corpus["expected"]["validAt"]).astimezone(UTC)
    grant = validate_content_transfer_grant(
        corpus["grant"],
        public_keys=keys,
        expected_intent=corpus["intent"],
        expected_plan=corpus["plan"],
        at=at,
    )
    assert grant["grantId"] == corpus["expected"]["grantId"]

    for case in corpus["invalidCases"]:
        candidate = _replace_pointer(corpus["grant"], case["path"], case["value"])
        with pytest.raises(PublicSubmissionContractError):
            validate_content_transfer_grant(
                candidate,
                public_keys=keys,
                expected_intent=corpus["intent"],
                expected_plan=corpus["plan"],
            )

    descriptor = grant["objects"][0]
    result = validate_content_transfer_result(
        {
            "schemaVersion": "limitless.service-content-transfer-result/1.0",
            "grantId": grant["grantId"],
            "submissionRef": grant["submissionRef"],
            **descriptor,
            "disposition": "created",
        },
        expected_plan=corpus["plan"],
    )
    assert result["digest"] == descriptor["digest"]
    with pytest.raises(PublicSubmissionContractError, match="bound"):
        validate_content_transfer_result(
            {**result, "digest": "sha256:" + "0" * 64},
            expected_plan=corpus["plan"],
        )


def test_admission_corpus_is_signed_source_neutral_and_mutation_complete() -> None:
    corpus = _corpus("public-admission-lifecycle-1.0.json")
    key = corpus["publisherPublicKey"]
    keys = {key["keyId"]: _decode(key["value"])}
    at = datetime.fromisoformat(corpus["expected"]["validAt"])
    validators: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
        "acceptance": lambda value: validate_contribution_policy_acceptance(value, public_keys=keys, at=at),
        "assessment": validate_public_admission_assessment,
        "revocation": lambda value: validate_public_release_revocation_request(value, public_keys=keys, at=at),
    }
    acceptance = validators["acceptance"](corpus["acceptance"])
    assessment = validators["assessment"](corpus["assessment"])
    revocation = validators["revocation"](corpus["revocation"])
    assert acceptance["policyDigest"] == corpus["expected"]["policyDigest"]
    assert assessment_state(assessment) == corpus["expected"]["assessmentState"]
    assert acceptance["publisher"] == revocation["publisher"]

    for case in corpus["invalidCases"]:
        candidate = _replace_path(corpus[case["record"]], case["path"], case["replacement"])
        with pytest.raises(PublicAdmissionContractError, match=case["error"]):
            validators[case["record"]](candidate)
