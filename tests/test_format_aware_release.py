"""Experimental format-aware publication contract tests."""

from __future__ import annotations

from base64 import urlsafe_b64decode
from copy import deepcopy
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from limitless_library.contracts import load_json, sha256_json
from limitless_library.public_submission_contracts import (
    IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2,
    IMMUTABLE_RELEASE_SCHEMA_VERSIONS,
    MAX_EXACT_ARTIFACT_BYTES,
    SUBMISSION_INTENT_SCHEMA_VERSION_1_2,
    SUBMISSION_INTENT_SCHEMA_VERSIONS,
    PublicSubmissionContractError,
    build_immutable_release,
    build_submission_intent,
    build_submission_plan,
    validate_immutable_release,
    validate_submission_intent,
    validate_submission_plan,
)
from limitless_library.service_identity import InstallationSigner

NOW = datetime(2026, 8, 21, 16, 0, tzinfo=UTC)
EXACT_FORMAT = "limitless.exact-file-bundle/1.0"
EXACT_MEDIA_TYPE = "application/vnd.limitless.exact-file-bundle+json"


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _replace_pointer(value: dict[str, Any], pointer: str, replacement: Any) -> dict:
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


def _fields(publisher: InstallationSigner) -> dict:
    evidence = sha256_json({"receiver": "format-aware-test"})
    target = {
        "platform": "linux",
        "architecture": "x86_64",
        "runtime": "python",
        "versionRange": ">=3.11,<4",
        "interfaces": ["limitless.mcp/v1"],
    }
    return {
        "requestId": "request:format-aware-publication",
        "publisher": {
            "publisherId": publisher.key_id,
            "authorityId": "installation-space:format-aware-test",
            "keyId": publisher.key_id,
        },
        "destination": {
            "collectionId": "collection:public",
            "audience": "public",
        },
        "candidate": {
            "title": "Portable exact component",
            "summary": "A receiver-verifiable exact file bundle.",
            "treatment": "exact-component",
            "capabilities": ["limitless.mcp/v1"],
        },
        "lineage": {
            "lineageId": "lineage:portable-exact-component",
            "version": "1.0.0",
            "releaseClass": "initial",
            "parents": [],
            "supersedes": None,
        },
        "contentObjects": [
            {
                "role": "artifact",
                "digest": sha256_json({"bundle": "portable-exact-component"}),
                "byteLength": 401,
                "format": EXACT_FORMAT,
                "mediaType": EXACT_MEDIA_TYPE,
            },
            {
                "role": "manifest",
                "digest": sha256_json({"manifest": "portable-exact-component"}),
                "byteLength": 201,
            },
        ],
        "compatibility": {
            "supportedTargets": [target],
            "verifiedTargets": [
                {"target": target, "evidenceDigests": [evidence]}
            ],
        },
        "buildContext": {
            "platform": "linux",
            "architecture": "x86_64",
            "runtime": "python",
            "version": "3.13",
            "interfaces": ["limitless.mcp/v1"],
        },
        "evidenceDigests": [evidence],
        "rights": {
            "license": "Apache-2.0",
            "grantedBy": publisher.key_id,
            "allowedUses": ["build-application"],
            "hasAuthority": True,
            "policyDigest": sha256_json({"policy": "public-contribution-v1"}),
        },
        "submittedAt": NOW,
    }


def _intent(
    publisher: InstallationSigner,
    *,
    fields: dict | None = None,
    schema_version: str = SUBMISSION_INTENT_SCHEMA_VERSION_1_2,
) -> dict:
    return build_submission_intent(
        signer=publisher,
        schema_version=schema_version,
        **(fields or _fields(publisher)),
    )


def test_format_descriptor_survives_signed_intent_and_release() -> None:
    publisher = InstallationSigner.generate()
    service = InstallationSigner.generate()
    intent = _intent(publisher)
    known = [item["digest"] for item in intent["contentObjects"]]
    plan = build_submission_plan(
        intent=intent,
        known_object_digests=known,
        review_stages=["rights", "security"],
        issued_at=NOW,
        signer=service,
    )
    release = build_immutable_release(
        intent=intent,
        plan=plan,
        publisher_id=publisher.key_id,
        reviewer_id="service:format-aware-curator",
        review_evidence_digests=[sha256_json({"review": "passed"})],
        created_at=NOW,
        signer=service,
    )

    descriptor = next(
        item for item in intent["contentObjects"] if item["role"] == "artifact"
    )
    assert descriptor["format"] == EXACT_FORMAT
    assert descriptor["mediaType"] == EXACT_MEDIA_TYPE
    assert release["schemaVersion"] == IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2
    assert release["contentObjects"] == intent["contentObjects"]
    assert SUBMISSION_INTENT_SCHEMA_VERSION_1_2 in SUBMISSION_INTENT_SCHEMA_VERSIONS
    assert IMMUTABLE_RELEASE_SCHEMA_VERSION_1_2 in IMMUTABLE_RELEASE_SCHEMA_VERSIONS


def test_transfer_plan_retains_the_legacy_three_field_object_shape() -> None:
    publisher = InstallationSigner.generate()
    service = InstallationSigner.generate()
    intent = _intent(publisher)
    plan = build_submission_plan(
        intent=intent,
        known_object_digests=[],
        review_stages=["rights"],
        issued_at=NOW,
        signer=service,
    )

    assert plan["state"] == "needs-content"
    assert all(
        set(descriptor) == {"role", "digest", "byteLength"}
        for descriptor in plan["requiredObjects"]
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda item: item.pop("format"), "unsupported shape"),
        (lambda item: item.__setitem__("format", "application/zip"), "format is unsupported"),
        (lambda item: item.__setitem__("mediaType", "application/json"), "format is unsupported"),
        (lambda item: item.__setitem__("byteLength", MAX_EXACT_ARTIFACT_BYTES + 1), "format is unsupported"),
    ],
)
def test_format_aware_intent_rejects_unsafe_artifact_descriptors(
    mutation,
    message: str,
) -> None:
    publisher = InstallationSigner.generate()
    fields = _fields(publisher)
    artifact = next(
        item for item in fields["contentObjects"] if item["role"] == "artifact"
    )
    mutation(artifact)

    with pytest.raises(PublicSubmissionContractError, match=message):
        _intent(publisher, fields=fields)


def test_legacy_current_intent_cannot_smuggle_a_format_descriptor() -> None:
    publisher = InstallationSigner.generate()
    fields = deepcopy(_fields(publisher))

    with pytest.raises(PublicSubmissionContractError, match="unsupported shape"):
        _intent(
            publisher,
            fields=fields,
            schema_version="limitless.service-submission-intent/1.1",
        )


def test_static_format_aware_release_corpus_is_signed_and_bound() -> None:
    path = Path(
        str(
            files("limitless_library.conformance").joinpath(
                "public-format-aware-release-1.2.json"
            )
        )
    )
    corpus = load_json(path)
    assert corpus["corpusDigest"] == sha256_json(
        {key: value for key, value in corpus.items() if key != "corpusDigest"}
    )
    keys = {
        item["keyId"]: _decode(item["publicKey"])
        for item in corpus["publicKeys"].values()
    }
    at = datetime.fromisoformat(corpus["expected"]["validAt"]).astimezone(UTC)
    intent = validate_submission_intent(corpus["intent"], public_keys=keys)
    needs_content = validate_submission_plan(
        corpus["needsContentPlan"],
        public_keys=keys,
        expected_intent=intent,
        at=at,
    )
    accepted = validate_submission_plan(
        corpus["acceptedPlan"],
        public_keys=keys,
        expected_intent=intent,
        at=at,
    )
    release = validate_immutable_release(
        corpus["release"],
        public_keys=keys,
        expected_intent=intent,
        expected_plan=accepted,
    )

    assert all(
        set(item) == {"role", "digest", "byteLength"}
        for item in needs_content["requiredObjects"]
    )
    assert intent["intentDigest"] == corpus["expected"]["intentDigest"]
    assert release["releaseId"] == corpus["expected"]["releaseId"]

    for case in corpus["invalidCases"]:
        candidate = _replace_pointer(
            corpus[case["record"]], case["path"], case["value"]
        )
        with pytest.raises(PublicSubmissionContractError):
            if case["record"] == "intent":
                validate_submission_intent(candidate, public_keys=keys)
            else:
                validate_immutable_release(
                    candidate,
                    public_keys=keys,
                    expected_intent=intent,
                    expected_plan=accepted,
                )
