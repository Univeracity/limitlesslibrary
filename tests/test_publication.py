from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from limitless_library.contracts import canonical_json_bytes, sha256_json, strict_json_loads
from limitless_library.public_submission_contracts import (
    build_submission_plan,
    public_submission_ref,
)
from limitless_library.publication import (
    PublicationError,
    publication_status,
    publish_draft,
    revoke_publication,
)
from limitless_library.service_connector import (
    ServiceConnector,
    ServiceHttpResponse,
    ServiceProfile,
    VerifiedService,
)
from limitless_library.service_contracts import build_service_discovery
from limitless_library.service_identity import InstallationSigner

NOW = datetime(2026, 8, 20, 23, 30, tzinfo=UTC)


class PublicationWorkflowTransport:
    def __init__(self, *, signer: InstallationSigner, policy: dict[str, str]) -> None:
        self.signer = signer
        self.policy = policy
        self.intent: dict | None = None
        self.uploaded: set[str] = set()
        self.upload_calls = 0
        self.admission_state = "pending"
        self.release_ref = {
            "releaseId": "release:" + "7" * 32,
            "releaseDigest": "sha256:" + "7" * 64,
        }
        self.revocation_calls = 0

    def submission_ref(self) -> str:
        assert self.intent is not None
        return public_submission_ref(
            tenant_id=self.intent["publisher"]["authorityId"],
            publisher_id=self.intent["publisher"]["publisherId"],
            request_id=self.intent["requestId"],
        )

    def plan(self, known: set[str]) -> dict:
        assert self.intent is not None
        return build_submission_plan(
            intent=self.intent,
            known_object_digests=known,
            review_stages=("compatibility", "quality", "rights", "security"),
            issued_at=NOW,
            signer=self.signer,
            submission_ref=self.submission_ref(),
        )

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
        assert method == "POST"
        assert headers["authorization"] == "Bearer anonymous-session-token"
        if url.endswith("/v1/publication-policy/acceptances"):
            value = {
                "schemaVersion": "limitless.public-policy-acceptance-response/1.0",
                "acceptanceRef": "public-policy-acceptance:workflow",
                "policyRevision": self.policy["revision"],
                "policyDigest": self.policy["digest"],
                "acceptedAt": NOW.isoformat().replace("+00:00", "Z"),
            }
        elif url.endswith("/v1/submissions"):
            assert body is not None
            self.intent = strict_json_loads(body.decode("utf-8"))
            value = self.plan(self.uploaded)
        elif url.endswith("/admission-status"):
            assert self.intent is not None
            value = {
                "schemaVersion": "limitless.public-admission-status/1.0",
                "admissionRef": "public-admission:workflow",
                "submissionRef": self.submission_ref(),
                "state": self.admission_state,
                "releaseRef": self.release_ref if self.admission_state in {"active", "revoked"} else None,
                "reasonCodes": [],
                "generation": 2,
                "updatedAt": NOW.isoformat().replace("+00:00", "Z"),
            }
        elif url.endswith("/revocations"):
            assert body is not None
            request = strict_json_loads(body.decode("utf-8"))
            assert request["submissionRef"] == self.submission_ref()
            assert request["releaseId"] == self.release_ref["releaseId"]
            self.admission_state = "revoked"
            self.revocation_calls += 1
            value = {
                "schemaVersion": "limitless.public-admission-status/1.0",
                "admissionRef": "public-admission:workflow",
                "submissionRef": self.submission_ref(),
                "state": "revoked",
                "releaseRef": self.release_ref,
                "reasonCodes": [request["reasonCode"]],
                "generation": 2,
                "updatedAt": NOW.isoformat().replace("+00:00", "Z"),
            }
        else:
            raise AssertionError(f"unexpected URL: {url}")
        encoded = canonical_json_bytes(value)
        assert len(encoded) <= maximum_bytes and timeout_seconds > 0
        return ServiceHttpResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=encoded,
        )

    def upload_file(
        self,
        url: str,
        *,
        headers: dict[str, str],
        source: object,
        byte_length: int,
        expected_digest: str,
        maximum_bytes: int,
        timeout_seconds: float,
    ) -> ServiceHttpResponse:
        assert self.intent is not None
        content = source.read()
        assert len(content) == byte_length
        self.uploaded.add(expected_digest)
        self.upload_calls += 1
        descriptor = next(item for item in self.intent["contentObjects"] if item["digest"] == expected_digest)
        plan = self.plan(set())
        value = {
            "schemaVersion": "limitless.service-content-transfer-result/1.0",
            "grantId": "grant:" + "5" * 32,
            "submissionRef": plan["submissionRef"],
            "role": descriptor["role"],
            "digest": descriptor["digest"],
            "byteLength": descriptor["byteLength"],
            "disposition": "created",
        }
        encoded = canonical_json_bytes(value)
        assert url.endswith(f"/{descriptor['role']}/{expected_digest}")
        assert headers["content-length"] == str(byte_length)
        assert len(encoded) <= maximum_bytes and timeout_seconds > 0
        return ServiceHttpResponse(
            status=201,
            headers={"content-type": "application/json"},
            body=encoded,
        )


def _fixture() -> tuple[
    ServiceConnector,
    PublicationWorkflowTransport,
    InstallationSigner,
    dict,
]:
    publisher = InstallationSigner.generate()
    result_signer = InstallationSigner.generate()
    root = InstallationSigner.generate()
    data_policy = sha256_json({"policy": "data"})
    publication_policy = sha256_json({"policy": "publication"})
    discovery = build_service_discovery(
        service_id="service:publication-workflow",
        api_base_url="https://api.limitlesslibrary.com",
        signing_keys=[
            (
                result_signer.key_id,
                result_signer.public_bytes(),
                NOW - timedelta(days=1),
                NOW + timedelta(days=30),
            )
        ],
        data_use_policy_url="https://limitlesslibrary.com/data-use",
        data_use_policy_digest=data_policy,
        publication_policy_revision="policy:publication-workflow",
        publication_policy_url="https://limitlesslibrary.com/publication-policy",
        publication_policy_digest=publication_policy,
        rate_limit_class="public-test",
        issued_at=NOW,
        root_signer=root,
    )
    transport = PublicationWorkflowTransport(
        signer=result_signer,
        policy=discovery["publicationPolicy"],
    )
    connector = ServiceConnector(
        ServiceProfile(
            api_base_url=discovery["apiBaseUrl"],
            service_id=discovery["serviceId"],
            root_key_id=root.key_id,
            root_public_key=root.public_bytes(),
            accepted_policy_digest=data_policy,
            requested_audiences=("public",),
            access_token="anonymous-session-token",
        ),
        transport=transport,
        clock=lambda: NOW,
    )
    connector._cached = VerifiedService(
        discovery=discovery,
        root_transitions={},
        result_keys={result_signer.key_id: result_signer.public_bytes()},
    )
    connector._cached_until = float("inf")
    publisher_id = "installation:" + "8" * 32
    authority = {
        "schemaVersion": "limitless.installation-publisher-authority/1.0",
        "serviceId": discovery["serviceId"],
        "publisherId": publisher_id,
        "authorityId": "installation-space:" + "8" * 32,
        "keyId": publisher.key_id,
        "generation": 1,
    }
    return connector, transport, publisher, authority


def _write_draft(tmp_path: Path) -> Path:
    (tmp_path / "method.md").write_text("Verify locally, then adopt.\n", encoding="utf-8")
    draft = {
        "schemaVersion": "limitless.publication-draft/1.0",
        "candidate": {
            "title": "Receiver-owned verification",
            "summary": "A source-free method for proving adoption locally.",
            "treatment": "source-free-method",
            "capabilities": ["limitless.mcp/v1"],
        },
        "lineage": {
            "lineageId": "lineage:receiver-verification-method",
            "version": "1.0.0",
            "releaseClass": "initial",
            "parents": [],
            "supersedes": None,
        },
        "objects": [{"role": "method", "path": "method.md"}],
        "compatibility": {
            "supportedTargets": [
                {
                    "platform": "linux",
                    "architecture": "x86_64",
                    "runtime": "python",
                    "versionRange": ">=3.11,<4",
                    "interfaces": ["limitless.mcp/v1"],
                }
            ],
            "verifiedTargets": [],
        },
        "buildContext": {
            "platform": "linux",
            "architecture": "x86_64",
            "runtime": "python",
            "version": "3.12.0",
            "interfaces": ["limitless.mcp/v1"],
        },
        "evidenceDigests": [sha256_json({"evidence": "receiver-owned"})],
        "rights": {
            "license": "CC0-1.0",
            "allowedUses": ["derive-method"],
            "hasAuthority": True,
        },
    }
    path = tmp_path / "publication.json"
    path.write_bytes(canonical_json_bytes(draft) + b"\n")
    return path


def test_one_command_publication_is_resumable_and_cwd_independent(tmp_path: Path) -> None:
    connector, transport, signer, publisher = _fixture()
    draft = _write_draft(tmp_path)

    first = publish_draft(
        connector,
        draft_path=draft,
        state_path=None,
        signer=signer,
        publisher=publisher,
        accept_publication_policy=True,
        now=NOW,
    )
    state = Path(first["statePath"])
    original = state.read_bytes()
    second = publish_draft(
        connector,
        draft_path=draft,
        state_path=None,
        signer=signer,
        publisher=publisher,
        accept_publication_policy=True,
        now=NOW,
    )

    assert first["planState"] == "accepted"
    assert first["admissionState"] == "pending"
    assert len(first["uploadedObjects"]) == 1
    assert second["submissionRef"] == first["submissionRef"]
    assert second["uploadedObjects"] == []
    assert transport.upload_calls == 1
    assert state.read_bytes() == original
    assert state.stat().st_mode & 0o777 == 0o600


def test_publication_requires_explicit_policy_acceptance(tmp_path: Path) -> None:
    connector, _transport, signer, publisher = _fixture()
    draft = _write_draft(tmp_path)

    with pytest.raises(PublicationError, match="accept-publication-policy"):
        publish_draft(
            connector,
            draft_path=draft,
            state_path=None,
            signer=signer,
            publisher=publisher,
            accept_publication_policy=False,
            now=NOW,
        )


def test_status_and_revocation_resume_from_owner_only_state(tmp_path: Path) -> None:
    connector, transport, signer, publisher = _fixture()
    draft = _write_draft(tmp_path)
    published = publish_draft(
        connector,
        draft_path=draft,
        state_path=None,
        signer=signer,
        publisher=publisher,
        accept_publication_policy=True,
        now=NOW,
    )
    state = Path(published["statePath"])
    transport.admission_state = "active"

    active = publication_status(
        connector,
        state_path=state,
        signer=signer,
        publisher=publisher,
    )
    revoked = revoke_publication(
        connector,
        state_path=state,
        signer=signer,
        publisher=publisher,
        reason_code="publisher-withdrawal",
        now=NOW,
    )
    replay = revoke_publication(
        connector,
        state_path=state,
        signer=signer,
        publisher=publisher,
        reason_code="publisher-withdrawal",
        now=NOW,
    )

    assert active["admissionState"] == "active"
    assert active["submissionRef"] == published["submissionRef"]
    assert revoked["admissionState"] == "revoked"
    assert replay["admissionState"] == "revoked"
    assert transport.revocation_calls == 1


def test_followup_rejects_symlinked_or_tampered_state(tmp_path: Path) -> None:
    connector, _transport, signer, publisher = _fixture()
    draft = _write_draft(tmp_path)
    published = publish_draft(
        connector,
        draft_path=draft,
        state_path=None,
        signer=signer,
        publisher=publisher,
        accept_publication_policy=True,
        now=NOW,
    )
    state = Path(published["statePath"])
    link = tmp_path / "state-link.json"
    link.symlink_to(state)
    with pytest.raises(PublicationError, match="unsafe"):
        publication_status(
            connector,
            state_path=link,
            signer=signer,
            publisher=publisher,
        )

    value = strict_json_loads(state.read_text(encoding="utf-8"))
    value["publisher"]["generation"] = 2
    state.write_bytes(canonical_json_bytes(value) + b"\n")
    state.chmod(0o600)
    with pytest.raises(PublicationError, match="current authority"):
        publication_status(
            connector,
            state_path=state,
            signer=signer,
            publisher=publisher,
        )
