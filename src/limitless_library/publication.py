"""One-command, resumable anonymous publication to the official service."""

from __future__ import annotations

import os
import re
import stat
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from secrets import token_hex
from typing import Any

from .contracts import (
    ContractError,
    load_json,
    sha256_json,
    strict_json_loads,
    write_new_json,
)
from .exact_file_bundle import (
    EXACT_FILE_BUNDLE_SCHEMA_VERSION,
    MAX_EXACT_FILE_BUNDLE_BYTES,
    ExactFileBundleError,
    parse_exact_file_bundle,
)
from .public_admission_contracts import (
    PublicAdmissionContractError,
    build_contribution_policy_acceptance,
    build_public_release_revocation_request,
)
from .public_submission_contracts import (
    PublicSubmissionContractError,
    build_submission_intent,
    public_submission_ref,
    validate_submission_intent,
)
from .service_connector import ServiceConnector, ServiceConnectorError
from .service_identity import InstallationSigner

PUBLICATION_DRAFT_SCHEMA_VERSION = "limitless.publication-draft/1.0"
PUBLICATION_STATE_SCHEMA_VERSION = "limitless.publication-state/1.0"
MAX_PUBLICATION_DRAFT_BYTES = 64 * 1024
MAX_PUBLICATION_STATE_BYTES = 128 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_POLICY_REVISION = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,119}$")
_EXACT_FILE_BUNDLE_MEDIA_TYPE = "application/vnd.limitless.exact-file-bundle+json"


class PublicationError(ServiceConnectorError):
    """A local publication draft or resumable operation is unsafe."""


def default_publication_state_path(draft_path: Path) -> Path:
    draft = Path(draft_path)
    return draft.with_name(draft.name + ".state.json")


def _draft(value: Any) -> dict[str, Any]:
    fields = {
        "schemaVersion",
        "candidate",
        "lineage",
        "objects",
        "compatibility",
        "buildContext",
        "evidenceDigests",
        "rights",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schemaVersion") != PUBLICATION_DRAFT_SCHEMA_VERSION
        or not isinstance(value.get("objects"), list)
        or not 1 <= len(value["objects"]) <= 32
        or not isinstance(value.get("rights"), dict)
        or set(value["rights"]) != {"license", "allowedUses", "hasAuthority"}
        or value["rights"]["hasAuthority"] is not True
    ):
        raise PublicationError("publication draft has an unsupported shape")
    sources: list[dict[str, str]] = []
    for item in value["objects"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"role", "path"}
            or item["role"] not in {"artifact", "manifest", "method", "verification"}
            or not isinstance(item["path"], str)
            or not item["path"]
            or "\x00" in item["path"]
        ):
            raise PublicationError("publication draft object is invalid")
        sources.append({"role": item["role"], "path": item["path"]})
    if len({(item["role"], item["path"]) for item in sources}) != len(sources):
        raise PublicationError("publication draft objects must be unique")
    return {**value, "objects": sources, "rights": dict(value["rights"])}


def _source_descriptor(role: str, configured: str, *, base: Path) -> dict[str, Any]:
    selected = Path(configured)
    path = selected if selected.is_absolute() else base / selected
    try:
        path = path.resolve(strict=True)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise PublicationError("publication source must be a regular file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            current = os.fstat(descriptor)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_size != info.st_size
                or current.st_dev != info.st_dev
                or current.st_ino != info.st_ino
                or not 1 <= current.st_size <= 1024 * 1024 * 1024
            ):
                raise PublicationError("publication source changed or is invalid")
            hasher = sha256()
            artifact_payload = bytearray()
            while True:
                chunk = os.read(descriptor, 128 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                if role == "artifact":
                    artifact_payload.extend(chunk)
                    if len(artifact_payload) > MAX_EXACT_FILE_BUNDLE_BYTES:
                        raise PublicationError("publication artifact exceeds the exact bundle limit")
            if role == "artifact":
                try:
                    parse_exact_file_bundle(bytes(artifact_payload))
                except ExactFileBundleError as error:
                    raise PublicationError(
                        "publication artifact is not a canonical exact file bundle"
                    ) from error
        finally:
            os.close(descriptor)
    except PublicationError:
        raise
    except OSError as error:
        raise PublicationError("publication source is unavailable") from error
    return {
        "role": role,
        "digest": "sha256:" + hasher.hexdigest(),
        "byteLength": current.st_size,
        "path": str(path),
        **(
            {
                "format": EXACT_FILE_BUNDLE_SCHEMA_VERSION,
                "mediaType": _EXACT_FILE_BUNDLE_MEDIA_TYPE,
            }
            if role == "artifact"
            else {}
        ),
    }


def _new_state(
    *,
    draft: dict[str, Any],
    draft_path: Path,
    service_id: str,
    policy: dict[str, str],
    signer: InstallationSigner,
    publisher: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    sources = [_source_descriptor(item["role"], item["path"], base=draft_path.parent) for item in draft["objects"]]
    intent = build_submission_intent(
        signer=signer,
        requestId="request:publish-" + token_hex(16),
        publisher={
            "publisherId": publisher["publisherId"],
            "authorityId": publisher["authorityId"],
            "keyId": signer.key_id,
        },
        destination={"collectionId": "collection:public", "audience": "public"},
        candidate=draft["candidate"],
        lineage=draft["lineage"],
        contentObjects=[
            {key: item[key] for key in item if key != "path"}
            for item in sources
        ],
        compatibility=draft["compatibility"],
        buildContext=draft["buildContext"],
        evidenceDigests=draft["evidenceDigests"],
        rights={
            **draft["rights"],
            "grantedBy": publisher["publisherId"],
            "policyDigest": policy["digest"],
        },
        submittedAt=now,
    )
    return {
        "schemaVersion": PUBLICATION_STATE_SCHEMA_VERSION,
        "serviceId": service_id,
        "publicationPolicy": {
            "revision": policy["revision"],
            "digest": policy["digest"],
        },
        "draftDigest": sha256_json(draft),
        "publisher": {key: publisher[key] for key in ("publisherId", "authorityId", "keyId", "generation")},
        "intent": intent,
        "sources": sources,
    }


def _saved_state(
    value: Any,
    *,
    service_id: str,
    signer: InstallationSigner,
    publisher: dict[str, Any],
) -> dict[str, Any]:
    fields = {
        "schemaVersion",
        "serviceId",
        "publicationPolicy",
        "draftDigest",
        "publisher",
        "intent",
        "sources",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise PublicationError("publication state has an unsupported shape")
    expected_publisher = {key: publisher[key] for key in ("publisherId", "authorityId", "keyId", "generation")}
    stored_policy = value.get("publicationPolicy")
    if (
        value["schemaVersion"] != PUBLICATION_STATE_SCHEMA_VERSION
        or value["serviceId"] != service_id
        or value["publisher"] != expected_publisher
        or not isinstance(stored_policy, dict)
        or set(stored_policy) != {"revision", "digest"}
        or not isinstance(stored_policy["revision"], str)
        or _POLICY_REVISION.fullmatch(stored_policy["revision"]) is None
        or not isinstance(stored_policy["digest"], str)
        or _DIGEST.fullmatch(stored_policy["digest"]) is None
        or not isinstance(value.get("draftDigest"), str)
        or _DIGEST.fullmatch(value["draftDigest"]) is None
        or not isinstance(value["sources"], list)
    ):
        raise PublicationError("publication state differs from current authority")
    try:
        intent = validate_submission_intent(value["intent"], public_keys={signer.key_id: signer.public_bytes()})
    except PublicSubmissionContractError as error:
        raise PublicationError("publication state intent is invalid") from error
    if (
        intent["publisher"] != {key: expected_publisher[key] for key in ("publisherId", "authorityId", "keyId")}
        or intent["rights"]["policyDigest"] != stored_policy["digest"]
    ):
        raise PublicationError("publication state intent is unbound")
    sources: list[dict[str, Any]] = []
    for item in value["sources"]:
        role = item.get("role") if isinstance(item, dict) else None
        fields = {"role", "digest", "byteLength", "path"}
        if role == "artifact":
            fields.update({"format", "mediaType"})
        if (
            not isinstance(item, dict)
            or set(item) != fields
            or not isinstance(item["path"], str)
            or not Path(item["path"]).is_absolute()
            or role == "artifact"
            and (
                item["format"] != EXACT_FILE_BUNDLE_SCHEMA_VERSION
                or item["mediaType"] != _EXACT_FILE_BUNDLE_MEDIA_TYPE
            )
        ):
            raise PublicationError("publication state source is invalid")
        sources.append(dict(item))
    declared = [{key: item[key] for key in item} for item in intent["contentObjects"]]
    supplied = [{key: item[key] for key in item if key != "path"} for item in sources]
    if supplied != declared:
        raise PublicationError("publication state sources differ from its intent")
    return {**value, "intent": intent, "sources": sources}


def _state(
    value: Any,
    *,
    draft: dict[str, Any],
    service_id: str,
    policy: dict[str, str],
    signer: InstallationSigner,
    publisher: dict[str, Any],
) -> dict[str, Any]:
    state = _saved_state(
        value,
        service_id=service_id,
        signer=signer,
        publisher=publisher,
    )
    if state["publicationPolicy"] != {"revision": policy["revision"], "digest": policy["digest"]} or state[
        "draftDigest"
    ] != sha256_json(draft):
        raise PublicationError("publication state differs from current authority")
    return state


def publish_draft(
    connector: ServiceConnector,
    *,
    draft_path: Path,
    state_path: Path | None,
    signer: InstallationSigner,
    publisher: dict[str, Any],
    accepted_publication_policy_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Prepare once, resume safely, and publish only explicitly named bytes."""

    if (
        not isinstance(accepted_publication_policy_digest, str)
        or _DIGEST.fullmatch(accepted_publication_policy_digest) is None
    ):
        raise PublicationError("review the advertised publication policy and provide its exact accepted digest")
    if not isinstance(connector, ServiceConnector) or not isinstance(signer, InstallationSigner):
        raise PublicationError("publication authority is invalid")
    try:
        selected_draft = Path(draft_path).resolve(strict=True)
        draft_info = selected_draft.stat()
    except OSError as error:
        raise PublicationError("publication draft is unavailable") from error
    if not stat.S_ISREG(draft_info.st_mode) or not 1 <= draft_info.st_size <= MAX_PUBLICATION_DRAFT_BYTES:
        raise PublicationError("publication draft is invalid")
    configured_state = default_publication_state_path(selected_draft) if state_path is None else Path(state_path)
    if configured_state.is_symlink():
        raise PublicationError("publication state path is unsafe")
    selected_state = configured_state.resolve(strict=False)
    if not selected_state.is_absolute():
        raise PublicationError("publication state path must be absolute")
    try:
        draft = _draft(load_json(selected_draft))
    except (ContractError, OSError, ValueError) as error:
        raise PublicationError("publication draft is invalid") from error
    verified = connector.inspect()
    policy = verified.discovery.get("publicationPolicy")
    if not isinstance(policy, dict):
        raise PublicationError("service does not advertise public publication")
    if policy.get("digest") != accepted_publication_policy_digest:
        raise PublicationError("the advertised publication policy differs from the reviewed digest")
    current = datetime.now(tz=UTC) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise PublicationError("publication time is invalid")
    current = current.astimezone(UTC).replace(microsecond=0)

    if selected_state.exists():
        try:
            _selected, saved = _load_publication_state(
                selected_state,
                service_id=connector.profile.service_id,
                signer=signer,
                publisher=publisher,
            )
            prepared = _state(
                saved,
                draft=draft,
                service_id=connector.profile.service_id,
                policy=policy,
                signer=signer,
                publisher=publisher,
            )
        except (ContractError, OSError, ValueError) as error:
            raise PublicationError("publication state is invalid") from error
    else:
        prepared = _new_state(
            draft=draft,
            draft_path=selected_draft,
            service_id=connector.profile.service_id,
            policy=policy,
            signer=signer,
            publisher=publisher,
            now=current,
        )
        try:
            write_new_json(selected_state, prepared)
        except (ContractError, OSError, ValueError) as error:
            raise PublicationError("publication state could not be created") from error

    acceptance = build_contribution_policy_acceptance(
        signer=signer,
        service_id=connector.profile.service_id,
        publisher_id=publisher["publisherId"],
        authority_id=publisher["authorityId"],
        policy_revision=policy["revision"],
        policy_digest=policy["digest"],
        request_id="request:policy-acceptance-" + token_hex(16),
        issued_at=current,
    )
    connector.accept_publication_policy(acceptance, publisher_public_key=signer.public_bytes())
    intent = prepared["intent"]
    plan = connector.negotiate_submission(intent, publisher_public_key=signer.public_bytes())
    uploaded: list[dict[str, Any]] = []
    if plan["state"] == "needs-content":
        sources = {(item["role"], item["digest"], item["byteLength"]): item["path"] for item in prepared["sources"]}
        for descriptor in plan["requiredObjects"]:
            key = (
                descriptor["role"],
                descriptor["digest"],
                descriptor["byteLength"],
            )
            path = sources.get(key)
            if path is None:
                raise PublicationError("service requested content outside the prepared publication")
            uploaded.append(
                connector.upload_submission_object(
                    intent=intent,
                    plan=plan,
                    role=descriptor["role"],
                    source=Path(path),
                )
            )
        plan = connector.negotiate_submission(intent, publisher_public_key=signer.public_bytes())
    if plan["state"] != "accepted":
        raise PublicationError("service did not accept the content-complete submission")
    status = connector.submission_status(plan["submissionRef"])
    return {
        "schemaVersion": "limitless.publication-result/1.0",
        "submissionRef": plan["submissionRef"],
        "intentDigest": intent["intentDigest"],
        "planState": plan["state"],
        "admissionState": status["state"],
        "uploadedObjects": [
            {key: item[key] for key in ("role", "digest", "byteLength", "disposition")} for item in uploaded
        ],
        "statePath": str(selected_state),
    }


def _load_publication_state(
    state_path: Path,
    *,
    service_id: str,
    signer: InstallationSigner,
    publisher: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    configured = Path(state_path)
    selected = configured if configured.is_absolute() else Path.cwd() / configured
    descriptor: int | None = None
    try:
        before = selected.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or os.name == "posix"
            and stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= MAX_PUBLICATION_STATE_BYTES
        ):
            raise PublicationError("publication state path is unsafe")
        descriptor = os.open(
            selected,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_size != before.st_size
            or current.st_dev != before.st_dev
            or current.st_ino != before.st_ino
        ):
            raise PublicationError("publication state changed or is invalid")
        encoded = bytearray()
        while len(encoded) <= MAX_PUBLICATION_STATE_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_PUBLICATION_STATE_BYTES + 1 - len(encoded)),
            )
            if not chunk:
                break
            encoded.extend(chunk)
        after = os.fstat(descriptor)
        if len(encoded) != current.st_size or after.st_size != current.st_size:
            raise PublicationError("publication state changed or is invalid")
        value = strict_json_loads(bytes(encoded).decode("utf-8"))
    except PublicationError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise PublicationError("publication state is invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return selected.resolve(strict=True), _saved_state(
        value,
        service_id=service_id,
        signer=signer,
        publisher=publisher,
    )


def _followup_status(
    connector: ServiceConnector,
    *,
    state_path: Path,
    signer: InstallationSigner,
    publisher: dict[str, Any],
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    if not isinstance(connector, ServiceConnector) or not isinstance(signer, InstallationSigner):
        raise PublicationError("publication authority is invalid")
    selected, state = _load_publication_state(
        state_path,
        service_id=connector.profile.service_id,
        signer=signer,
        publisher=publisher,
    )
    intent = state["intent"]
    reference = public_submission_ref(
        tenant_id=publisher["authorityId"],
        publisher_id=publisher["publisherId"],
        request_id=intent["requestId"],
    )
    status = connector.submission_status(reference)
    return selected, state, status


def publication_status(
    connector: ServiceConnector,
    *,
    state_path: Path,
    signer: InstallationSigner,
    publisher: dict[str, Any],
) -> dict[str, Any]:
    """Inspect one prepared publication without resending its source bytes."""

    selected, _state_value, status = _followup_status(
        connector,
        state_path=state_path,
        signer=signer,
        publisher=publisher,
    )
    return {
        "schemaVersion": "limitless.publication-status-result/1.0",
        "submissionRef": status["submissionRef"],
        "admissionState": status["state"],
        "releaseRef": status["releaseRef"],
        "reasonCodes": status["reasonCodes"],
        "generation": status["generation"],
        "updatedAt": status["updatedAt"],
        "statePath": str(selected),
    }


def revoke_publication(
    connector: ServiceConnector,
    *,
    state_path: Path,
    signer: InstallationSigner,
    publisher: dict[str, Any],
    reason_code: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Withdraw the active release bound to one prepared publication."""

    selected, _state_value, status = _followup_status(
        connector,
        state_path=state_path,
        signer=signer,
        publisher=publisher,
    )
    if status["state"] == "revoked":
        revoked = status
    else:
        release = status["releaseRef"]
        if status["state"] != "active" or release is None:
            raise PublicationError("only an active publication can be revoked")
        current = datetime.now(tz=UTC) if now is None else now
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise PublicationError("publication revocation time is invalid")
        try:
            request = build_public_release_revocation_request(
                signer=signer,
                service_id=connector.profile.service_id,
                publisher_id=publisher["publisherId"],
                authority_id=publisher["authorityId"],
                submission_ref=status["submissionRef"],
                release_id=release["releaseId"],
                reason_code=reason_code,
                request_id="request:publication-revocation-" + token_hex(16),
                issued_at=current,
            )
        except PublicAdmissionContractError as error:
            raise PublicationError("publication revocation input is invalid") from error
        revoked = connector.revoke_submission_release(
            request,
            publisher_public_key=signer.public_bytes(),
        )
    return {
        "schemaVersion": "limitless.publication-revocation-result/1.0",
        "submissionRef": revoked["submissionRef"],
        "admissionState": revoked["state"],
        "releaseRef": revoked["releaseRef"],
        "reasonCodes": revoked["reasonCodes"],
        "generation": revoked["generation"],
        "updatedAt": revoked["updatedAt"],
        "statePath": str(selected),
    }
