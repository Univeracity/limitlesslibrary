"""One-command, resumable anonymous publication to the official service."""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from secrets import token_hex
from typing import Any

from .contracts import ContractError, load_json, sha256_json, write_new_json
from .public_admission_contracts import build_contribution_policy_acceptance
from .public_submission_contracts import (
    PublicSubmissionContractError,
    build_submission_intent,
    validate_submission_intent,
)
from .service_connector import ServiceConnector, ServiceConnectorError
from .service_identity import InstallationSigner

PUBLICATION_DRAFT_SCHEMA_VERSION = "limitless.publication-draft/1.0"
PUBLICATION_STATE_SCHEMA_VERSION = "limitless.publication-state/1.0"
MAX_PUBLICATION_DRAFT_BYTES = 64 * 1024


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
            while True:
                chunk = os.read(descriptor, 128 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
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
        contentObjects=[{key: item[key] for key in ("role", "digest", "byteLength")} for item in sources],
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


def _state(
    value: Any,
    *,
    draft: dict[str, Any],
    service_id: str,
    policy: dict[str, str],
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
    if (
        value["schemaVersion"] != PUBLICATION_STATE_SCHEMA_VERSION
        or value["serviceId"] != service_id
        or value["publicationPolicy"] != {"revision": policy["revision"], "digest": policy["digest"]}
        or value["draftDigest"] != sha256_json(draft)
        or value["publisher"] != expected_publisher
        or not isinstance(value["sources"], list)
    ):
        raise PublicationError("publication state differs from current authority")
    try:
        intent = validate_submission_intent(value["intent"], public_keys={signer.key_id: signer.public_bytes()})
    except PublicSubmissionContractError as error:
        raise PublicationError("publication state intent is invalid") from error
    sources: list[dict[str, Any]] = []
    for item in value["sources"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"role", "digest", "byteLength", "path"}
            or not isinstance(item["path"], str)
            or not Path(item["path"]).is_absolute()
        ):
            raise PublicationError("publication state source is invalid")
        sources.append(dict(item))
    declared = {(item["role"], item["digest"], item["byteLength"]) for item in intent["contentObjects"]}
    if {(item["role"], item["digest"], item["byteLength"]) for item in sources} != declared:
        raise PublicationError("publication state sources differ from its intent")
    return {**value, "intent": intent, "sources": sources}


def publish_draft(
    connector: ServiceConnector,
    *,
    draft_path: Path,
    state_path: Path | None,
    signer: InstallationSigner,
    publisher: dict[str, Any],
    accept_publication_policy: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Prepare once, resume safely, and publish only explicitly named bytes."""

    if not accept_publication_policy:
        raise PublicationError("review the advertised publication policy and pass --accept-publication-policy")
    if not isinstance(connector, ServiceConnector) or not isinstance(signer, InstallationSigner):
        raise PublicationError("publication authority is invalid")
    try:
        selected_draft = Path(draft_path).resolve(strict=True)
        draft_info = selected_draft.stat()
    except OSError as error:
        raise PublicationError("publication draft is unavailable") from error
    if not stat.S_ISREG(draft_info.st_mode) or not 1 <= draft_info.st_size <= MAX_PUBLICATION_DRAFT_BYTES:
        raise PublicationError("publication draft is invalid")
    selected_state = (
        default_publication_state_path(selected_draft) if state_path is None else Path(state_path).resolve(strict=False)
    )
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
    current = datetime.now(tz=UTC) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise PublicationError("publication time is invalid")
    current = current.astimezone(UTC).replace(microsecond=0)

    if selected_state.is_symlink():
        raise PublicationError("publication state path is unsafe")
    if selected_state.exists():
        try:
            state_info = selected_state.lstat()
        except OSError as error:
            raise PublicationError("publication state is unavailable") from error
        if not stat.S_ISREG(state_info.st_mode) or (os.name == "posix" and stat.S_IMODE(state_info.st_mode) != 0o600):
            raise PublicationError("publication state path is unsafe")
        try:
            prepared = _state(
                load_json(selected_state),
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
