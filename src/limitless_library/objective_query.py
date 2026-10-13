"""One objective, one bounded treatment, with owner-owned local continuation."""

from __future__ import annotations

import copy
import os
import re
import secrets
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .contracts import canonical_json_bytes, sha256_json, utc_now, without, write_new_json
from .method_capture import CapturedMethodCatalog
from .method_projection import local_method
from .official_service import (
    OfficialServiceActivationError,
    OfficialServiceNotConfiguredError,
    OfficialServiceUnavailableError,
    activated_service_connector,
    load_activation_state,
)
from .query_policy import QueryPolicyError, load_query_policy, private_directory, read_private_json, resolve_receivers
from .schemas import SchemaError, validate
from .service_connector import ServiceConnector, ServiceConnectorError, ServiceUnavailableError

QUERY_REF = re.compile(r"^query:([0-9a-f]{32})$")
MAX_VIEW_BYTES = 32 * 1024
MAX_QUERY_RECORD_BYTES = 256 * 1024
MAX_QUERY_RECORDS = 2000


class ObjectiveQueryError(ValueError):
    """The objective or its host-owned continuation is invalid."""


def save_query_record(root: Path, reference: str, payload: dict[str, Any]) -> None:
    match = QUERY_REF.fullmatch(reference)
    if match is None:
        raise ObjectiveQueryError("query reference is invalid")
    directory = private_directory(root)
    import fcntl

    lock = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            raise ObjectiveQueryError("private query lock must be a regular file")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if len(list(directory.glob("query-*.json"))) >= MAX_QUERY_RECORDS:
            raise ObjectiveQueryError("private query record capacity is exhausted")
        record = {"schemaVersion": "limitless.private-query-record/1.0", "queryRef": reference, "payload": payload}
        record["recordDigest"] = sha256_json(record)
        if len(canonical_json_bytes(record)) > MAX_QUERY_RECORD_BYTES:
            raise ObjectiveQueryError("private query record exceeds its byte limit")
        write_new_json(directory / f"query-{match.group(1)}.json", record)
    finally:
        os.close(lock)


def load_query_record(root: Path, reference: str) -> dict[str, Any]:
    match = QUERY_REF.fullmatch(reference)
    if match is None:
        raise ObjectiveQueryError("query reference is invalid")
    directory = private_directory(root, create=False)
    record = read_private_json(directory / f"query-{match.group(1)}.json", maximum=MAX_QUERY_RECORD_BYTES)
    if (
        set(record) != {"schemaVersion", "queryRef", "payload", "recordDigest"}
        or record["schemaVersion"] != "limitless.private-query-record/1.0"
        or record["queryRef"] != reference
        or record["recordDigest"] != sha256_json(without(record, "recordDigest"))
        or not isinstance(record["payload"], dict)
    ):
        raise ObjectiveQueryError("private query record is invalid or changed")
    return record["payload"]


def validate_objective_result(value: dict[str, Any]) -> dict[str, Any]:
    try:
        validate(value, "objective-result-1.0.schema.json", "objective result")
        if value["resultDigest"] != sha256_json(without(value, "resultDigest")):
            raise ObjectiveQueryError("objective result digest differs")
        if len(canonical_json_bytes(value)) > MAX_VIEW_BYTES:
            raise ObjectiveQueryError("objective result exceeds its byte limit")
    except SchemaError as error:
        raise ObjectiveQueryError(str(error)) from error
    return value


class ObjectiveQueryEngine:
    """Policy is reloaded on each call; legacy tools never invoke this engine."""

    def __init__(
        self,
        catalog: CapturedMethodCatalog,
        *,
        policy_path: Path | None,
        state_dir: Path | None,
        connector_factory: Callable[[], ServiceConnector] = activated_service_connector,
        now: Callable[[], str] = utc_now,
    ):
        self.catalog = catalog
        self.policy_path = policy_path
        self.state_dir = state_dir
        self._factory = connector_factory
        self._now = now
        self._connector: ServiceConnector | None = None
        self._service_profile_digest: str | None = None

    def _service(self) -> ServiceConnector:
        if self._factory is activated_service_connector:
            activation = load_activation_state()
            if activation is None:
                raise OfficialServiceNotConfiguredError("official service is disabled")
            digest = activation["profileDigest"]
            if digest != self._service_profile_digest:
                self._connector = None
                self._service_profile_digest = digest
        if self._connector is None:
            self._connector = self._factory()
        return self._connector

    def check(self, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            validate(arguments, "objective-query-1.0.schema.json", "objective query")
            objective = arguments["objective"].strip()
            if not objective:
                raise ObjectiveQueryError("objective must contain text")
            policy = load_query_policy(self.policy_path)
            receiver, service_receiver = resolve_receivers(policy)
        except (SchemaError, QueryPolicyError) as error:
            raise ObjectiveQueryError(str(error)) from error
        evaluated_at = self._now()
        match, complete = self.catalog.query_objective(
            objective,
            receiver=receiver,
            requested_uses=tuple(policy["requestedUses"]),
            tenant_scopes=tuple(policy["tenantScopes"]),
            evaluated_at=evaluated_at,
            allow_exact=policy["allowExact"] and policy["localReceiver"] is not None,
        )
        coverage = {"local": "complete" if complete else "partial", "service": "disabled", "continuation": "available"}
        selection = None
        origin = None
        treatment = "abstain"
        integrity = "not-applicable"
        reason = "no-safe-selection"
        query = None
        service_result = None
        if match is not None:
            chosen = match["decision"]["selected"]
            treatment = "exact-component" if chosen["offer"]["kind"] == "exact-component" else "source-free-method"
            origin = "local"
            integrity = "local-digest"
            reason = "matched-local"
            selection = {
                "reference": chosen["offer"]["id"],
                "version": chosen["capsule"]["version"],
                "digest": chosen["capsule"]["digest"],
                "title": match["title"],
                "license": chosen["capsule"]["license"],
                "method": chosen["offer"]["method"],
            }
            if policy["executionMode"] == "service":
                coverage["service"] = "not-needed"
        elif policy["executionMode"] == "service":
            try:
                connector = self._service()
                query = connector.build_query(
                    request_id="request:library-" + secrets.token_hex(16),
                    objective=objective,
                    receiver_context=service_receiver,
                    requested_treatments=("exact-component", "source-free-method")
                    if policy["allowExact"]
                    else ("source-free-method",),
                )
                if sha256_json(load_query_policy(self.policy_path)) != sha256_json(policy):
                    raise QueryPolicyError("query policy changed before objective transfer")
                service_result = connector.query(query)
                coverage["service"] = "complete"
                if service_result["treatment"] != "abstention":
                    treatment = service_result["treatment"]
                    origin = "service"
                    integrity = "service-signature"
                    reason = "matched-service"
                    chosen = service_result["selection"]
                    selection = {
                        "reference": chosen["capabilityId"],
                        "version": chosen.get("immutable", {}).get("revision"),
                        "digest": chosen["cardDigest"],
                        "title": chosen["title"],
                        "license": chosen["provenance"]["license"],
                        "method": local_method(chosen["method"]) if treatment == "source-free-method" else None,
                    }
            except (OfficialServiceUnavailableError, OfficialServiceNotConfiguredError, ServiceUnavailableError):
                coverage["service"] = "unavailable"
                reason = "service-unavailable"
            except QueryPolicyError:
                query = None
                coverage["service"] = "policy-attention"
                reason = "query-policy-changed"
            except (OfficialServiceActivationError, ServiceConnectorError):
                self._connector = None
                coverage["service"] = "verification-failed"
                reason = "service-verification-failed"
        reference = "query:" + secrets.token_hex(16)
        view = {
            "schemaVersion": "limitless.objective-result/1.0",
            "queryRef": reference,
            "objectiveDigest": sha256_json({"objective": objective}),
            "policyDigest": sha256_json(policy),
            "receiverDigest": sha256_json({"local": receiver, "service": service_receiver}),
            "treatment": treatment,
            "origin": origin,
            "selection": selection,
            "nextAction": "apply-method-and-check"
            if treatment == "source-free-method"
            else "verify-before-adoption"
            if treatment == "exact-component"
            else "start-fresh",
            "assurance": {"selectionIntegrity": integrity, "outcome": "not-asserted"},
            "coverage": coverage,
            "reason": reason,
        }
        if len(canonical_json_bytes({**view, "resultDigest": "sha256:" + "0" * 64})) > MAX_VIEW_BYTES:
            view.update(
                {
                    "treatment": "abstain",
                    "origin": None,
                    "selection": None,
                    "nextAction": "start-fresh",
                    "reason": "result-too-large",
                }
            )
            view["assurance"]["selectionIntegrity"] = "not-applicable"
            match = query = service_result = None
        payload = {
            "objective": objective,
            "evaluatedAt": evaluated_at,
            "policy": policy,
            "receiver": receiver,
            "serviceReceiver": service_receiver,
            "localMatch": match,
            "serviceQuery": query,
            "serviceResult": service_result,
        }
        try:
            if self.state_dir is None or os.name != "posix":
                raise ObjectiveQueryError("private continuation storage is unavailable")
            save_query_record(self.state_dir, reference, payload)
        except (OSError, ValueError):
            view["queryRef"] = None
            coverage["continuation"] = "unavailable"
        view["resultDigest"] = sha256_json(view)
        validate_objective_result(view)
        return copy.deepcopy(view)
