"""Sanitized, source-minimized local Work Capsule catalog."""

from __future__ import annotations

import copy
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import (
    ContractError,
    load_json,
    parse_utc,
    regular_file_under,
    relative_path,
    sha256_file,
    sha256_json,
    without,
)
from .schemas import SchemaError, validate


class CatalogError(ValueError):
    """A catalog cannot produce a safe, bound decision."""


_WORD = re.compile(r"[a-z0-9]+")
_SEARCH_NOISE = frozenset(
    {
        "a",
        "about",
        "an",
        "and",
        "for",
        "from",
        "in",
        "into",
        "library",
        "local",
        "method",
        "of",
        "omarchy",
        "plugin",
        "the",
        "to",
        "user",
        "with",
    }
)


@dataclass(frozen=True)
class _Capsule:
    root: Path
    record: dict[str, Any]


def _capsule_digest(capsule: dict[str, Any]) -> str:
    return sha256_json(without(capsule, "capsuleDigest"))


def seal_capsule(draft: dict[str, Any], root: Path) -> dict[str, Any]:
    """Bind exact offer files and the complete capsule to their current bytes."""

    if "capsuleDigest" in draft:
        raise CatalogError("capsule draft must not predeclare capsuleDigest")
    capsule = copy.deepcopy(draft)
    try:
        offers = capsule["offers"]
    except (KeyError, TypeError) as error:
        raise CatalogError("capsule draft must contain offers") from error
    if not isinstance(offers, list):
        raise CatalogError("capsule offers must be an array")
    for offer in offers:
        if not isinstance(offer, dict):
            raise CatalogError("capsule offers must be objects")
        if offer.get("kind") == "exact-component":
            files = offer.get("files")
            if not isinstance(files, list):
                raise CatalogError("exact-component offer must contain files")
            for item in files:
                if not isinstance(item, dict) or set(item) != {"source"}:
                    raise CatalogError("exact-component draft files must contain only source")
                try:
                    source = regular_file_under(root, item["source"], "capsule source")
                except ContractError as error:
                    raise CatalogError(str(error)) from error
                item["digest"] = sha256_file(source)
    capsule["capsuleDigest"] = _capsule_digest(capsule)
    validate_capsule(capsule, root)
    return capsule


def validate_capsule(capsule: dict[str, Any], root: Path) -> dict[str, Any]:
    try:
        validate(capsule, "capsule-0.1.schema.json", "capsule")
    except SchemaError as error:
        raise CatalogError(str(error)) from error
    if capsule["capsuleDigest"] != _capsule_digest(capsule):
        raise CatalogError("capsuleDigest does not bind the exact capsule record")
    offer_ids: set[str] = set()
    for offer in capsule["offers"]:
        if offer["id"] in offer_ids:
            raise CatalogError(f"duplicate offer id: {offer['id']}")
        offer_ids.add(offer["id"])
        if offer["kind"] != "exact-component":
            continue
        sources: set[str] = set()
        for item in offer["files"]:
            try:
                relative_path(item["source"], "capsule source")
                source = regular_file_under(root, item["source"], "capsule source")
            except ContractError as error:
                raise CatalogError(str(error)) from error
            if item["source"] in sources:
                raise CatalogError(f"duplicate exact source: {item['source']}")
            sources.add(item["source"])
            if sha256_file(source) != item["digest"]:
                raise CatalogError(f"exact source digest differs: {item['source']}")
    return capsule


def _matches(offer: dict[str, Any], request: dict[str, Any]) -> bool:
    if offer["taskKind"] != request["taskKind"]:
        return False
    policy = offer["policy"]
    if policy["state"] != "active":
        return False
    if request["requestedUse"] not in policy["allowedUses"] and "*" not in policy["allowedUses"]:
        return False
    if request["tenantScope"] not in policy["tenantScopes"] and "*" not in policy["tenantScopes"]:
        return False
    compatibility = offer["compatibility"]
    if not set(compatibility["constraints"]).issubset(request["receiver"]["constraints"]):
        return False
    receiver_toolchain = request["receiver"]["toolchain"]
    return all(receiver_toolchain.get(name) in allowed for name, allowed in compatibility["toolchain"].items())


def _public_offer(offer: dict[str, Any]) -> dict[str, Any]:
    """Project only material the receiver needs after policy evaluation."""

    return {key: copy.deepcopy(offer[key]) for key in ("id", "kind", "taskKind", "files", "method")}


def _search_terms(value: str) -> set[str]:
    return {term for term in _WORD.findall(value.lower()) if len(term) > 1 and term not in _SEARCH_NOISE}


def _objective_score(capsule: dict[str, Any], offer: dict[str, Any], objective: str) -> int:
    """Return a conservative lexical tie-break score for one eligible offer.

    Eligibility, rights, compatibility, and explicit priority remain controlling.
    Objective text is used only when otherwise-equal eligible offers would force
    an abstention, and only a unique positive match can break that tie.
    """

    query = _search_terms(objective)
    if not query:
        return 0
    title = _search_terms(str(capsule.get("title", "")))
    method = offer.get("method")
    if not isinstance(method, dict):
        return 5 * len(query & title)
    summary = _search_terms(str(method.get("summary", "")))
    details: set[str] = set()
    for field in ("steps", "verification"):
        values = method.get(field)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str):
                    details.update(_search_terms(value))
    return 5 * len(query & title) + 3 * len(query & summary) + len(query & details)


class LocalCatalog:
    """An immutable-on-load catalog of independently redistributable capsules."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        try:
            info = self.root.lstat()
        except OSError as error:
            raise CatalogError(f"catalog root is unavailable: {self.root}") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise CatalogError("catalog root must be a real directory")
        capsules: list[_Capsule] = []
        for manifest in sorted(self.root.glob("*/capsule.json")):
            if manifest.is_symlink() or manifest.parent.is_symlink():
                raise CatalogError(f"catalog manifest crosses a symlink: {manifest}")
            try:
                record = load_json(manifest)
                validate_capsule(record, manifest.parent)
            except (ContractError, CatalogError) as error:
                raise CatalogError(f"cannot load {manifest.relative_to(self.root)}: {error}") from error
            capsules.append(_Capsule(root=manifest.parent, record=record))
        if not capsules:
            raise CatalogError("catalog contains no capsule.json manifests")
        identities: set[tuple[str, str]] = set()
        for capsule in capsules:
            identity = (capsule.record["id"], capsule.record["version"])
            if identity in identities:
                raise CatalogError(f"duplicate capsule identity: {identity[0]} {identity[1]}")
            identities.add(identity)
        self._capsules = tuple(capsules)
        self.catalog_digest = sha256_json(
            [
                {
                    "id": capsule.record["id"],
                    "version": capsule.record["version"],
                    "digest": capsule.record["capsuleDigest"],
                }
                for capsule in sorted(capsules, key=lambda item: (item.record["id"], item.record["version"]))
            ]
        )

    def query(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return one exact offer, one method, or non-disclosing abstention."""

        try:
            validate(request, "query-0.1.schema.json", "query")
            parse_utc(request["evaluatedAt"], "evaluatedAt")
        except (SchemaError, ContractError) as error:
            raise CatalogError(str(error)) from error
        candidates: list[tuple[int, str, str, _Capsule, dict[str, Any]]] = []
        for capsule in self._capsules:
            for offer in capsule.record["offers"]:
                if _matches(offer, request):
                    candidates.append((offer["priority"], capsule.record["id"], offer["id"], capsule, offer))
        candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        selected_candidate: tuple[int, str, str, _Capsule, dict[str, Any]] | None = None
        if candidates:
            top_priority = candidates[0][0]
            top = [candidate for candidate in candidates if candidate[0] == top_priority]
            if len(top) == 1:
                selected_candidate = top[0]
            elif isinstance(request.get("objective"), str):
                ranked = sorted(
                    ((_objective_score(item[3].record, item[4], request["objective"]), item) for item in top),
                    key=lambda item: (-item[0], item[1][1], item[1][2]),
                )
                if ranked[0][0] > 0 and ranked[0][0] > ranked[1][0]:
                    selected_candidate = ranked[0][1]
        selected: dict[str, Any] | None = None
        if selected_candidate is not None:
            capsule = selected_candidate[3].record
            offer = selected_candidate[4]
            selected = {
                "capsule": {
                    "id": capsule["id"],
                    "version": capsule["version"],
                    "digest": capsule["capsuleDigest"],
                    "license": capsule["license"],
                },
                "offer": _public_offer(offer),
            }
        if selected is None:
            decision = "abstain"
            treatment = "abstain"
            reason = "no-safe-selection"
        elif selected["offer"]["kind"] == "exact-component":
            decision = "reuse"
            treatment = "exact-adoption"
            reason = "eligible-offer"
        else:
            decision = "instantiate"
            treatment = "method-guided"
            reason = "eligible-offer"
        result = {
            "schemaVersion": "limitless.decision/0.1",
            "decision": decision,
            "treatment": treatment,
            "requestDigest": sha256_json(request),
            "catalogDigest": self.catalog_digest,
            "selected": selected,
            "reason": reason,
        }
        result["decisionDigest"] = sha256_json(result)
        self.validate_decision(result, request=request)
        return result

    def validate_decision(self, decision: dict[str, Any], *, request: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            validate(decision, "decision-0.1.schema.json", "decision")
        except SchemaError as error:
            raise CatalogError(str(error)) from error
        if decision["decisionDigest"] != sha256_json(without(decision, "decisionDigest")):
            raise CatalogError("decisionDigest does not bind the exact decision")
        if decision["catalogDigest"] != self.catalog_digest:
            raise CatalogError("decision is stale or belongs to another catalog")
        if request is not None and decision["requestDigest"] != sha256_json(request):
            raise CatalogError("decision is not bound to this query")
        if decision["selected"] is None:
            return decision
        selected = decision["selected"]
        matches = [
            capsule
            for capsule in self._capsules
            if capsule.record["id"] == selected["capsule"]["id"]
            and capsule.record["version"] == selected["capsule"]["version"]
            and capsule.record["capsuleDigest"] == selected["capsule"]["digest"]
            and capsule.record["license"] == selected["capsule"]["license"]
        ]
        if len(matches) != 1:
            raise CatalogError("selected capsule is unavailable or ambiguous")
        offers = [offer for offer in matches[0].record["offers"] if _public_offer(offer) == selected["offer"]]
        if len(offers) != 1:
            raise CatalogError("selected offer differs from the current capsule")
        return decision

    def selected_capsule_root(self, decision: dict[str, Any]) -> Path:
        self.validate_decision(decision)
        selected = decision.get("selected")
        if selected is None:
            raise CatalogError("abstention has no capsule root")
        for capsule in self._capsules:
            if capsule.record["capsuleDigest"] == selected["capsule"]["digest"]:
                return capsule.root
        raise CatalogError("selected capsule is unavailable")
