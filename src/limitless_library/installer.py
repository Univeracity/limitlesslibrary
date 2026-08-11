"""Exact-byte installation and receiver-owned verified adoption."""

from __future__ import annotations

import copy
import os
import stat
from pathlib import Path
from typing import Any

from .catalog import CatalogError, LocalCatalog
from .contracts import (
    ContractError,
    regular_file_under,
    relative_path,
    safe_destination,
    sha256_file,
    sha256_json,
    tree_digest,
    utc_now,
    without,
    write_new_json,
)
from .sandbox import SandboxError, run_receiver_verifier
from .schemas import SchemaError, validate


class AdoptionError(RuntimeError):
    """An exact component could not be installed and verified safely."""


def _recipe_digest(recipe: dict[str, Any]) -> str:
    return sha256_json(without(recipe, "recipeDigest"))


def seal_recipe(draft: dict[str, Any], receiver: Path) -> dict[str, Any]:
    """Bind a receiver-authored recipe to the receiver's verifier bytes."""

    if "recipeDigest" in draft:
        raise AdoptionError("recipe draft must not predeclare recipeDigest")
    recipe = copy.deepcopy(draft)
    verifiers = recipe.get("verifiers")
    if not isinstance(verifiers, list):
        raise AdoptionError("recipe draft must contain verifiers")
    for verifier in verifiers:
        if not isinstance(verifier, dict):
            raise AdoptionError("recipe verifiers must be objects")
        source = verifier.get("source")
        if not isinstance(source, dict) or set(source) != {"path"}:
            raise AdoptionError("recipe draft verifier source must contain only path")
        try:
            file = regular_file_under(receiver, source["path"], "verifier source")
        except ContractError as error:
            raise AdoptionError(str(error)) from error
        source["digest"] = sha256_file(file)
    recipe["recipeDigest"] = _recipe_digest(recipe)
    validate_recipe(recipe, receiver)
    return recipe


def validate_recipe(recipe: dict[str, Any], receiver: Path) -> dict[str, Any]:
    try:
        validate(recipe, "recipe-0.1.schema.json", "recipe")
    except SchemaError as error:
        raise AdoptionError(str(error)) from error
    if recipe["recipeDigest"] != _recipe_digest(recipe):
        raise AdoptionError("recipeDigest does not bind the exact recipe")
    sources = [mapping["source"] for mapping in recipe["mappings"]]
    targets = [mapping["target"] for mapping in recipe["mappings"]]
    if len(sources) != len(set(sources)) or len(targets) != len(set(targets)):
        raise AdoptionError("recipe mappings must have unique sources and targets")
    verifier_ids = [verifier["id"] for verifier in recipe["verifiers"]]
    if len(verifier_ids) != len(set(verifier_ids)):
        raise AdoptionError("recipe verifier IDs must be unique")
    kinds = [verifier["kind"] for verifier in recipe["verifiers"]]
    if kinds.count("adherence") != 1 or "obligation" not in kinds:
        raise AdoptionError("recipe requires exactly one adherence verifier and at least one obligation verifier")
    for mapping in recipe["mappings"]:
        try:
            relative_path(mapping["source"], "mapping source")
            relative_path(mapping["target"], "mapping target")
        except ContractError as error:
            raise AdoptionError(str(error)) from error
    for verifier in recipe["verifiers"]:
        try:
            source = regular_file_under(receiver, verifier["source"]["path"], "verifier source")
        except ContractError as error:
            raise AdoptionError(str(error)) from error
        if sha256_file(source) != verifier["source"]["digest"]:
            raise AdoptionError(f"verifier bytes differ: {verifier['id']}")
        for item in verifier["argv"]:
            if ("{" in item or "}" in item) and item not in {"{python}", "{receiver}"}:
                raise AdoptionError(f"verifier {verifier['id']} uses an unsupported argv placeholder")
    return recipe


def _real_receiver(receiver: Path) -> Path:
    receiver = Path(receiver)
    try:
        info = receiver.lstat()
    except OSError as error:
        raise AdoptionError(f"receiver is unavailable: {receiver}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AdoptionError("receiver must be a real directory")
    return receiver.resolve()


def _make_parent_directories(receiver: Path, destination: Path, created: list[Path]) -> None:
    missing: list[Path] = []
    current = destination.parent
    while current != receiver and not current.exists() and not current.is_symlink():
        missing.append(current)
        current = current.parent
    if current != receiver:
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise AdoptionError("installation target parent is unsafe")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o755)
        except FileExistsError:
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise AdoptionError("installation target parent changed during installation")
        else:
            created.append(directory)


def _install_file(source: Path, destination: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, 0o644)
    except OSError as error:
        raise AdoptionError(f"cannot create exact installation target: {destination}") from error
    try:
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            descriptor = -1
            for block in iter(lambda: input_handle.read(1024 * 1024), b""):
                output_handle.write(block)
            output_handle.flush()
            os.fsync(output_handle.fileno())
    finally:
        if descriptor != -1:
            os.close(descriptor)


def _validate_verifier_result(result: dict[str, Any], verifier: dict[str, Any], asset_digest: str) -> None:
    try:
        validate(result, "verifier-result-0.1.schema.json", f"verifier result {verifier['id']}")
    except SchemaError as error:
        raise AdoptionError(str(error)) from error
    if result["verifierId"] != verifier["id"] or result["kind"] != verifier["kind"]:
        raise AdoptionError(f"verifier result identity differs: {verifier['id']}")
    if verifier["kind"] == "adherence" and result["assetDigest"] != asset_digest:
        raise AdoptionError("adherence verifier did not bind the selected capsule")


def adopt_exact_component(
    catalog: LocalCatalog,
    decision: dict[str, Any],
    recipe: dict[str, Any],
    receiver: Path,
    *,
    owner_authorized: bool,
    receipt_path: Path | None = None,
) -> dict[str, Any]:
    """Install exact bytes, run bound receiver checks, and emit adoption evidence.

    On any failure, files created by this invocation are removed. Existing
    receiver files are never overwritten.
    """

    if owner_authorized is not True:
        raise AdoptionError("receiver owner authorization must be explicitly asserted")
    receiver = _real_receiver(receiver)
    try:
        catalog.validate_decision(decision)
        validate_recipe(recipe, receiver)
    except (CatalogError, AdoptionError) as error:
        raise AdoptionError(str(error)) from error
    if decision["decision"] != "reuse" or decision["treatment"] != "exact-adoption":
        raise AdoptionError("only an exact-adoption reuse decision can be installed")
    selected = decision["selected"]
    if selected is None:
        raise AdoptionError("exact-adoption decision has no selected offer")
    offer = selected["offer"]
    if recipe["offerRef"] != {"capsuleDigest": selected["capsule"]["digest"], "offerId": offer["id"]}:
        raise AdoptionError("recipe is not bound to the selected offer")
    declared_sources = [item["source"] for item in offer["files"]]
    mapping_sources = [item["source"] for item in recipe["mappings"]]
    if sorted(declared_sources) != sorted(mapping_sources):
        raise AdoptionError("recipe must map every exact source exactly once")
    capsule_root = catalog.selected_capsule_root(decision)
    file_by_source = {item["source"]: item for item in offer["files"]}
    prepared: list[tuple[dict[str, str], Path, Path]] = []
    for mapping in recipe["mappings"]:
        try:
            source = regular_file_under(capsule_root, mapping["source"], "capsule source")
            destination = safe_destination(receiver, mapping["target"])
        except ContractError as error:
            raise AdoptionError(str(error)) from error
        declared = file_by_source[mapping["source"]]
        if sha256_file(source) != declared["digest"]:
            raise AdoptionError(f"capsule source changed: {mapping['source']}")
        prepared.append((mapping, source, destination))
    if receipt_path is not None and Path(receipt_path).exists():
        raise AdoptionError(f"refusing to overwrite adoption receipt: {receipt_path}")

    created_files: list[Path] = []
    created_directories: list[Path] = []
    try:
        installed: list[dict[str, str]] = []
        for mapping, source, destination in prepared:
            _make_parent_directories(receiver, destination, created_directories)
            _install_file(source, destination)
            created_files.append(destination)
            digest = sha256_file(destination)
            if digest != file_by_source[mapping["source"]]["digest"]:
                raise AdoptionError(f"installed bytes differ: {mapping['target']}")
            installed.append({"source": mapping["source"], "target": mapping["target"], "digest": digest})

        verifier_evidence: list[dict[str, str]] = []
        asset_digest = selected["capsule"]["digest"]
        for verifier in recipe["verifiers"]:
            result = run_receiver_verifier(verifier, receiver, asset_digest=asset_digest)
            _validate_verifier_result(result, verifier, asset_digest)
            verifier_evidence.append(
                {
                    "id": verifier["id"],
                    "kind": verifier["kind"],
                    "verifierDigest": verifier["source"]["digest"],
                    "resultDigest": sha256_json(result),
                }
            )
        for item in installed:
            if sha256_file(regular_file_under(receiver, item["target"], "installed target")) != item["digest"]:
                raise AdoptionError(f"installed bytes changed during verification: {item['target']}")
        receipt = {
            "schemaVersion": "limitless.adoption-receipt/0.1",
            "generatedAt": utc_now(),
            "decisionDigest": decision["decisionDigest"],
            "recipeDigest": recipe["recipeDigest"],
            "capsule": copy.deepcopy(selected["capsule"]),
            "offerId": offer["id"],
            "installedFiles": installed,
            "verifierResults": verifier_evidence,
            "receiverStateDigest": tree_digest(receiver),
            "containment": {
                "network": "none",
                "filesystem": "read-only-worktree",
                "secrets": "none",  # pragma: allowlist secret -- containment declaration
                "runner": "bubblewrap",
            },
            "disposition": {
                "technicalIntegrationVerified": True,
                "runtimeAdherenceVerified": True,
                "ownerAuthorization": "operator-asserted",
            },
        }
        receipt["receiptDigest"] = sha256_json(receipt)
        try:
            validate(receipt, "adoption-receipt-0.1.schema.json", "adoption receipt")
        except SchemaError as error:
            raise AdoptionError(str(error)) from error
        if receipt_path is not None:
            write_new_json(Path(receipt_path), receipt)
        return receipt
    except (AdoptionError, CatalogError, ContractError, SandboxError) as error:
        for path in reversed(created_files):
            path.unlink(missing_ok=True)
        for directory in reversed(created_directories):
            try:
                directory.rmdir()
            except OSError:
                pass
        if isinstance(error, AdoptionError):
            raise
        raise AdoptionError(str(error)) from error
