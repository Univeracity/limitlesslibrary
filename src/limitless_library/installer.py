"""Exact-byte installation and receiver-owned verified adoption."""

from __future__ import annotations

import copy
import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from .catalog import CatalogError, LocalCatalog
from .contracts import (
    ContractError,
    regular_file_under,
    relative_path,
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


def _directory_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    return flags | getattr(os, "O_NOFOLLOW", 0)


def _check_private_directory(descriptor: int, label: str) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        raise AdoptionError(f"{label} is not a directory")
    if os.name == "posix":
        import grp
        import pwd

        if info.st_uid != os.geteuid():
            raise AdoptionError(f"{label} must be owned by the current user")
        mode = stat.S_IMODE(info.st_mode)
        group_users = {
            account.pw_uid for account in pwd.getpwall() if account.pw_gid == info.st_gid
        }
        try:
            group_users.update(pwd.getpwnam(name).pw_uid for name in grp.getgrgid(info.st_gid).gr_mem)
        except KeyError:
            pass
        if mode & 0o002 or mode & 0o020 and any(user != os.geteuid() for user in group_users):
            raise AdoptionError(f"{label} must not be group- or world-writable")


def _open_receiver(receiver: Path) -> int:
    before = receiver.lstat()
    try:
        descriptor = os.open(receiver, _directory_flags())
    except OSError as error:
        raise AdoptionError("receiver cannot be opened safely") from error
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise AdoptionError("receiver changed while it was opened")
        _check_private_directory(descriptor, "receiver")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_parent_beneath(
    receiver_descriptor: int,
    target: str,
    created_directories: list[tuple[int, str]],
    *,
    create: bool = True,
) -> tuple[int, str]:
    parts = relative_path(target, "installation target").parts
    current = os.dup(receiver_descriptor)
    try:
        for index, part in enumerate(parts[:-1]):
            try:
                child = os.open(part, _directory_flags(), dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise AdoptionError(f"installation target parent is unavailable: {target}")
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                else:
                    created_directories.append((os.dup(current), part))
                try:
                    child = os.open(part, _directory_flags(), dir_fd=current)
                except OSError as error:
                    raise AdoptionError(
                        f"installation target parent changed during installation: {'/'.join(parts[: index + 1])}"
                    ) from error
            except OSError as error:
                raise AdoptionError(f"installation target has an unsafe parent: {target}") from error
            try:
                _check_private_directory(child, f"installation target parent {'/'.join(parts[: index + 1])}")
            except Exception:
                os.close(child)
                raise
            os.close(current)
            current = child
        return current, parts[-1]
    except Exception:
        os.close(current)
        raise


def _install_file(source: Path, parent_descriptor: int, name: str, target: str) -> str:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        # Exact components may contain private receiver material. The bundle
        # binds bytes, not a permission mode, so default new files to the
        # narrowest useful owner-only permissions.
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
    except OSError as error:
        if isinstance(error, FileExistsError):
            raise AdoptionError(f"refusing to overwrite receiver path: {target}") from error
        raise AdoptionError(f"cannot create exact installation target: {target}") from error
    installed_digest = hashlib.sha256()
    try:
        with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
            descriptor = -1
            for block in iter(lambda: input_handle.read(1024 * 1024), b""):
                output_handle.write(block)
                installed_digest.update(block)
            output_handle.flush()
            os.fsync(output_handle.fileno())
    except Exception:
        try:
            os.unlink(name, dir_fd=parent_descriptor)
        except OSError:
            pass
        raise
    finally:
        if descriptor != -1:
            os.close(descriptor)
    return "sha256:" + installed_digest.hexdigest()


def _sha256_beneath(receiver_descriptor: int, target: str) -> str:
    parent, name = _open_parent_beneath(receiver_descriptor, target, [], create=False)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        os.close(parent)
        raise AdoptionError(f"installed target is unavailable or unsafe: {target}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AdoptionError(f"installed target is not a regular file: {target}")
        value = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                value.update(block)
        return "sha256:" + value.hexdigest()
    finally:
        if descriptor != -1:
            os.close(descriptor)
        os.close(parent)


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
    prepared: list[tuple[dict[str, str], Path, str]] = []
    for mapping in recipe["mappings"]:
        try:
            source = regular_file_under(capsule_root, mapping["source"], "capsule source")
            relative_path(mapping["target"], "installation target")
        except ContractError as error:
            raise AdoptionError(str(error)) from error
        declared = file_by_source[mapping["source"]]
        if sha256_file(source) != declared["digest"]:
            raise AdoptionError(f"capsule source changed: {mapping['source']}")
        prepared.append((mapping, source, mapping["target"]))
    if receipt_path is not None and Path(receipt_path).exists():
        raise AdoptionError(f"refusing to overwrite adoption receipt: {receipt_path}")

    receiver_descriptor = _open_receiver(receiver)
    created_files: list[tuple[int, str]] = []
    created_directories: list[tuple[int, str]] = []
    try:
        installed: list[dict[str, str]] = []
        for mapping, source, target in prepared:
            parent, name = _open_parent_beneath(receiver_descriptor, target, created_directories)
            try:
                digest = _install_file(source, parent, name, target)
            except Exception:
                os.close(parent)
                raise
            created_files.append((parent, name))
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
            if _sha256_beneath(receiver_descriptor, item["target"]) != item["digest"]:
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
        for descriptor, _name in created_files:
            os.close(descriptor)
        for descriptor, _name in created_directories:
            os.close(descriptor)
        os.close(receiver_descriptor)
        return receipt
    except (AdoptionError, CatalogError, ContractError, OSError, SandboxError) as error:
        for descriptor, name in reversed(created_files):
            try:
                os.unlink(name, dir_fd=descriptor)
            except OSError:
                pass
            os.close(descriptor)
        for descriptor, name in reversed(created_directories):
            try:
                os.rmdir(name, dir_fd=descriptor)
            except OSError:
                pass
            os.close(descriptor)
        os.close(receiver_descriptor)
        if isinstance(error, AdoptionError):
            raise
        raise AdoptionError(str(error)) from error
