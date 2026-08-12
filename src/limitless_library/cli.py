"""Command-line interface for the sanitized local alpha."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import CatalogError, LocalCatalog, seal_capsule
from .contracts import ContractError, load_json, write_new_json
from .demo import DemoError, format_demo, run_demo
from .installer import AdoptionError, adopt_exact_component, seal_recipe, validate_recipe
from .sandbox import containment_readiness


def _print(value: dict[str, object]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _format_doctor(result: dict[str, object]) -> str:
    checks = result["checks"]
    if not isinstance(checks, dict):
        raise TypeError("doctor checks must be an object")

    def state(name: str) -> str:
        return "ready" if checks[name] is True else "blocked"

    lines = [
        "Limitless local readiness",
        "",
        f"  Python: {result['pythonVersion']}",
        f"  Linux host: {state('linuxHost')}",
        f"  POSIX resource limits: {state('posixResourceLimits')}",
        f"  Bubblewrap executable: {state('bubblewrapExecutable')}",
        f"  Bubblewrap containment probe: {state('bubblewrapProbe')}",
        "",
    ]
    if result["status"] == "ready":
        lines.append("READY: exact adoption can run with receiver-owned containment.")
    else:
        lines.extend([f"BLOCKED: {result['reason']}", f"Next: {result['remediation']}"])
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo = subparsers.add_parser("demo", help="run the complete verified-reuse lifecycle locally")
    demo.add_argument("--workspace", type=Path, help="new directory in which to retain all demo evidence")
    demo.add_argument("--format", choices=("text", "json"), default="text")

    doctor = subparsers.add_parser("doctor", help="check whether exact adoption can run safely on this host")
    doctor.add_argument("--format", choices=("text", "json"), default="text")

    validate_catalog = subparsers.add_parser("validate-catalog", help="validate every capsule and exact file")
    validate_catalog.add_argument("--catalog", type=Path, required=True)

    query = subparsers.add_parser("query", help="select exact reuse, a method, or abstention")
    query.add_argument("--catalog", type=Path, required=True)
    query.add_argument("--request", type=Path, required=True)
    query.add_argument("--output", type=Path)

    capsule = subparsers.add_parser("seal-capsule", help="bind a capsule draft to exact payload bytes")
    capsule.add_argument("--draft", type=Path, required=True)
    capsule.add_argument("--root", type=Path, required=True)
    capsule.add_argument("--output", type=Path, required=True)

    recipe = subparsers.add_parser("seal-recipe", help="bind a receiver recipe to verifier bytes")
    recipe.add_argument("--draft", type=Path, required=True)
    recipe.add_argument("--receiver", type=Path, required=True)
    recipe.add_argument("--output", type=Path, required=True)

    validate_recipe_parser = subparsers.add_parser("validate-recipe", help="validate a sealed receiver recipe")
    validate_recipe_parser.add_argument("--recipe", type=Path, required=True)
    validate_recipe_parser.add_argument("--receiver", type=Path, required=True)

    adopt = subparsers.add_parser("adopt", help="install and verify an exact component")
    adopt.add_argument("--catalog", type=Path, required=True)
    adopt.add_argument("--decision", type=Path, required=True)
    adopt.add_argument("--recipe", type=Path, required=True)
    adopt.add_argument("--receiver", type=Path, required=True)
    adopt.add_argument("--receipt", type=Path, required=True)
    adopt.add_argument("--owner-authorized", action="store_true", help="assert receiver-owner authorization")
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.command == "demo":
            result = run_demo(args.workspace)
            if args.format == "json":
                _print(result)
            else:
                print(format_demo(result))
        elif args.command == "doctor":
            result = containment_readiness()
            if args.format == "json":
                _print(result)
            else:
                print(_format_doctor(result))
            if result["status"] != "ready":
                raise SystemExit(1)
        elif args.command == "validate-catalog":
            catalog = LocalCatalog(args.catalog)
            _print({"status": "valid", "catalogDigest": catalog.catalog_digest})
        elif args.command == "query":
            decision = LocalCatalog(args.catalog).query(load_json(args.request))
            if args.output:
                write_new_json(args.output, decision)
            else:
                _print(decision)
        elif args.command == "seal-capsule":
            write_new_json(args.output, seal_capsule(load_json(args.draft), args.root))
        elif args.command == "seal-recipe":
            write_new_json(args.output, seal_recipe(load_json(args.draft), args.receiver))
        elif args.command == "validate-recipe":
            recipe = validate_recipe(load_json(args.recipe), args.receiver)
            _print({"status": "valid", "recipeDigest": recipe["recipeDigest"]})
        elif args.command == "adopt":
            receipt = adopt_exact_component(
                LocalCatalog(args.catalog),
                load_json(args.decision),
                load_json(args.recipe),
                args.receiver,
                owner_authorized=args.owner_authorized,
                receipt_path=args.receipt,
            )
            _print(receipt)
    except (AdoptionError, CatalogError, ContractError, DemoError) as error:
        print(f"limitless: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
