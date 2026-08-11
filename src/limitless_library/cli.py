"""Command-line interface for the sanitized local alpha."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import CatalogError, LocalCatalog, seal_capsule
from .contracts import ContractError, load_json, write_new_json
from .installer import AdoptionError, adopt_exact_component, seal_recipe, validate_recipe


def _print(value: dict[str, object]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

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
        if args.command == "validate-catalog":
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
    except (AdoptionError, CatalogError, ContractError) as error:
        print(f"limitless: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
