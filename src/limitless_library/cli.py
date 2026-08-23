"""Command-line interface for the sanitized local alpha."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agent_integration import (
    AgentIntegrationError,
    antigravity_connection_status,
    connect_antigravity,
    disconnect_antigravity,
)
from .catalog import CatalogError, LocalCatalog, seal_capsule
from .contracts import ContractError, load_json, write_new_json
from .demo import DemoError, format_demo, run_demo
from .installer import AdoptionError, adopt_exact_component, seal_recipe, validate_recipe
from .official_service import (
    activate_official_service,
    activated_service_connector,
    activated_service_profile,
    activation_details,
)
from .publication import (
    PublicationError,
    publication_status,
    publish_draft,
    revoke_publication,
)
from .sandbox import containment_readiness
from .service_connector import (
    ServiceConnector,
    ServiceConnectorError,
    ServiceProfile,
)
from .service_identity import installation_publisher_authority


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


def _service_connector(profile_path: Path | None) -> ServiceConnector:
    try:
        token = os.environ.get("LIMITLESS_SERVICE_TOKEN")
        if profile_path is None and token is None:
            return activated_service_connector()
        profile = (
            activated_service_profile(access_token=token)
            if profile_path is None
            else ServiceProfile.from_json(
                load_json(profile_path),
                access_token=token,
            )
        )
    except (ContractError, OSError, ValueError) as error:
        raise ServiceConnectorError("service profile is invalid") from error
    return ServiceConnector(profile)


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

    agent_connect = subparsers.add_parser(
        "agent-connect",
        help="connect a supported agent to the local Limitless MCP server",
    )
    agent_connect.add_argument("agent", choices=("antigravity", "agy"))
    agent_connect.add_argument("--catalog", type=Path, required=True)

    agent_status = subparsers.add_parser(
        "agent-status",
        help="inspect a supported agent's local Limitless MCP connection",
    )
    agent_status.add_argument("agent", choices=("antigravity", "agy"))

    agent_disconnect = subparsers.add_parser(
        "agent-disconnect",
        help="remove only a plugin-owned supported-agent MCP connection",
    )
    agent_disconnect.add_argument("agent", choices=("antigravity", "agy"))

    subparsers.add_parser(
        "service-activate",
        help="enable the release-pinned official service after verifying its authority",
    )

    subparsers.add_parser(
        "service-status",
        help="show the local or explicitly enabled official-service boundary",
    )

    service_inspect = subparsers.add_parser(
        "service-inspect",
        help="verify the enabled official service without sending a task",
    )
    service_inspect.add_argument(
        "--profile",
        type=Path,
        help="advanced: inspect an explicit alternate service profile",
    )

    service_query = subparsers.add_parser(
        "service-query",
        help="submit and verify one query to the enabled official service",
    )
    service_query.add_argument(
        "--profile",
        type=Path,
        help="advanced: query through an explicit alternate service profile",
    )

    service_publish = subparsers.add_parser(
        "service-publish",
        help="prepare, resume, and publish one draft through anonymous authority",
    )
    service_publish.add_argument("--draft", type=Path, required=True)
    service_publish.add_argument(
        "--state",
        type=Path,
        help="local resumable state (defaults beside the draft)",
    )
    service_publish.add_argument(
        "--accept-publication-policy-digest",
        required=True,
        help="exact digest of the service-advertised policy reviewed for this submission",
    )

    publication_status_parser = subparsers.add_parser(
        "service-publication-status",
        help="inspect admission for one locally prepared publication",
    )
    publication_status_parser.add_argument("--state", type=Path, required=True)

    publication_revoke = subparsers.add_parser(
        "service-publication-revoke",
        help="withdraw the active release for one locally prepared publication",
    )
    publication_revoke.add_argument("--state", type=Path, required=True)
    publication_revoke.add_argument(
        "--reason-code",
        default="publisher-withdrawal",
        help="non-sensitive machine-readable withdrawal reason",
    )
    service_query.add_argument("--request", type=Path)
    service_query.add_argument("--objective")
    service_query.add_argument("--receiver", type=Path)
    service_query.add_argument("--request-id")
    service_query.add_argument("--output", type=Path)
    service_query.add_argument(
        "--artifact-output",
        type=Path,
        help="fetch a selected exact artifact into this new file",
    )

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
        elif args.command == "agent-connect":
            _print(connect_antigravity(args.catalog))
        elif args.command == "agent-status":
            _print(antigravity_connection_status())
        elif args.command == "agent-disconnect":
            _print(disconnect_antigravity())
        elif args.command == "service-activate":
            activate_official_service()
            _print(activation_details())
        elif args.command == "service-status":
            _print(activation_details())
        elif args.command == "service-inspect":
            connector = _service_connector(args.profile)
            verified = connector.inspect()
            _print(
                {
                    "status": "connected",
                    "profile": connector.profile.public_summary(),
                    "policy": verified.discovery["dataUsePolicy"],
                    "publicationPolicy": verified.discovery.get("publicationPolicy"),
                    "resultVersions": verified.discovery["resultVersions"],
                    "expiresAt": verified.discovery["expiresAt"],
                }
            )
        elif args.command == "service-query":
            connector = _service_connector(args.profile)
            if args.request is not None:
                if any(item is not None for item in (args.objective, args.receiver, args.request_id)):
                    raise ServiceConnectorError("--request cannot be combined with query-building arguments")
                request = load_json(args.request)
            else:
                if not args.objective or args.receiver is None or not args.request_id:
                    raise ServiceConnectorError("use --request, or provide --objective, --receiver, and --request-id")
                request = connector.build_query(
                    request_id=args.request_id,
                    objective=args.objective,
                    receiver_context=load_json(args.receiver),
                )
            result = connector.query(request)
            staged = None
            if args.artifact_output:
                staged = connector.fetch_selected_artifact(
                    query=request,
                    result=result,
                    destination=args.artifact_output,
                )
            if args.output:
                write_new_json(args.output, result)
            if staged is not None:
                _print(staged)
            elif not args.output:
                _print(result)
        elif args.command == "service-publish":
            connector = activated_service_connector()
            signer, publisher = installation_publisher_authority(service_id=connector.profile.service_id)
            _print(
                publish_draft(
                    connector,
                    draft_path=args.draft,
                    state_path=args.state,
                    signer=signer,
                    publisher=publisher,
                    accepted_publication_policy_digest=args.accept_publication_policy_digest,
                )
            )
        elif args.command in {
            "service-publication-status",
            "service-publication-revoke",
        }:
            connector = activated_service_connector()
            signer, publisher = installation_publisher_authority(service_id=connector.profile.service_id)
            if args.command == "service-publication-status":
                result = publication_status(
                    connector,
                    state_path=args.state,
                    signer=signer,
                    publisher=publisher,
                )
            else:
                result = revoke_publication(
                    connector,
                    state_path=args.state,
                    signer=signer,
                    publisher=publisher,
                    reason_code=args.reason_code,
                )
            _print(result)
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
    except (
        AdoptionError,
        AgentIntegrationError,
        CatalogError,
        ContractError,
        DemoError,
        PublicationError,
        ServiceConnectorError,
    ) as error:
        print(f"limitless: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
