"""Bounded stdio MCP adapter for local query and reusable method capture."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from . import __version__
from .catalog import CatalogError, LocalCatalog
from .contracts import strict_json_loads
from .mcp_compat import LibraryToolDispatcher
from .mcp_protocol import (
    McpToolCallError,
    McpToolDispatcher,
    McpToolSession,
    jsonrpc_error,
)
from .method_capture import (
    CapturedMethodCatalog,
    MethodCaptureError,
    default_method_store,
    register_method,
    schedule_submission,
)
from .method_feedback import MethodFeedbackError, record_method_feedback
from .objective_query import ObjectiveQueryEngine, ObjectiveQueryError
from .query_policy import QueryPolicyError
from .schemas import load_schema

SERVER_NAME = "limitless-library"
TOOL_NAME = "limitless_query_before_work"
REGISTER_METHOD_TOOL_NAME = "limitless_register_method"
OBJECTIVE_TOOL_NAME = "limitless_check"
FEEDBACK_TOOL_NAME = "limitless_record_outcome"
FEEDBACK_INSTRUCTIONS = (
    " Record actual fresh-use outcomes with limitless_record_outcome when a queryRef is available."
    " Reports are private and self-reported; delivery alone is not success."
)
MAX_REQUEST_BYTES = 1024 * 1024
SERVER_INSTRUCTIONS = "Query before material work; locally verify any selected bytes before adoption."
METHOD_INSTRUCTIONS = (
    " After completing and checking useful original work, register one concise source-free method with "
    "limitless_register_method when its steps and limits could save future work. State the observed outcome, "
    "keep private paths and secrets out, and do not turn copied source into a method. Registration is local "
    "unless this MCP installation has explicit standing public-method authorization."
)
OBJECTIVE_INSTRUCTIONS = (
    " Prefer limitless_check with the concise objective already in context. The owner configures the actual "
    "receiver and whether public service search is permitted; do not supply paths, credentials, or policy. "
    "Returned methods are guidance to apply freshly and check, not proof of success or permission to execute."
)


def objective_tool(*, service_queries: bool = False) -> dict[str, Any]:
    return {
        "name": OBJECTIVE_TOOL_NAME,
        "title": "Check before work",
        "description": "Find one reusable method or approved component for a concise objective, or safely start fresh.",
        "inputSchema": load_schema("objective-query-1.0.schema.json"),
        "outputSchema": load_schema("objective-result-1.0.schema.json"),
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": service_queries},
    }


def feedback_tool() -> dict[str, Any]:
    return {
        "name": FEEDBACK_TOOL_NAME,
        "title": "Record reuse outcome",
        "description": "Keep a private self-report of fresh use, failure, or blockage for an existing queryRef; never publishes or attests success.",
        "inputSchema": load_schema("method-feedback-input-1.0.schema.json"),
        "outputSchema": load_schema("method-feedback-result-1.0.schema.json"),
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    }


def _tool() -> dict[str, Any]:
    return {
        "name": TOOL_NAME,
        "title": "Query before work",
        "description": "Select one permissioned exact component or source-free method, or abstain.",
        "inputSchema": load_schema("query-0.1.schema.json"),
        "outputSchema": load_schema("decision-0.1.schema.json"),
        "annotations": {
            "readOnlyHint": True,
            "openWorldHint": False,
        },
    }


def _register_method_tool(*, public_submission: bool = False) -> dict[str, Any]:
    text = {"type": "string", "minLength": 1}
    return {
        "name": REGISTER_METHOD_TOOL_NAME,
        "title": "Register a reusable method",
        "description": "After verified original work, save one concise source-free method locally; authorized public sharing queues separately.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["title", "taskKind", "method", "observedOutcome", "platform"],
            "properties": {
                "title": {**text, "maxLength": 120},
                "taskKind": {"type": "string", "pattern": "^[a-z0-9]+(?:-[a-z0-9]+)*$", "maxLength": 100},
                "observedOutcome": {**text, "maxLength": 400},
                "platform": {"type": "string", "pattern": "^(?:any|[a-z][a-z0-9._-]{0,63})$"},
                "method": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["summary", "steps", "constraints", "evaluation", "limitations"],
                    "properties": {
                        "summary": {**text, "maxLength": 400},
                        "steps": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 16,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["index", "instruction", "check", "expected"],
                                "properties": {
                                    "index": {"type": "integer", "minimum": 1, "maximum": 16},
                                    "instruction": {**text, "maxLength": 400},
                                    "check": {**text, "maxLength": 80},
                                    "expected": {**text, "maxLength": 240},
                                },
                            },
                        },
                        "constraints": {
                            "type": "array",
                            "maxItems": 16,
                            "uniqueItems": True,
                            "items": {**text, "maxLength": 240},
                        },
                        "evaluation": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 16,
                            "uniqueItems": True,
                            "items": {**text, "maxLength": 240},
                        },
                        "limitations": {
                            "type": "array",
                            "maxItems": 16,
                            "uniqueItems": True,
                            "items": {**text, "maxLength": 240},
                        },
                    },
                },
            },
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["schemaVersion", "status", "methodRef", "destination", "submission"],
            "properties": {
                "schemaVersion": {"const": "limitless.method-registration-result/0.1"},
                "status": {"enum": ["registered", "duplicate"]},
                "methodRef": {"type": "string", "pattern": "^method:[0-9a-f]{64}$"},
                "destination": {"enum": ["local", "public"]},
                "submission": {
                    "enum": ["local", "queued", "retryable", "submitted", "active", "rejected", "policy-attention"]
                },
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": public_submission,
        },
    }


def handle_message(registry: LocalCatalog, message: dict[str, Any]) -> dict[str, Any] | None:
    return _dispatcher(registry).handle(message)


def _dispatcher(
    registry: LocalCatalog,
    *,
    method_store: Path | None = None,
    public_method_policy_digest: str | None = None,
    objective_engine: ObjectiveQueryEngine | None = None,
) -> McpToolDispatcher:
    captured_catalog = (
        objective_engine.catalog if objective_engine is not None else CapturedMethodCatalog(registry, method_store)
    )

    def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == FEEDBACK_TOOL_NAME and objective_engine is not None and objective_engine.state_dir is not None:
            try:
                return record_method_feedback(objective_engine.state_dir, arguments)
            except (MethodFeedbackError, OSError, ValueError) as error:
                raise McpToolCallError(str(error)) from error
        if name == OBJECTIVE_TOOL_NAME and objective_engine is not None:
            try:
                return objective_engine.check(arguments)
            except (ObjectiveQueryError, QueryPolicyError, OSError) as error:
                raise McpToolCallError(str(error)) from error
        if name == TOOL_NAME:
            try:
                return captured_catalog.query(arguments)
            except (CatalogError, MethodCaptureError, OSError) as error:
                raise McpToolCallError(str(error)) from error
        if name == REGISTER_METHOD_TOOL_NAME and method_store is not None:
            try:
                return register_method(method_store, arguments, public_policy_digest=public_method_policy_digest)
            except (MethodCaptureError, OSError) as error:
                raise McpToolCallError(str(error)) from error
        raise McpToolCallError("tool is not available")

    tools = [_tool()]
    if objective_engine is not None:
        tools.append(objective_tool(service_queries=True))
        if objective_engine.state_dir is not None:
            tools.append(feedback_tool())
    if method_store is not None:
        tools.append(_register_method_tool(public_submission=public_method_policy_digest is not None))
    return LibraryToolDispatcher(
        server_name=SERVER_NAME,
        server_version=__version__,
        instructions=SERVER_INSTRUCTIONS
        + (OBJECTIVE_INSTRUCTIONS if objective_engine is not None else "")
        + (FEEDBACK_INSTRUCTIONS if objective_engine is not None and objective_engine.state_dir is not None else "")
        + (METHOD_INSTRUCTIONS if method_store is not None else ""),
        tools=tools,
        call_tool=call_tool,
        cache_scope="private",
    )


def _bounded_lines(stream: Any) -> Iterator[tuple[str | None, str | None]]:
    while True:
        raw = stream.readline(MAX_REQUEST_BYTES + 1)
        if not raw:
            return
        if len(raw) > MAX_REQUEST_BYTES or (len(raw) == MAX_REQUEST_BYTES and not raw.endswith(b"\n")):
            while raw and not raw.endswith(b"\n"):
                raw = stream.readline(MAX_REQUEST_BYTES + 1)
            yield None, f"MCP request exceeds {MAX_REQUEST_BYTES} bytes"
            continue
        try:
            yield raw.decode("utf-8"), None
        except UnicodeDecodeError:
            yield None, "MCP request is not UTF-8 JSON"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, help="configured local capsule catalog; optional for private methods")
    parser.add_argument("--method-store", type=Path, help="private local method store (defaults to XDG data home)")
    parser.add_argument("--query-policy", type=Path, help="separate owner policy for objective/service queries")
    parser.add_argument("--query-state", type=Path, help="private query continuations; never artifact installation")
    parser.add_argument(
        "--submit-methods-publicly",
        action="store_true",
        help="standing owner authorization to submit independently authored CC0 methods after registration",
    )
    parser.add_argument(
        "--public-method-policy-digest",
        help="exact reviewed service publication policy digest for authorized public methods",
    )
    args = parser.parse_args()
    if args.submit_methods_publicly != bool(args.public_method_policy_digest):
        parser.error(
            "public method submission requires both --submit-methods-publicly and --public-method-policy-digest"
        )
    if args.public_method_policy_digest is not None and (
        len(args.public_method_policy_digest) != 71
        or not args.public_method_policy_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in args.public_method_policy_digest[7:])
    ):
        parser.error("public method policy digest must be sha256: followed by 64 lowercase hex characters")
    try:
        method_store = args.method_store or default_method_store()
    except MethodCaptureError as error:
        if args.submit_methods_publicly:
            print(f"method capture is unavailable: {error}", file=sys.stderr)
            raise SystemExit(2) from error
        method_store = None
    data_root = method_store.parent if method_store is not None else None
    try:
        catalog = (
            LocalCatalog(args.catalog) if args.catalog is not None else LocalCatalog.empty(data_root or Path.cwd())
        )
    except CatalogError as error:
        print(f"cannot load catalog: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    objective_engine = ObjectiveQueryEngine(
        CapturedMethodCatalog(catalog, method_store),
        policy_path=args.query_policy or (data_root / "query-policy.json" if data_root is not None else None),
        state_dir=args.query_state or (data_root / "queries" if data_root is not None else None),
    )
    session = McpToolSession(
        _dispatcher(
            catalog,
            method_store=method_store,
            public_method_policy_digest=args.public_method_policy_digest,
            objective_engine=objective_engine,
        )
    )
    if args.submit_methods_publicly and method_store.is_dir():
        schedule_submission(method_store, args.public_method_policy_digest)
    for line, framing_error in _bounded_lines(sys.stdin.buffer):
        if framing_error:
            response = jsonrpc_error(None, -32700, framing_error)
        else:
            try:
                message = strict_json_loads(line)
                if not isinstance(message, dict):
                    raise TypeError("JSON-RPC message must be an object")
                response = session.handle(message)
            except (TypeError, ValueError, CatalogError) as error:
                response = jsonrpc_error(None, -32700, str(error))
        if response is not None:
            print(json.dumps(response, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
