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
from .mcp_protocol import (
    McpToolCallError,
    McpToolDispatcher,
    McpToolSession,
    jsonrpc_error,
)
from .method_capture import MethodCaptureError, default_method_store, register_method, schedule_submission
from .schemas import load_schema

SERVER_NAME = "limitless-library"
TOOL_NAME = "limitless_query_before_work"
REGISTER_METHOD_TOOL_NAME = "limitless_register_method"
MAX_REQUEST_BYTES = 1024 * 1024
SERVER_INSTRUCTIONS = "Query before material work; locally verify any selected bytes before adoption."
METHOD_INSTRUCTIONS = (
    " After completing and checking useful original work, register one concise source-free method with "
    "limitless_register_method when its steps and limits could save future work. State the observed outcome, "
    "keep private paths and secrets out, and do not turn copied source into a method. Registration is local "
    "unless this MCP installation has explicit standing public-method authorization."
)


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
    registry: LocalCatalog, *, method_store: Path | None = None, public_method_policy_digest: str | None = None
) -> McpToolDispatcher:
    def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == TOOL_NAME:
            try:
                return registry.query(arguments)
            except CatalogError as error:
                raise McpToolCallError(str(error)) from error
        if name == REGISTER_METHOD_TOOL_NAME and method_store is not None:
            try:
                return register_method(method_store, arguments, public_policy_digest=public_method_policy_digest)
            except (MethodCaptureError, OSError) as error:
                raise McpToolCallError(str(error)) from error
        raise McpToolCallError("tool is not available")

    return McpToolDispatcher(
        server_name=SERVER_NAME,
        server_version=__version__,
        instructions=SERVER_INSTRUCTIONS + (METHOD_INSTRUCTIONS if method_store is not None else ""),
        tools=[_tool(), _register_method_tool(public_submission=public_method_policy_digest is not None)]
        if method_store is not None
        else [_tool()],
        call_tool=call_tool,
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
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--method-store", type=Path, help="private local method store (defaults to XDG data home)")
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
        catalog = LocalCatalog(args.catalog)
    except CatalogError as error:
        print(f"cannot load catalog: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    try:
        method_store = args.method_store or default_method_store()
    except MethodCaptureError as error:
        if args.submit_methods_publicly:
            print(f"method capture is unavailable: {error}", file=sys.stderr)
            raise SystemExit(2) from error
        method_store = None
    session = McpToolSession(
        _dispatcher(
            catalog,
            method_store=method_store,
            public_method_policy_digest=args.public_method_policy_digest,
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
