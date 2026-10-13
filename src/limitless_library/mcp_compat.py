"""Discovery compatibility for the original single-tool Python connectors."""

from __future__ import annotations

from typing import Any

from .mcp_protocol import CLIENT_INFO_META_KEY, McpToolDispatcher


class LibraryToolDispatcher(McpToolDispatcher):
    """Keep original connector discovery usable as Library tools are added.

    These client versions require an exact one-tool listing. Metadata selects
    presentation only; it never grants publication, execution, or service use.
    Other agents discover the complete host-configured tool set.
    """

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        response = super().handle(message)
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        client = meta.get(CLIENT_INFO_META_KEY) if isinstance(meta, dict) else None
        if (
            message.get("method") == "tools/list"
            and isinstance(response, dict)
            and isinstance(response.get("result"), dict)
            and isinstance(client, dict)
            and client.get("name") == "limitless-library-python"
            and client.get("version") in {"0.1.0a0", "0.1.0a1"}
        ):
            result = response["result"]
            if isinstance(result.get("tools"), list):
                result["tools"] = [tool for tool in result["tools"] if tool["name"] == "limitless_query_before_work"]
        return response
