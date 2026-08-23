"""Public API for the Limitless Library local alpha."""

__version__ = "0.1.0a0"

from .agent_integration import (
    AGENT_IDS,
    AGENT_MCP_SERVER_NAME,
    ANTIGRAVITY_AGENT,
    AgentIntegrationError,
    antigravity_connection_status,
    connect_antigravity,
    disconnect_antigravity,
)
from .catalog import CatalogError, LocalCatalog, seal_capsule
from .connector import ConnectorError, McpStdioConnector, query_local
from .exact_file_bundle import (
    EXACT_FILE_BUNDLE_SCHEMA_VERSION,
    ExactBundleFile,
    ExactFileBundle,
    ExactFileBundleError,
    build_exact_file_bundle,
    parse_exact_file_bundle,
)
from .installer import AdoptionError, adopt_exact_component, seal_recipe, validate_recipe
from .mcp_protocol import McpToolCallError, McpToolDispatcher, McpToolSession
from .official_service import (
    OfficialServiceActivationError,
    OfficialServiceNotConfiguredError,
    OfficialServiceUnavailableError,
    activate_official_service,
    activated_service_connector,
    activated_service_profile,
    activation_details,
)
from .service_connector import (
    ServiceConnector,
    ServiceConnectorError,
    ServiceHttpResponse,
    ServiceProfile,
    ServiceTransport,
    ServiceUnavailableError,
    UrllibServiceTransport,
    VerifiedService,
)

__all__ = [
    "AGENT_IDS",
    "AGENT_MCP_SERVER_NAME",
    "ANTIGRAVITY_AGENT",
    "EXACT_FILE_BUNDLE_SCHEMA_VERSION",
    "AdoptionError",
    "AgentIntegrationError",
    "CatalogError",
    "ConnectorError",
    "ExactBundleFile",
    "ExactFileBundle",
    "ExactFileBundleError",
    "LocalCatalog",
    "McpStdioConnector",
    "McpToolCallError",
    "McpToolDispatcher",
    "McpToolSession",
    "OfficialServiceActivationError",
    "OfficialServiceNotConfiguredError",
    "OfficialServiceUnavailableError",
    "ServiceConnector",
    "ServiceConnectorError",
    "ServiceHttpResponse",
    "ServiceProfile",
    "ServiceTransport",
    "ServiceUnavailableError",
    "UrllibServiceTransport",
    "VerifiedService",
    "activate_official_service",
    "activated_service_connector",
    "activated_service_profile",
    "activation_details",
    "adopt_exact_component",
    "antigravity_connection_status",
    "build_exact_file_bundle",
    "connect_antigravity",
    "disconnect_antigravity",
    "parse_exact_file_bundle",
    "query_local",
    "seal_capsule",
    "seal_recipe",
    "validate_recipe",
]
