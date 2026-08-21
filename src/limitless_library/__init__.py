"""Public API for the Limitless Library local alpha."""

__version__ = "0.1.0a0"

from .catalog import CatalogError, LocalCatalog, seal_capsule
from .connector import ConnectorError, McpStdioConnector, query_local
from .installer import AdoptionError, adopt_exact_component, seal_recipe, validate_recipe
from .mcp_protocol import McpToolCallError, McpToolDispatcher, McpToolSession
from .official_service import (
    OfficialServiceActivationError,
    OfficialServiceNotConfiguredError,
    OfficialServiceUnavailableError,
    activate_official_service,
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
    "AdoptionError",
    "CatalogError",
    "ConnectorError",
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
    "activated_service_profile",
    "activation_details",
    "adopt_exact_component",
    "query_local",
    "seal_capsule",
    "seal_recipe",
    "validate_recipe",
]
