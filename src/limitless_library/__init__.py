"""Public API for the Limitless Library local alpha."""

__version__ = "0.1.0a0"

from .catalog import CatalogError, LocalCatalog, seal_capsule
from .connector import ConnectorError, McpStdioConnector, query_local
from .installer import AdoptionError, adopt_exact_component, seal_recipe, validate_recipe

__all__ = [
    "AdoptionError",
    "CatalogError",
    "ConnectorError",
    "LocalCatalog",
    "McpStdioConnector",
    "adopt_exact_component",
    "query_local",
    "seal_capsule",
    "seal_recipe",
    "validate_recipe",
]
