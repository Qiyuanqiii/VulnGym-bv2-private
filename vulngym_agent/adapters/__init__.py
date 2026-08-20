"""Boundary adapters for VulnGym official and sidecar data."""

from vulngym_agent.adapters.schema_adapter import (
    ENTRY_FIELDS,
    LOCATION_FIELDS,
    MAX_TRACE_NODES,
    SchemaAdapter,
    adapt_entry,
    adapt_t2_entry,
    normalize_entry,
    validate_entry,
)

__all__ = [
    "ENTRY_FIELDS",
    "LOCATION_FIELDS",
    "MAX_TRACE_NODES",
    "SchemaAdapter",
    "adapt_entry",
    "adapt_t2_entry",
    "normalize_entry",
    "validate_entry",
]
