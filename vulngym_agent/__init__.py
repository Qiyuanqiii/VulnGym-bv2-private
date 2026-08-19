"""VulnGym T1/T2 automation primitives."""

from vulngym_agent.adapters import (
    SchemaAdapter,
    adapt_entry,
    adapt_t2_entry,
    normalize_entry,
    validate_entry,
)
from vulngym_agent.models import (
    EvidenceItem,
    FieldValidation,
    SchemaAdapterError,
    SchemaIssue,
    SchemaValidationResult,
    ValidationReport,
)

__all__ = [
    "EvidenceItem",
    "FieldValidation",
    "SchemaAdapter",
    "SchemaAdapterError",
    "SchemaIssue",
    "SchemaValidationResult",
    "ValidationReport",
    "adapt_entry",
    "adapt_t2_entry",
    "normalize_entry",
    "validate_entry",
]
