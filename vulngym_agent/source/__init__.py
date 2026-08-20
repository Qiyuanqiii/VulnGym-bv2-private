"""Read-only source-analysis foundations."""

from .entry_search import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_CANDIDATES,
    DEFAULT_MAX_FILES,
    EntryPointCandidate,
    EntryPointSearcher,
    EntryPointSearchIssue,
    EntryPointSearchResult,
    search_entry_points,
)

__all__ = [
    "DEFAULT_MAX_BYTES", "DEFAULT_MAX_CANDIDATES", "DEFAULT_MAX_FILES",
    "EntryPointCandidate", "EntryPointSearcher", "EntryPointSearchIssue",
    "EntryPointSearchResult", "search_entry_points",
]
