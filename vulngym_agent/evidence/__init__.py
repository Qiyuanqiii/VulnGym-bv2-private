"""Bounded, offline loading of per-entry local evidence packages."""

from .advisory import AdvisoryFacts, extract_advisory_facts

from .package import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_PACKAGE_BYTES,
    DEFAULT_MAX_PACKAGE_FILES,
    HARD_MAX_PACKAGE_FILES,
    LoadedEvidenceFile,
    LocalEvidencePackage,
    PackageIssue,
    PackageLoadResult,
    PackageSpec,
    load_evidence_package,
)

__all__ = [
    "AdvisoryFacts",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_PACKAGE_BYTES",
    "DEFAULT_MAX_PACKAGE_FILES",
    "HARD_MAX_PACKAGE_FILES",
    "LoadedEvidenceFile",
    "LocalEvidencePackage",
    "PackageIssue",
    "PackageLoadResult",
    "PackageSpec",
    "load_evidence_package",
    "extract_advisory_facts",
]
