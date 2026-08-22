"""Agent-level workflows built from deterministic tools and validators."""

from typing import TYPE_CHECKING, Any

from .model_runtime import (
    AttemptModelRuntime,
    AttemptModelTranscript,
    ModelBlocked,
    ModelRequest,
    ModelResult,
    ReplayResponse,
    ReplayStructuredModelBackend,
    StructuredModelBackend,
)
from .t1_validator import T1DeterministicValidator, T1ValidationOutcome
from .t2_inputs import T2Hints, T2TaskInputV1
from .t2_producer import T2Producer
from .t2_toolbox import LOCAL_T2_TOOL_NAMES, LocalT2Toolbox

if TYPE_CHECKING:
    from .discovery_toolbox import DiscoveryToolbox
    from .real_t2_producer import LocalStructuredT2Producer
    from .source_discovery_producer import SourceDiscoveryAttemptController
    from .source_discovery_reviewer import SourceDiscoveryReviewerController
    from .t2_execution import LocalT2ContextFactory


def __getattr__(name: str) -> Any:
    """Load context-dependent T2 workflows without creating import cycles."""

    if name == "LocalStructuredT2Producer":
        from .real_t2_producer import LocalStructuredT2Producer

        globals()[name] = LocalStructuredT2Producer
        return LocalStructuredT2Producer
    if name == "LocalT2ContextFactory":
        from .t2_execution import LocalT2ContextFactory

        globals()[name] = LocalT2ContextFactory
        return LocalT2ContextFactory
    if name in {
        "DISCOVERY_TOOL_CONTRACT_IDS",
        "DISCOVERY_TOOL_NAMES",
        "DiscoveryToolbox",
    }:
        from .discovery_toolbox import (
            DISCOVERY_TOOL_CONTRACT_IDS,
            DISCOVERY_TOOL_NAMES,
            DiscoveryToolbox,
        )

        exports = {
            "DISCOVERY_TOOL_CONTRACT_IDS": DISCOVERY_TOOL_CONTRACT_IDS,
            "DISCOVERY_TOOL_NAMES": DISCOVERY_TOOL_NAMES,
            "DiscoveryToolbox": DiscoveryToolbox,
        }
        globals().update(exports)
        return exports[name]
    if name == "SourceDiscoveryAttemptController":
        from .source_discovery_producer import SourceDiscoveryAttemptController

        globals()[name] = SourceDiscoveryAttemptController
        return SourceDiscoveryAttemptController
    if name == "SourceDiscoveryReviewerController":
        from .source_discovery_reviewer import SourceDiscoveryReviewerController

        globals()[name] = SourceDiscoveryReviewerController
        return SourceDiscoveryReviewerController
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "AttemptModelRuntime",
    "AttemptModelTranscript",
    "DISCOVERY_TOOL_CONTRACT_IDS",
    "DISCOVERY_TOOL_NAMES",
    "DiscoveryToolbox",
    "ModelBlocked",
    "ModelRequest",
    "ModelResult",
    "ReplayResponse",
    "ReplayStructuredModelBackend",
    "SourceDiscoveryAttemptController",
    "SourceDiscoveryReviewerController",
    "StructuredModelBackend",
    "LOCAL_T2_TOOL_NAMES",
    "LocalStructuredT2Producer",
    "LocalT2ContextFactory",
    "LocalT2Toolbox",
    "T1DeterministicValidator",
    "T1ValidationOutcome",
    "T2Hints",
    "T2Producer",
    "T2TaskInputV1",
]
