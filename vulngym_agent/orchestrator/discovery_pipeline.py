"""Strict, single-task offline orchestration for the D2 -> D3 discovery lane.

The pipeline deliberately receives factories rather than live source and budget
capabilities.  This keeps D3 completely lazy when D2 defers and gives D2 and
D3 distinct one-owner capabilities when review is required.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Final

from vulngym_agent.agents.model_runtime import StructuredModelBackend
from vulngym_agent.agents.source_discovery_producer import (
    SourceDiscoveryAttemptController,
)
from vulngym_agent.agents.source_discovery_reviewer import (
    SourceDiscoveryReviewerController,
)
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryTaskInputV1,
    DiscoveryTaskResult,
)
from vulngym_agent.benchmark.discovery_projection import project_discovery_result
from vulngym_agent.benchmark.producer_contracts import (
    ProducerDeferredV1,
    ProducerDraftV1,
    ProducerResultV1,
)
from vulngym_agent.benchmark.reviewer_contracts import (
    ReviewerDeferredV1,
    ReviewerFinalizedV1,
    ReviewerInputV1,
    ReviewerResultV1,
    parse_reviewer_result_v1,
)
from vulngym_agent.benchmark.reviewer_projection import project_discovery_run_v1
from vulngym_agent.benchmark.sealed_tree_access import BoundSealedTree
from vulngym_agent.orchestrator.budget import Budget


SOURCE_DISCOVERY_RUN_CONTRACT_VERSION: Final[int] = 1
SOURCE_DISCOVERY_RUN_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym source discovery offline run v1\0"
)

_MAX_RUN_WIRE_BYTES: Final[int] = 6 * 1024 * 1024
_RUN_KEYS: Final[frozenset[str]] = frozenset(
    {
        "contract_version",
        "discovery_result",
        "producer_result",
        "reviewer_result",
        "run_sha256",
    }
)

TreeFactory = Callable[[], BoundSealedTree]
BudgetFactory = Callable[[], Budget]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _task_has_exact_types(value: object) -> bool:
    try:
        return (
            type(value) is DiscoveryTaskInputV1
            and type(value.task_id) is str
            and type(value.repo_url) is str
            and type(value.commit) is str
            and type(value.instruction_id) is str
            and type(value.snapshot_manifest_sha256) is str
            and type(value.snapshot_content_root) is str
            and type(value.snapshot_id) is str
            and type(value.contract_version) is int
        )
    except (AttributeError, RecursionError, RuntimeError, TypeError, ValueError):
        return False


def _producer_deferred_has_exact_types(value: object) -> bool:
    try:
        return (
            type(value) is ProducerDeferredV1
            and _task_has_exact_types(value.task)
            and type(value.stage) is str
            and type(value.reason_code) is str
            and type(value.missing_information) is tuple
            and all(type(item) is str for item in value.missing_information)
            and type(value.coverage_status) is str
            and type(value.policy_version) is str
            and type(value.contract_version) is int
        )
    except (AttributeError, RecursionError, RuntimeError, TypeError, ValueError):
        return False


def _canonical_task(value: object) -> DiscoveryTaskInputV1:
    if not _task_has_exact_types(value):
        raise ValueError("task must be an exact DiscoveryTaskInputV1")
    try:
        canonical = DiscoveryTaskInputV1(
            task_id=value.task_id,
            repo_url=value.repo_url,
            commit=value.commit,
            instruction_id=value.instruction_id,
            snapshot_manifest_sha256=value.snapshot_manifest_sha256,
            snapshot_content_root=value.snapshot_content_root,
            contract_version=value.contract_version,
        )
        if canonical.snapshot_id != value.snapshot_id:
            raise ValueError("snapshot_id does not match the task snapshot")
        return canonical
    except (AttributeError, KeyError, RecursionError, RuntimeError, TypeError, ValueError):
        raise ValueError("task did not pass strict normalization") from None


def _canonical_producer(value: object) -> ProducerResultV1:
    if type(value) is ProducerDraftV1:
        try:
            # ReviewerInputV1 performs the bounded, full exact-type graph
            # preflight before invoking the draft's serializer.
            return ReviewerInputV1(producer_draft=value).producer_draft
        except (
            AttributeError,
            KeyError,
            RecursionError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            raise ValueError(
                "producer_result did not pass strict normalization"
            ) from None
    elif type(value) is ProducerDeferredV1:
        if not _producer_deferred_has_exact_types(value):
            raise ValueError(
                "producer_result contains a polymorphic contract value"
            )
    else:
        raise ValueError("producer_result must be an exact D2 result")
    try:
        return ProducerDeferredV1(
            task=_canonical_task(value.task),
            stage=value.stage,
            reason_code=value.reason_code,
            missing_information=value.missing_information,
            coverage_status=value.coverage_status,
            policy_version=value.policy_version,
            contract_version=value.contract_version,
        )
    except (
        AttributeError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise ValueError("producer_result did not pass strict normalization") from None


def _canonical_reviewer(value: object | None) -> ReviewerResultV1 | None:
    if value is None:
        return None
    if type(value) not in (ReviewerFinalizedV1, ReviewerDeferredV1):
        raise ValueError("reviewer_result must be an exact D3 result or None")
    try:
        # The public parser rebuilds exact nested D3 values and rejects any
        # polymorphic node before that node's serialization can run.
        return parse_reviewer_result_v1(value)
    except (
        AttributeError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise ValueError("reviewer_result did not pass strict normalization") from None


def _canonical_discovery(value: object) -> DiscoveryTaskResult:
    if type(value) is not DiscoveryTaskResult:
        raise ValueError("discovery_result must be an exact DiscoveryTaskResult")
    try:
        # This public projection first rejects polymorphic nested D0 nodes.
        project_discovery_result(value)
        return DiscoveryTaskResult.from_dict(value.to_dict())
    except (AttributeError, KeyError, RecursionError, RuntimeError, TypeError, ValueError):
        raise ValueError("discovery_result did not pass strict normalization") from None


def _producer_from_dict(value: Any) -> ProducerResultV1:
    if type(value) is not dict:
        raise ValueError("producer_result must be an object")
    result_type = value.get("result_type")
    if result_type == "draft":
        return ProducerDraftV1.from_dict(value)
    if result_type == "deferred":
        return ProducerDeferredV1.from_dict(value)
    raise ValueError("producer_result has an invalid discriminator")


def _reviewer_from_dict(value: Any) -> ReviewerResultV1 | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise ValueError("reviewer_result must be an object or null")
    result_type = value.get("result_type")
    if result_type == "finalized":
        return ReviewerFinalizedV1.from_dict(value)
    if result_type == "deferred":
        return ReviewerDeferredV1.from_dict(value)
    raise ValueError("reviewer_result has an invalid discriminator")


@dataclass(frozen=True, slots=True)
class SourceDiscoveryRunV1:
    """Closed D2/D3 sidecars plus their exact public D0 projection."""

    producer_result: ProducerResultV1
    reviewer_result: ReviewerResultV1 | None
    discovery_result: DiscoveryTaskResult
    contract_version: int = SOURCE_DISCOVERY_RUN_CONTRACT_VERSION
    run_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ValueError("contract_version must be integer 1")
        producer = _canonical_producer(self.producer_result)
        reviewer = _canonical_reviewer(self.reviewer_result)
        discovery = _canonical_discovery(self.discovery_result)
        try:
            expected = project_discovery_run_v1(producer, reviewer)
        except (AttributeError, KeyError, RecursionError, RuntimeError, TypeError, ValueError):
            raise ValueError("producer and reviewer results do not form one closed run") from None
        if discovery != expected:
            raise ValueError("discovery_result is not the exact D2/D3 projection")
        object.__setattr__(self, "producer_result", producer)
        object.__setattr__(self, "reviewer_result", reviewer)
        object.__setattr__(self, "discovery_result", expected)
        object.__setattr__(
            self,
            "run_sha256",
            hashlib.sha256(
                SOURCE_DISCOVERY_RUN_DIGEST_DOMAIN
                + _canonical_json(self._digest_dict())
            ).hexdigest(),
        )
        if len(self.to_wire()) > _MAX_RUN_WIRE_BYTES:
            raise ValueError("source discovery run exceeds its wire limit")

    @property
    def task(self) -> DiscoveryTaskInputV1:
        return self.producer_result.task

    @property
    def task_id(self) -> str:
        return self.task.task_id

    @property
    def snapshot_id(self) -> str:
        return self.task.snapshot_id

    def _digest_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "discovery_result": self.discovery_result.to_dict(),
            "producer_result": self.producer_result.to_dict(),
            "reviewer_result": (
                None
                if self.reviewer_result is None
                else self.reviewer_result.to_dict()
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._digest_dict(), "run_sha256": self.run_sha256}

    def to_wire(self) -> bytes:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "SourceDiscoveryRunV1":
        if type(value) is not dict or frozenset(value) != _RUN_KEYS:
            raise ValueError("SourceDiscoveryRunV1 must use the fixed schema")
        if type(value["contract_version"]) is not int:
            raise ValueError("contract_version must be an integer")
        if type(value["run_sha256"]) is not str:
            raise ValueError("run_sha256 must be a string")
        try:
            discovery_value = value["discovery_result"]
            if type(discovery_value) is not dict:
                raise ValueError("discovery_result must be an object")
            result = cls(
                producer_result=_producer_from_dict(value["producer_result"]),
                reviewer_result=_reviewer_from_dict(value["reviewer_result"]),
                discovery_result=DiscoveryTaskResult.from_dict(discovery_value),
                contract_version=value["contract_version"],
            )
        except (AttributeError, KeyError, RecursionError, RuntimeError, TypeError, ValueError):
            raise ValueError("SourceDiscoveryRunV1 did not pass strict normalization") from None
        if value["run_sha256"] != result.run_sha256:
            raise ValueError("run_sha256 does not match the closed run")
        return result

    @classmethod
    def from_wire(cls, value: Any) -> "SourceDiscoveryRunV1":
        if type(value) is str:
            if not value or len(value) > _MAX_RUN_WIRE_BYTES:
                raise ValueError("source discovery run wire is empty or oversized")
            try:
                raw = value.encode("utf-8")
            except UnicodeError:
                raise ValueError("source discovery run wire is not UTF-8") from None
        elif type(value) in (bytes, bytearray, memoryview):
            wire_size = value.nbytes if type(value) is memoryview else len(value)
            if wire_size > _MAX_RUN_WIRE_BYTES:
                raise ValueError("source discovery run wire is oversized")
            raw = bytes(value)
        else:
            raise ValueError("source discovery run wire must be text or bytes")
        if not raw or len(raw) > _MAX_RUN_WIRE_BYTES:
            raise ValueError("source discovery run wire is empty or oversized")

        def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, child in pairs:
                if key in result:
                    raise ValueError("source discovery run wire repeats an object key")
                result[key] = child
            return result

        try:
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=object_from_pairs,
            )
            if type(payload) is not dict or _canonical_json(payload) != raw:
                raise ValueError("source discovery run wire is not canonical")
        except (RecursionError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            raise ValueError("source discovery run wire is invalid") from None
        return cls.from_dict(payload)


def _acquire_tree(factory: TreeFactory, *, name: str) -> BoundSealedTree:
    if not callable(factory):
        raise ValueError(f"{name} must be callable")
    tree: BoundSealedTree | None = None
    try:
        tree = factory()
        if type(tree) is not BoundSealedTree:
            raise ValueError(f"{name} must return an exact BoundSealedTree")
        return tree
    except BaseException:
        # This also covers asynchronous interruption after the factory has
        # returned but before the capability is handed to the caller.
        _close_tree(tree)
        raise


def _acquire_budget(factory: BudgetFactory, *, name: str) -> Budget:
    if not callable(factory):
        raise ValueError(f"{name} must be callable")
    budget = factory()
    if type(budget) is not Budget:
        raise ValueError(f"{name} must return an exact Budget")
    if budget.events or budget.usage.to_dict() != {
        "llm_calls": 0,
        "repair_iterations": 0,
        "tool_calls": 0,
    }:
        raise ValueError(f"{name} must return a fresh Budget")
    return budget


def _close_tree(tree: BoundSealedTree | None) -> None:
    if type(tree) is not BoundSealedTree:
        return
    try:
        tree.finalize()
    except BaseException:
        pass


def _require_closed_tree(tree: BoundSealedTree, *, name: str) -> None:
    try:
        if tree.usage_snapshot().finalized is not True:
            raise RuntimeError(f"{name} did not close its source capability")
    except BaseException:
        _close_tree(tree)
        raise


def run_source_discovery_task_v1(
    task: DiscoveryTaskInputV1,
    *,
    d2_tree_factory: TreeFactory,
    d2_budget_factory: BudgetFactory,
    d2_backend: StructuredModelBackend,
    d3_tree_factory: TreeFactory,
    d3_budget_factory: BudgetFactory,
    d3_backend: StructuredModelBackend,
) -> SourceDiscoveryRunV1:
    """Run one task offline with lazy, independent D2 and D3 capabilities."""

    canonical_task = _canonical_task(task)
    d2_tree: BoundSealedTree | None = None
    try:
        d2_tree = _acquire_tree(d2_tree_factory, name="d2_tree_factory")
        d2_budget = _acquire_budget(d2_budget_factory, name="d2_budget_factory")
        producer_result = _canonical_producer(
            SourceDiscoveryAttemptController(
                canonical_task,
                d2_tree,
                d2_budget,
                d2_backend,
            ).run()
        )
        if producer_result.task != canonical_task:
            raise ValueError("producer_result task does not match the requested task")
        _require_closed_tree(d2_tree, name="D2")
    except BaseException:
        _close_tree(d2_tree)
        raise

    reviewer_result: ReviewerResultV1 | None = None
    if type(producer_result) is ProducerDraftV1:
        d3_tree: BoundSealedTree | None = None
        try:
            d3_tree = _acquire_tree(d3_tree_factory, name="d3_tree_factory")
            d3_budget = _acquire_budget(d3_budget_factory, name="d3_budget_factory")
            if d3_tree is d2_tree or d3_budget is d2_budget:
                raise ValueError("D2 and D3 must use independent tree and budget values")
            reviewer_input = ReviewerInputV1(producer_draft=producer_result)
            reviewer_result = _canonical_reviewer(
                SourceDiscoveryReviewerController(
                    reviewer_input,
                    d3_tree,
                    d3_budget,
                    d3_backend,
                ).run()
            )
            if reviewer_result is None:
                raise ValueError("D3 controller must return an exact reviewer result")
            _require_closed_tree(d3_tree, name="D3")
        except BaseException:
            _close_tree(d3_tree)
            raise

    discovery_result = project_discovery_run_v1(producer_result, reviewer_result)
    return SourceDiscoveryRunV1(
        producer_result=producer_result,
        reviewer_result=reviewer_result,
        discovery_result=discovery_result,
    )


__all__ = [
    "SOURCE_DISCOVERY_RUN_CONTRACT_VERSION",
    "SOURCE_DISCOVERY_RUN_DIGEST_DOMAIN",
    "SourceDiscoveryRunV1",
    "run_source_discovery_task_v1",
]
