"""Independent verification of one committed E4 execution publication."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Final

from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.harness import (
    ArtifactBundleDigest,
    BenchmarkHarnessError,
    load_artifact_bundle_index,
)
from vulngym_agent.evaluator.contracts import (
    EVALUATOR_CONTRACT_MAX_WIRE_BYTES,
    DiscoveryBatchExecutionPlanV2,
    DiscoveryBatchExecutionReceiptV2,
    EvaluatorContractError,
)
from vulngym_agent.evaluator.e4_receipt import (
    E4_SUCCESS_RECEIPT_FILENAME,
    E4_SUCCESS_RECEIPT_MAX_BYTES,
    E4BatchSuccessReceiptV2,
    E4ReceiptError,
)
from vulngym_agent.evaluator.supervisor import (
    EvaluatorSupervisorError,
    _assert_publication_chain,
    _is_reparse,
    _materialized_identity,
    _read_bounded_regular_file,
)
from vulngym_agent.orchestrator.discovery_replay import (
    DiscoveryReplayError,
    read_discovery_run_bundle,
)


E4_PUBLICATION_READER_VERSION: Final[str] = (
    "discovery-e4-publication-reader-v1"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_ROOT_MEMBERS: Final[frozenset[str]] = frozenset(
    {
        "artifact-index.json",
        "bundles",
        "execution-plan.json",
        "execution-receipt.json",
        E4_SUCCESS_RECEIPT_FILENAME,
    }
)


class E4PublicationReaderError(RuntimeError):
    """Stable, path-free rejection from the committed-output reader."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "publication_invalid"
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise E4PublicationReaderError(
            "publication_invalid", "published discovery result is not canonical"
        ) from None


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise E4PublicationReaderError(
            "invalid_argument", f"{name} must be lower-case SHA-256"
        )
    return value


def _checked_publication_root(
    value: str | os.PathLike[str],
) -> tuple[
    Path,
    tuple[tuple[Path, tuple[int, int]], ...],
    tuple[int, int],
]:
    if type(value) not in {str, type(Path())}:
        raise E4PublicationReaderError(
            "invalid_argument", "publication root must be an exact path value"
        )
    try:
        raw = os.fspath(value)
        if type(raw) is not str or not raw:
            raise ValueError("empty path")
        root = Path(os.path.abspath(raw))
    except (OSError, TypeError, ValueError):
        raise E4PublicationReaderError(
            "invalid_argument", "publication root path is invalid"
        ) from None
    if not root.name or root.name in {".", ".."}:
        raise E4PublicationReaderError(
            "invalid_argument", "publication root name is invalid"
        )
    checked_chain: list[tuple[Path, tuple[int, int]]] = []
    try:
        for component in reversed((root.parent, *root.parent.parents)):
            state = os.lstat(component)
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
            ):
                raise E4PublicationReaderError(
                    "unsafe_publication", "publication parent chain is unsafe"
                )
            checked_chain.append(
                (component, (state.st_dev, state.st_ino))
            )
        root_state = os.lstat(root)
        if (
            not stat.S_ISDIR(root_state.st_mode)
            or stat.S_ISLNK(root_state.st_mode)
            or _is_reparse(root_state)
        ):
            raise E4PublicationReaderError(
                "unsafe_publication", "publication root is unsafe"
            )
        resolved_root = root.resolve(strict=True)
        resolved_state = os.lstat(resolved_root)
        if (
            not stat.S_ISDIR(resolved_state.st_mode)
            or stat.S_ISLNK(resolved_state.st_mode)
            or _is_reparse(resolved_state)
            or (resolved_state.st_dev, resolved_state.st_ino)
            != (root_state.st_dev, root_state.st_ino)
        ):
            raise E4PublicationReaderError(
                "unsafe_publication", "publication root resolution changed"
            )
    except E4PublicationReaderError:
        raise
    except OSError as error:
        raise E4PublicationReaderError(
            "unsafe_publication", "publication root is unavailable"
        ) from error
    return (
        root,
        tuple(checked_chain),
        (root_state.st_dev, root_state.st_ino),
    )


def _member_names(root: Path) -> frozenset[str]:
    try:
        with os.scandir(root) as entries:
            return frozenset(item.name for item in entries)
    except OSError as error:
        raise E4PublicationReaderError(
            "publication_invalid", "publication membership is unavailable"
        ) from error


def _assert_exact_membership(
    root: Path,
    *,
    task_ids: tuple[str, ...] | None,
) -> None:
    if _member_names(root) != _ROOT_MEMBERS:
        raise E4PublicationReaderError(
            "publication_invalid", "publication root membership is not exact"
        )
    bundles = root / "bundles"
    state = os.lstat(bundles)
    if (
        not stat.S_ISDIR(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or _is_reparse(state)
    ):
        raise E4PublicationReaderError(
            "publication_invalid", "publication bundle root is unsafe"
        )
    if task_ids is not None and _member_names(bundles) != frozenset(task_ids):
        raise E4PublicationReaderError(
            "publication_invalid", "publication bundle membership is not exact"
        )


def _read_contracts(
    root: Path,
    *,
    expected_receipt_sha256: str,
    expected_wire_sha256: str,
) -> tuple[
    E4BatchSuccessReceiptV2,
    DiscoveryBatchExecutionReceiptV2,
    DiscoveryBatchExecutionPlanV2,
]:
    success_receipt = E4BatchSuccessReceiptV2.from_bytes(
        _read_bounded_regular_file(
            root / E4_SUCCESS_RECEIPT_FILENAME,
            maximum_bytes=E4_SUCCESS_RECEIPT_MAX_BYTES,
        ),
        expected_receipt_sha256=expected_receipt_sha256,
        expected_wire_sha256=expected_wire_sha256,
    )
    embedded_execution = success_receipt.execution_receipt
    execution_receipt = DiscoveryBatchExecutionReceiptV2.from_bytes(
        _read_bounded_regular_file(
            root / "execution-receipt.json",
            maximum_bytes=EVALUATOR_CONTRACT_MAX_WIRE_BYTES,
        ),
        expected_receipt_sha256=(
            success_receipt.execution_receipt_sha256
        ),
        expected_wire_sha256=(
            success_receipt.execution_receipt_wire_sha256
        ),
    )
    plan = execution_receipt.plan
    parsed_plan = DiscoveryBatchExecutionPlanV2.from_bytes(
        _read_bounded_regular_file(
            root / "execution-plan.json",
            maximum_bytes=EVALUATOR_CONTRACT_MAX_WIRE_BYTES,
        ),
        expected_plan_sha256=plan.plan_sha256,
        expected_wire_sha256=plan.wire_sha256,
    )
    if (
        execution_receipt != embedded_execution
        or parsed_plan != plan
        or execution_receipt.plan != parsed_plan
    ):
        raise E4PublicationReaderError(
            "publication_invalid", "published execution contracts are detached"
        )
    return success_receipt, execution_receipt, parsed_plan


def read_committed_e4_discovery_execution_v1(
    output_root: str | os.PathLike[str],
    *,
    expected_receipt_sha256: str,
    expected_wire_sha256: str,
) -> E4BatchSuccessReceiptV2:
    """Re-establish an E4 success receipt from one stable committed tree."""

    receipt_sha256 = _require_sha256(
        expected_receipt_sha256, name="expected_receipt_sha256"
    )
    wire_sha256 = _require_sha256(
        expected_wire_sha256, name="expected_wire_sha256"
    )
    root, parent_chain, root_identity = _checked_publication_root(output_root)
    try:
        _assert_exact_membership(root, task_ids=None)
        before_identity = _materialized_identity(root)
        success_receipt, execution_receipt, plan = _read_contracts(
            root,
            expected_receipt_sha256=receipt_sha256,
            expected_wire_sha256=wire_sha256,
        )
        task_ids = tuple(item.task_id for item in plan.tasks)
        _assert_exact_membership(root, task_ids=task_ids)
        task_specs = tuple(
            SnapshotTaskSpec(
                task_id=member.task_id,
                repo_url=member.repo_url,
                commit=member.commit,
                split=member.split,
                instruction_id=member.instruction_id,
            )
            for member in plan.batch.tasks
        )
        expected_bundles = tuple(
            ArtifactBundleDigest(
                task_id=receipt.task_id,
                dataset_sha256=receipt.dataset_sha256,
            )
            for receipt in execution_receipt.tasks
        )
        index = load_artifact_bundle_index(
            root / "artifact-index.json",
            expected_sha256=execution_receipt.artifact_index_sha256,
            split=plan.batch.split,
            tasks=task_specs,
        )
        if tuple(index.bundles) != expected_bundles:
            raise E4PublicationReaderError(
                "publication_invalid", "artifact index order or digest is detached"
            )
        for member, task_plan, task_receipt in zip(
            plan.batch.tasks,
            plan.tasks,
            execution_receipt.tasks,
            strict=True,
        ):
            verified = read_discovery_run_bundle(
                root / "bundles" / member.task_id,
                expected_dataset_sha256=task_receipt.dataset_sha256,
                expected_task_id=member.task_id,
            )
            expected_task = DiscoveryTaskInputV1(
                task_id=member.task_id,
                repo_url=member.repo_url,
                commit=member.commit,
                instruction_id=member.instruction_id,
                snapshot_manifest_sha256=member.snapshot_manifest_sha256,
                snapshot_content_root=member.snapshot_content_root,
            )
            run = verified.run
            run_wire = run.to_wire()
            result_sha256 = hashlib.sha256(
                _canonical_json(run.discovery_result.to_dict())
            ).hexdigest()
            if (
                run.task != expected_task
                or run.task.snapshot_id != task_plan.snapshot_id
                or run.run_sha256 != task_receipt.run_sha256
                or hashlib.sha256(run_wire).hexdigest()
                != task_receipt.run_wire_sha256
                or result_sha256 != task_receipt.discovery_result_sha256
                or verified.dataset_sha256 != task_receipt.dataset_sha256
            ):
                raise E4PublicationReaderError(
                    "publication_invalid",
                    "published discovery run is detached from its receipt",
                )

        repeated_success, repeated_execution, repeated_plan = _read_contracts(
            root,
            expected_receipt_sha256=receipt_sha256,
            expected_wire_sha256=wire_sha256,
        )
        _assert_exact_membership(root, task_ids=task_ids)
        after_identity = _materialized_identity(root)
        root_after = os.lstat(root)
        _assert_publication_chain(parent_chain)
        if (
            repeated_success != success_receipt
            or repeated_execution != execution_receipt
            or repeated_plan != plan
            or after_identity != before_identity
            or (root_after.st_dev, root_after.st_ino) != root_identity
        ):
            raise E4PublicationReaderError(
                "publication_invalid", "publication changed during verification"
            )
        return repeated_success
    except E4PublicationReaderError:
        raise
    except (
        BenchmarkHarnessError,
        DiscoveryReplayError,
        E4ReceiptError,
        EvaluatorContractError,
        EvaluatorSupervisorError,
        AttributeError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        raise E4PublicationReaderError(
            "publication_invalid", "committed E4 publication did not verify"
        ) from error


__all__ = [
    "E4_PUBLICATION_READER_VERSION",
    "E4PublicationReaderError",
    "read_committed_e4_discovery_execution_v1",
]
