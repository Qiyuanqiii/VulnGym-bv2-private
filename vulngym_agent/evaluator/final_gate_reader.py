"""Independent verification of one committed E4 20+50 final-gate tree.

The reader accepts only the final, fixed-name publication layout.  Its trust
roots are the caller-supplied semantic and wire pins for the top-level receipt
and, for the training projection only, a caller-trusted benchmark root.  It
does not discover alternate files or infer pins from directory contents.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Final, Literal

from vulngym_agent.benchmark.contracts import (
    BenchmarkContractError,
    SnapshotTaskSpec,
)
from vulngym_agent.benchmark.projection_reader import (
    DiscoveryProjectionReaderError,
    DiscoveryProjectionTaskBindingV1,
    VerifiedDiscoveryProjectionV1,
    read_committed_discovery_projection_v1,
)
from vulngym_agent.benchmark.sealed_snapshot import (
    SealedSnapshotError,
    _windows_assert_no_named_streams,
)
from vulngym_agent.evaluator.e4_receipt import (
    E4BatchSuccessReceiptV1,
    E4ReceiptError,
)
from vulngym_agent.evaluator.contracts import DiscoveryTaskExecutionPlanV1
from vulngym_agent.evaluator.batch_configs import (
    BatchReplayConfigError,
    BatchReplayConfigManifestV1,
    TaskReplayConfigBindingV1,
)
from vulngym_agent.evaluator.final_gate import (
    FINAL_GATE_EXECUTION_DIRECTORY,
    FINAL_GATE_MAX_WIRE_BYTES,
    FINAL_GATE_PLAN_FILENAME,
    FINAL_GATE_PROJECTION_DIRECTORY,
    FINAL_GATE_RECEIPT_FILENAME,
    FINAL_GATE_ROOT_MEMBERS,
    FINAL_GATE_SPLIT_MEMBERS,
    FINAL_GATE_TEST_DIRECTORY,
    FINAL_GATE_TRAIN_DIRECTORY,
    FinalGateContractError,
    FinalGatePlanV1,
    FinalGateReceiptV1,
    FinalGateSplitPlanV1,
    FinalGateSplitReceiptClosureV1,
)
from vulngym_agent.evaluator.publication_reader import (
    E4PublicationReaderError,
    read_committed_e4_discovery_execution_v1,
)
from vulngym_agent.evaluator.supervisor import (
    EvaluatorSupervisorError,
    _is_reparse,
    _materialized_identity,
)


FINAL_GATE_READER_VERSION: Final[str] = "discovery-e4-final-gate-reader-v1"

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_SPLIT_DIRECTORIES: Final[dict[str, str]] = {
    "test": FINAL_GATE_TEST_DIRECTORY,
    "train": FINAL_GATE_TRAIN_DIRECTORY,
}


class FinalGateReaderError(RuntimeError):
    """Stable, path-free rejection for a committed final-gate publication."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "final_gate_invalid"
        # This reader is intentionally usable only at the committed-name
        # boundary.  Any failed verification must therefore be reported as a
        # committed publication whose validity is uncertain, never as a safe
        # pre-commit failure.
        self.committed = True
        super().__init__(message)


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise FinalGateReaderError(
            "invalid_argument", f"{name} must be lower-case SHA-256"
        )
    return value


def _directory_identity(
    value: os.stat_result,
) -> tuple[int, int, int | None, int | None]:
    return (
        value.st_dev,
        value.st_ino,
        getattr(value, "st_mtime_ns", None),
        getattr(value, "st_ctime_ns", None),
    )


def _file_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int | None]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        getattr(value, "st_mtime_ns", None),
    )


def _is_private_contract_file(value: os.stat_result) -> bool:
    if os.name != "posix":
        return True
    return (
        value.st_mode & (stat.S_IRWXG | stat.S_IRWXO) == 0
        and value.st_uid == os.geteuid()
    )


def _e4_wire_sha256_exact(value: E4BatchSuccessReceiptV1) -> str:
    payload = value.to_bytes()
    if type(payload) is not bytes:
        raise FinalGateReaderError(
            "binding_mismatch", "E4 receipt wire has an invalid exact type"
        )
    return hashlib.sha256(payload).hexdigest()


def _checked_root(
    value: str | os.PathLike[str],
) -> tuple[
    Path,
    tuple[tuple[Path, tuple[int, int]], ...],
    tuple[int, int, int | None, int | None],
]:
    if type(value) not in {str, type(Path())}:
        raise FinalGateReaderError(
            "invalid_argument", "final-gate root must be an exact path value"
        )
    try:
        raw = os.fspath(value)
        if type(raw) is not str or not raw:
            raise ValueError("empty path")
        root = Path(os.path.abspath(raw))
    except (OSError, TypeError, ValueError):
        raise FinalGateReaderError(
            "invalid_argument", "final-gate root path is invalid"
        ) from None
    if not root.name or root.name in {".", ".."}:
        raise FinalGateReaderError(
            "invalid_argument", "final-gate root name is invalid"
        )

    chain: list[tuple[Path, tuple[int, int]]] = []
    try:
        for component in reversed((root.parent, *root.parent.parents)):
            state = os.lstat(component)
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
            ):
                raise FinalGateReaderError(
                    "unsafe_path", "final-gate parent chain is unsafe"
                )
            chain.append((component, (state.st_dev, state.st_ino)))
        root_state = os.lstat(root)
        if (
            not stat.S_ISDIR(root_state.st_mode)
            or stat.S_ISLNK(root_state.st_mode)
            or _is_reparse(root_state)
        ):
            raise FinalGateReaderError(
                "unsafe_path", "final-gate root is unsafe"
            )
        resolved = root.resolve(strict=True)
        resolved_state = os.lstat(resolved)
        if (
            not stat.S_ISDIR(resolved_state.st_mode)
            or stat.S_ISLNK(resolved_state.st_mode)
            or _is_reparse(resolved_state)
            or (resolved_state.st_dev, resolved_state.st_ino)
            != (root_state.st_dev, root_state.st_ino)
        ):
            raise FinalGateReaderError(
                "unsafe_path", "final-gate root resolution changed identity"
            )
    except FinalGateReaderError:
        raise
    except OSError:
        raise FinalGateReaderError(
            "unsafe_path", "final-gate root is unavailable"
        ) from None
    return root, tuple(chain), _directory_identity(root_state)


def _assert_parent_chain(
    chain: tuple[tuple[Path, tuple[int, int]], ...]
) -> None:
    try:
        for component, expected in chain:
            state = os.lstat(component)
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
                or (state.st_dev, state.st_ino) != expected
            ):
                raise FinalGateReaderError(
                    "input_changed", "final-gate parent chain changed while reading"
                )
    except FinalGateReaderError:
        raise
    except OSError:
        raise FinalGateReaderError(
            "input_changed", "final-gate parent chain changed while reading"
        ) from None


def _member_names(root: Path) -> frozenset[str]:
    try:
        with os.scandir(root) as entries:
            return frozenset(item.name for item in entries)
    except OSError:
        raise FinalGateReaderError(
            "input_changed", "final-gate membership is unavailable"
        ) from None


def _require_plain_directory(path: Path) -> None:
    try:
        state = os.lstat(path)
    except OSError:
        raise FinalGateReaderError(
            "unsafe_member", "final-gate directory is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or _is_reparse(state)
    ):
        raise FinalGateReaderError(
            "unsafe_member", "final-gate directory is unsafe"
        )


def _plain_directory_identity(
    path: Path,
) -> tuple[int, int, int | None, int | None]:
    _require_plain_directory(path)
    try:
        return _directory_identity(os.lstat(path))
    except OSError:
        raise FinalGateReaderError(
            "input_changed", "final-gate directory identity is unavailable"
        ) from None


def _assert_exact_layout(root: Path) -> None:
    if _member_names(root) != FINAL_GATE_ROOT_MEMBERS:
        raise FinalGateReaderError(
            "final_gate_invalid", "final-gate root membership is not exact"
        )
    for split_directory in (
        FINAL_GATE_TEST_DIRECTORY,
        FINAL_GATE_TRAIN_DIRECTORY,
    ):
        split_root = root / split_directory
        _require_plain_directory(split_root)
        if _member_names(split_root) != FINAL_GATE_SPLIT_MEMBERS:
            raise FinalGateReaderError(
                "final_gate_invalid", "final-gate split membership is not exact"
            )
        _require_plain_directory(split_root / FINAL_GATE_EXECUTION_DIRECTORY)
        _require_plain_directory(split_root / FINAL_GATE_PROJECTION_DIRECTORY)


def _read_contract_member_once(
    root: Path, name: str
) -> tuple[bytes, tuple[int, int, int, int | None]]:
    path = root / name
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_nlink != 1
            or not _is_private_contract_file(before)
            or before.st_size < 0
            or before.st_size > FINAL_GATE_MAX_WIRE_BYTES
        ):
            raise FinalGateReaderError(
                "unsafe_member", "final-gate contract member is unsafe or oversized"
            )
        if os.name == "nt":
            _windows_assert_no_named_streams(path)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            identity = _file_identity(opened)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or opened.st_nlink != 1
                or not _is_private_contract_file(opened)
                or identity != _file_identity(before)
            ):
                raise FinalGateReaderError(
                    "input_changed", "final-gate contract changed while opening"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, FINAL_GATE_MAX_WIRE_BYTES + 1 - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > FINAL_GATE_MAX_WIRE_BYTES:
                    raise FinalGateReaderError(
                        "limit_exceeded", "final-gate contract exceeds its byte limit"
                    )
            finished = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = os.lstat(path)
        if (
            not stat.S_ISREG(finished.st_mode)
            or _is_reparse(finished)
            or finished.st_nlink != 1
            or not _is_private_contract_file(finished)
            or not stat.S_ISREG(after.st_mode)
            or stat.S_ISLNK(after.st_mode)
            or _is_reparse(after)
            or after.st_nlink != 1
            or not _is_private_contract_file(after)
            or _file_identity(finished) != identity
            or _file_identity(after) != identity
            or total != opened.st_size
        ):
            raise FinalGateReaderError(
                "input_changed", "final-gate contract changed while reading"
            )
        return b"".join(chunks), identity
    except FinalGateReaderError:
        raise
    except (OSError, SealedSnapshotError):
        raise FinalGateReaderError(
            "unsafe_member", "final-gate contract could not be read safely"
        ) from None


def _read_and_parse_contracts(
    root: Path,
    *,
    expected_receipt_sha256: str,
    expected_wire_sha256: str,
) -> tuple[
    FinalGateReceiptV1,
    FinalGatePlanV1,
    tuple[int, int, int, int | None],
    tuple[int, int, int, int | None],
]:
    receipt_payload, receipt_identity = _read_contract_member_once(
        root, FINAL_GATE_RECEIPT_FILENAME
    )
    receipt = FinalGateReceiptV1.from_bytes(
        receipt_payload,
        expected_receipt_sha256=expected_receipt_sha256,
        expected_wire_sha256=expected_wire_sha256,
    )
    plan_payload, plan_identity = _read_contract_member_once(
        root, FINAL_GATE_PLAN_FILENAME
    )
    plan = FinalGatePlanV1.from_bytes(
        plan_payload,
        expected_plan_sha256=receipt.plan_sha256,
        expected_wire_sha256=receipt.plan_wire_sha256,
    )
    if plan != receipt.plan or plan.to_bytes() != plan_payload:
        raise FinalGateReaderError(
            "binding_mismatch", "independent final-gate plan is detached"
        )
    return receipt, plan, receipt_identity, plan_identity


def _projection_bindings(
    e4_receipt: E4BatchSuccessReceiptV1,
) -> tuple[DiscoveryProjectionTaskBindingV1, ...]:
    execution_receipt = e4_receipt.execution_receipt
    execution_plan = execution_receipt.plan
    try:
        values = tuple(
            DiscoveryProjectionTaskBindingV1(
                task=SnapshotTaskSpec(
                    task_id=batch_task.task_id,
                    repo_url=batch_task.repo_url,
                    commit=batch_task.commit,
                    split=batch_task.split,
                    instruction_id=batch_task.instruction_id,
                ),
                snapshot_id=task_plan.snapshot_id,
                dataset_sha256=task_receipt.dataset_sha256,
            )
            for batch_task, task_plan, task_receipt in zip(
                execution_plan.batch.tasks,
                execution_plan.tasks,
                execution_receipt.tasks,
                strict=True,
            )
        )
        if any(
            batch_task.task_id != task_plan.task_id
            or task_plan.task_id != task_receipt.task_id
            or task_plan.snapshot_id != task_receipt.snapshot_id
            for batch_task, task_plan, task_receipt in zip(
                execution_plan.batch.tasks,
                execution_plan.tasks,
                execution_receipt.tasks,
                strict=True,
            )
        ):
            raise FinalGateReaderError(
                "binding_mismatch", "E4 projection task identities are detached"
            )
    except (
        AttributeError,
        BenchmarkContractError,
        BatchReplayConfigError,
        DiscoveryProjectionReaderError,
        TypeError,
        ValueError,
    ):
        raise FinalGateReaderError(
            "binding_mismatch", "E4 output cannot form exact projection bindings"
        ) from None
    return values


def _verify_projection_summary(
    verified: VerifiedDiscoveryProjectionV1,
    *,
    split: Literal["test", "train"],
    closure: FinalGateSplitReceiptClosureV1,
) -> None:
    try:
        summary = verified.summary
        if (
            summary.split != split
            or summary.task_count != closure.task_count
            or summary.finalized_task_count != closure.finalized_task_count
            or summary.deferred_task_count != closure.deferred_task_count
            or summary.candidate_count != closure.candidate_count
            or summary.finding_count != closure.finding_count
            or summary.bundle_index_sha256 != closure.artifact_index_sha256
            or summary.output_manifest_sha256
            != closure.projection_manifest_sha256
            or verified.aggregate_file_sha256
            != closure.aggregate_file_sha256
        ):
            raise FinalGateReaderError(
                "binding_mismatch", "projection closure is detached from its output"
            )
    except FinalGateReaderError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise FinalGateReaderError(
            "binding_mismatch", "projection reader returned an invalid closure"
        ) from None


def _verify_split(
    root: Path,
    *,
    split: Literal["test", "train"],
    final_plan: FinalGatePlanV1,
    split_plan: FinalGateSplitPlanV1,
    closure: FinalGateSplitReceiptClosureV1,
    benchmark_root: str | os.PathLike[str] | None,
) -> tuple[
    tuple[int, int, int | None, int | None],
    tuple[tuple[object, ...], ...],
    tuple[tuple[object, ...], ...],
]:
    if split == "train":
        if type(benchmark_root) not in {str, type(Path())}:
            raise FinalGateReaderError(
                "invalid_argument",
                "training final-gate verification requires a benchmark root",
            )
        try:
            if type(os.fspath(benchmark_root)) is not str or not os.fspath(
                benchmark_root
            ):
                raise ValueError("empty path")
        except (OSError, TypeError, ValueError):
            raise FinalGateReaderError(
                "invalid_argument", "training benchmark root is invalid"
            ) from None
    split_root = root / _SPLIT_DIRECTORIES[split]
    execution_root = split_root / FINAL_GATE_EXECUTION_DIRECTORY
    projection_root = split_root / FINAL_GATE_PROJECTION_DIRECTORY
    split_identity = _plain_directory_identity(split_root)
    execution_before = _materialized_identity(execution_root)
    e4_receipt = read_committed_e4_discovery_execution_v1(
        execution_root,
        expected_receipt_sha256=closure.e4_receipt_sha256,
        expected_wire_sha256=closure.e4_receipt_wire_sha256,
    )
    if type(e4_receipt) is not E4BatchSuccessReceiptV1:
        raise FinalGateReaderError(
            "binding_mismatch", "E4 reader returned an invalid exact type"
        )
    execution_identity = _materialized_identity(execution_root)
    if execution_identity != execution_before:
        raise FinalGateReaderError(
            "input_changed", "E4 split output changed during verification"
        )
    try:
        execution_receipt = e4_receipt.execution_receipt
        execution_plan = execution_receipt.plan
        batch = execution_plan.batch
        policy = execution_plan.execution_policy
        if (
            e4_receipt.receipt_sha256 != closure.e4_receipt_sha256
            or _e4_wire_sha256_exact(e4_receipt)
            != closure.e4_receipt_wire_sha256
            or batch.split != split
            or batch.task_count != split_plan.task_count
            or batch.task_count != closure.task_count
            or len(batch.tasks) != closure.task_count
            or len(execution_plan.tasks) != closure.task_count
            or len(execution_receipt.tasks) != closure.task_count
            or len(e4_receipt.success_closures) != closure.task_count
            or batch.batch_manifest_sha256
            != split_plan.sealed_batch_manifest_sha256
            or batch.attestation_key_id != split_plan.snapshot_key_id
            or batch.public_manifest_sha256 != final_plan.public_manifest_sha256
            or policy.policy_sha256 != final_plan.execution_policy_sha256
            or policy.policy_sha256 != closure.execution_policy_sha256
            or policy.wire_sha256
            != final_plan.execution_policy_wire_sha256
            or policy.wire_sha256 != closure.execution_policy_wire_sha256
            or execution_plan.plan_sha256 != closure.execution_plan_sha256
            or execution_plan.wire_sha256
            != closure.execution_plan_wire_sha256
            or execution_receipt.artifact_index_sha256
            != closure.artifact_index_sha256
        ):
            raise FinalGateReaderError(
                "binding_mismatch", "E4 split output is detached from final-gate pins"
            )
    except FinalGateReaderError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise FinalGateReaderError(
            "binding_mismatch", "E4 reader returned an invalid split closure"
        ) from None

    try:
        if any(
            type(task_plan) is not DiscoveryTaskExecutionPlanV1
            for task_plan in execution_plan.tasks
        ):
            raise FinalGateReaderError(
                "binding_mismatch", "E4 replay task plan has an invalid exact type"
            )
        replay_manifest = BatchReplayConfigManifestV1(
            split=split,
            tasks=tuple(
                TaskReplayConfigBindingV1(
                    task_id=task_plan.task_id,
                    d2_replay_sha256=task_plan.d2_replay_sha256,
                    d2_replay_wire_sha256=task_plan.d2_replay_wire_sha256,
                    d3_replay_sha256=task_plan.d3_replay_sha256,
                    d3_replay_wire_sha256=task_plan.d3_replay_wire_sha256,
                )
                for task_plan in execution_plan.tasks
            ),
        )
        replay_wire = replay_manifest.to_bytes()
        if (
            replay_manifest.manifest_sha256
            != split_plan.replay_manifest_sha256
            or hashlib.sha256(replay_wire).hexdigest()
            != split_plan.replay_manifest_wire_sha256
        ):
            raise FinalGateReaderError(
                "binding_mismatch", "E4 replay manifest is detached from final-gate pins"
            )
    except FinalGateReaderError:
        raise
    except (AttributeError, BatchReplayConfigError, TypeError, ValueError):
        raise FinalGateReaderError(
            "binding_mismatch", "E4 task plans cannot reconstruct replay pins"
        ) from None

    bindings = _projection_bindings(e4_receipt)
    if len(bindings) != closure.task_count:
        raise FinalGateReaderError(
            "binding_mismatch", "projection binding count is detached"
        )
    projection_before = _materialized_identity(projection_root)
    verified_projection = read_committed_discovery_projection_v1(
        projection_root,
        expected_split=split,
        expected_manifest_sha256=closure.projection_manifest_sha256,
        expected_artifact_index_sha256=closure.artifact_index_sha256,
        expected_tasks=bindings,
        benchmark_root=benchmark_root if split == "train" else None,
    )
    if type(verified_projection) is not VerifiedDiscoveryProjectionV1:
        raise FinalGateReaderError(
            "binding_mismatch", "projection reader returned an invalid exact type"
        )
    _verify_projection_summary(
        verified_projection, split=split, closure=closure
    )
    projection_identity = _materialized_identity(projection_root)
    if (
        projection_identity != projection_before
        or _materialized_identity(execution_root) != execution_identity
        or _plain_directory_identity(split_root) != split_identity
    ):
        raise FinalGateReaderError(
            "input_changed", "final-gate split changed during verification"
        )
    return split_identity, execution_identity, projection_identity


def read_committed_e4_final_gate_v1(
    output_root: str | os.PathLike[str],
    *,
    expected_receipt_sha256: str,
    expected_wire_sha256: str,
    benchmark_root: str | os.PathLike[str] | None,
) -> FinalGateReceiptV1:
    """Re-establish the exact receipt for one stable committed final gate.

    The blind test execution and projection are verified before the trusted
    training aggregate surface is entered.  In particular, the test projection
    is always called with ``benchmark_root=None``.
    """

    receipt_pin = _require_sha256(
        expected_receipt_sha256, name="expected_receipt_sha256"
    )
    wire_pin = _require_sha256(
        expected_wire_sha256, name="expected_wire_sha256"
    )
    root, parent_chain, root_identity = _checked_root(output_root)
    try:
        _assert_exact_layout(root)
        receipt, plan, receipt_identity, plan_identity = (
            _read_and_parse_contracts(
                root,
                expected_receipt_sha256=receipt_pin,
                expected_wire_sha256=wire_pin,
            )
        )

        # Preserve the plan's test-first authorization order at the reader
        # boundary.  No benchmark-root operation occurs before this call
        # returns successfully.
        test_identities = _verify_split(
            root,
            split="test",
            final_plan=plan,
            split_plan=plan.test,
            closure=receipt.test,
            benchmark_root=None,
        )
        train_identities = _verify_split(
            root,
            split="train",
            final_plan=plan,
            split_plan=plan.train,
            closure=receipt.train,
            benchmark_root=benchmark_root,
        )

        repeated_receipt, repeated_plan, repeated_receipt_identity, repeated_plan_identity = (
            _read_and_parse_contracts(
                root,
                expected_receipt_sha256=receipt_pin,
                expected_wire_sha256=wire_pin,
            )
        )
        _assert_exact_layout(root)
        final_root = os.lstat(root)
        _assert_parent_chain(parent_chain)
        final_test_split_identity = _plain_directory_identity(
            root / FINAL_GATE_TEST_DIRECTORY
        )
        final_train_split_identity = _plain_directory_identity(
            root / FINAL_GATE_TRAIN_DIRECTORY
        )
        final_test_execution_identity = _materialized_identity(
            root / FINAL_GATE_TEST_DIRECTORY / FINAL_GATE_EXECUTION_DIRECTORY
        )
        final_test_projection_identity = _materialized_identity(
            root / FINAL_GATE_TEST_DIRECTORY / FINAL_GATE_PROJECTION_DIRECTORY
        )
        final_train_execution_identity = _materialized_identity(
            root / FINAL_GATE_TRAIN_DIRECTORY / FINAL_GATE_EXECUTION_DIRECTORY
        )
        final_train_projection_identity = _materialized_identity(
            root / FINAL_GATE_TRAIN_DIRECTORY / FINAL_GATE_PROJECTION_DIRECTORY
        )
        if (
            repeated_receipt != receipt
            or repeated_plan != plan
            or repeated_receipt_identity != receipt_identity
            or repeated_plan_identity != plan_identity
            or _directory_identity(final_root) != root_identity
            or test_identities
            != (
                final_test_split_identity,
                final_test_execution_identity,
                final_test_projection_identity,
            )
            or train_identities
            != (
                final_train_split_identity,
                final_train_execution_identity,
                final_train_projection_identity,
            )
        ):
            raise FinalGateReaderError(
                "input_changed", "final-gate publication changed during verification"
            )
        return repeated_receipt
    except FinalGateReaderError:
        raise
    except (
        DiscoveryProjectionReaderError,
        BatchReplayConfigError,
        E4PublicationReaderError,
        E4ReceiptError,
        EvaluatorSupervisorError,
        FinalGateContractError,
        AttributeError,
        OSError,
        TypeError,
        ValueError,
    ):
        raise FinalGateReaderError(
            "final_gate_invalid", "committed final-gate publication did not verify"
        ) from None


__all__ = [
    "FINAL_GATE_READER_VERSION",
    "FinalGateReaderError",
    "read_committed_e4_final_gate_v1",
]
