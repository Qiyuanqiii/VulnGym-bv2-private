"""Trusted test-first transaction coordinator for the fixed E4 final gate.

The single-split driver and projection writer each publish into a private
sibling staging tree.  Only after test execution, test projection/readback,
train execution, and train projection/readback have all closed does this
module publish that entire tree under its final name with one no-replace
rename.  A failed attempt report is returned but is never written into the
final-gate interface.

All public errors from this boundary are deliberately path-free.  A failure
before the outer rename leaves the final output absent (the mode-0700 staging
tree may remain for trusted inspection).  Once the rename may have committed,
any uncertainty is reported with ``committed=True``.
"""

from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import secrets
import stat
from typing import Final

from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.benchmark.harness import (
    BenchmarkHarnessError,
    DiscoveryProjectionSummary,
    _rename_directory_noreplace,
    project_verified_discovery_bundles,
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
from vulngym_agent.evaluator.batch_configs import (
    BatchReplayConfigError,
    BatchReplayConfigManifestV1,
    TaskReplayConfigBindingV1,
)
from vulngym_agent.evaluator.batch_runner import DiscoveryBatchAttemptReportV1
from vulngym_agent.evaluator.e4_driver import (
    E4DriverError,
    fixed_e4_execution_policy_v1,
    run_e4_discovery_split_v1,
)
from vulngym_agent.evaluator.e4_receipt import (
    E4BatchSuccessReceiptV1,
    E4ReceiptError,
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
    FINAL_GATE_TOP_K,
    FINAL_GATE_TRAIN_DIRECTORY,
    FinalGateContractError,
    FinalGatePlanV1,
    FinalGateReceiptV1,
    FinalGateSplitPlanV1,
    FinalGateSplitReceiptClosureV1,
)
from vulngym_agent.evaluator.supervisor import (
    EvaluatorSupervisorError,
    _materialized_identity,
)


FINAL_GATE_RUNNER_VERSION: Final[str] = "discovery-e4-final-gate-runner-v1"

_PATH_TYPE: Final[type[Path]] = type(Path())
_MIN_KEY_BYTES: Final[int] = 32
_MAX_KEY_BYTES: Final[int] = 4096
_MAX_OUTPUT_NAME_BYTES: Final[int] = 128
_STAGING_ATTEMPTS: Final[int] = 128


class FinalGateRunnerError(RuntimeError):
    """Stable, path-free rejection from the outer final-gate transaction."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = code if type(code) is str and code else "final_gate_failed"
        self.committed = committed is True
        super().__init__(message)


def _is_reparse(value: os.stat_result) -> bool:
    return bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    return (value.st_dev, value.st_ino)


def _require_safe_directory(path: Path, *, code: str) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError:
        raise FinalGateRunnerError(
            code, "final-gate directory input is unavailable"
        ) from None
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or _is_reparse(value):
        raise FinalGateRunnerError(
            code, "final-gate directory input is not a safe directory"
        )
    return value


def _require_private_directory(path: Path, *, code: str) -> os.stat_result:
    value = _require_safe_directory(path, code=code)
    if os.name == "posix" and stat.S_IMODE(value.st_mode) != 0o700:
        raise FinalGateRunnerError(
            code, "private final-gate directory mode is invalid"
        )
    return value


def _path_text(value: object, *, name: str) -> str:
    if type(value) not in {str, _PATH_TYPE}:
        raise FinalGateRunnerError(
            "invalid_argument", f"{name} must be an exact filesystem path"
        )
    try:
        raw = os.fspath(value)
    except (OSError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "invalid_argument", f"{name} is invalid"
        ) from None
    if type(raw) is not str or not raw or "\x00" in raw:
        raise FinalGateRunnerError(
            "invalid_argument", f"{name} is invalid"
        )
    return raw


def _canonical_existing_directory(value: object, *, name: str) -> Path:
    raw = _path_text(value, name=name)
    try:
        path = Path(os.path.abspath(raw))
    except (OSError, RuntimeError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "invalid_argument", f"{name} is unavailable"
        ) from None
    terminal: os.stat_result | None = None
    for component in reversed((path, *path.parents)):
        terminal = _require_safe_directory(component, code="invalid_argument")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "invalid_argument", f"{name} is unavailable"
        ) from None
    resolved_state = _require_safe_directory(resolved, code="invalid_argument")
    if terminal is None or _directory_identity(resolved_state) != _directory_identity(
        terminal
    ):
        raise FinalGateRunnerError(
            "invalid_argument", f"{name} changed during canonicalization"
        )
    return resolved


def _canonical_new_output(value: object) -> tuple[Path, Path, tuple[int, int]]:
    raw = _path_text(value, name="output_root")
    try:
        requested = Path(os.path.abspath(raw))
        name = requested.name
        if (
            not name
            or name in {".", ".."}
            or len(os.fsencode(name)) > _MAX_OUTPUT_NAME_BYTES
        ):
            raise ValueError("invalid output name")
        requested_parent = requested.parent
    except (OSError, RuntimeError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "invalid_argument", "final-gate output path is invalid"
        ) from None
    parent_state: os.stat_result | None = None
    for component in reversed((requested_parent, *requested_parent.parents)):
        parent_state = _require_safe_directory(component, code="invalid_argument")
    try:
        parent = requested_parent.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "invalid_argument", "final-gate output parent is invalid"
        ) from None
    resolved_parent_state = _require_safe_directory(
        parent, code="invalid_argument"
    )
    if (
        parent_state is None
        or _directory_identity(parent_state)
        != _directory_identity(resolved_parent_state)
        or (os.name == "nt" and ":" in name)
    ):
        raise FinalGateRunnerError(
            "invalid_argument", "final-gate output parent changed"
        )
    output = parent / name
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError:
        raise FinalGateRunnerError(
            "invalid_argument", "final-gate output state is unavailable"
        ) from None
    else:
        raise FinalGateRunnerError(
            "output_exists", "final-gate output already exists"
        )
    return output, parent, _directory_identity(resolved_parent_state)


def _path_contains(root: Path, candidate: Path) -> bool:
    try:
        common = os.path.commonpath(
            (os.path.normcase(str(root)), os.path.normcase(str(candidate)))
        )
    except ValueError:
        return False
    return common == os.path.normcase(str(root))


def _assert_output_disjoint(output: Path, inputs: tuple[Path, ...]) -> None:
    try:
        output_ancestor_identities = {
            _directory_identity(
                _require_safe_directory(component, code="path_overlap")
            )
            for component in (output.parent, *output.parent.parents)
        }
        input_identities = {
            _directory_identity(
                _require_safe_directory(root, code="path_overlap")
            )
            for root in inputs
        }
    except FinalGateRunnerError:
        raise
    if (
        input_identities & output_ancestor_identities
        or any(
            _path_contains(root, output) or _path_contains(output, root)
            for root in inputs
        )
    ):
        raise FinalGateRunnerError(
            "path_overlap", "final-gate output overlaps a trusted input"
        )


def _validate_command(value: object) -> str:
    raw = _path_text(value, name="docker_executable")
    if raw.strip() != raw:
        raise FinalGateRunnerError(
            "invalid_argument", "Docker executable identity is invalid"
        )
    return raw


def _validate_key(value: object, *, name: str) -> bytearray:
    if (
        type(value) is not bytearray
        or not _MIN_KEY_BYTES <= len(value) <= _MAX_KEY_BYTES
    ):
        raise FinalGateRunnerError(
            "invalid_argument", f"{name} must be an exact bounded bytearray"
        )
    return value


def _zero_key(value: object) -> None:
    if type(value) is bytearray:
        for index in range(len(value)):
            value[index] = 0


def _freeze_plan(value: object) -> FinalGatePlanV1:
    if type(value) is not FinalGatePlanV1:
        raise FinalGateRunnerError(
            "invalid_argument", "final-gate plan must have an exact contract type"
        )
    try:
        wire = value.to_bytes()
        result = FinalGatePlanV1.from_bytes(
            wire,
            expected_plan_sha256=value.plan_sha256,
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )
    except (AttributeError, FinalGateContractError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "plan_rejected", "final-gate plan did not normalize"
        ) from None
    if result != value or result.to_bytes() != wire:
        raise FinalGateRunnerError(
            "plan_rejected", "final-gate plan changed while freezing"
        )
    return result


def _assert_policy_matches_plan(
    plan: FinalGatePlanV1, runtime_image_id: object
) -> None:
    if type(runtime_image_id) is not str:
        raise FinalGateRunnerError(
            "invalid_argument", "runtime image identity must be an exact string"
        )
    try:
        policy = fixed_e4_execution_policy_v1(runtime_image_id)
        wire = policy.to_bytes()
    except E4DriverError:
        raise FinalGateRunnerError(
            "policy_rejected", "fixed E4 execution policy is invalid"
        ) from None
    except (AttributeError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "policy_rejected", "fixed E4 execution policy did not close"
        ) from None
    if (
        policy.policy_sha256 != plan.execution_policy_sha256
        or hashlib.sha256(wire).hexdigest()
        != plan.execution_policy_wire_sha256
        or policy.wire_sha256 != plan.execution_policy_wire_sha256
    ):
        raise FinalGateRunnerError(
            "policy_mismatch", "fixed E4 policy differs from the final-gate plan"
        )


def _assert_parent(parent: Path, expected: tuple[int, int]) -> None:
    current = _require_safe_directory(parent, code="output_parent_changed")
    if _directory_identity(current) != expected:
        raise FinalGateRunnerError(
            "output_parent_changed", "final-gate output parent changed"
        )


def _create_private_staging(
    output: Path, parent: Path, parent_identity: tuple[int, int]
) -> tuple[Path, tuple[int, int]]:
    _assert_parent(parent, parent_identity)
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError:
        raise FinalGateRunnerError(
            "output_state_changed", "final-gate output state changed"
        ) from None
    else:
        raise FinalGateRunnerError(
            "output_exists", "final-gate output appeared before staging"
        )
    for _ in range(_STAGING_ATTEMPTS):
        candidate = parent / (
            f".{output.name}.{secrets.token_hex(16)}.staging"
        )
        try:
            os.mkdir(candidate, 0o700)
        except FileExistsError:
            continue
        except OSError:
            raise FinalGateRunnerError(
                "staging_failed", "private final-gate staging could not be created"
            ) from None
        if os.name == "posix":
            try:
                os.chmod(candidate, 0o700, follow_symlinks=False)
            except OSError:
                raise FinalGateRunnerError(
                    "staging_failed", "private final-gate staging mode did not close"
                ) from None
        state = _require_private_directory(candidate, code="staging_failed")
        return candidate, _directory_identity(state)
    raise FinalGateRunnerError(
        "staging_failed", "private final-gate staging name allocation failed"
    )


def _create_private_directory(path: Path) -> tuple[int, int]:
    try:
        os.mkdir(path, 0o700)
        if os.name == "posix":
            os.chmod(path, 0o700, follow_symlinks=False)
    except OSError:
        raise FinalGateRunnerError(
            "staging_failed", "private final-gate split could not be created"
        ) from None
    return _directory_identity(
        _require_private_directory(path, code="staging_failed")
    )


def _assert_directory_identity(path: Path, expected: tuple[int, int]) -> None:
    if _directory_identity(
        _require_private_directory(path, code="staging_changed")
    ) != expected:
        raise FinalGateRunnerError(
            "staging_changed", "private final-gate staging identity changed"
        )


def _member_names(path: Path) -> frozenset[str]:
    try:
        return frozenset(item.name for item in os.scandir(path))
    except OSError:
        raise FinalGateRunnerError(
            "staging_changed", "private final-gate membership is unavailable"
        ) from None


def _assert_members(path: Path, expected: frozenset[str]) -> None:
    if _member_names(path) != expected:
        raise FinalGateRunnerError(
            "staging_changed", "private final-gate membership changed"
        )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count < 1:
            raise OSError(errno.EIO, "short final-gate write")
        written += count


def _write_control_file(path: Path, payload: bytes) -> tuple[int, int]:
    if type(payload) is not bytes or not payload:
        raise FinalGateRunnerError(
            "contract_rejected", "final-gate control bytes are invalid"
        )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor: int | None = None
    finished_identity: tuple[object, ...] | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
        ):
            raise OSError(errno.EINVAL, "control member is not regular")
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        finished = os.fstat(descriptor)
        if (
            not stat.S_ISREG(finished.st_mode)
            or _is_reparse(finished)
            or finished.st_nlink != 1
            or (finished.st_dev, finished.st_ino)
            != (opened.st_dev, opened.st_ino)
            or finished.st_size != len(payload)
            or (
                os.name == "posix"
                and stat.S_IMODE(finished.st_mode) != 0o600
            )
        ):
            raise OSError(errno.EIO, "control member changed while writing")
        finished_identity = (
            finished.st_dev,
            finished.st_ino,
            finished.st_size,
            getattr(finished, "st_mtime_ns", None),
            finished.st_nlink,
            stat.S_IMODE(finished.st_mode),
        )
    except OSError:
        raise FinalGateRunnerError(
            "staging_failed", "final-gate control file could not be persisted"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        final = os.lstat(path)
    except OSError:
        raise FinalGateRunnerError(
            "staging_changed", "final-gate control file disappeared"
        ) from None
    named_identity = (
        final.st_dev,
        final.st_ino,
        final.st_size,
        getattr(final, "st_mtime_ns", None),
        final.st_nlink,
        stat.S_IMODE(final.st_mode),
    )
    if (
        not stat.S_ISREG(final.st_mode)
        or stat.S_ISLNK(final.st_mode)
        or _is_reparse(final)
        or final.st_nlink != 1
        or (os.name == "posix" and stat.S_IMODE(final.st_mode) != 0o600)
        or finished_identity is None
        or named_identity != finished_identity
        or final.st_size != len(payload)
    ):
        raise FinalGateRunnerError(
            "staging_changed", "final-gate control file changed"
        )
    if os.name == "nt":
        try:
            _windows_assert_no_named_streams(path)
        except SealedSnapshotError:
            raise FinalGateRunnerError(
                "staging_changed",
                "final-gate control file has an alternate data stream",
            ) from None
    return _directory_identity(final)


def _read_control_file(path: Path) -> bytes:
    try:
        before = os.lstat(path)
    except OSError:
        raise FinalGateRunnerError(
            "staging_changed", "final-gate control file is unavailable"
        ) from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > FINAL_GATE_MAX_WIRE_BYTES
        or (os.name == "posix" and stat.S_IMODE(before.st_mode) != 0o600)
    ):
        raise FinalGateRunnerError(
            "staging_changed", "final-gate control file is unsafe"
        )
    if os.name == "nt":
        try:
            _windows_assert_no_named_streams(path)
        except SealedSnapshotError:
            raise FinalGateRunnerError(
                "staging_changed",
                "final-gate control file has an alternate data stream",
            ) from None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor: int | None = None
    chunks: list[bytes] = []
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        expected = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            getattr(before, "st_mtime_ns", None),
            before.st_nlink,
            stat.S_IMODE(before.st_mode),
        )
        observed = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            getattr(opened, "st_mtime_ns", None),
            opened.st_nlink,
            stat.S_IMODE(opened.st_mode),
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or observed != expected
        ):
            raise OSError(errno.EIO, "control member changed while opening")
        total = 0
        while total < opened.st_size:
            chunk = os.read(
                descriptor,
                min(64 * 1024, opened.st_size - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        finished = os.fstat(descriptor)
        finished_value = (
            finished.st_dev,
            finished.st_ino,
            finished.st_size,
            getattr(finished, "st_mtime_ns", None),
            finished.st_nlink,
            stat.S_IMODE(finished.st_mode),
        )
        if total != opened.st_size or finished_value != observed:
            raise OSError(errno.EIO, "control member changed while reading")
    except OSError:
        raise FinalGateRunnerError(
            "staging_changed", "final-gate control file could not be read"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError:
        raise FinalGateRunnerError(
            "staging_changed", "final-gate control file changed after reading"
        ) from None
    after_value = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        getattr(after, "st_mtime_ns", None),
        after.st_nlink,
        stat.S_IMODE(after.st_mode),
    )
    if after_value != expected:
        raise FinalGateRunnerError(
            "staging_changed", "final-gate control file changed after reading"
        )
    return b"".join(chunks)


def _sync_directory(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        if os.name != "posix":
            return
        raise FinalGateRunnerError(
            "sync_failed", "final-gate directory could not be opened for sync"
        ) from None
    try:
        try:
            os.fsync(descriptor)
        except OSError:
            if os.name == "posix":
                raise FinalGateRunnerError(
                    "sync_failed", "final-gate directory sync failed"
                ) from None
    finally:
        os.close(descriptor)


def _assert_replay_manifest_closure(
    execution_plan: object,
    *,
    split_plan: FinalGateSplitPlanV1,
) -> None:
    """Rebuild the actual ordered replay manifest from the committed plan."""

    try:
        task_bindings = tuple(
            TaskReplayConfigBindingV1(
                task_id=task.task_id,
                d2_replay_sha256=task.d2_replay_sha256,
                d2_replay_wire_sha256=task.d2_replay_wire_sha256,
                d3_replay_sha256=task.d3_replay_sha256,
                d3_replay_wire_sha256=task.d3_replay_wire_sha256,
            )
            for task in execution_plan.tasks
        )
        manifest = BatchReplayConfigManifestV1(
            split=split_plan.split,
            tasks=task_bindings,
        )
        manifest_wire = manifest.to_bytes()
    except (
        AttributeError,
        BatchReplayConfigError,
        TypeError,
        ValueError,
    ):
        raise FinalGateRunnerError(
            "replay_mismatch",
            "E4 execution plan cannot reconstruct its replay manifest",
        ) from None
    if (
        manifest.manifest_sha256 != split_plan.replay_manifest_sha256
        or hashlib.sha256(manifest_wire).hexdigest()
        != split_plan.replay_manifest_wire_sha256
        or manifest.wire_sha256 != split_plan.replay_manifest_wire_sha256
    ):
        raise FinalGateRunnerError(
            "replay_mismatch",
            "E4 execution replay manifest differs from the final-gate plan",
        )


def _freeze_e4_success(
    value: object,
    *,
    plan: FinalGatePlanV1,
    split_plan: FinalGateSplitPlanV1,
) -> E4BatchSuccessReceiptV1:
    if type(value) is not E4BatchSuccessReceiptV1:
        raise FinalGateRunnerError(
            "execution_mismatch", "E4 split result has an invalid exact type"
        )
    try:
        wire = value.to_bytes()
        result = E4BatchSuccessReceiptV1.from_bytes(
            wire,
            expected_receipt_sha256=value.receipt_sha256,
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )
        execution_plan = result.execution_receipt.plan
        execution_plan_wire = execution_plan.to_bytes()
        policy = execution_plan.execution_policy
        policy_wire = policy.to_bytes()
        batch = execution_plan.batch
    except (AttributeError, E4ReceiptError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "execution_mismatch", "E4 split success did not normalize"
        ) from None
    if (
        result != value
        or result.to_bytes() != wire
        or batch.split != split_plan.split
        or batch.task_count != split_plan.task_count
        or len(execution_plan.tasks) != split_plan.task_count
        or len(result.execution_receipt.tasks) != split_plan.task_count
        or batch.batch_manifest_sha256
        != split_plan.sealed_batch_manifest_sha256
        or batch.attestation_key_id != split_plan.snapshot_key_id
        or policy.policy_sha256 != plan.execution_policy_sha256
        or hashlib.sha256(policy_wire).hexdigest()
        != plan.execution_policy_wire_sha256
        or policy.wire_sha256 != plan.execution_policy_wire_sha256
        or execution_plan.wire_sha256
        != hashlib.sha256(execution_plan_wire).hexdigest()
    ):
        raise FinalGateRunnerError(
            "execution_mismatch", "E4 split success is detached from its plan"
        )
    _assert_replay_manifest_closure(
        execution_plan, split_plan=split_plan
    )
    return result


def _projection_bindings(
    success: E4BatchSuccessReceiptV1,
) -> tuple[DiscoveryProjectionTaskBindingV1, ...]:
    try:
        execution = success.execution_receipt
        plan = execution.plan
        bindings = tuple(
            DiscoveryProjectionTaskBindingV1(
                task=SnapshotTaskSpec(
                    task_id=member.task_id,
                    repo_url=member.repo_url,
                    commit=member.commit,
                    split=member.split,
                    instruction_id=member.instruction_id,
                ),
                snapshot_id=task_plan.snapshot_id,
                dataset_sha256=task_receipt.dataset_sha256,
            )
            for member, task_plan, task_receipt in zip(
                plan.batch.tasks, plan.tasks, execution.tasks, strict=True
            )
        )
    except (
        AttributeError,
        DiscoveryProjectionReaderError,
        TypeError,
        ValueError,
    ):
        raise FinalGateRunnerError(
            "execution_mismatch",
            "E4 split success cannot form exact projection bindings",
        ) from None
    if len(bindings) != len(plan.tasks):
        raise FinalGateRunnerError(
            "execution_mismatch", "E4 projection bindings do not cover the split"
        )
    return bindings


def _project_and_read_split(
    benchmark_root: Path,
    split_root: Path,
    *,
    split_plan: FinalGateSplitPlanV1,
    success: E4BatchSuccessReceiptV1,
) -> VerifiedDiscoveryProjectionV1:
    execution_root = split_root / FINAL_GATE_EXECUTION_DIRECTORY
    projection_root = split_root / FINAL_GATE_PROJECTION_DIRECTORY
    bindings = _projection_bindings(success)
    artifact_index_sha256 = success.execution_receipt.artifact_index_sha256
    try:
        summary = project_verified_discovery_bundles(
            benchmark_root,
            artifact_root=execution_root / "bundles",
            bundle_index=execution_root / "artifact-index.json",
            bundle_index_sha256=artifact_index_sha256,
            output_dir=projection_root,
            split=split_plan.split,
            top_k=FINAL_GATE_TOP_K,
        )
    except BenchmarkHarnessError:
        raise FinalGateRunnerError(
            "projection_failed", "E4 split projection did not close"
        ) from None
    except (OSError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "projection_failed", "E4 split projection failed safely"
        ) from None
    if (
        type(summary) is not DiscoveryProjectionSummary
        or summary.split != split_plan.split
        or summary.task_count != split_plan.task_count
        or summary.bundle_index_sha256 != artifact_index_sha256
    ):
        raise FinalGateRunnerError(
            "projection_mismatch", "projection summary differs from its split"
        )
    try:
        verified = read_committed_discovery_projection_v1(
            projection_root,
            expected_split=split_plan.split,
            expected_manifest_sha256=summary.output_manifest_sha256,
            expected_artifact_index_sha256=artifact_index_sha256,
            expected_tasks=bindings,
            benchmark_root=(
                benchmark_root if split_plan.split == "train" else None
            ),
        )
    except DiscoveryProjectionReaderError:
        raise FinalGateRunnerError(
            "projection_unverified", "committed E4 projection did not verify"
        ) from None
    except (OSError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "projection_unverified", "E4 projection readback failed safely"
        ) from None
    if (
        type(verified) is not VerifiedDiscoveryProjectionV1
        or verified.summary != summary
        or verified.summary.output_manifest_sha256
        != summary.output_manifest_sha256
        or (split_plan.split == "test" and verified.aggregate_file_sha256 is not None)
        or (split_plan.split == "train" and verified.aggregate_file_sha256 is None)
    ):
        raise FinalGateRunnerError(
            "projection_mismatch", "projection readback differs from publication"
        )
    return verified


def _split_closure(
    plan: FinalGatePlanV1,
    split_plan: FinalGateSplitPlanV1,
    success: E4BatchSuccessReceiptV1,
    projection: VerifiedDiscoveryProjectionV1,
) -> FinalGateSplitReceiptClosureV1:
    try:
        execution_plan = success.execution_receipt.plan
        execution_plan_wire = execution_plan.to_bytes()
        summary = projection.summary
        return FinalGateSplitReceiptClosureV1(
            split=split_plan.split,
            split_plan_sha256=split_plan.split_plan_sha256,
            split_plan_wire_sha256=split_plan.wire_sha256,
            e4_receipt_sha256=success.receipt_sha256,
            e4_receipt_wire_sha256=success.wire_sha256,
            execution_policy_sha256=plan.execution_policy_sha256,
            execution_policy_wire_sha256=plan.execution_policy_wire_sha256,
            execution_plan_sha256=execution_plan.plan_sha256,
            execution_plan_wire_sha256=hashlib.sha256(
                execution_plan_wire
            ).hexdigest(),
            artifact_index_sha256=success.execution_receipt.artifact_index_sha256,
            projection_manifest_sha256=summary.output_manifest_sha256,
            task_count=summary.task_count,
            finalized_task_count=summary.finalized_task_count,
            deferred_task_count=summary.deferred_task_count,
            candidate_count=summary.candidate_count,
            finding_count=summary.finding_count,
            aggregate_file_sha256=projection.aggregate_file_sha256,
        )
    except (AttributeError, FinalGateContractError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "closure_rejected", "final-gate split closure did not close"
        ) from None


def read_committed_e4_final_gate_v1(
    output_root: str | os.PathLike[str],
    *,
    expected_receipt_sha256: str,
    expected_wire_sha256: str,
    benchmark_root: str | os.PathLike[str],
) -> FinalGateReceiptV1:
    """Lazy bridge to the independently implemented committed reader."""

    from vulngym_agent.evaluator.final_gate_reader import (
        read_committed_e4_final_gate_v1 as reader,
    )

    return reader(
        output_root,
        expected_receipt_sha256=expected_receipt_sha256,
        expected_wire_sha256=expected_wire_sha256,
        benchmark_root=benchmark_root,
    )


def _component_materialized_identities(
    root: Path,
) -> tuple[tuple[str, tuple[tuple[object, ...], ...]], ...]:
    """Freeze each bounded writer component under its own byte budget."""

    components = (
        (
            "test_execution",
            root
            / FINAL_GATE_TEST_DIRECTORY
            / FINAL_GATE_EXECUTION_DIRECTORY,
        ),
        (
            "test_projection",
            root
            / FINAL_GATE_TEST_DIRECTORY
            / FINAL_GATE_PROJECTION_DIRECTORY,
        ),
        (
            "train_execution",
            root
            / FINAL_GATE_TRAIN_DIRECTORY
            / FINAL_GATE_EXECUTION_DIRECTORY,
        ),
        (
            "train_projection",
            root
            / FINAL_GATE_TRAIN_DIRECTORY
            / FINAL_GATE_PROJECTION_DIRECTORY,
        ),
    )
    try:
        return tuple(
            (name, _materialized_identity(path))
            for name, path in components
        )
    except (EvaluatorSupervisorError, OSError, TypeError, ValueError):
        raise FinalGateRunnerError(
            "staging_changed",
            "a final-gate execution or projection component changed",
        ) from None


def _outer_composite_identity(root: Path) -> tuple[object, ...]:
    """Freeze outer structure, contracts, and four bounded inner trees."""

    root_state = _require_private_directory(root, code="staging_changed")
    _assert_members(root, FINAL_GATE_ROOT_MEMBERS)
    directory_records: list[tuple[object, ...]] = [
        (
            "root",
            root_state.st_dev,
            root_state.st_ino,
            stat.S_IMODE(root_state.st_mode),
            root_state.st_nlink,
        )
    ]
    for split_name in (
        FINAL_GATE_TEST_DIRECTORY,
        FINAL_GATE_TRAIN_DIRECTORY,
    ):
        split_root = root / split_name
        split_state = _require_private_directory(
            split_root, code="staging_changed"
        )
        _assert_members(split_root, FINAL_GATE_SPLIT_MEMBERS)
        directory_records.append(
            (
                split_name,
                split_state.st_dev,
                split_state.st_ino,
                stat.S_IMODE(split_state.st_mode),
                split_state.st_nlink,
                getattr(split_state, "st_mtime_ns", None),
                getattr(split_state, "st_ctime_ns", None),
            )
        )
    control_records: list[tuple[object, ...]] = []
    for name in (FINAL_GATE_PLAN_FILENAME, FINAL_GATE_RECEIPT_FILENAME):
        path = root / name
        payload = _read_control_file(path)
        try:
            state = os.lstat(path)
        except OSError:
            raise FinalGateRunnerError(
                "staging_changed", "final-gate control identity is unavailable"
            ) from None
        control_records.append(
            (
                name,
                state.st_dev,
                state.st_ino,
                state.st_size,
                getattr(state, "st_mtime_ns", None),
                getattr(state, "st_ctime_ns", None),
                state.st_nlink,
                stat.S_IMODE(state.st_mode),
                hashlib.sha256(payload).hexdigest(),
            )
        )
    return (
        tuple(directory_records),
        tuple(control_records),
        _component_materialized_identities(root),
    )


def _publish_outer_transaction(
    *,
    staging: Path,
    staging_identity: tuple[int, int],
    output: Path,
    parent: Path,
    parent_identity: tuple[int, int],
    benchmark_root: Path,
    plan: FinalGatePlanV1,
    receipt: FinalGateReceiptV1,
) -> FinalGateReceiptV1:
    plan_wire = plan.to_bytes()
    receipt_wire = receipt.to_bytes()
    _write_control_file(staging / FINAL_GATE_PLAN_FILENAME, plan_wire)
    _write_control_file(staging / FINAL_GATE_RECEIPT_FILENAME, receipt_wire)
    _assert_members(staging, FINAL_GATE_ROOT_MEMBERS)
    actual_plan_wire = _read_control_file(
        staging / FINAL_GATE_PLAN_FILENAME
    )
    actual_receipt_wire = _read_control_file(
        staging / FINAL_GATE_RECEIPT_FILENAME
    )
    parsed_plan = FinalGatePlanV1.from_bytes(
        actual_plan_wire,
        expected_plan_sha256=plan.plan_sha256,
        expected_wire_sha256=hashlib.sha256(actual_plan_wire).hexdigest(),
    )
    parsed_receipt = FinalGateReceiptV1.from_bytes(
        actual_receipt_wire,
        expected_receipt_sha256=receipt.receipt_sha256,
        expected_wire_sha256=hashlib.sha256(actual_receipt_wire).hexdigest(),
    )
    if (
        actual_plan_wire != plan_wire
        or actual_receipt_wire != receipt_wire
        or parsed_plan != plan
        or parsed_receipt != receipt
    ):
        raise FinalGateRunnerError(
            "closure_rejected", "final-gate control contracts failed readback"
        )
    _sync_directory(staging / FINAL_GATE_TEST_DIRECTORY)
    _sync_directory(staging / FINAL_GATE_TRAIN_DIRECTORY)
    _sync_directory(staging)
    _assert_directory_identity(staging, staging_identity)
    composite_identity = _outer_composite_identity(staging)
    _assert_parent(parent, parent_identity)
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError:
        raise FinalGateRunnerError(
            "output_state_changed", "final-gate output state changed"
        ) from None
    else:
        raise FinalGateRunnerError(
            "output_exists", "final-gate output appeared before publication"
        )
    _assert_directory_identity(staging, staging_identity)
    if _outer_composite_identity(staging) != composite_identity:
        raise FinalGateRunnerError(
            "staging_changed",
            "final-gate transaction changed immediately before publication",
        )

    rename_returned = False
    try:
        _rename_directory_noreplace(staging, output)
        rename_returned = True
        published = _require_private_directory(
            output, code="publication_uncertain"
        )
        if _directory_identity(published) != staging_identity:
            raise FinalGateRunnerError(
                "publication_uncertain",
                "published final-gate identity is uncertain",
                committed=True,
            )
        _assert_parent(parent, parent_identity)
        _sync_directory(parent)
        result = read_committed_e4_final_gate_v1(
            output,
            expected_receipt_sha256=receipt.receipt_sha256,
            expected_wire_sha256=hashlib.sha256(receipt_wire).hexdigest(),
            benchmark_root=benchmark_root,
        )
        if (
            type(result) is not FinalGateReceiptV1
            or result != receipt
            or result.to_bytes() != receipt_wire
            or _outer_composite_identity(output) != composite_identity
        ):
            raise FinalGateRunnerError(
                "publication_uncertain",
                "committed final-gate readback differs",
                committed=True,
            )
        return result
    except BaseException as error:
        try:
            state = os.lstat(output)
            final_name_is_staging = (
                stat.S_ISDIR(state.st_mode)
                and not stat.S_ISLNK(state.st_mode)
                and not _is_reparse(state)
                and _directory_identity(state) == staging_identity
            )
        except OSError:
            final_name_is_staging = False
        committed = rename_returned or final_name_is_staging
        if not isinstance(error, Exception):
            if committed:
                try:
                    setattr(error, "committed", True)
                except BaseException:
                    pass
            raise
        if committed:
            if isinstance(error, FinalGateRunnerError) and error.committed:
                raise
            raise FinalGateRunnerError(
                "publication_uncertain",
                "committed final-gate output did not verify",
                committed=True,
            ) from None
        raise FinalGateRunnerError(
            "publication_failed", "final-gate publication did not commit"
        ) from None


def _run_e4_final_gate(
    benchmark_root: object,
    output_root: object,
    docker_executable: object,
    runtime_image_id: object,
    *,
    plan: object,
    test_sealed_batch_root: object,
    test_replay_config_root: object,
    train_sealed_batch_root: object,
    train_replay_config_root: object,
    test_snapshot_attestation_key: object,
    train_snapshot_attestation_key: object,
) -> FinalGateReceiptV1 | DiscoveryBatchAttemptReportV1:
    frozen_plan = _freeze_plan(plan)
    _assert_policy_matches_plan(frozen_plan, runtime_image_id)
    docker = _validate_command(docker_executable)
    benchmark = _canonical_existing_directory(
        benchmark_root, name="benchmark_root"
    )
    test_sealed = _canonical_existing_directory(
        test_sealed_batch_root, name="test_sealed_batch_root"
    )
    test_replay = _canonical_existing_directory(
        test_replay_config_root, name="test_replay_config_root"
    )
    train_sealed = _canonical_existing_directory(
        train_sealed_batch_root, name="train_sealed_batch_root"
    )
    train_replay = _canonical_existing_directory(
        train_replay_config_root, name="train_replay_config_root"
    )
    output, parent, parent_identity = _canonical_new_output(output_root)
    _assert_output_disjoint(
        output,
        (benchmark, test_sealed, test_replay, train_sealed, train_replay),
    )
    # Secret material is the final preflight surface.  No key length, alias,
    # or byte is inspected until every public scalar and filesystem binding
    # above has closed.
    test_key = _validate_key(
        test_snapshot_attestation_key, name="test_snapshot_attestation_key"
    )
    train_key = _validate_key(
        train_snapshot_attestation_key, name="train_snapshot_attestation_key"
    )
    if test_key is train_key:
        raise FinalGateRunnerError(
            "invalid_argument", "test and train attestation keys must be distinct"
        )

    staging, staging_identity = _create_private_staging(
        output, parent, parent_identity
    )
    test_root = staging / FINAL_GATE_TEST_DIRECTORY
    test_identity = _create_private_directory(test_root)
    _assert_members(staging, frozenset({FINAL_GATE_TEST_DIRECTORY}))

    test_result = run_e4_discovery_split_v1(
        benchmark,
        test_sealed,
        test_replay,
        test_root / FINAL_GATE_EXECUTION_DIRECTORY,
        split="test",
        expected_sealed_batch_manifest_sha256=(
            frozen_plan.test.sealed_batch_manifest_sha256
        ),
        expected_replay_manifest_sha256=frozen_plan.test.replay_manifest_sha256,
        expected_replay_manifest_wire_sha256=(
            frozen_plan.test.replay_manifest_wire_sha256
        ),
        snapshot_attestation_key=test_key,
        snapshot_key_id=frozen_plan.test.snapshot_key_id,
        runtime_image_id=runtime_image_id,
        docker_executable=docker,
    )
    if type(test_result) is DiscoveryBatchAttemptReportV1:
        return test_result
    test_success = _freeze_e4_success(
        test_result, plan=frozen_plan, split_plan=frozen_plan.test
    )
    test_projection = _project_and_read_split(
        benchmark,
        test_root,
        split_plan=frozen_plan.test,
        success=test_success,
    )
    _assert_directory_identity(test_root, test_identity)
    _assert_members(test_root, FINAL_GATE_SPLIT_MEMBERS)
    test_closure = _split_closure(
        frozen_plan, frozen_plan.test, test_success, test_projection
    )

    # The train subtree does not exist until the blind test projection has
    # independently verified.  This is the outer transaction's main gate.
    train_root = staging / FINAL_GATE_TRAIN_DIRECTORY
    train_identity = _create_private_directory(train_root)
    _assert_members(
        staging,
        frozenset({FINAL_GATE_TEST_DIRECTORY, FINAL_GATE_TRAIN_DIRECTORY}),
    )
    train_result = run_e4_discovery_split_v1(
        benchmark,
        train_sealed,
        train_replay,
        train_root / FINAL_GATE_EXECUTION_DIRECTORY,
        split="train",
        expected_sealed_batch_manifest_sha256=(
            frozen_plan.train.sealed_batch_manifest_sha256
        ),
        expected_replay_manifest_sha256=frozen_plan.train.replay_manifest_sha256,
        expected_replay_manifest_wire_sha256=(
            frozen_plan.train.replay_manifest_wire_sha256
        ),
        snapshot_attestation_key=train_key,
        snapshot_key_id=frozen_plan.train.snapshot_key_id,
        runtime_image_id=runtime_image_id,
        docker_executable=docker,
    )
    if type(train_result) is DiscoveryBatchAttemptReportV1:
        return train_result
    train_success = _freeze_e4_success(
        train_result, plan=frozen_plan, split_plan=frozen_plan.train
    )
    train_projection = _project_and_read_split(
        benchmark,
        train_root,
        split_plan=frozen_plan.train,
        success=train_success,
    )
    _assert_directory_identity(train_root, train_identity)
    _assert_members(train_root, FINAL_GATE_SPLIT_MEMBERS)
    train_closure = _split_closure(
        frozen_plan, frozen_plan.train, train_success, train_projection
    )
    try:
        receipt = FinalGateReceiptV1(
            plan=frozen_plan, test=test_closure, train=train_closure
        )
    except FinalGateContractError:
        raise FinalGateRunnerError(
            "closure_rejected", "final-gate receipt did not close"
        ) from None
    _assert_directory_identity(staging, staging_identity)
    return _publish_outer_transaction(
        staging=staging,
        staging_identity=staging_identity,
        output=output,
        parent=parent,
        parent_identity=parent_identity,
        benchmark_root=benchmark,
        plan=frozen_plan,
        receipt=receipt,
    )


def run_e4_final_gate_v1(
    benchmark_root: str | Path,
    output_root: str | Path,
    docker_executable: str | Path,
    runtime_image_id: str,
    *,
    plan: FinalGatePlanV1,
    test_sealed_batch_root: str | Path,
    test_replay_config_root: str | Path,
    train_sealed_batch_root: str | Path,
    train_replay_config_root: str | Path,
    test_snapshot_attestation_key: bytearray,
    train_snapshot_attestation_key: bytearray,
) -> FinalGateReceiptV1 | DiscoveryBatchAttemptReportV1:
    """Run the fixed blind-test-first 20+50 E4 final-gate transaction."""

    try:
        return _run_e4_final_gate(
            benchmark_root,
            output_root,
            docker_executable,
            runtime_image_id,
            plan=plan,
            test_sealed_batch_root=test_sealed_batch_root,
            test_replay_config_root=test_replay_config_root,
            train_sealed_batch_root=train_sealed_batch_root,
            train_replay_config_root=train_replay_config_root,
            test_snapshot_attestation_key=test_snapshot_attestation_key,
            train_snapshot_attestation_key=train_snapshot_attestation_key,
        )
    except FinalGateRunnerError:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise FinalGateRunnerError(
            "final_gate_failed", "E4 final gate failed safely"
        ) from None
    finally:
        # The buffers are caller-owned, but ownership of their contents ends
        # at this call boundary on success, ordinary failure, and BaseException.
        _zero_key(test_snapshot_attestation_key)
        _zero_key(train_snapshot_attestation_key)


__all__ = [
    "FINAL_GATE_RUNNER_VERSION",
    "FinalGateRunnerError",
    "read_committed_e4_final_gate_v1",
    "run_e4_final_gate_v1",
]
