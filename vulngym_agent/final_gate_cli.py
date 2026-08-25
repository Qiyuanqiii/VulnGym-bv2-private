"""Command-line boundary for the fixed E4 20+50 final gate.

The CLI intentionally exposes no model, backend, resource, scheduler, or
projection knobs.  A trusted caller supplies one externally double-pinned
final-gate plan plus two independent private attestation keys.  The ``run``
command delegates the complete test-first transaction to the final-gate
runner; ``verify-output`` re-establishes one committed publication from its
external receipt pins.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Final, Sequence

from vulngym_agent.benchmark.sealed_snapshot import (
    SealedSnapshotError,
    _windows_assert_no_named_streams,
)
from vulngym_agent.evaluator.batch_runner import (
    DiscoveryBatchAttemptReportV2,
)
from vulngym_agent.evaluator.final_gate import (
    FINAL_GATE_MAX_WIRE_BYTES,
    FinalGateContractError,
    FinalGatePlanV1,
    FinalGateReceiptV1,
    FinalGateSplitReceiptClosureV1,
)
from vulngym_agent.evaluator.final_gate_reader import (
    FinalGateReaderError,
    read_committed_e4_final_gate_v1,
)
from vulngym_agent.evaluator.final_gate_runner import (
    FinalGateRunnerError,
    run_e4_final_gate_v1,
)
from vulngym_agent.evaluator.e4_driver import (
    E4DriverError,
    fixed_e4_execution_policy_v1,
)
from vulngym_agent.trusted_inputs import (
    TrustedInputError,
    paths_overlap_v1,
    read_attestation_key_file_v1,
    zero_secret_buffer_v1,
)


FINAL_GATE_CLI_VERSION: Final[str] = "discovery-e4-final-gate-cli-v1"

EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_ATTEMPT_FAILED: Final[int] = 10
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
EXIT_INTERRUPTED: Final[int] = 130

_SUCCESS_SUMMARY_KIND: Final[str] = (
    "vulngym.discovery-e4-final-gate-cli-success-summary.v1"
)
_ERROR_SUMMARY_KIND: Final[str] = (
    "vulngym.discovery-e4-final-gate-cli-error-summary.v1"
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"sha256:[0-9a-f]{64}\Z"
)
_ERROR_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-z][a-z0-9_]{0,63}\Z"
)
_PATH_TYPE: Final[type[Path]] = type(Path())


class FinalGateCliError(RuntimeError):
    """Stable, path-free failure at the final-gate CLI boundary."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = _safe_error_code(code, fallback="command_rejected")
        self.committed = committed is True
        super().__init__(message)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _ = message
        self.exit(
            EXIT_REJECTED,
            "error: final-gate command arguments rejected\n",
        )


def _safe_error_code(value: object, *, fallback: str) -> str:
    if type(value) is str and _ERROR_CODE_RE.fullmatch(value) is not None:
        return value
    return fallback


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.final_gate_cli",
        description="Run or verify the fixed E4 20+50 final gate.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser(
        "run",
        help="run the fixed blind-test-first final gate",
        allow_abbrev=False,
    )
    run.add_argument("--benchmark-root", type=Path, required=True)
    run.add_argument("--output-root", type=Path, required=True)
    run.add_argument("--docker-executable", type=Path, required=True)
    run.add_argument("--runtime-image-id", required=True)
    run.add_argument("--plan-file", type=Path, required=True)
    run.add_argument("--expected-plan-sha256", required=True)
    run.add_argument("--expected-plan-wire-sha256", required=True)
    run.add_argument("--test-sealed-batch-root", type=Path, required=True)
    run.add_argument("--test-replay-config-root", type=Path, required=True)
    run.add_argument("--train-sealed-batch-root", type=Path, required=True)
    run.add_argument("--train-replay-config-root", type=Path, required=True)
    run.add_argument("--test-key-file", type=Path, required=True)
    run.add_argument("--train-key-file", type=Path, required=True)

    verify = commands.add_parser(
        "verify-output",
        help="verify one committed final-gate publication",
        allow_abbrev=False,
    )
    verify.add_argument("--output-root", type=Path, required=True)
    verify.add_argument("--benchmark-root", type=Path, required=True)
    verify.add_argument("--expected-receipt-sha256", required=True)
    verify.add_argument("--expected-wire-sha256", required=True)
    return parser


def _canonical_json_line(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise FinalGateCliError(
            "summary_invalid", "final-gate CLI summary did not normalize"
        ) from None


def _write_stdout_bytes(payload: bytes) -> None:
    if type(payload) is not bytes:
        raise FinalGateCliError(
            "summary_invalid", "final-gate CLI output must be exact bytes"
        )
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload)
        binary.flush()
        return
    sys.stdout.write(payload.decode("utf-8", errors="strict"))
    sys.stdout.flush()


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise FinalGateCliError(
            "invalid_argument", f"{name} must be lower-case SHA-256"
        )
    return value


def _summary_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise FinalGateCliError(
            "success_contract_mismatch",
            f"final-gate success has an invalid {name}",
            committed=True,
        )
    return value


def _split_summary_v1(
    value: object, *, expected_split: str
) -> dict[str, object]:
    if type(value) is not FinalGateSplitReceiptClosureV1:
        raise FinalGateCliError(
            "success_contract_mismatch",
            "final-gate split closure has an invalid exact type",
            committed=True,
        )
    try:
        if value.split != expected_split:
            raise FinalGateCliError(
                "success_contract_mismatch",
                "final-gate split closure is detached",
                committed=True,
            )
        result: dict[str, object] = {
            "artifact_index_sha256": _summary_sha256(
                value.artifact_index_sha256, name="artifact index digest"
            ),
            "candidate_count": value.candidate_count,
            "deferred_task_count": value.deferred_task_count,
            "e4_receipt_sha256": _summary_sha256(
                value.e4_receipt_sha256, name="E4 receipt semantic digest"
            ),
            "e4_receipt_wire_sha256": _summary_sha256(
                value.e4_receipt_wire_sha256, name="E4 receipt wire digest"
            ),
            "execution_plan_sha256": _summary_sha256(
                value.execution_plan_sha256,
                name="execution plan semantic digest",
            ),
            "execution_plan_wire_sha256": _summary_sha256(
                value.execution_plan_wire_sha256,
                name="execution plan wire digest",
            ),
            "finalized_task_count": value.finalized_task_count,
            "finding_count": value.finding_count,
            "projection_manifest_sha256": _summary_sha256(
                value.projection_manifest_sha256,
                name="projection manifest digest",
            ),
            "task_count": value.task_count,
        }
        counts = (
            result["candidate_count"],
            result["deferred_task_count"],
            result["finalized_task_count"],
            result["finding_count"],
            result["task_count"],
        )
        if any(type(item) is not int or item < 0 for item in counts):
            raise FinalGateCliError(
                "success_contract_mismatch",
                "final-gate split counters are invalid",
                committed=True,
            )
        expected_count = 20 if expected_split == "test" else 50
        if (
            value.status != "closed"
            or value.task_count != expected_count
            or value.finalized_task_count + value.deferred_task_count
            != value.task_count
            or value.finding_count > value.candidate_count
        ):
            raise FinalGateCliError(
                "success_contract_mismatch",
                "final-gate split counters do not close exactly",
                committed=True,
            )
        if expected_split == "train":
            result["aggregate_file_sha256"] = _summary_sha256(
                value.aggregate_file_sha256,
                name="training aggregate file digest",
            )
        elif value.aggregate_file_sha256 is not None:
            raise FinalGateCliError(
                "success_contract_mismatch",
                "test split unexpectedly carries a training aggregate",
                committed=True,
            )
        return result
    except FinalGateCliError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise FinalGateCliError(
            "success_contract_mismatch",
            "final-gate split closure could not form a summary",
            committed=True,
        ) from None


def _success_summary_v1(value: object) -> dict[str, object]:
    if type(value) is not FinalGateReceiptV1:
        raise FinalGateCliError(
            "success_contract_mismatch",
            "final-gate success has an invalid exact type",
            committed=True,
        )
    try:
        plan = value.plan
        if type(plan) is not FinalGatePlanV1 or value.status != "closed":
            raise FinalGateCliError(
                "success_contract_mismatch",
                "final-gate receipt is not mechanically closed",
                committed=True,
            )
        return {
            "contract_version": 1,
            "kind": _SUCCESS_SUMMARY_KIND,
            "plan_sha256": _summary_sha256(
                value.plan_sha256, name="plan semantic digest"
            ),
            "plan_wire_sha256": _summary_sha256(
                value.plan_wire_sha256, name="plan wire digest"
            ),
            "policy_sha256": _summary_sha256(
                plan.execution_policy_sha256,
                name="policy semantic digest",
            ),
            "policy_wire_sha256": _summary_sha256(
                plan.execution_policy_wire_sha256,
                name="policy wire digest",
            ),
            "receipt_sha256": _summary_sha256(
                value.receipt_sha256, name="receipt semantic digest"
            ),
            "receipt_wire_sha256": _summary_sha256(
                value.wire_sha256, name="receipt wire digest"
            ),
            "status": "closed",
            "test": _split_summary_v1(value.test, expected_split="test"),
            "train": _split_summary_v1(value.train, expected_split="train"),
        }
    except FinalGateCliError:
        raise
    except (AttributeError, FinalGateContractError, TypeError, ValueError):
        raise FinalGateCliError(
            "success_contract_mismatch",
            "final-gate success could not form its path-free summary",
            committed=True,
        ) from None


def _attempt_report_bytes(value: object) -> bytes:
    if type(value) is not DiscoveryBatchAttemptReportV2:
        raise FinalGateCliError(
            "runner_contract_mismatch",
            "final-gate runner returned an invalid result union",
        )
    try:
        payload = value.to_bytes()
        if (
            type(payload) is not bytes
            or not payload
            or type(value.report_sha256) is not str
            or _SHA256_RE.fullmatch(value.report_sha256) is None
            or hashlib.sha256(payload).hexdigest() != value.wire_sha256
        ):
            raise ValueError("attempt report is detached")
        return payload
    except (AttributeError, TypeError, ValueError):
        raise FinalGateCliError(
            "runner_contract_mismatch",
            "final-gate attempt report did not normalize",
        ) from None


def _is_reparse(value: os.stat_result) -> bool:
    return bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _binding_identity(
    value: os.stat_result,
) -> tuple[int, int, int, int | None]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        getattr(value, "st_mtime_ns", None),
    )


def _same_api_identity(value: os.stat_result) -> tuple[object, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", None),
        getattr(value, "st_ctime_ns", None),
        getattr(value, "st_uid", None),
    )


def _checked_parent_chain(
    path: Path,
) -> tuple[tuple[Path, tuple[int, int]], ...]:
    checked: list[tuple[Path, tuple[int, int]]] = []
    for component in reversed((path.parent, *path.parent.parents)):
        try:
            state = os.lstat(component)
        except OSError:
            raise FinalGateCliError(
                "plan_input_rejected", "plan parent directory is unavailable"
            ) from None
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
        ):
            raise FinalGateCliError(
                "plan_input_rejected", "plan parent directory is unsafe"
            )
        checked.append((component, (state.st_dev, state.st_ino)))
    return tuple(checked)


def _assert_parent_chain(
    checked: tuple[tuple[Path, tuple[int, int]], ...]
) -> None:
    try:
        for component, expected in checked:
            state = os.lstat(component)
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
                or (state.st_dev, state.st_ino) != expected
            ):
                raise FinalGateCliError(
                    "plan_input_rejected",
                    "plan parent directory changed while reading",
                )
    except FinalGateCliError:
        raise
    except OSError:
        raise FinalGateCliError(
            "plan_input_rejected",
            "plan parent directory changed while reading",
        ) from None


def _validate_plan_file_state(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or value.st_nlink != 1
        or value.st_size < 1
        or value.st_size > FINAL_GATE_MAX_WIRE_BYTES
    ):
        raise FinalGateCliError(
            "plan_input_rejected", "plan file is unsafe or oversized"
        )
    if os.name == "posix" and (
        value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) & 0o077
    ):
        raise FinalGateCliError(
            "plan_input_rejected", "plan file is not owner-private"
        )


def _read_plan_file_once(
    path: Path,
) -> tuple[bytes, tuple[object, ...]]:
    try:
        before = os.lstat(path)
    except OSError:
        raise FinalGateCliError(
            "plan_input_rejected", "plan file is unavailable"
        ) from None
    _validate_plan_file_state(before)
    if os.name == "nt":
        try:
            _windows_assert_no_named_streams(path)
        except SealedSnapshotError:
            raise FinalGateCliError(
                "plan_input_rejected", "plan file has alternate data streams"
            ) from None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise FinalGateCliError(
            "plan_input_rejected", "plan file could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        _validate_plan_file_state(opened)
        if _binding_identity(opened) != _binding_identity(before):
            raise FinalGateCliError(
                "plan_input_rejected", "plan file changed while opening"
            )
        opened_identity = _same_api_identity(opened)
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
                raise FinalGateCliError(
                    "plan_input_rejected", "plan file exceeds its byte limit"
                )
        finished = os.fstat(descriptor)
        _validate_plan_file_state(finished)
        if (
            _same_api_identity(finished) != opened_identity
            or total != opened.st_size
        ):
            raise FinalGateCliError(
                "plan_input_rejected", "plan file changed while reading"
            )
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError:
        raise FinalGateCliError(
            "plan_input_rejected", "plan file changed while reading"
        ) from None
    _validate_plan_file_state(after)
    if (
        _same_api_identity(after) != _same_api_identity(before)
        or _binding_identity(after) != _binding_identity(finished)
    ):
        raise FinalGateCliError(
            "plan_input_rejected", "plan file changed while reading"
        )
    return b"".join(chunks), _same_api_identity(after)


def _read_final_gate_plan_file_v1(
    path: Path,
    *,
    expected_plan_sha256: str,
    expected_wire_sha256: str,
) -> FinalGatePlanV1:
    semantic_pin = _require_sha256(
        expected_plan_sha256, name="expected_plan_sha256"
    )
    wire_pin = _require_sha256(
        expected_wire_sha256, name="expected_wire_sha256"
    )
    if type(path) is not _PATH_TYPE:
        raise FinalGateCliError(
            "invalid_argument", "plan file must be an exact path value"
        )
    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError, ValueError):
        raise FinalGateCliError(
            "invalid_argument", "plan file path is invalid"
        ) from None
    parent_chain = _checked_parent_chain(absolute)
    first_payload, first_identity = _read_plan_file_once(absolute)
    second_payload, second_identity = _read_plan_file_once(absolute)
    _assert_parent_chain(parent_chain)
    if (
        first_payload != second_payload
        or first_identity != second_identity
        or hashlib.sha256(second_payload).hexdigest() != wire_pin
    ):
        raise FinalGateCliError(
            "plan_input_rejected", "plan file changed or differs from its wire pin"
        )
    try:
        plan = FinalGatePlanV1.from_bytes(
            second_payload,
            expected_plan_sha256=semantic_pin,
            expected_wire_sha256=wire_pin,
        )
    except FinalGateContractError:
        raise FinalGateCliError(
            "plan_input_rejected", "plan file did not match its contract pins"
        ) from None
    if (
        type(plan) is not FinalGatePlanV1
        or plan.plan_sha256 != semantic_pin
        or plan.wire_sha256 != wire_pin
        or plan.to_bytes() != second_payload
    ):
        raise FinalGateCliError(
            "plan_input_rejected", "plan file returned a detached contract"
        )
    return plan


def _validate_namespace(args: object, *, command: str) -> argparse.Namespace:
    if type(args) is not argparse.Namespace:
        raise FinalGateCliError(
            "invalid_argument", "command arguments have an invalid exact type"
        )
    command_value = vars(args).get("command")
    if type(command_value) is not str or command_value != command:
        raise FinalGateCliError(
            "invalid_argument", "command arguments have an invalid exact type"
        )
    return args


def _validate_path_values(
    values: tuple[object, ...],
) -> tuple[Path, ...]:
    if any(type(value) is not _PATH_TYPE for value in values):
        raise FinalGateCliError(
            "invalid_argument", "command path input has an invalid exact type"
        )
    return values


def _validate_run_scalars(args: argparse.Namespace) -> None:
    _require_sha256(args.expected_plan_sha256, name="expected_plan_sha256")
    _require_sha256(
        args.expected_plan_wire_sha256,
        name="expected_plan_wire_sha256",
    )
    if (
        type(args.runtime_image_id) is not str
        or _IMAGE_ID_RE.fullmatch(args.runtime_image_id) is None
    ):
        raise FinalGateCliError(
            "invalid_argument", "runtime image identity is invalid"
        )
    if type(args.docker_executable) is not _PATH_TYPE:
        raise FinalGateCliError(
            "invalid_argument", "Docker executable path is invalid"
        )
    try:
        docker_text = os.fspath(args.docker_executable)
    except (OSError, TypeError, ValueError):
        raise FinalGateCliError(
            "invalid_argument", "Docker executable path is invalid"
        ) from None
    if (
        type(docker_text) is not str
        or not docker_text
        or "\x00" in docker_text
        or docker_text.strip() != docker_text
    ):
        raise FinalGateCliError(
            "invalid_argument", "Docker executable path is invalid"
        )


def _validate_plan_runtime_binding(
    plan: FinalGatePlanV1, *, runtime_image_id: str
) -> None:
    if type(plan) is not FinalGatePlanV1:
        raise FinalGateCliError(
            "plan_input_rejected", "plan reader returned an invalid exact type"
        )
    try:
        policy = fixed_e4_execution_policy_v1(runtime_image_id)
        policy_wire = policy.to_bytes()
    except E4DriverError:
        raise FinalGateCliError(
            "invalid_argument", "fixed runtime policy is invalid"
        ) from None
    except (AttributeError, TypeError, ValueError):
        raise FinalGateCliError(
            "invalid_argument", "fixed runtime policy did not normalize"
        ) from None
    if (
        policy.policy_sha256 != plan.execution_policy_sha256
        or hashlib.sha256(policy_wire).hexdigest()
        != plan.execution_policy_wire_sha256
        or policy.wire_sha256 != plan.execution_policy_wire_sha256
    ):
        raise FinalGateCliError(
            "policy_mismatch", "runtime policy differs from the final-gate plan"
        )


def _validate_verify_scalars(args: argparse.Namespace) -> None:
    _require_sha256(
        args.expected_receipt_sha256,
        name="expected_receipt_sha256",
    )
    _require_sha256(
        args.expected_wire_sha256,
        name="expected_wire_sha256",
    )


def _checked_overlap(
    left: Path,
    right: Path,
    *,
    left_exists: bool,
    right_directory: bool,
) -> bool:
    result = paths_overlap_v1(
        left,
        right,
        left_exists=left_exists,
        right_directory=right_directory,
    )
    if type(result) is not bool:
        raise FinalGateCliError(
            "trusted_input_rejected",
            "trusted path comparison returned an invalid exact type",
        )
    return result


def _preflight_file_identities(paths: tuple[Path, ...]) -> None:
    identities: list[tuple[int, int]] = []
    try:
        for path in paths:
            state = os.lstat(path)
            if (
                not stat.S_ISREG(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
            ):
                raise FinalGateCliError(
                    "trusted_input_rejected",
                    "trusted file input is unsafe",
                )
            identities.append((state.st_dev, state.st_ino))
    except FinalGateCliError:
        raise
    except OSError:
        raise FinalGateCliError(
            "trusted_input_rejected", "trusted file input is unavailable"
        ) from None
    if len(set(identities)) != len(identities):
        raise FinalGateCliError(
            "path_overlap", "plan and key files reuse a file identity"
        )


def _directory_identity_snapshot(
    paths: tuple[Path, ...],
) -> tuple[
    tuple[
        tuple[int, int],
        frozenset[tuple[int, int]],
    ],
    ...,
]:
    snapshots: list[
        tuple[tuple[int, int], frozenset[tuple[int, int]]]
    ] = []
    try:
        for path in paths:
            absolute = Path(os.path.abspath(os.fspath(path)))
            ancestry: set[tuple[int, int]] = set()
            terminal: tuple[int, int] | None = None
            for index, component in enumerate(
                (absolute, *absolute.parents)
            ):
                state = os.lstat(component)
                if (
                    not stat.S_ISDIR(state.st_mode)
                    or stat.S_ISLNK(state.st_mode)
                    or _is_reparse(state)
                ):
                    raise FinalGateCliError(
                        "trusted_input_rejected",
                        "trusted directory chain is unsafe",
                    )
                identity = (state.st_dev, state.st_ino)
                if index == 0:
                    terminal = identity
                ancestry.add(identity)
            if terminal is None:
                raise FinalGateCliError(
                    "trusted_input_rejected",
                    "trusted directory identity is unavailable",
                )
            resolved = absolute.resolve(strict=True)
            resolved_state = os.lstat(resolved)
            if (
                not stat.S_ISDIR(resolved_state.st_mode)
                or stat.S_ISLNK(resolved_state.st_mode)
                or _is_reparse(resolved_state)
                or (resolved_state.st_dev, resolved_state.st_ino)
                != terminal
            ):
                raise FinalGateCliError(
                    "trusted_input_rejected",
                    "trusted directory resolution changed identity",
                )
            snapshots.append((terminal, frozenset(ancestry)))
    except FinalGateCliError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        raise FinalGateCliError(
            "trusted_input_rejected",
            "trusted directory identity is unavailable",
        ) from None

    terminals = tuple(item[0] for item in snapshots)
    if len(set(terminals)) != len(terminals):
        raise FinalGateCliError(
            "path_overlap", "trusted directories reuse one identity"
        )
    for index, (left_terminal, left_ancestry) in enumerate(snapshots):
        for right_terminal, right_ancestry in snapshots[index + 1 :]:
            if (
                left_terminal in right_ancestry
                or right_terminal in left_ancestry
            ):
                raise FinalGateCliError(
                    "path_overlap", "trusted directory identities overlap"
                )
    return tuple(snapshots)


def _preflight_run_paths(args: argparse.Namespace) -> None:
    directories = (
        args.benchmark_root,
        args.test_sealed_batch_root,
        args.test_replay_config_root,
        args.train_sealed_batch_root,
        args.train_replay_config_root,
    )
    files = (args.plan_file, args.test_key_file, args.train_key_file)

    try:
        os.lstat(args.output_root)
    except FileNotFoundError:
        pass
    except OSError:
        raise FinalGateCliError(
            "trusted_input_rejected", "final-gate output state is unavailable"
        ) from None
    else:
        raise FinalGateCliError(
            "output_exists", "final-gate output already exists"
        )

    directory_snapshot = _directory_identity_snapshot(directories)

    for directory in directories:
        if _checked_overlap(
            args.output_root,
            directory,
            left_exists=False,
            right_directory=True,
        ):
            raise FinalGateCliError(
                "path_overlap", "final-gate output overlaps a trusted directory"
            )
    for file_path in files:
        if _checked_overlap(
            args.output_root,
            file_path,
            left_exists=False,
            right_directory=False,
        ):
            raise FinalGateCliError(
                "path_overlap", "final-gate output overlaps a trusted file"
            )
    for index, left in enumerate(directories):
        for right in directories[index + 1 :]:
            if _checked_overlap(
                left,
                right,
                left_exists=True,
                right_directory=True,
            ):
                raise FinalGateCliError(
                    "path_overlap", "trusted final-gate directories overlap"
                )
        for file_path in files:
            if _checked_overlap(
                left,
                file_path,
                left_exists=True,
                right_directory=False,
            ):
                raise FinalGateCliError(
                    "path_overlap", "trusted directory overlaps a plan or key file"
                )
    _preflight_file_identities(files)
    if _directory_identity_snapshot(directories) != directory_snapshot:
        raise FinalGateCliError(
            "trusted_input_rejected",
            "trusted directory identities changed during preflight",
        )


def _run(args: argparse.Namespace) -> object:
    """Read two independent keys, delegate once, and always clear both."""

    _validate_namespace(args, command="run")
    _validate_run_scalars(args)
    _validate_path_values(
        (
            args.benchmark_root,
            args.output_root,
            args.docker_executable,
            args.plan_file,
            args.test_sealed_batch_root,
            args.test_replay_config_root,
            args.train_sealed_batch_root,
            args.train_replay_config_root,
            args.test_key_file,
            args.train_key_file,
        )
    )
    _preflight_run_paths(args)
    plan = _read_final_gate_plan_file_v1(
        args.plan_file,
        expected_plan_sha256=args.expected_plan_sha256,
        expected_wire_sha256=args.expected_plan_wire_sha256,
    )
    _validate_plan_runtime_binding(
        plan, runtime_image_id=args.runtime_image_id
    )

    test_key: object | None = None
    train_key: object | None = None
    try:
        test_key = read_attestation_key_file_v1(args.test_key_file)
        if type(test_key) is not bytearray:
            raise FinalGateCliError(
                "trusted_key_rejected",
                "test key reader returned an invalid exact type",
            )
        train_key = read_attestation_key_file_v1(args.train_key_file)
        if type(train_key) is not bytearray:
            raise FinalGateCliError(
                "trusted_key_rejected",
                "train key reader returned an invalid exact type",
            )
        if test_key is train_key:
            raise FinalGateCliError(
                "trusted_key_rejected", "test and train key buffers are not independent"
            )
        return run_e4_final_gate_v1(
            args.benchmark_root,
            args.output_root,
            args.docker_executable,
            args.runtime_image_id,
            plan=plan,
            test_sealed_batch_root=args.test_sealed_batch_root,
            test_replay_config_root=args.test_replay_config_root,
            train_sealed_batch_root=args.train_sealed_batch_root,
            train_replay_config_root=args.train_replay_config_root,
            test_snapshot_attestation_key=test_key,
            train_snapshot_attestation_key=train_key,
        )
    finally:
        if type(test_key) is bytearray:
            zero_secret_buffer_v1(test_key)
        if type(train_key) is bytearray:
            zero_secret_buffer_v1(train_key)


def _verify_output(args: argparse.Namespace) -> FinalGateReceiptV1:
    _validate_namespace(args, command="verify-output")
    _validate_verify_scalars(args)
    _validate_path_values((args.output_root, args.benchmark_root))
    directory_snapshot = _directory_identity_snapshot(
        (args.output_root, args.benchmark_root)
    )
    if _checked_overlap(
        args.output_root,
        args.benchmark_root,
        left_exists=True,
        right_directory=True,
    ):
        raise FinalGateCliError(
            "path_overlap", "committed output overlaps the benchmark root"
        )
    if (
        _directory_identity_snapshot(
            (args.output_root, args.benchmark_root)
        )
        != directory_snapshot
    ):
        raise FinalGateCliError(
            "trusted_input_rejected",
            "verification directory identities changed during preflight",
        )
    result = read_committed_e4_final_gate_v1(
        args.output_root,
        expected_receipt_sha256=args.expected_receipt_sha256,
        expected_wire_sha256=args.expected_wire_sha256,
        benchmark_root=args.benchmark_root,
    )
    try:
        if (
            type(result) is not FinalGateReceiptV1
            or result.receipt_sha256 != args.expected_receipt_sha256
            or result.wire_sha256 != args.expected_wire_sha256
        ):
            raise FinalGateCliError(
                "publication_mismatch",
                "committed final-gate reader returned a detached receipt",
                committed=True,
            )
    except FinalGateCliError:
        raise
    except (AttributeError, FinalGateContractError, TypeError, ValueError):
        raise FinalGateCliError(
            "publication_mismatch",
            "committed final-gate reader returned an invalid receipt",
            committed=True,
        ) from None
    return result


def _error_summary_bytes(
    code: object, *, committed: bool, interrupted: bool = False
) -> bytes:
    if committed:
        status = "committed_uncertain"
    elif interrupted:
        status = "interrupted"
    else:
        status = "rejected"
    return _canonical_json_line(
        {
            "code": _safe_error_code(code, fallback="command_rejected"),
            "contract_version": 1,
            "kind": _ERROR_SUMMARY_KIND,
            "status": status,
        }
    )


def _emit_success(value: object) -> int:
    _write_stdout_bytes(_canonical_json_line(_success_summary_v1(value)))
    return EXIT_SUCCESS


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "run":
            result = _run(args)
            if type(result) is FinalGateReceiptV1:
                return _emit_success(result)
            _write_stdout_bytes(_attempt_report_bytes(result))
            return EXIT_ATTEMPT_FAILED
        return _emit_success(_verify_output(args))
    except FinalGateReaderError as error:
        _write_stdout_bytes(
            _error_summary_bytes(error.code, committed=True)
        )
        return EXIT_COMMITTED_UNCERTAIN
    except FinalGateRunnerError as error:
        committed = error.committed is True
        _write_stdout_bytes(
            _error_summary_bytes(error.code, committed=committed)
        )
        return EXIT_COMMITTED_UNCERTAIN if committed else EXIT_REJECTED
    except FinalGateCliError as error:
        committed = error.committed is True
        _write_stdout_bytes(
            _error_summary_bytes(error.code, committed=committed)
        )
        return EXIT_COMMITTED_UNCERTAIN if committed else EXIT_REJECTED
    except TrustedInputError:
        _write_stdout_bytes(
            _error_summary_bytes("trusted_input_rejected", committed=False)
        )
        return EXIT_REJECTED
    except Exception as error:
        committed = (
            args.command == "verify-output"
            or getattr(error, "committed", False) is True
        )
        _write_stdout_bytes(
            _error_summary_bytes("command_rejected", committed=committed)
        )
        return EXIT_COMMITTED_UNCERTAIN if committed else EXIT_REJECTED
    except BaseException as error:
        committed = (
            args.command == "verify-output"
            or getattr(error, "committed", False) is True
        )
        _write_stdout_bytes(
            _error_summary_bytes(
                "command_interrupted",
                committed=committed,
                interrupted=not committed,
            )
        )
        return EXIT_COMMITTED_UNCERTAIN if committed else EXIT_INTERRUPTED


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXIT_ATTEMPT_FAILED",
    "EXIT_COMMITTED_UNCERTAIN",
    "EXIT_INTERRUPTED",
    "EXIT_REJECTED",
    "EXIT_SUCCESS",
    "FINAL_GATE_CLI_VERSION",
    "FinalGateCliError",
    "main",
]
