"""Minimal command-line boundary for the fixed E4 discovery driver."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Final, Sequence

from vulngym_agent.evaluator.batch_runner import (
    DiscoveryBatchAttemptReportV2,
)
from vulngym_agent.evaluator.e4_driver import (
    E4DriverError,
    run_e4_discovery_split_v1,
)
from vulngym_agent.evaluator.e4_receipt import E4BatchSuccessReceiptV2
from vulngym_agent.evaluator.publication_reader import (
    E4PublicationReaderError,
    read_committed_e4_discovery_execution_v1,
)
from vulngym_agent.trusted_inputs import (
    TrustedInputError,
    paths_overlap_v1,
    read_attestation_key_file_v1,
    zero_secret_buffer_v1,
)


E4_CLI_VERSION: Final[str] = "discovery-e4-cli-v1"

EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_ATTEMPT_FAILED: Final[int] = 10
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
EXIT_INTERRUPTED: Final[int] = 130

_SUCCESS_SUMMARY_KIND: Final[str] = "vulngym.e4-cli-success-summary.v1"
_ERROR_SUMMARY_KIND: Final[str] = "vulngym.e4-cli-error-summary.v1"
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_ERROR_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-z][a-z0-9_]{0,63}\Z"
)
_SPLIT_COUNTS: Final[dict[str, int]] = {"test": 20, "train": 50}


class E4CliError(RuntimeError):
    """Stable, path-free failure at the CLI-only boundary."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = _safe_error_code(code, fallback="command_rejected")
        self.committed = committed is True
        super().__init__(message)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally echoes the offending argv, which may contain a
        # trusted local path.  Keep its conventional exit while suppressing it.
        _ = message
        self.exit(EXIT_REJECTED, "error: E4 command arguments rejected\n")


def _safe_error_code(value: object, *, fallback: str) -> str:
    if type(value) is str and _ERROR_CODE_RE.fullmatch(value) is not None:
        return value
    return fallback


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.e4_cli",
        description="Run or verify the fixed offline E4 discovery split.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser(
        "run-split",
        help="run one fixed train or test split",
        allow_abbrev=False,
    )
    run.add_argument("--benchmark-root", type=Path, required=True)
    run.add_argument("--sealed-batch-root", type=Path, required=True)
    run.add_argument("--replay-config-root", type=Path, required=True)
    run.add_argument("--output-root", type=Path, required=True)
    run.add_argument("--split", choices=("train", "test"), required=True)
    run.add_argument(
        "--expected-sealed-batch-manifest-sha256", required=True
    )
    run.add_argument("--expected-replay-manifest-sha256", required=True)
    run.add_argument(
        "--expected-replay-manifest-wire-sha256", required=True
    )
    run.add_argument("--key-file", type=Path, required=True)
    run.add_argument("--snapshot-key-id", required=True)
    run.add_argument("--runtime-image-id", required=True)
    run.add_argument("--docker-executable", type=Path, required=True)

    verify = commands.add_parser(
        "verify-output",
        help="verify one committed E4 success publication",
        allow_abbrev=False,
    )
    verify.add_argument("--output-root", type=Path, required=True)
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
        raise E4CliError(
            "summary_invalid", "E4 CLI summary did not normalize"
        ) from None


def _write_stdout_bytes(payload: bytes) -> None:
    if type(payload) is not bytes:
        raise E4CliError(
            "summary_invalid", "E4 CLI output must be exact bytes"
        )
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload)
        binary.flush()
        return
    # StringIO and similar test streams have no binary facade.  Production
    # always takes the byte-preserving branch above.
    sys.stdout.write(payload.decode("utf-8", errors="strict"))
    sys.stdout.flush()


def _summary_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise E4CliError(
            "success_contract_mismatch",
            f"verified E4 success has an invalid {name}",
            committed=True,
        )
    return value


def _success_summary_v1(value: object) -> dict[str, object]:
    if type(value) is not E4BatchSuccessReceiptV2:
        raise E4CliError(
            "success_contract_mismatch",
            "verified E4 success has an invalid exact type",
            committed=True,
        )
    try:
        execution = value.execution_receipt
        plan = execution.plan
        batch = plan.batch
        policy = plan.execution_policy
        split = batch.split
        task_count = batch.task_count
        if (
            type(split) is not str
            or split not in _SPLIT_COUNTS
            or type(task_count) is not int
            or task_count != _SPLIT_COUNTS[split]
        ):
            raise E4CliError(
                "success_contract_mismatch",
                "verified E4 success has an invalid split closure",
                committed=True,
            )
        return {
            "artifact_index_sha256": _summary_sha256(
                execution.artifact_index_sha256,
                name="artifact index digest",
            ),
            "contract_version": 1,
            "kind": _SUCCESS_SUMMARY_KIND,
            "plan_sha256": _summary_sha256(
                plan.plan_sha256, name="plan semantic digest"
            ),
            "plan_wire_sha256": _summary_sha256(
                plan.wire_sha256, name="plan wire digest"
            ),
            "policy_sha256": _summary_sha256(
                policy.policy_sha256, name="policy semantic digest"
            ),
            "policy_wire_sha256": _summary_sha256(
                policy.wire_sha256, name="policy wire digest"
            ),
            "receipt_sha256": _summary_sha256(
                value.receipt_sha256, name="receipt semantic digest"
            ),
            "receipt_wire_sha256": _summary_sha256(
                value.wire_sha256, name="receipt wire digest"
            ),
            "split": split,
            "status": "succeeded",
            "task_count": task_count,
        }
    except E4CliError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise E4CliError(
            "success_contract_mismatch",
            "verified E4 success could not form its path-free summary",
            committed=True,
        ) from None


def _attempt_report_bytes(value: object) -> bytes:
    if type(value) is not DiscoveryBatchAttemptReportV2:
        raise E4CliError(
            "driver_contract_mismatch",
            "E4 driver returned an invalid result union",
        )
    try:
        payload = value.to_bytes()
        if (
            type(payload) is not bytes
            or not payload
            or _SHA256_RE.fullmatch(value.report_sha256) is None
            or hashlib.sha256(payload).hexdigest() != value.wire_sha256
        ):
            raise ValueError("attempt report is detached")
        return payload
    except (AttributeError, TypeError, ValueError):
        raise E4CliError(
            "driver_contract_mismatch",
            "E4 attempt report did not normalize",
        ) from None


def _validate_run_scalars(args: argparse.Namespace) -> None:
    for value in (
        args.expected_sealed_batch_manifest_sha256,
        args.expected_replay_manifest_sha256,
        args.expected_replay_manifest_wire_sha256,
    ):
        if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
            raise E4CliError(
                "invalid_argument",
                "E4 run digest input must be lower-case SHA-256",
            )
    if (
        type(args.runtime_image_id) is not str
        or _IMAGE_ID_RE.fullmatch(args.runtime_image_id) is None
    ):
        raise E4CliError(
            "invalid_argument", "E4 runtime image identity is invalid"
        )
    if (
        type(args.snapshot_key_id) is not str
        or _KEY_ID_RE.fullmatch(args.snapshot_key_id) is None
    ):
        raise E4CliError(
            "invalid_argument", "E4 snapshot key identity is invalid"
        )


def _run_split(args: argparse.Namespace) -> object:
    """Load, use, and unconditionally clear one CLI-owned key buffer."""

    key: object | None = None
    try:
        _validate_run_scalars(args)
        overlaps = paths_overlap_v1(
            args.output_root,
            args.key_file,
            left_exists=False,
            right_directory=False,
        )
        if type(overlaps) is not bool:
            raise E4CliError(
                "trusted_input_rejected",
                "trusted path comparison returned an invalid exact type",
            )
        if overlaps:
            raise E4CliError(
                "path_overlap",
                "E4 success output overlaps its attestation key",
            )
        key = read_attestation_key_file_v1(args.key_file)
        if type(key) is not bytearray:
            raise E4CliError(
                "trusted_key_rejected",
                "trusted key reader returned an invalid exact type",
            )
        return run_e4_discovery_split_v1(
            args.benchmark_root,
            args.sealed_batch_root,
            args.replay_config_root,
            args.output_root,
            split=args.split,
            expected_sealed_batch_manifest_sha256=(
                args.expected_sealed_batch_manifest_sha256
            ),
            expected_replay_manifest_sha256=(
                args.expected_replay_manifest_sha256
            ),
            expected_replay_manifest_wire_sha256=(
                args.expected_replay_manifest_wire_sha256
            ),
            snapshot_attestation_key=key,
            snapshot_key_id=args.snapshot_key_id,
            runtime_image_id=args.runtime_image_id,
            docker_executable=args.docker_executable,
        )
    finally:
        if type(key) is bytearray:
            zero_secret_buffer_v1(key)


def _verify_output(args: argparse.Namespace) -> E4BatchSuccessReceiptV2:
    result = read_committed_e4_discovery_execution_v1(
        args.output_root,
        expected_receipt_sha256=args.expected_receipt_sha256,
        expected_wire_sha256=args.expected_wire_sha256,
    )
    try:
        if (
            type(result) is not E4BatchSuccessReceiptV2
            or result.receipt_sha256 != args.expected_receipt_sha256
            or result.wire_sha256 != args.expected_wire_sha256
        ):
            raise E4CliError(
                "publication_mismatch",
                "committed E4 reader returned a detached success",
                committed=True,
            )
    except E4CliError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise E4CliError(
            "publication_mismatch",
            "committed E4 reader returned an invalid success",
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
        if args.command == "run-split":
            result = _run_split(args)
            if type(result) is E4BatchSuccessReceiptV2:
                return _emit_success(result)
            payload = _attempt_report_bytes(result)
            _write_stdout_bytes(payload)
            return EXIT_ATTEMPT_FAILED
        return _emit_success(_verify_output(args))
    except E4PublicationReaderError as error:
        _write_stdout_bytes(
            _error_summary_bytes(error.code, committed=True)
        )
        return EXIT_COMMITTED_UNCERTAIN
    except E4DriverError as error:
        committed = error.committed is True
        _write_stdout_bytes(
            _error_summary_bytes(error.code, committed=committed)
        )
        return EXIT_COMMITTED_UNCERTAIN if committed else EXIT_REJECTED
    except E4CliError as error:
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
    "E4_CLI_VERSION",
    "E4CliError",
    "EXIT_ATTEMPT_FAILED",
    "EXIT_COMMITTED_UNCERTAIN",
    "EXIT_INTERRUPTED",
    "EXIT_REJECTED",
    "EXIT_SUCCESS",
    "main",
]
