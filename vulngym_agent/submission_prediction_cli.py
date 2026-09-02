"""CLI for exporting and independently verifying submission predictions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Final, Sequence

from vulngym_agent.submission_prediction import (
    SubmissionPredictionError,
    verify_submission_predictions,
    write_submission_predictions,
)


SUBMISSION_PREDICTION_CLI_VERSION: Final[str] = "submission-prediction-cli-v1"
EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
EXIT_INTERRUPTED: Final[int] = 130
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _ = message
        self.exit(EXIT_REJECTED, "error: submission prediction arguments rejected\n")


def _sha256(value: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _count(value: str) -> int:
    try:
        parsed = int(value, 10)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("count must be an integer") from None
    if not 1 <= parsed <= 100_000:
        raise argparse.ArgumentTypeError("count must be between 1 and 100000")
    return parsed


def _canonical_stdout(value: Any) -> None:
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload.encode("utf-8"))
        binary.flush()
    else:
        sys.stdout.write(payload)
        sys.stdout.flush()


def _add_common_count(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expected-task-count", required=True, type=_count)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="python -m vulngym_agent.submission_prediction_cli",
        description=(
            "Export complete terminal T2 candidates with their actual T1 reports "
            "without changing the internal finalized-only Entry contract."
        ),
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)

    export = subparsers.add_parser("export", help="export one pinned replay run")
    export.add_argument("--replay-dir", required=True, type=Path)
    export.add_argument(
        "--replay-dataset-sha256", required=True, type=_sha256
    )
    export.add_argument("--output-dir", required=True, type=Path)
    export.add_argument(
        "--protected-path",
        action="append",
        default=[],
        type=Path,
        help="trusted local path whose spelling must not occur in replay artifacts",
    )
    _add_common_count(export)

    verify = subparsers.add_parser(
        "verify", help="verify an export against its pinned source replay"
    )
    verify.add_argument("--submission-dir", required=True, type=Path)
    verify.add_argument("--replay-dir", required=True, type=Path)
    verify.add_argument(
        "--source-replay-dataset-sha256", required=True, type=_sha256
    )
    verify.add_argument("--submission-sha256", required=True, type=_sha256)
    verify.add_argument(
        "--protected-path",
        action="append",
        default=[],
        type=Path,
        help="trusted local path whose spelling must not occur in replay artifacts",
    )
    _add_common_count(verify)
    return parser


def _summary(operation: str, manifest: Any) -> dict[str, Any]:
    return {
        "cli_version": SUBMISSION_PREDICTION_CLI_VERSION,
        "contract_version": 1,
        "kind": "vulngym.submission-prediction-summary.v1",
        "operation": operation,
        "status": "ok",
        "source_replay_dataset_sha256": (
            manifest.source_replay_dataset_sha256
        ),
        "submission_sha256": manifest.submission_sha256,
        "task_count": manifest.task_count,
        "status_counts": dict(manifest.status_counts),
        "verdict_counts": dict(manifest.verdict_counts),
    }


def _write_error(code: str) -> None:
    try:
        sys.stderr.write(f"error[{code}]: submission prediction rejected\n")
        sys.stderr.flush()
    except BaseException:
        pass


def _run_export(
    args: argparse.Namespace, mutation_state: list[bool]
) -> Any:
    """Run export without a false-uncommitted window after it returns."""

    mutation_state[0] = True
    try:
        return write_submission_predictions(
            args.output_dir,
            args.replay_dir,
            expected_source_replay_dataset_sha256=(
                args.replay_dataset_sha256
            ),
            expected_task_count=args.expected_task_count,
            protected_paths=args.protected_path,
        )
    except SubmissionPredictionError as error:
        mutation_state[0] = error.committed
        raise
    except BaseException:
        # The core converts every post-commit failure to a committed
        # SubmissionPredictionError. A bare failure therefore precedes commit.
        mutation_state[0] = False
        raise


def main(argv: Sequence[str] | None = None) -> int:
    mutation_state = [False]
    arguments_parsed = False
    try:
        args = _parser().parse_args(argv)
        arguments_parsed = True
        if args.operation == "export":
            manifest = _run_export(args, mutation_state)
        else:
            bundle = verify_submission_predictions(
                args.submission_dir,
                args.replay_dir,
                expected_source_replay_dataset_sha256=(
                    args.source_replay_dataset_sha256
                ),
                expected_task_count=args.expected_task_count,
                expected_submission_sha256=args.submission_sha256,
                protected_paths=args.protected_path,
            )
            manifest = bundle.manifest
        _canonical_stdout(_summary(args.operation, manifest))
        return EXIT_SUCCESS
    except SubmissionPredictionError as error:
        publication_may_exist = error.committed or mutation_state[0]
        _write_error(
            error.code
            if error.committed or not mutation_state[0]
            else "committed_uncertain"
        )
        return (
            EXIT_COMMITTED_UNCERTAIN
            if publication_may_exist
            else EXIT_REJECTED
        )
    except SystemExit as error:
        if mutation_state[0]:
            _write_error("committed_uncertain")
            return EXIT_COMMITTED_UNCERTAIN
        if arguments_parsed:
            _write_error("operation_failed")
            return EXIT_REJECTED
        return EXIT_SUCCESS if error.code in (None, EXIT_SUCCESS) else EXIT_REJECTED
    except KeyboardInterrupt:
        code = "committed_uncertain" if mutation_state[0] else "interrupted"
        _write_error(code)
        return (
            EXIT_COMMITTED_UNCERTAIN
            if mutation_state[0]
            else EXIT_INTERRUPTED
        )
    except BaseException:
        code = "committed_uncertain" if mutation_state[0] else "operation_failed"
        _write_error(code)
        return (
            EXIT_COMMITTED_UNCERTAIN if mutation_state[0] else EXIT_REJECTED
        )


if __name__ == "__main__":
    raise SystemExit(main())
