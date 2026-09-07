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
    SubmissionPredictionExportInput,
    build_submission_review_evidence,
    build_submission_handoff,
    combine_submission_prediction_exports,
    verify_submission_predictions,
    verify_submission_handoff,
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

    review = subparsers.add_parser(
        "review", help="emit read-only reviewer evidence for one pinned replay"
    )
    review.add_argument("--replay-dir", required=True, type=Path)
    review.add_argument(
        "--replay-dataset-sha256", required=True, type=_sha256
    )
    review.add_argument(
        "--protected-path",
        action="append",
        default=[],
        type=Path,
        help="trusted local path whose spelling must not occur in replay artifacts",
    )
    _add_common_count(review)

    for name in ("handoff", "verify-handoff"):
        command = subparsers.add_parser(name, help=(
            "emit a read-only mixed-batch JSON handoff (includes candidate code)"
            if name == "handoff" else "verify a handoff against pinned source and external digest"))
        command.add_argument("--replay-dir", required=True, type=Path)
        command.add_argument("--replay-dataset-sha256", required=True, type=_sha256)
        command.add_argument("--protected-path", action="append", default=[], type=Path)
        _add_common_count(command)
        if name == "verify-handoff":
            command.add_argument("--handoff-file", required=True, type=Path)
            command.add_argument("--handoff-sha256", required=True, type=_sha256)

    combine = subparsers.add_parser(
        "combine", help="combine pinned submission exports"
    )
    combine.add_argument("--output-dir", required=True, type=Path)
    combine.add_argument(
        "--input-submission-dir", action="append", required=True, type=Path
    )
    combine.add_argument(
        "--input-source-replay-dataset-sha256",
        action="append",
        required=True,
        type=_sha256,
    )
    combine.add_argument(
        "--input-submission-sha256",
        action="append",
        required=True,
        type=_sha256,
    )
    combine.add_argument(
        "--input-task-count", action="append", required=True, type=_count
    )
    combine.add_argument(
        "--protected-path",
        action="append",
        default=[],
        type=Path,
        help="trusted local path whose spelling must not occur in replay artifacts",
    )
    _add_common_count(combine)
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


def _combine_inputs(
    args: argparse.Namespace,
) -> tuple[SubmissionPredictionExportInput, ...]:
    directories = tuple(args.input_submission_dir)
    source_digests = tuple(args.input_source_replay_dataset_sha256)
    submission_digests = tuple(args.input_submission_sha256)
    counts = tuple(args.input_task_count)
    if not (
        len(directories)
        == len(source_digests)
        == len(submission_digests)
        == len(counts)
    ):
        raise SubmissionPredictionError(
            "input_argument_mismatch",
            "combine input arguments must have matching counts",
        )
    return tuple(
        SubmissionPredictionExportInput(
            directory=directory,
            source_replay_dataset_sha256=source_digest,
            submission_sha256=submission_digest,
            task_count=count,
        )
        for directory, source_digest, submission_digest, count in zip(
            directories, source_digests, submission_digests, counts, strict=True
        )
    )


def _run_combine(
    args: argparse.Namespace, mutation_state: list[bool]
) -> Any:
    """Run combine without a false-uncommitted window after it returns."""

    mutation_state[0] = True
    try:
        return combine_submission_prediction_exports(
            args.output_dir,
            _combine_inputs(args),
            expected_task_count=args.expected_task_count,
            protected_paths=args.protected_path,
        )
    except SubmissionPredictionError as error:
        mutation_state[0] = error.committed
        raise
    except BaseException:
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
            _canonical_stdout(_summary(args.operation, manifest))
        elif args.operation == "combine":
            manifest = _run_combine(args, mutation_state)
            _canonical_stdout(_summary(args.operation, manifest))
        elif args.operation == "verify":
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
        elif args.operation in {"handoff", "verify-handoff"}:
            options = {
                "expected_source_replay_dataset_sha256": args.replay_dataset_sha256,
                "expected_task_count": args.expected_task_count,
                "protected_paths": args.protected_path,
            }
            if args.operation == "handoff":
                result = build_submission_handoff(args.replay_dir, **options)
            else:
                result = verify_submission_handoff(
                    args.handoff_file, args.replay_dir,
                    expected_handoff_sha256=args.handoff_sha256, **options)
            _canonical_stdout(result)
        else:
            review = build_submission_review_evidence(
                args.replay_dir,
                expected_source_replay_dataset_sha256=(
                    args.replay_dataset_sha256
                ),
                expected_task_count=args.expected_task_count,
                protected_paths=args.protected_path,
            )
            _canonical_stdout(review)
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
