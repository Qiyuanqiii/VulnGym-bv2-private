"""Trusted CLI for acquiring exact GitHub sources and writing source maps."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Final, Sequence

from vulngym_agent.benchmark.source_acquisition import (
    GITHUB_TRANSPORTS,
    SOURCE_NOT_READY_EXIT_STATUS,
    SourceAcquisitionError,
    SourceAcquisitionInput,
    prepare_source_acquisition,
    verify_source_acquisition,
)


_SHA256_LENGTH: Final[int] = 64


def _sha256(value: str) -> str:
    if len(value) != _SHA256_LENGTH or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repository-store",
        type=Path,
        required=True,
        help=(
            "operator contract: store dedicated to this complete input union; "
            "single split runs require an independent store, and every combined "
            "or reused store run must use the same complete test+train union and "
            "exact digest pins. Verification enforces only refs and objects derived "
            "from the current invocation; it cannot prove prior store-use history"
        ),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--git-executable", type=Path, required=True)
    parser.add_argument(
        "--github-transport",
        choices=GITHUB_TRANSPORTS,
        default="https",
    )
    parser.add_argument("--ssh-executable", type=Path)
    parser.add_argument("--test-task-export-dir", type=Path)
    parser.add_argument("--test-expected-tasks-sha256", type=_sha256)
    parser.add_argument("--train-task-export-dir", type=Path)
    parser.add_argument("--train-expected-tasks-sha256", type=_sha256)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Acquire exact GitHub commits into independent bare repositories "
            "and prepare canonical VulnGym source maps."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser(
        "prepare", help="fetch missing exact commits, verify, and publish controls"
    )
    verify = commands.add_parser(
        "verify", help="verify existing repositories and controls without network"
    )
    _add_common_arguments(prepare)
    _add_common_arguments(verify)
    return parser


def _inputs_from_args(args: argparse.Namespace) -> tuple[SourceAcquisitionInput, ...]:
    values: list[SourceAcquisitionInput] = []
    for split in ("test", "train"):
        directory = getattr(args, f"{split}_task_export_dir")
        digest = getattr(args, f"{split}_expected_tasks_sha256")
        if (directory is None) != (digest is None):
            raise ValueError("task-export path and digest must be supplied together")
        if directory is not None:
            values.append(
                SourceAcquisitionInput(
                    task_export_dir=directory,
                    expected_tasks_sha256=digest,
                )
            )
    if not values:
        raise ValueError("at least one task export is required")
    if args.github_transport == "ssh" and args.ssh_executable is None:
        raise ValueError("SSH transport requires --ssh-executable")
    if args.github_transport == "https" and args.ssh_executable is not None:
        raise ValueError("--ssh-executable is only valid for SSH transport")
    return tuple(values)


def _print_json(value: object) -> None:
    print(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


def _suppress_failed_stdout_finalization() -> None:
    """Prevent a poisoned stdout buffer from changing the process exit status."""

    stream = sys.stdout
    try:
        stream.flush()
    except BaseException:
        # CPython retries flushing sys.stdout during finalization and changes
        # the requested status to 120 if that retry fails. Detach only the
        # broken process-global reference; never close a caller-owned stream.
        if sys.stdout is stream:
            sys.stdout = None


def _report_output_failure(*, publication_uncertain: bool) -> int:
    _suppress_failed_stdout_finalization()
    code = "publication_uncertain" if publication_uncertain else "io_failed"
    message = (
        "source acquisition output may be committed"
        if publication_uncertain
        else "source acquisition command failed"
    )
    try:
        print(f"error[{code}]: {message}", file=sys.stderr)
    except BaseException:
        pass
    return 5


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = _inputs_from_args(args)
        operation = (
            prepare_source_acquisition
            if args.command == "prepare"
            else verify_source_acquisition
        )
        summary = operation(
            inputs,
            repository_store=args.repository_store,
            output_dir=args.output_dir,
            git_executable=args.git_executable,
            github_transport=args.github_transport,
            ssh_executable=args.ssh_executable,
        )
    except SourceAcquisitionError as error:
        print(
            f"error[{error.code}]: source acquisition command failed",
            file=sys.stderr,
        )
        return error.exit_status
    except (TypeError, ValueError):
        print(
            "error[input_rejected]: source acquisition command rejected its inputs",
            file=sys.stderr,
        )
        return 2
    except OSError:
        print("error[io_failed]: source acquisition command failed", file=sys.stderr)
        return 5
    try:
        _print_json(summary.to_dict())
    except BaseException:
        return _report_output_failure(
            publication_uncertain=args.command == "prepare"
        )
    return 0 if summary.ready else SOURCE_NOT_READY_EXIT_STATUS


if __name__ == "__main__":
    raise SystemExit(main())
