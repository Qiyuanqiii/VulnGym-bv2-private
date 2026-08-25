"""Credential-free step CLI for one trusted D2/D3 replay authoring draft."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
from typing import Final, Sequence

from vulngym_agent.evaluator.replay_authoring import (
    ReplayAuthoringError,
    ReplayAuthoringPendingRequestV1,
    ReplayAuthoringResponseV1,
    ReplayAuthoringSummaryV1,
    append_replay_authoring_response_v1,
    initialize_replay_authoring_v1,
    inspect_replay_authoring_v1,
    publish_replay_authoring_v1,
    read_authoring_response_file_v1,
    read_pinned_authoring_task_v1,
)
from vulngym_agent.benchmark.snapshot_batch import SnapshotBatchError
from vulngym_agent.trusted_inputs import (
    TrustedInputError,
    paths_overlap_v1,
    read_attestation_key_file_v1,
    zero_secret_buffer_v1,
)


REPLAY_AUTHORING_CLI_VERSION: Final[str] = "replay-authoring-cli-v1"
EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_PENDING: Final[int] = 10
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
EXIT_INTERRUPTED: Final[int] = 130

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _ = message
        self.exit(EXIT_REJECTED, "error: replay authoring arguments rejected\n")


def _sha256(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _add_task_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--task-file", type=Path, required=True)
    parser.add_argument("--expected-task-wire-sha256", type=_sha256, required=True)


def _add_execution_arguments(parser: argparse.ArgumentParser) -> None:
    _add_task_arguments(parser)
    parser.add_argument("--sealed-bundle-root", type=Path, required=True)
    parser.add_argument("--draft-root", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--key-id", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.replay_authoring_cli",
        description="Author one fixed offline D2/D3 replay pair step by step.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser(
        "init", help="create a new empty two-file authoring draft", allow_abbrev=False
    )
    _add_task_arguments(initialize)
    initialize.add_argument("--draft-root", type=Path, required=True)

    next_request = commands.add_parser(
        "next-request",
        help="replay the current prefix and emit the sole next request",
        allow_abbrev=False,
    )
    _add_execution_arguments(next_request)

    respond = commands.add_parser(
        "respond",
        help="atomically append one request-bound response envelope",
        allow_abbrev=False,
    )
    _add_execution_arguments(respond)
    respond.add_argument("--response-file", type=Path, required=True)

    finalize = commands.add_parser(
        "finalize",
        help="require exact offline closure and publish the canonical pair",
        allow_abbrev=False,
    )
    _add_execution_arguments(finalize)
    finalize.add_argument("--output-root", type=Path, required=True)
    return parser


def _write_stdout(value: object) -> None:
    if type(value) not in (
        ReplayAuthoringPendingRequestV1,
        ReplayAuthoringSummaryV1,
    ):
        raise ReplayAuthoringError(
            "output_invalid", "authoring CLI received an invalid result type"
        )
    payload = value.to_bytes()
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload)
        binary.flush()
    else:
        sys.stdout.write(payload.decode("utf-8", errors="strict"))
        sys.stdout.flush()


def _write_error(code: str) -> None:
    try:
        sys.stderr.write(f"error[{code}]: replay authoring failed\n")
        sys.stderr.flush()
    except BaseException:
        pass


def _assert_no_overlap(
    left: Path,
    right: Path,
    *,
    left_exists: bool,
    right_directory: bool,
) -> None:
    if paths_overlap_v1(
        left,
        right,
        left_exists=left_exists,
        right_directory=right_directory,
    ):
        raise ReplayAuthoringError(
            "path_overlap", "authoring control paths overlap"
        )


def _task(args: argparse.Namespace):
    return read_pinned_authoring_task_v1(
        args.task_file,
        expected_wire_sha256=args.expected_task_wire_sha256,
    )


def _validate_mutating_paths(args: argparse.Namespace) -> None:
    _assert_no_overlap(
        args.sealed_bundle_root,
        args.draft_root,
        left_exists=True,
        right_directory=True,
    )
    for protected in (args.key_file, args.task_file):
        _assert_no_overlap(
            args.sealed_bundle_root,
            protected,
            left_exists=True,
            right_directory=False,
        )
    _assert_no_overlap(
        args.draft_root,
        args.key_file,
        left_exists=True,
        right_directory=False,
    )
    _assert_no_overlap(
        args.draft_root,
        args.task_file,
        left_exists=True,
        right_directory=False,
    )
    _assert_no_overlap(
        args.draft_root,
        args.sealed_bundle_root,
        left_exists=True,
        right_directory=True,
    )
    if args.command == "respond":
        _assert_no_overlap(
            args.sealed_bundle_root,
            args.response_file,
            left_exists=True,
            right_directory=False,
        )
        _assert_no_overlap(
            args.draft_root,
            args.response_file,
            left_exists=True,
            right_directory=False,
        )
    files = [args.task_file, args.key_file]
    if args.command == "respond":
        files.append(args.response_file)
    normalized = [_normalized_existing_file(item) for item in files]
    texts = [item[0] for item in normalized]
    identities = [item[1:] for item in normalized]
    if len(texts) != len(set(texts)) or len(identities) != len(set(identities)):
        raise ReplayAuthoringError(
            "path_overlap", "authoring control files overlap"
        )
    if args.command == "finalize":
        for right, directory in (
            (args.draft_root, True),
            (args.sealed_bundle_root, True),
            (args.key_file, False),
            (args.task_file, False),
        ):
            _assert_no_overlap(
                args.output_root,
                right,
                left_exists=False,
                right_directory=directory,
            )


def _normalized_existing_file(path: Path) -> tuple[str, int, int]:
    try:
        absolute = Path(os.path.abspath(os.fspath(path)))
        state = os.stat(absolute, follow_symlinks=False)
    except (OSError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "input_unavailable", "authoring control file is unavailable"
        ) from None
    return (
        os.path.normcase(os.path.abspath(os.fspath(absolute))),
        state.st_dev,
        state.st_ino,
    )


def _run_with_key(
    args: argparse.Namespace,
    task: object,
    *,
    mutation_state: list[bool],
) -> object:
    key: bytearray | None = None
    try:
        key = read_attestation_key_file_v1(args.key_file)
        if args.command == "next-request":
            return inspect_replay_authoring_v1(
                task,
                args.sealed_bundle_root,
                args.draft_root,
                attestation_key=key,
                expected_key_id=args.key_id,
            )
        if args.command == "respond":
            response: ReplayAuthoringResponseV1 = read_authoring_response_file_v1(
                args.response_file
            )
            mutation_state[0] = True
            try:
                return append_replay_authoring_response_v1(
                    task,
                    args.sealed_bundle_root,
                    args.draft_root,
                    response,
                    attestation_key=key,
                    expected_key_id=args.key_id,
                )
            except KeyboardInterrupt:
                # The core API only lets a bare interrupt escape when its
                # exact readback proved that the replace did not commit.
                mutation_state[0] = False
                raise
        mutation_state[0] = True
        try:
            return publish_replay_authoring_v1(
                task,
                args.sealed_bundle_root,
                args.draft_root,
                args.output_root,
                attestation_key=key,
                expected_key_id=args.key_id,
            )
        except KeyboardInterrupt:
            mutation_state[0] = False
            raise
    finally:
        zero_secret_buffer_v1(key)


def _run_init(
    task: object,
    draft_root: Path,
    *,
    mutation_state: list[bool],
) -> object:
    """Run init with no false-uncommitted window after the call returns."""

    mutation_state[0] = True
    try:
        return initialize_replay_authoring_v1(task.task_id, draft_root)
    except KeyboardInterrupt:
        # The core API only exposes a bare interrupt after proving that its
        # no-replace publication did not commit.
        mutation_state[0] = False
        raise


def main(argv: Sequence[str] | None = None) -> int:
    mutation_state = [False]
    try:
        args = _parser().parse_args(argv)
        if args.command == "init":
            _assert_no_overlap(
                args.draft_root,
                args.task_file,
                left_exists=False,
                right_directory=False,
            )
        else:
            _validate_mutating_paths(args)
        task = _task(args)
        if args.command == "init":
            result = _run_init(
                task, args.draft_root, mutation_state=mutation_state
            )
        else:
            result = _run_with_key(
                args, task, mutation_state=mutation_state
            )
        try:
            _write_stdout(result)
        except KeyboardInterrupt:
            _write_error(
                "committed_uncertain" if mutation_state[0] else "interrupted"
            )
            return (
                EXIT_COMMITTED_UNCERTAIN
                if mutation_state[0]
                else EXIT_INTERRUPTED
            )
        except Exception:
            _write_error(
                "committed_uncertain" if mutation_state[0] else "output_failed"
            )
            return (
                EXIT_COMMITTED_UNCERTAIN if mutation_state[0] else EXIT_REJECTED
            )
        except BaseException:
            _write_error(
                "committed_uncertain" if mutation_state[0] else "interrupted"
            )
            return (
                EXIT_COMMITTED_UNCERTAIN
                if mutation_state[0]
                else EXIT_INTERRUPTED
            )
    except KeyboardInterrupt:
        _write_error(
            "committed_uncertain" if mutation_state[0] else "interrupted"
        )
        return (
            EXIT_COMMITTED_UNCERTAIN if mutation_state[0] else EXIT_INTERRUPTED
        )
    except ReplayAuthoringError as error:
        _write_error(error.code)
        return EXIT_COMMITTED_UNCERTAIN if error.committed else EXIT_REJECTED
    except SnapshotBatchError as error:
        _write_error("input_rejected")
        return EXIT_COMMITTED_UNCERTAIN if error.committed else EXIT_REJECTED
    except (TrustedInputError, OSError, TypeError, ValueError):
        _write_error(
            "committed_uncertain" if mutation_state[0] else "input_rejected"
        )
        return EXIT_COMMITTED_UNCERTAIN if mutation_state[0] else EXIT_REJECTED
    except Exception:
        _write_error(
            "committed_uncertain" if mutation_state[0] else "internal_error"
        )
        return EXIT_COMMITTED_UNCERTAIN if mutation_state[0] else EXIT_REJECTED
    return (
        EXIT_PENDING
        if type(result) is ReplayAuthoringPendingRequestV1
        else EXIT_SUCCESS
    )


if __name__ == "__main__":
    raise SystemExit(main())
