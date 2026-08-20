"""Path-sanitized CLI for sealed snapshot batch preparation and verification."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Final, Sequence

from vulngym_agent.benchmark.snapshot_batch import (
    SnapshotBatchError,
    _canonical_existing_path as _batch_canonical_existing_path,
    _canonical_new_child as _batch_canonical_new_child,
    prepare_snapshot_batch,
    verify_snapshot_batch,
)


_SHA256_LENGTH: Final[int] = 64
_MIN_KEY_BYTES: Final[int] = 32
_MAX_KEY_BYTES: Final[int] = 4_096


class _CliInputError(ValueError):
    pass


def _sha256(value: str) -> str:
    if len(value) != _SHA256_LENGTH or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _is_reparse(result: os.stat_result) -> bool:
    attributes = getattr(result, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _stable_path_identity(
    result: os.stat_result,
) -> tuple[int, int, int, int | None]:
    return (
        result.st_dev,
        result.st_ino,
        result.st_size,
        getattr(result, "st_mtime_ns", None),
    )


def _root_chain(path: Path) -> tuple[Path, ...]:
    return tuple(reversed(path.parents)) + (path,)


def _checked_directory_chain(
    path: Path,
) -> tuple[tuple[Path, tuple[int, int]], ...]:
    checked: list[tuple[Path, tuple[int, int]]] = []
    for component in _root_chain(path):
        try:
            state = os.lstat(component)
        except OSError as error:
            raise _CliInputError("key parent directory is unavailable") from error
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
        ):
            raise _CliInputError("key parent directory is unsafe")
        checked.append((component, (state.st_dev, state.st_ino)))
    return tuple(checked)


def _assert_directory_chain(
    checked: Sequence[tuple[Path, tuple[int, int]]],
) -> None:
    for component, expected in checked:
        try:
            state = os.lstat(component)
        except OSError as error:
            raise _CliInputError("key parent directory changed") from error
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
            or (state.st_dev, state.st_ino) != expected
        ):
            raise _CliInputError("key parent directory changed")


def _validate_key_state(state: os.stat_result) -> None:
    if (
        not stat.S_ISREG(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or _is_reparse(state)
        or state.st_nlink > 1
        or not _MIN_KEY_BYTES <= state.st_size <= _MAX_KEY_BYTES
    ):
        raise _CliInputError("key file violates the fixed secret-file contract")
    if os.name == "posix" and (
        state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) & 0o077
    ):
        raise _CliInputError(
            "key file must be owned by the current user and inaccessible to group/other"
        )


def _read_key_file(path: Path) -> bytes:
    path = _batch_canonical_existing_path(path, directory=False, status=2)
    checked_parent = _checked_directory_chain(path.parent)
    try:
        before = os.lstat(path)
    except OSError as error:
        raise _CliInputError("key file is unavailable") from error
    _validate_key_state(before)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise _CliInputError("key file cannot be opened") from error
    try:
        opened = os.fstat(descriptor)
        _validate_key_state(opened)
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            getattr(opened, "st_mtime_ns", None),
            getattr(opened, "st_ctime_ns", None),
        )
        if (
            _stable_path_identity(opened) != _stable_path_identity(before)
        ):
            raise _CliInputError("key file changed while opening")
        chunks: list[bytes] = []
        remaining = _MAX_KEY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        key = b"".join(chunks)
        finished = os.fstat(descriptor)
        finished_identity = (
            finished.st_dev,
            finished.st_ino,
            finished.st_size,
            getattr(finished, "st_mtime_ns", None),
            getattr(finished, "st_ctime_ns", None),
        )
        if (
            finished_identity != opened_identity
            or len(key) != opened.st_size
            or not _MIN_KEY_BYTES <= len(key) <= _MAX_KEY_BYTES
        ):
            raise _CliInputError("key file changed while reading")
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError as error:
        raise _CliInputError("key file changed during validation") from error
    _validate_key_state(after)
    _assert_directory_chain(checked_parent)
    if _stable_path_identity(after) != _stable_path_identity(before):
        raise _CliInputError("key file changed during validation")
    return key


def _paths_overlap(left: Path, right: Path, *, left_exists: bool) -> bool:
    canonical_left = (
        _batch_canonical_existing_path(left, directory=True, status=2)
        if left_exists
        else _batch_canonical_new_child(left, status=2)
    )
    canonical_right = _batch_canonical_existing_path(
        right, directory=False, status=2
    )
    left_text = os.path.normcase(os.path.abspath(os.fspath(canonical_left)))
    right_text = os.path.normcase(os.path.abspath(os.fspath(canonical_right)))
    try:
        common = os.path.commonpath((left_text, right_text))
    except ValueError:
        return False
    return common in {left_text, right_text}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or verify an authenticated VulnGym source-snapshot batch."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser(
        "prepare", help="prepare all answer-free tasks and publish once"
    )
    prepare.add_argument("--task-export-dir", type=Path, required=True)
    prepare.add_argument("--expected-tasks-sha256", type=_sha256, required=True)
    prepare.add_argument(
        "--expected-public-manifest-sha256", type=_sha256, required=True
    )
    prepare.add_argument("--source-map", type=Path, required=True)
    prepare.add_argument("--expected-source-map-sha256", type=_sha256, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--key-file", type=Path, required=True)
    prepare.add_argument("--key-id", required=True)

    verify = commands.add_parser(
        "verify-batch", help="authenticate the batch and deeply verify every task"
    )
    verify.add_argument("--sealed-root", type=Path, required=True)
    verify.add_argument("--expected-manifest-sha256", type=_sha256, required=True)
    verify.add_argument("--key-file", type=Path, required=True)
    verify.add_argument("--expected-key-id", required=True)
    return parser


def _print_json(value: object) -> None:
    print(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            if _paths_overlap(args.output_dir, args.key_file, left_exists=False):
                raise _CliInputError("output and key paths conflict")
            key = _read_key_file(args.key_file)
            summary = prepare_snapshot_batch(
                args.task_export_dir,
                expected_tasks_sha256=args.expected_tasks_sha256,
                expected_public_manifest_sha256=args.expected_public_manifest_sha256,
                source_map_path=args.source_map,
                expected_source_map_sha256=args.expected_source_map_sha256,
                output_dir=args.output_dir,
                attestation_key=key,
                key_id=args.key_id,
            )
        else:
            # A missing or non-canonical artifact root is a verification
            # failure, while key/configuration failures remain usage errors.
            _batch_canonical_existing_path(
                args.sealed_root,
                directory=True,
                status=4,
            )
            if _paths_overlap(args.sealed_root, args.key_file, left_exists=True):
                raise _CliInputError("sealed batch and key paths conflict")
            key = _read_key_file(args.key_file)
            summary = verify_snapshot_batch(
                args.sealed_root,
                expected_manifest_sha256=args.expected_manifest_sha256,
                attestation_key=key,
                expected_key_id=args.expected_key_id,
            )
    except SnapshotBatchError as error:
        # Codes are useful to orchestration; messages remain deliberately
        # generic so OS exceptions can never disclose local absolute paths.
        print(f"error[{error.code}]: snapshot batch command failed", file=sys.stderr)
        return error.exit_status
    except (_CliInputError, ValueError, TypeError):
        print("error[input_rejected]: snapshot batch command rejected its inputs", file=sys.stderr)
        return 2
    except OSError:
        print("error[io_failed]: snapshot batch command failed", file=sys.stderr)
        return 5
    _print_json(summary.to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
