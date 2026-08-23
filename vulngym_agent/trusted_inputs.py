"""Shared trusted CLI input primitives for local evaluator secrets and paths."""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Final

from vulngym_agent.benchmark.snapshot_batch import (
    _canonical_existing_path,
    _canonical_new_child,
)


MIN_ATTESTATION_KEY_BYTES: Final[int] = 32
MAX_ATTESTATION_KEY_BYTES: Final[int] = 4_096


class TrustedInputError(ValueError):
    """Path-free rejection at a shared trusted CLI input boundary."""


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
            raise TrustedInputError(
                "secret parent directory is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
        ):
            raise TrustedInputError("secret parent directory is unsafe")
        checked.append((component, (state.st_dev, state.st_ino)))
    return tuple(checked)


def _assert_directory_chain(
    checked: tuple[tuple[Path, tuple[int, int]], ...],
) -> None:
    for component, expected in checked:
        try:
            state = os.lstat(component)
        except OSError as error:
            raise TrustedInputError(
                "secret parent directory changed"
            ) from error
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
            or (state.st_dev, state.st_ino) != expected
        ):
            raise TrustedInputError("secret parent directory changed")


def _validate_key_state(state: os.stat_result) -> None:
    if (
        not stat.S_ISREG(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or _is_reparse(state)
        or state.st_nlink > 1
        or not MIN_ATTESTATION_KEY_BYTES
        <= state.st_size
        <= MAX_ATTESTATION_KEY_BYTES
    ):
        raise TrustedInputError(
            "key file violates the fixed secret-file contract"
        )
    if os.name == "posix" and (
        state.st_uid != os.geteuid() or stat.S_IMODE(state.st_mode) & 0o077
    ):
        raise TrustedInputError(
            "key file must be owned by the current user and inaccessible to group/other"
        )


def read_attestation_key_file_v1(path: Path) -> bytearray:
    """Read one stable, private attestation key and return a zeroable buffer."""

    canonical = _canonical_existing_path(path, directory=False, status=2)
    checked_parent = _checked_directory_chain(canonical.parent)
    try:
        before = os.lstat(canonical)
    except OSError as error:
        raise TrustedInputError("key file is unavailable") from error
    _validate_key_state(before)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(canonical, flags)
    except OSError as error:
        raise TrustedInputError("key file cannot be opened") from error
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
        if _stable_path_identity(opened) != _stable_path_identity(before):
            raise TrustedInputError("key file changed while opening")
        chunks: list[bytes] = []
        remaining = MAX_ATTESTATION_KEY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        key = bytearray(b"".join(chunks))
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
            or not MIN_ATTESTATION_KEY_BYTES
            <= len(key)
            <= MAX_ATTESTATION_KEY_BYTES
        ):
            zero_secret_buffer_v1(key)
            raise TrustedInputError("key file changed while reading")
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(canonical)
    except OSError as error:
        zero_secret_buffer_v1(key)
        raise TrustedInputError("key file changed during validation") from error
    try:
        _validate_key_state(after)
        _assert_directory_chain(checked_parent)
        if _stable_path_identity(after) != _stable_path_identity(before):
            raise TrustedInputError("key file changed during validation")
    except BaseException:
        zero_secret_buffer_v1(key)
        raise
    return key


def paths_overlap_v1(
    left: Path,
    right: Path,
    *,
    left_exists: bool,
    right_directory: bool = False,
) -> bool:
    """Compare one existing/new path with one existing protected path."""

    canonical_left = (
        _canonical_existing_path(left, directory=True, status=2)
        if left_exists
        else _canonical_new_child(left, status=2)
    )
    canonical_right = _canonical_existing_path(
        right, directory=right_directory, status=2
    )
    left_text = os.path.normcase(os.path.abspath(os.fspath(canonical_left)))
    right_text = os.path.normcase(os.path.abspath(os.fspath(canonical_right)))
    try:
        common = os.path.commonpath((left_text, right_text))
    except ValueError:
        return False
    return common in {left_text, right_text}


def zero_secret_buffer_v1(value: bytearray | None) -> None:
    """Best-effort in-place clearing for a caller-owned exact bytearray."""

    if value is None:
        return
    if type(value) is not bytearray:
        raise TypeError("secret buffer must be an exact bytearray")
    for index in range(len(value)):
        value[index] = 0


__all__ = [
    "MAX_ATTESTATION_KEY_BYTES",
    "MIN_ATTESTATION_KEY_BYTES",
    "TrustedInputError",
    "paths_overlap_v1",
    "read_attestation_key_file_v1",
    "zero_secret_buffer_v1",
]
