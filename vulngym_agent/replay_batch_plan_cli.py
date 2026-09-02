"""Build and verify formal replay batches and the fixed 20+50 gate plan.

This trusted control-plane CLI deliberately does not call a model and does not
execute a benchmark task.  It closes the mechanical gap between the existing
single-task ``replay_authoring_cli`` and the strict batch/final-gate readers:

* ``build-split`` packages 20 test or 50 train authoring publications in the
  pinned public task order;
* ``verify-split`` independently re-reads that exact batch;
* ``build-plan`` binds both replay manifests, both sealed-batch pins, distinct
  key IDs, and the fixed OCI execution policy into ``FinalGatePlanV1``; and
* ``verify-plan`` independently re-reads the plan and both replay batches.

All publications use a new same-parent staging directory and an atomic
no-replace rename.  Success output is canonical, path-free JSON.  Replay
responses remain untrusted input and this module never labels them correct.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Final, Literal, Sequence
import uuid

from vulngym_agent.benchmark.harness import (
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
    load_answer_free_tasks,
)
from vulngym_agent.evaluator.batch_configs import (
    BATCH_REPLAY_CONFIG_DIRECTORY,
    BATCH_REPLAY_CONFIG_MANIFEST_FILENAME,
    BATCH_REPLAY_D2_FILENAME,
    BATCH_REPLAY_D3_FILENAME,
    BatchReplayConfigError,
    BatchReplayConfigManifestV1,
    TaskReplayConfigBindingV1,
    load_batch_replay_configs_v1,
)
from vulngym_agent.evaluator.e4_driver import (
    E4DriverError,
    fixed_e4_execution_policy_v1,
)
from vulngym_agent.evaluator.final_gate import (
    FINAL_GATE_MAX_WIRE_BYTES,
    FINAL_GATE_PLAN_FILENAME,
    FinalGateContractError,
    FinalGatePlanV1,
    FinalGateSplitPlanV1,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    OciReplayConfigV1,
    OciWorkerEntryError,
    REPLAY_CONFIG_MAX_BYTES,
)
from vulngym_agent.evaluator.replay_authoring import (
    ReplayAuthoringError,
    validate_formal_replay_pair_v1,
)
from vulngym_agent.trusted_inputs import TrustedInputError, paths_overlap_v1


REPLAY_BATCH_PLAN_CLI_VERSION: Final[str] = "replay-batch-plan-cli-v1"
REPLAY_BATCH_PLAN_SUMMARY_KIND: Final[str] = (
    "vulngym.replay-batch-plan-summary.v1"
)
EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
EXIT_INTERRUPTED: Final[int] = 130

_SPLIT_COUNTS: Final[dict[str, int]] = {
    "test": PROFILE_TEST_TASKS,
    "train": PROFILE_TRAIN_TASKS,
}
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"sha256:[0-9a-f]{64}\Z"
)
_AUTHORING_INDEX_KIND: Final[str] = "vulngym.replay-authoring-index.v1"
_AUTHORING_INDEX_DOMAIN: Final[bytes] = b"vulngym:replay-authoring-index:v1\x00"
_AUTHORING_INDEX_MAX_BYTES: Final[int] = 512 * 1024


class ReplayBatchPlanError(RuntimeError):
    """Stable, path-free failure at the batch/plan publication boundary."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = code if type(code) is str and code else "operation_failed"
        self.committed = committed is True
        super().__init__(message)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _ = message
        self.exit(EXIT_REJECTED, "error: replay batch/plan arguments rejected\n")


def _sha256(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _image_id(value: str) -> str:
    if type(value) is not str or _IMAGE_ID_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "image ID must be sha256 followed by 64 lower-case hex characters"
        )
    return value


def _add_replay_pin_arguments(
    parser: argparse.ArgumentParser, prefix: str
) -> None:
    parser.add_argument(
        f"--{prefix}-replay-root", type=Path, required=True
    )
    parser.add_argument(
        f"--{prefix}-replay-manifest-sha256", type=_sha256, required=True
    )
    parser.add_argument(
        f"--{prefix}-replay-manifest-wire-sha256",
        type=_sha256,
        required=True,
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.replay_batch_plan_cli",
        description=(
            "Package formal single-task replays and build the fixed 20+50 "
            "final-gate plan without executing any task."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build_split = commands.add_parser(
        "build-split",
        help="package one exact public split of formal replay pairs",
        allow_abbrev=False,
    )
    build_split.add_argument("--benchmark-root", type=Path, required=True)
    build_split.add_argument("--split", choices=("test", "train"), required=True)
    build_split.add_argument(
        "--authoring-output-root", type=Path, required=True
    )
    build_split.add_argument("--authoring-index-file", type=Path, required=True)
    build_split.add_argument(
        "--expected-authoring-index-sha256", type=_sha256, required=True
    )
    build_split.add_argument(
        "--expected-authoring-index-wire-sha256", type=_sha256, required=True
    )
    build_split.add_argument("--output-root", type=Path, required=True)

    verify_split = commands.add_parser(
        "verify-split",
        help="independently read one packaged replay split",
        allow_abbrev=False,
    )
    verify_split.add_argument("--benchmark-root", type=Path, required=True)
    verify_split.add_argument("--split", choices=("test", "train"), required=True)
    verify_split.add_argument("--replay-root", type=Path, required=True)
    verify_split.add_argument(
        "--expected-manifest-sha256", type=_sha256, required=True
    )
    verify_split.add_argument(
        "--expected-manifest-wire-sha256", type=_sha256, required=True
    )

    build_plan = commands.add_parser(
        "build-plan",
        help="bind both replay batches into a fixed final-gate plan",
        allow_abbrev=False,
    )
    build_plan.add_argument("--benchmark-root", type=Path, required=True)
    _add_replay_pin_arguments(build_plan, "test")
    _add_replay_pin_arguments(build_plan, "train")
    build_plan.add_argument(
        "--test-sealed-batch-manifest-sha256", type=_sha256, required=True
    )
    build_plan.add_argument(
        "--train-sealed-batch-manifest-sha256", type=_sha256, required=True
    )
    build_plan.add_argument("--test-key-id", required=True)
    build_plan.add_argument("--train-key-id", required=True)
    build_plan.add_argument("--runtime-image-id", type=_image_id, required=True)
    build_plan.add_argument("--output-root", type=Path, required=True)

    verify_plan = commands.add_parser(
        "verify-plan",
        help="independently read a plan and both replay batches",
        allow_abbrev=False,
    )
    verify_plan.add_argument("--benchmark-root", type=Path, required=True)
    verify_plan.add_argument("--test-replay-root", type=Path, required=True)
    verify_plan.add_argument("--train-replay-root", type=Path, required=True)
    verify_plan.add_argument("--plan-root", type=Path, required=True)
    verify_plan.add_argument(
        "--expected-plan-sha256", type=_sha256, required=True
    )
    verify_plan.add_argument(
        "--expected-plan-wire-sha256", type=_sha256, required=True
    )
    verify_plan.add_argument("--runtime-image-id", type=_image_id, required=True)
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
        raise ReplayBatchPlanError(
            "output_invalid", "summary did not normalize"
        ) from None


def _summary(
    operation: str,
    status: str,
    *,
    split: str | None = None,
    task_count: int | None = None,
    replay_manifest_sha256: str | None = None,
    replay_manifest_wire_sha256: str | None = None,
    authoring_index_sha256: str | None = None,
    authoring_index_wire_sha256: str | None = None,
    plan: FinalGatePlanV1 | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "cli_version": REPLAY_BATCH_PLAN_CLI_VERSION,
        "contract_version": 1,
        "kind": REPLAY_BATCH_PLAN_SUMMARY_KIND,
        "operation": operation,
        "status": status,
    }
    if split is not None:
        value.update(
            {
                "formal_replay_count": task_count,
                "authoring_index_sha256": authoring_index_sha256,
                "authoring_index_wire_sha256": authoring_index_wire_sha256,
                "replay_manifest_sha256": replay_manifest_sha256,
                "replay_manifest_wire_sha256": replay_manifest_wire_sha256,
                "split": split,
                "task_count": task_count,
            }
        )
    if plan is not None:
        value.update(
            {
                "execution_policy_sha256": plan.execution_policy_sha256,
                "execution_policy_wire_sha256": (
                    plan.execution_policy_wire_sha256
                ),
                "plan_sha256": plan.plan_sha256,
                "plan_wire_sha256": plan.wire_sha256,
                "test_replay_manifest_sha256": (
                    plan.test.replay_manifest_sha256
                ),
                "test_replay_manifest_wire_sha256": (
                    plan.test.replay_manifest_wire_sha256
                ),
                "test_task_count": plan.test.task_count,
                "total_task_count": plan.test.task_count + plan.train.task_count,
                "train_replay_manifest_sha256": (
                    plan.train.replay_manifest_sha256
                ),
                "train_replay_manifest_wire_sha256": (
                    plan.train.replay_manifest_wire_sha256
                ),
                "train_task_count": plan.train.task_count,
            }
        )
    return value


def _write_stdout(value: object) -> None:
    payload = _canonical_json_line(value)
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload)
        binary.flush()
    else:
        sys.stdout.write(payload.decode("utf-8", errors="strict"))
        sys.stdout.flush()


def _write_error(code: str) -> None:
    try:
        sys.stderr.write(f"error[{code}]: replay batch/plan operation failed\n")
        sys.stderr.flush()
    except BaseException:
        pass


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
        getattr(value, "st_ctime_ns", 0),
    )


def _binding_identity(value: os.stat_result) -> tuple[int, ...]:
    """Compare a named file with its handle across platform stat APIs."""

    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
    )


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        getattr(value, "st_mtime_ns", 0),
        getattr(value, "st_ctime_ns", 0),
    )


def _require_private_directory(path: Path) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError:
        raise ReplayBatchPlanError(
            "input_unavailable", "required directory is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or (os.name == "posix" and value.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise ReplayBatchPlanError(
            "unsafe_path", "required directory is unsafe"
        )
    return value


def _scan_exact_directory(
    path: Path, expected_names: frozenset[str]
) -> tuple[int, ...]:
    before = _require_private_directory(path)
    try:
        with os.scandir(path) as entries:
            names = frozenset(entry.name for entry in entries)
    except OSError:
        raise ReplayBatchPlanError(
            "input_unavailable", "directory could not be enumerated"
        ) from None
    after = _require_private_directory(path)
    if _directory_identity(before) != _directory_identity(after):
        raise ReplayBatchPlanError(
            "input_changed", "directory changed while it was read"
        )
    if names != expected_names:
        raise ReplayBatchPlanError(
            "layout_invalid", "directory membership is invalid"
        )
    return _directory_identity(after)


def _read_private_regular(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        before = os.lstat(path)
    except OSError:
        raise ReplayBatchPlanError(
            "input_unavailable", "required file is unavailable"
        ) from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum_bytes
        or (os.name == "posix" and before.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise ReplayBatchPlanError(
            "unsafe_path", "required file is unsafe or exceeds its limit"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReplayBatchPlanError(
            "input_unavailable", "required file could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        if _binding_identity(opened) != _binding_identity(before):
            raise ReplayBatchPlanError(
                "input_changed", "required file changed before opening"
            )
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor, min(64 * 1024, maximum_bytes + 1 - consumed)
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise ReplayBatchPlanError(
                    "limit_exceeded", "required file exceeds its limit"
                )
        finished = os.fstat(descriptor)
        if _identity(finished) != _identity(opened) or consumed != opened.st_size:
            raise ReplayBatchPlanError(
                "input_changed", "required file changed while it was read"
            )
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError:
        raise ReplayBatchPlanError(
            "input_changed", "required file changed after reading"
        ) from None
    if _identity(after) != _identity(before):
        raise ReplayBatchPlanError(
            "input_changed", "required file changed after reading"
        )
    return b"".join(chunks)


def _strict_json_object(payload: bytes) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if type(key) is not str or key in result:
                raise ValueError("duplicate or invalid JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")
            ),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise ReplayBatchPlanError(
            "authoring_index_rejected", "authoring index is invalid"
        ) from None
    if type(value) is not dict or _canonical_json_line(value) != payload:
        raise ReplayBatchPlanError(
            "authoring_index_rejected", "authoring index is not canonical"
        )
    return value


def _load_authoring_index(
    path: Path,
    *,
    expected_sha256: str,
    expected_wire_sha256: str,
    expected_tasks: tuple[tuple[str, str], ...],
) -> dict[str, tuple[str, str, str, str]]:
    payload = _read_private_regular(path, maximum_bytes=_AUTHORING_INDEX_MAX_BYTES)
    if hashlib.sha256(payload).hexdigest() != expected_wire_sha256:
        raise ReplayBatchPlanError(
            "authoring_index_rejected", "authoring index wire pin differs"
        )
    raw = _strict_json_object(payload)
    if frozenset(raw) != frozenset(
        {"contract_version", "index_sha256", "kind", "tasks"}
    ):
        raise ReplayBatchPlanError(
            "authoring_index_rejected", "authoring index fields are invalid"
        )
    tasks = raw["tasks"]
    if (
        raw["contract_version"] != 1
        or raw["kind"] != _AUTHORING_INDEX_KIND
        or type(raw["index_sha256"]) is not str
        or type(tasks) is not list
    ):
        raise ReplayBatchPlanError(
            "authoring_index_rejected", "authoring index header is invalid"
        )
    core = {
        "contract_version": raw["contract_version"],
        "kind": raw["kind"],
        "tasks": tasks,
    }
    semantic = hashlib.sha256(
        _AUTHORING_INDEX_DOMAIN + _canonical_json_line(core)[:-1]
    ).hexdigest()
    if raw["index_sha256"] != semantic or semantic != expected_sha256:
        raise ReplayBatchPlanError(
            "authoring_index_rejected", "authoring index semantic pin differs"
        )
    if len(tasks) != len(expected_tasks):
        raise ReplayBatchPlanError(
            "authoring_index_rejected", "authoring index task set is incomplete"
        )
    result: dict[str, tuple[str, str, str, str]] = {}
    observed_order: list[tuple[str, str]] = []
    required = frozenset(
        {
            "d2_sha256",
            "d2_wire_sha256",
            "d3_sha256",
            "d3_wire_sha256",
            "split",
            "task_id",
        }
    )
    for item in tasks:
        if type(item) is not dict or frozenset(item) != required:
            raise ReplayBatchPlanError(
                "authoring_index_rejected", "authoring index task is invalid"
            )
        split = item["split"]
        task_id = item["task_id"]
        digests = (
            item["d2_sha256"],
            item["d2_wire_sha256"],
            item["d3_sha256"],
            item["d3_wire_sha256"],
        )
        if (
            type(split) is not str
            or split not in {"test", "train"}
            or type(task_id) is not str
            or task_id in result
            or any(type(value) is not str or _SHA256_RE.fullmatch(value) is None for value in digests)
        ):
            raise ReplayBatchPlanError(
                "authoring_index_rejected", "authoring index binding is invalid"
            )
        observed_order.append((split, task_id))
        result[task_id] = digests
    if tuple(observed_order) != expected_tasks:
        raise ReplayBatchPlanError(
            "authoring_index_rejected", "authoring index task order differs"
        )
    return result


def _write_private_regular(path: Path, payload: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    failure: BaseException | None = None
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except BaseException as error:
        failure = error
    try:
        os.close(descriptor)
    except BaseException as error:
        if failure is None:
            failure = error
    if failure is not None:
        raise failure


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_noreplace(
    source: Path,
    destination: Path,
    *,
    source_dir_fd: int | None = None,
    destination_dir_fd: int | None = None,
) -> None:
    if os.name == "posix":
        try:
            renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except (AttributeError, OSError):
            renameat2 = None
        if renameat2 is None:
            raise OSError(errno.ENOTSUP, "atomic no-replace rename unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100 if source_dir_fd is None else source_dir_fd,
            os.fsencode(source),
            -100 if destination_dir_fd is None else destination_dir_fd,
            os.fsencode(destination),
            1,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(str(destination))
        raise OSError(error_number, "atomic no-replace publication failed")
    if source_dir_fd is not None or destination_dir_fd is not None:
        raise OSError(errno.ENOTSUP, "relative directory rename unavailable")
    try:
        os.lstat(destination)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(str(destination))
    os.rename(source, destination)


def _assert_no_overlap(
    new_root: Path, protected: tuple[tuple[Path, bool], ...]
) -> None:
    for path, is_directory in protected:
        if paths_overlap_v1(
            new_root,
            path,
            left_exists=False,
            right_directory=is_directory,
        ):
            raise ReplayBatchPlanError(
                "path_overlap", "output overlaps a trusted input"
            )


def _assert_existing_roots_disjoint(paths: tuple[Path, ...]) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if paths_overlap_v1(
                left, right, left_exists=True, right_directory=True
            ):
                raise ReplayBatchPlanError(
                    "path_overlap", "trusted input roots overlap"
                )


def _root_chain(path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    chain: list[Path] = []
    current = absolute
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    chain.reverse()
    return tuple(chain)


def _require_safe_directory(path: Path) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError:
        raise ReplayBatchPlanError(
            "input_unavailable", "required directory is unavailable"
        ) from None
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or _is_reparse(value):
        raise ReplayBatchPlanError("unsafe_path", "required directory is unsafe")
    return value


def _guard_parent_chain(path: Path) -> tuple[tuple[Path, tuple[int, int]], ...]:
    result: list[tuple[Path, tuple[int, int]]] = []
    chain = _root_chain(path)
    for index, component in enumerate(chain):
        value = (
            _require_private_directory(component)
            if index == len(chain) - 1
            else _require_safe_directory(component)
        )
        result.append((component, (value.st_dev, value.st_ino)))
    return tuple(result)


def _assert_parent_chain(
    guard: tuple[tuple[Path, tuple[int, int]], ...]
) -> None:
    for index, (component, expected) in enumerate(guard):
        value = (
            _require_private_directory(component)
            if index == len(guard) - 1
            else _require_safe_directory(component)
        )
        if (value.st_dev, value.st_ino) != expected:
            raise ReplayBatchPlanError(
                "output_parent_changed", "output parent chain changed"
            )


def _named_directory_identity(path: Path) -> tuple[int, int] | None:
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise ReplayBatchPlanError(
            "publication_uncertain", "publication identity is unavailable", committed=True
        ) from None
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or _is_reparse(value):
        return None
    return value.st_dev, value.st_ino


def _publish_directory(
    output_root: Path,
    *,
    populate: Callable[[Path], None],
    verify: Callable[[Path], object],
) -> object:
    try:
        output = Path(os.path.abspath(os.fspath(output_root)))
    except (OSError, TypeError, ValueError):
        raise ReplayBatchPlanError(
            "invalid_argument", "output root is invalid"
        ) from None
    parent = output.parent
    parent_guard = _guard_parent_chain(parent)
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError:
        raise ReplayBatchPlanError(
            "output_unavailable", "output root state is unavailable"
        ) from None
    else:
        raise ReplayBatchPlanError(
            "output_exists", "output root already exists"
        )
    staging = parent / f".{output.name}.replay-batch-plan-{uuid.uuid4().hex}"
    os.mkdir(staging, 0o700)
    if os.name == "posix":
        os.chmod(staging, 0o700)
    created = os.lstat(staging)
    if not stat.S_ISDIR(created.st_mode) or stat.S_ISLNK(created.st_mode) or _is_reparse(created):
        raise ReplayBatchPlanError("publication_failed", "staging is unsafe")
    staging_identity = (created.st_dev, created.st_ino)
    committed = False
    parent_descriptor: int | None = None
    staging_descriptor: int | None = None
    try:
        if os.name == "posix":
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            parent_descriptor = os.open(parent, directory_flags)
            opened_parent = os.fstat(parent_descriptor)
            if (opened_parent.st_dev, opened_parent.st_ino) != parent_guard[-1][1]:
                raise ReplayBatchPlanError(
                    "output_parent_changed", "output parent changed before opening"
                )
            staging_descriptor = os.open(
                staging.name, directory_flags, dir_fd=parent_descriptor
            )
            opened_staging = os.fstat(staging_descriptor)
            if (opened_staging.st_dev, opened_staging.st_ino) != staging_identity:
                raise ReplayBatchPlanError(
                    "output_staging_changed", "staging changed before opening"
                )
        populate(staging)
        before = verify(staging)
        _fsync_directory(staging)
        _assert_parent_chain(parent_guard)
        if _named_directory_identity(staging) != staging_identity:
            raise ReplayBatchPlanError(
                "output_staging_changed", "staging changed before publication"
            )
        try:
            if parent_descriptor is not None:
                _rename_directory_noreplace(
                    Path(staging.name),
                    Path(output.name),
                    source_dir_fd=parent_descriptor,
                    destination_dir_fd=parent_descriptor,
                )
            else:
                _rename_directory_noreplace(staging, output)
            committed = True
        except BaseException as error:
            try:
                _assert_parent_chain(parent_guard)
                staging_after = _named_directory_identity(staging)
                output_after = _named_directory_identity(output)
            except BaseException:
                raise ReplayBatchPlanError(
                    "publication_uncertain",
                    "publication state could not be classified",
                    committed=True,
                ) from None
            if staging_after == staging_identity and output_after != staging_identity:
                if isinstance(error, FileExistsError):
                    raise ReplayBatchPlanError(
                        "output_exists", "output root was created concurrently"
                    ) from None
                raise error
            if staging_after is None and output_after == staging_identity:
                committed = True
            else:
                raise ReplayBatchPlanError(
                    "publication_uncertain",
                    "publication state could not be classified",
                    committed=True,
                ) from None
        _fsync_directory(parent)
        _assert_parent_chain(parent_guard)
        if _named_directory_identity(output) != staging_identity:
            raise ReplayBatchPlanError(
                "publication_uncertain",
                "published output identity changed",
                committed=True,
            )
        after = verify(output)
        if after != before:
            raise ReplayBatchPlanError(
                "publication_uncertain",
                "published output changed during readback",
                committed=True,
            )
        _assert_parent_chain(parent_guard)
        if _named_directory_identity(output) != staging_identity:
            raise ReplayBatchPlanError(
                "publication_uncertain",
                "published output identity changed after readback",
                committed=True,
            )
        return after
    except ReplayBatchPlanError as error:
        if committed and not error.committed:
            raise ReplayBatchPlanError(
                "publication_uncertain",
                "published output could not be confirmed",
                committed=True,
            ) from None
        raise
    except BaseException:
        if committed:
            raise ReplayBatchPlanError(
                "publication_uncertain",
                "published output could not be confirmed",
                committed=True,
            ) from None
        raise
    finally:
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _public_tasks(
    benchmark_root: Path, split: Literal["test", "train"]
) -> tuple[object, ...]:
    try:
        tasks = load_answer_free_tasks(benchmark_root, split=split)
    except Exception:
        raise ReplayBatchPlanError(
            "benchmark_rejected", "public benchmark could not be verified"
        ) from None
    expected = _SPLIT_COUNTS[split]
    if (
        type(tasks) is not tuple
        or len(tasks) != expected
        or any(getattr(task, "split", None) != split for task in tasks)
    ):
        raise ReplayBatchPlanError(
            "benchmark_rejected", "public benchmark split is incomplete"
        )
    task_ids = tuple(getattr(task, "task_id", None) for task in tasks)
    if any(type(task_id) is not str for task_id in task_ids) or len(
        set(task_ids)
    ) != len(task_ids):
        raise ReplayBatchPlanError(
            "benchmark_rejected", "public benchmark task IDs are invalid"
        )
    return tasks


def _read_authoring_outputs(
    root: Path,
    tasks: tuple[object, ...],
    frozen: dict[str, tuple[str, str, str, str]],
) -> tuple[
    BatchReplayConfigManifestV1,
    tuple[tuple[bytes, bytes], ...],
]:
    task_ids = tuple(str(getattr(task, "task_id")) for task in tasks)
    root_identity = _scan_exact_directory(root, frozenset(task_ids))
    directory_identities: dict[Path, tuple[int, ...]] = {}
    wires: list[tuple[bytes, bytes]] = []
    bindings: list[TaskReplayConfigBindingV1] = []
    split = str(getattr(tasks[0], "split"))
    for task_id in task_ids:
        task_root = root / task_id
        directory_identities[task_root] = _scan_exact_directory(
            task_root,
            frozenset({BATCH_REPLAY_D2_FILENAME, BATCH_REPLAY_D3_FILENAME}),
        )
        d2_wire = _read_private_regular(
            task_root / BATCH_REPLAY_D2_FILENAME,
            maximum_bytes=REPLAY_CONFIG_MAX_BYTES,
        )
        d3_wire = _read_private_regular(
            task_root / BATCH_REPLAY_D3_FILENAME,
            maximum_bytes=REPLAY_CONFIG_MAX_BYTES,
        )
        try:
            d2 = OciReplayConfigV1.from_bytes(d2_wire)
            d3 = OciReplayConfigV1.from_bytes(d3_wire)
            if d2.task_id != task_id or d3.task_id != task_id:
                raise ReplayBatchPlanError(
                    "replay_binding_mismatch",
                    "authoring output binds a different task",
                )
            validate_formal_replay_pair_v1(d2, d3)
            binding = TaskReplayConfigBindingV1.from_configs(d2, d3)
        except ReplayBatchPlanError:
            raise
        except (OciWorkerEntryError, ReplayAuthoringError, BatchReplayConfigError):
            raise ReplayBatchPlanError(
                "formal_replay_rejected",
                "authoring output is not a formal replay pair",
            ) from None
        expected = frozen.get(task_id)
        observed = (
            d2.config_sha256,
            d2.wire_sha256,
            d3.config_sha256,
            d3.wire_sha256,
        )
        if expected is None or observed != expected:
            raise ReplayBatchPlanError(
                "authoring_binding_mismatch",
                "authoring output differs from the frozen index",
            )
        wires.append((d2_wire, d3_wire))
        bindings.append(binding)
    if _scan_exact_directory(root, frozenset(task_ids)) != root_identity:
        raise ReplayBatchPlanError(
            "input_changed", "authoring output root changed while it was read"
        )
    for task_root, expected_identity in directory_identities.items():
        if (
            _scan_exact_directory(
                task_root,
                frozenset(
                    {BATCH_REPLAY_D2_FILENAME, BATCH_REPLAY_D3_FILENAME}
                ),
            )
            != expected_identity
        ):
            raise ReplayBatchPlanError(
                "input_changed", "authoring task output changed while it was read"
            )
    try:
        manifest = BatchReplayConfigManifestV1(
            split=split,
            tasks=tuple(bindings),
        )
    except BatchReplayConfigError:
        raise ReplayBatchPlanError(
            "formal_replay_rejected", "replay manifest could not be constructed"
        ) from None
    return manifest, tuple(wires)


def _load_replay_split(
    benchmark_root: Path,
    replay_root: Path,
    *,
    split: Literal["test", "train"],
    expected_manifest_sha256: str,
    expected_manifest_wire_sha256: str,
) -> tuple[tuple[OciReplayConfigV1, OciReplayConfigV1], ...]:
    tasks = _public_tasks(benchmark_root, split)
    task_ids = tuple(str(getattr(task, "task_id")) for task in tasks)
    try:
        pairs = load_batch_replay_configs_v1(
            replay_root,
            expected_manifest_sha256=expected_manifest_sha256,
            expected_manifest_wire_sha256=expected_manifest_wire_sha256,
            expected_split=split,
            expected_task_ids=task_ids,
        )
        for d2, d3 in pairs:
            validate_formal_replay_pair_v1(d2, d3)
    except (BatchReplayConfigError, ReplayAuthoringError):
        raise ReplayBatchPlanError(
            "formal_replay_rejected", "replay batch did not verify"
        ) from None
    return pairs


def _build_split(args: argparse.Namespace) -> dict[str, object]:
    split: Literal["test", "train"] = args.split
    tasks = _public_tasks(args.benchmark_root, split)
    test_tasks = tasks if split == "test" else _public_tasks(args.benchmark_root, "test")
    train_tasks = tasks if split == "train" else _public_tasks(args.benchmark_root, "train")
    expected_index_tasks = tuple(
        (expected_split, str(getattr(task, "task_id")))
        for expected_split, expected_split_tasks in (
            ("test", test_tasks),
            ("train", train_tasks),
        )
        for task in expected_split_tasks
    )
    frozen = _load_authoring_index(
        args.authoring_index_file,
        expected_sha256=args.expected_authoring_index_sha256,
        expected_wire_sha256=args.expected_authoring_index_wire_sha256,
        expected_tasks=expected_index_tasks,
    )
    _assert_existing_roots_disjoint(
        (args.benchmark_root, args.authoring_output_root)
    )
    _assert_no_overlap(
        args.output_root,
        (
            (args.benchmark_root, True),
            (args.authoring_output_root, True),
            (args.authoring_index_file, False),
        ),
    )
    manifest, wires = _read_authoring_outputs(
        args.authoring_output_root, tasks, frozen
    )
    task_ids = tuple(str(getattr(task, "task_id")) for task in tasks)

    def populate(staging: Path) -> None:
        configs = staging / BATCH_REPLAY_CONFIG_DIRECTORY
        os.mkdir(configs, 0o700)
        if os.name == "posix":
            os.chmod(configs, 0o700)
        _write_private_regular(
            staging / BATCH_REPLAY_CONFIG_MANIFEST_FILENAME,
            manifest.to_bytes(),
        )
        for task_id, (d2_wire, d3_wire) in zip(task_ids, wires, strict=True):
            task_root = configs / task_id
            os.mkdir(task_root, 0o700)
            if os.name == "posix":
                os.chmod(task_root, 0o700)
            _write_private_regular(
                task_root / BATCH_REPLAY_D2_FILENAME, d2_wire
            )
            _write_private_regular(
                task_root / BATCH_REPLAY_D3_FILENAME, d3_wire
            )
            _fsync_directory(task_root)
        _fsync_directory(configs)

    def verify(root: Path) -> tuple[tuple[str, str], ...]:
        pairs = _load_replay_split(
            args.benchmark_root,
            root,
            split=split,
            expected_manifest_sha256=manifest.manifest_sha256,
            expected_manifest_wire_sha256=manifest.wire_sha256,
        )
        return tuple((d2.config_sha256, d3.config_sha256) for d2, d3 in pairs)

    _publish_directory(args.output_root, populate=populate, verify=verify)
    return _summary(
        "build-split",
        "published",
        split=split,
        task_count=len(task_ids),
        replay_manifest_sha256=manifest.manifest_sha256,
        replay_manifest_wire_sha256=manifest.wire_sha256,
        authoring_index_sha256=args.expected_authoring_index_sha256,
        authoring_index_wire_sha256=args.expected_authoring_index_wire_sha256,
    )


def _verify_split(args: argparse.Namespace) -> dict[str, object]:
    split: Literal["test", "train"] = args.split
    _assert_existing_roots_disjoint(
        (args.benchmark_root, args.replay_root)
    )
    pairs = _load_replay_split(
        args.benchmark_root,
        args.replay_root,
        split=split,
        expected_manifest_sha256=args.expected_manifest_sha256,
        expected_manifest_wire_sha256=args.expected_manifest_wire_sha256,
    )
    return _summary(
        "verify-split",
        "verified",
        split=split,
        task_count=len(pairs),
        replay_manifest_sha256=args.expected_manifest_sha256,
        replay_manifest_wire_sha256=args.expected_manifest_wire_sha256,
    )


def _plan_from_args(args: argparse.Namespace) -> FinalGatePlanV1:
    if args.test_key_id == args.train_key_id:
        raise ReplayBatchPlanError(
            "key_identity_reused", "test and train key IDs must differ"
        )
    _assert_existing_roots_disjoint(
        (
            args.benchmark_root,
            args.test_replay_root,
            args.train_replay_root,
        )
    )
    _load_replay_split(
        args.benchmark_root,
        args.test_replay_root,
        split="test",
        expected_manifest_sha256=args.test_replay_manifest_sha256,
        expected_manifest_wire_sha256=(
            args.test_replay_manifest_wire_sha256
        ),
    )
    _load_replay_split(
        args.benchmark_root,
        args.train_replay_root,
        split="train",
        expected_manifest_sha256=args.train_replay_manifest_sha256,
        expected_manifest_wire_sha256=(
            args.train_replay_manifest_wire_sha256
        ),
    )
    try:
        policy = fixed_e4_execution_policy_v1(args.runtime_image_id)
        test = FinalGateSplitPlanV1(
            split="test",
            task_count=PROFILE_TEST_TASKS,
            sealed_batch_manifest_sha256=(
                args.test_sealed_batch_manifest_sha256
            ),
            replay_manifest_sha256=args.test_replay_manifest_sha256,
            replay_manifest_wire_sha256=(
                args.test_replay_manifest_wire_sha256
            ),
            snapshot_key_id=args.test_key_id,
        )
        train = FinalGateSplitPlanV1(
            split="train",
            task_count=PROFILE_TRAIN_TASKS,
            sealed_batch_manifest_sha256=(
                args.train_sealed_batch_manifest_sha256
            ),
            replay_manifest_sha256=args.train_replay_manifest_sha256,
            replay_manifest_wire_sha256=(
                args.train_replay_manifest_wire_sha256
            ),
            snapshot_key_id=args.train_key_id,
        )
        return FinalGatePlanV1(
            execution_policy_sha256=policy.policy_sha256,
            execution_policy_wire_sha256=policy.wire_sha256,
            test=test,
            train=train,
        )
    except (E4DriverError, FinalGateContractError):
        raise ReplayBatchPlanError(
            "plan_rejected", "final-gate plan could not be constructed"
        ) from None


def _read_plan_root(
    root: Path,
    *,
    expected_plan_sha256: str,
    expected_plan_wire_sha256: str,
) -> FinalGatePlanV1:
    identity = _scan_exact_directory(
        root, frozenset({FINAL_GATE_PLAN_FILENAME})
    )
    payload = _read_private_regular(
        root / FINAL_GATE_PLAN_FILENAME,
        maximum_bytes=FINAL_GATE_MAX_WIRE_BYTES,
    )
    try:
        plan = FinalGatePlanV1.from_bytes(
            payload,
            expected_plan_sha256=expected_plan_sha256,
            expected_wire_sha256=expected_plan_wire_sha256,
        )
    except FinalGateContractError:
        raise ReplayBatchPlanError(
            "plan_rejected", "final-gate plan did not verify"
        ) from None
    if (
        _scan_exact_directory(root, frozenset({FINAL_GATE_PLAN_FILENAME}))
        != identity
    ):
        raise ReplayBatchPlanError(
            "input_changed", "final-gate plan root changed while it was read"
        )
    return plan


def _build_plan(args: argparse.Namespace) -> dict[str, object]:
    _assert_no_overlap(
        args.output_root,
        (
            (args.benchmark_root, True),
            (args.test_replay_root, True),
            (args.train_replay_root, True),
        ),
    )
    plan = _plan_from_args(args)
    payload = plan.to_bytes()

    def populate(staging: Path) -> None:
        _write_private_regular(staging / FINAL_GATE_PLAN_FILENAME, payload)

    def verify(root: Path) -> tuple[str, str]:
        parsed = _read_plan_root(
            root,
            expected_plan_sha256=plan.plan_sha256,
            expected_plan_wire_sha256=plan.wire_sha256,
        )
        if parsed != plan:
            raise ReplayBatchPlanError(
                "publication_mismatch", "published plan differs from its input"
            )
        return parsed.plan_sha256, parsed.wire_sha256

    _publish_directory(args.output_root, populate=populate, verify=verify)
    return _summary("build-plan", "published", plan=plan)


def _verify_plan(args: argparse.Namespace) -> dict[str, object]:
    _assert_existing_roots_disjoint(
        (
            args.benchmark_root,
            args.test_replay_root,
            args.train_replay_root,
            args.plan_root,
        )
    )
    plan = _read_plan_root(
        args.plan_root,
        expected_plan_sha256=args.expected_plan_sha256,
        expected_plan_wire_sha256=args.expected_plan_wire_sha256,
    )
    if plan.test.snapshot_key_id == plan.train.snapshot_key_id:
        raise ReplayBatchPlanError(
            "key_identity_reused", "test and train key IDs must differ"
        )
    try:
        policy = fixed_e4_execution_policy_v1(args.runtime_image_id)
    except E4DriverError:
        raise ReplayBatchPlanError(
            "plan_rejected", "runtime image ID is invalid"
        ) from None
    if (
        plan.execution_policy_sha256 != policy.policy_sha256
        or plan.execution_policy_wire_sha256 != policy.wire_sha256
    ):
        raise ReplayBatchPlanError(
            "policy_mismatch", "runtime policy differs from the plan"
        )
    _load_replay_split(
        args.benchmark_root,
        args.test_replay_root,
        split="test",
        expected_manifest_sha256=plan.test.replay_manifest_sha256,
        expected_manifest_wire_sha256=plan.test.replay_manifest_wire_sha256,
    )
    _load_replay_split(
        args.benchmark_root,
        args.train_replay_root,
        split="train",
        expected_manifest_sha256=plan.train.replay_manifest_sha256,
        expected_manifest_wire_sha256=plan.train.replay_manifest_wire_sha256,
    )
    return _summary("verify-plan", "verified", plan=plan)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build-split":
            result = _build_split(args)
        elif args.command == "verify-split":
            result = _verify_split(args)
        elif args.command == "build-plan":
            result = _build_plan(args)
        elif args.command == "verify-plan":
            result = _verify_plan(args)
        else:
            raise ReplayBatchPlanError(
                "invalid_argument", "command is invalid"
            )
        _write_stdout(result)
        return EXIT_SUCCESS
    except KeyboardInterrupt:
        _write_error("interrupted")
        return EXIT_INTERRUPTED
    except ReplayBatchPlanError as error:
        _write_error(error.code)
        return EXIT_COMMITTED_UNCERTAIN if error.committed else EXIT_REJECTED
    except (
        BatchReplayConfigError,
        E4DriverError,
        FinalGateContractError,
        OciWorkerEntryError,
        ReplayAuthoringError,
        TrustedInputError,
        OSError,
        TypeError,
        ValueError,
    ):
        _write_error("input_rejected")
        return EXIT_REJECTED
    except Exception:
        _write_error("internal_error")
        return EXIT_REJECTED
    except BaseException:
        _write_error("interrupted")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXIT_COMMITTED_UNCERTAIN",
    "EXIT_INTERRUPTED",
    "EXIT_REJECTED",
    "EXIT_SUCCESS",
    "REPLAY_BATCH_PLAN_CLI_VERSION",
    "REPLAY_BATCH_PLAN_SUMMARY_KIND",
    "ReplayBatchPlanError",
    "main",
]
