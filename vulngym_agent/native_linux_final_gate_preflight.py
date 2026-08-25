"""Fail-closed readiness checks for the native-Linux E4 final gate.

This module deliberately does not start Docker, create containers, build or
pull images, or publish benchmark output.  It first closes the trusted static
inputs in blind-test-first order and only then performs bounded, read-only
Docker observations.  Host and daemon exclusivity cannot be inferred from a
process snapshot; the final check therefore verifies a separately pinned,
fully bound operator assertion instead of claiming that automation proved it.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import shutil
import stat
import sys
import tempfile
from typing import Any, Final, Literal

from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.benchmark.harness import (
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
    load_answer_free_tasks,
)
from vulngym_agent.benchmark.sealed_snapshot import DEFAULT_SNAPSHOT_POLICY
from vulngym_agent.evaluator.batch_configs import load_batch_replay_configs_v1
from vulngym_agent.evaluator.bounded_process import (
    BoundedProcessError,
    run_bounded_process_v1,
)
from vulngym_agent.evaluator.contracts import (
    DiscoveryBatchExecutionPlanV2,
    ExecutionPolicyBindingV1,
)
from vulngym_agent.evaluator.e4_driver import fixed_e4_execution_policy_v1
from vulngym_agent.evaluator.final_gate import (
    FINAL_GATE_MAX_WIRE_BYTES,
    FinalGatePlanV1,
    FinalGateSplitPlanV1,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    OciReplayConfigV1,
    REPLAY_BACKEND_ID,
    REPLAY_MODEL_ID,
)
from vulngym_agent.evaluator.runtime_evidence import (
    RuntimeBindingPinsV1,
    RuntimeEvidenceError,
    docker_endpoint_sha256_v1,
    docker_info_identity_sha256_v1 as _runtime_docker_info_identity_sha256_v1,
    docker_socket_identity_sha256_v1,
)
from vulngym_agent.evaluator.replay_authoring import (
    ReplayAuthoringError,
    validate_formal_replay_pair_v1,
)
from vulngym_agent.evaluator.supervisor import (
    DiscoveryExecutionSession,
    prepare_discovery_execution_plan_v1,
)
from vulngym_agent.trusted_inputs import (
    read_attestation_key_file_v1,
    zero_secret_buffer_v1,
)
from vulngym_agent.linux_host_security import (
    DockerSocketGuardV1,
    LinuxDirectoryGuardV1,
    LinuxHostSecurityError,
    LinuxMountTableV1,
    assert_docker_socket_guard_stable_v1,
    assert_linux_mount_table_stable_v1,
    assert_root_owned_directory_guard_stable_v1,
    bind_docker_socket_guard_v1,
    bind_root_owned_directory_chain_v1,
    capture_linux_mount_table_v1,
    linux_paths_overlap_v1,
)


NATIVE_LINUX_FINAL_GATE_PREFLIGHT_VERSION: Final[str] = (
    "native-linux-final-gate-preflight-v2"
)
READINESS_REPORT_KIND: Final[str] = (
    "vulngym.native-linux-final-gate-readiness-report.v2"
)
OPERATOR_ASSERTION_KIND: Final[str] = (
    "vulngym.native-linux-final-gate-operator-assertion.v2"
)
READINESS_REPORT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym native Linux final gate readiness report v2\0"
)
HOST_IDENTITY_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym native Linux host identity v1\0"
)
FILESYSTEM_IDENTITY_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym native Linux filesystem identity v1\0"
)

MIN_HOST_CPUS: Final[int] = 8
MIN_DAEMON_CPUS: Final[int] = 8
MIN_TOTAL_RAM_BYTES: Final[int] = 16 * 1024 * 1024 * 1024
MIN_AVAILABLE_RAM_BYTES: Final[int] = 6 * 1024 * 1024 * 1024
MIN_OUTPUT_FREE_BYTES: Final[int] = 100 * 1024 * 1024 * 1024
MIN_DOCKER_FREE_BYTES: Final[int] = 64 * 1024 * 1024 * 1024
MIN_SCRATCH_FREE_BYTES: Final[int] = 32 * 1024 * 1024 * 1024
MIN_UNIQUE_STORAGE_FREE_BYTES: Final[int] = 200 * 1024 * 1024 * 1024
MIN_OUTPUT_FREE_INODES: Final[int] = 100_000

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"sha256:[0-9a-f]{64}\Z"
)
_UNIX_ENDPOINT_RE: Final[re.Pattern[str]] = re.compile(
    r"unix:///[A-Za-z0-9_@+./-]{1,240}\Z"
)
_SAFE_LOCAL_FILESYSTEMS: Final[frozenset[str]] = frozenset(
    {"ext4", "xfs", "btrfs", "zfs"}
)
_CHECK_NAMES: Final[tuple[str, ...]] = (
    "argument_contracts",
    "native_linux_host",
    "path_and_permission_contracts",
    "final_gate_plan",
    "static_test_inputs",
    "static_train_inputs",
    "host_resources",
    "docker_cli",
    "docker_local_socket",
    "docker_daemon_identity",
    "docker_isolation_capabilities",
    "runtime_image_identity",
    "daemon_cleanliness",
    "operator_external_isolation_assertion",
)
_ASSERTION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "contract_version",
        "kind",
        "daemon_endpoint_sha256",
        "daemon_info_sha256",
        "docker_executable_sha256",
        "docker_socket_identity_sha256",
        "exclusive_docker_daemon",
        "exclusive_native_linux_host",
        "final_gate_plan_sha256",
        "final_gate_plan_wire_sha256",
        "host_egress_disabled_for_gate",
        "host_identity_sha256",
        "no_concurrent_docker_clients",
        "runtime_image_id",
        "runtime_image_inspect_sha256",
        "scoring_gold_physically_isolated",
        "server_observation_sha256",
    }
)
_ASSERTION_TRUE_FIELDS: Final[tuple[str, ...]] = (
    "exclusive_docker_daemon",
    "exclusive_native_linux_host",
    "host_egress_disabled_for_gate",
    "no_concurrent_docker_clients",
    "scoring_gold_physically_isolated",
)
_READINESS_ROOT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "bindings",
        "capacities",
        "checks",
        "contract_version",
        "inputs",
        "kind",
        "preflight_version",
        "report_sha256",
        "status",
    }
)
_READINESS_BINDING_KEYS: Final[frozenset[str]] = frozenset(
    {
        "daemon_endpoint_sha256",
        "daemon_info_sha256",
        "docker_executable_sha256",
        "docker_socket_identity_sha256",
        "execution_policy_sha256",
        "execution_policy_wire_sha256",
        "final_gate_plan_sha256",
        "final_gate_plan_wire_sha256",
        "host_identity_sha256",
        "kernel_release_sha256",
        "operator_assertion_wire_sha256",
        "runtime_image_id",
        "runtime_image_inspect_sha256",
        "server_observation_sha256",
    }
)
_KNOWN_CONTAINER_MARKERS: Final[tuple[Path, ...]] = (
    Path("/.dockerenv"),
    Path("/run/.containerenv"),
)
_KNOWN_CGROUP_CONTAINER_TOKENS: Final[tuple[bytes, ...]] = (
    b"/docker/",
    b"/kubepods/",
    b"/containerd/",
    b"/libpod/",
    b"/lxc/",
)


class NativeLinuxFinalGatePreflightError(RuntimeError):
    """Stable, path-free preflight rejection."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "preflight_failed"
        super().__init__(message)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise NativeLinuxFinalGatePreflightError(
            "invalid_cli", "native Linux final-gate arguments were rejected"
        )


@dataclass(frozen=True, slots=True)
class _ValidatedPaths:
    benchmark_root: Path
    control_root: Path
    implementation_root: Path
    scratch_root: Path
    output_root: Path
    output_parent: Path
    docker_executable: Path
    plan_file: Path
    test_sealed_batch_root: Path
    test_replay_config_root: Path
    train_sealed_batch_root: Path
    train_replay_config_root: Path
    test_key_file: Path
    train_key_file: Path
    operator_assertion_file: Path | None
    mount_table: LinuxMountTableV1 | None = None


@dataclass(frozen=True, slots=True)
class _DockerDaemonObservation:
    server_sha256: str
    info_sha256: str
    server: dict[str, Any]
    info: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _FilesystemCapacity:
    role: str
    root: Path
    filesystem_type: str
    free_bytes: int
    free_inodes: int
    identity: tuple[int, int]

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(
            FILESYSTEM_IDENTITY_DIGEST_DOMAIN
            + _canonical_json(
                {"device": self.identity[0], "filesystem_id": self.identity[1]}
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class NativeLinuxFinalGateReadinessV2:
    """Double-pinned, ready-only runtime closure consumed by final-gate CLI."""

    runtime_binding: RuntimeBindingPinsV1
    final_gate_plan_sha256: str
    final_gate_plan_wire_sha256: str
    execution_policy_sha256: str
    execution_policy_wire_sha256: str
    report_sha256: str
    wire_sha256: str


READINESS_REPORT_MAX_BYTES: Final[int] = 4 * 1024 * 1024


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise NativeLinuxFinalGatePreflightError(
            "report_invalid", "readiness data did not normalize"
        ) from None


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_json_shape(
    value: object, *, depth: int = 0, counter: list[int] | None = None
) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > 100_000 or depth > 32:
        raise ValueError("JSON structure exceeds its limit")
    if value is None or type(value) in {bool, int, str}:
        return
    if type(value) is list:
        for item in value:
            _validate_json_shape(item, depth=depth + 1, counter=counter)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON key is not a string")
            _validate_json_shape(item, depth=depth + 1, counter=counter)
        return
    raise ValueError("unsupported JSON value")


def _parse_json_document(payload: bytes, *, maximum_bytes: int) -> object:
    if type(payload) is not bytes or not payload or len(payload) > maximum_bytes:
        raise NativeLinuxFinalGatePreflightError(
            "docker_response_invalid", "Docker returned an invalid response size"
        )
    try:
        text = payload.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_json_shape(value)
    except (RecursionError, UnicodeError, ValueError):
        raise NativeLinuxFinalGatePreflightError(
            "docker_response_invalid", "Docker returned invalid JSON"
        ) from None
    return value


def docker_info_identity_sha256_v1(value: object) -> str:
    """Digest the stable daemon/cgroup/runtime subset of ``docker info``."""
    try:
        return _runtime_docker_info_identity_sha256_v1(value)
    except RuntimeEvidenceError:
        raise NativeLinuxFinalGatePreflightError(
            "docker_identity_invalid", "Docker info identity is invalid"
        ) from None


def docker_server_identity_sha256_v1(value: object) -> str:
    """Digest the exact normalized ``docker version .Server`` object."""

    if (
        type(value) is not dict
        or any(
            type(value.get(name)) is not str or not value[name]
            for name in ("Version", "ApiVersion", "Os", "Arch")
        )
        or value.get("Os") != "linux"
        or value.get("Arch") != "amd64"
    ):
        raise NativeLinuxFinalGatePreflightError(
            "docker_identity_invalid", "Docker server identity is invalid"
        )
    try:
        _validate_json_shape(value)
    except ValueError:
        raise NativeLinuxFinalGatePreflightError(
            "docker_identity_invalid", "Docker server identity is invalid"
        ) from None
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def runtime_image_inspect_sha256_v1(value: object) -> str:
    """Digest one exact normalized Docker image-inspect object."""

    if type(value) is not dict:
        raise NativeLinuxFinalGatePreflightError(
            "runtime_image_invalid", "runtime image identity is invalid"
        )
    try:
        _validate_json_shape(value)
    except ValueError:
        raise NativeLinuxFinalGatePreflightError(
            "runtime_image_invalid", "runtime image identity is invalid"
        ) from None
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise NativeLinuxFinalGatePreflightError(
            "invalid_argument", f"{name} is not lower-case SHA-256"
        )
    return value


def _require_image_id(value: object) -> str:
    if type(value) is not str or _IMAGE_ID_RE.fullmatch(value) is None:
        raise NativeLinuxFinalGatePreflightError(
            "invalid_argument", "runtime image ID is invalid"
        )
    return value


def _check_record(
    name: str, status: Literal["ready", "not_ready", "not_checked"], code: str
) -> dict[str, str]:
    return {"code": code, "name": name, "status": status}


def _initial_checks() -> list[dict[str, str]]:
    return [_check_record(name, "not_checked", "not_checked") for name in _CHECK_NAMES]


def _set_check(
    checks: list[dict[str, str]],
    name: str,
    status: Literal["ready", "not_ready"],
    code: str,
) -> None:
    index = _CHECK_NAMES.index(name)
    checks[index] = _check_record(name, status, code)


def _report_bytes(
    *,
    checks: list[dict[str, str]],
    bindings: dict[str, object],
    capacities: dict[str, object],
    inputs: dict[str, object],
) -> bytes:
    ready = all(item["status"] == "ready" for item in checks)
    core: dict[str, object] = {
        "bindings": bindings,
        "capacities": capacities,
        "checks": checks,
        "contract_version": 2,
        "inputs": inputs,
        "kind": READINESS_REPORT_KIND,
        "preflight_version": NATIVE_LINUX_FINAL_GATE_PREFLIGHT_VERSION,
        "status": "ready" if ready else "not_ready",
    }
    digest = hashlib.sha256(
        READINESS_REPORT_DIGEST_DOMAIN + _canonical_json(core)
    ).hexdigest()
    return _canonical_json({**core, "report_sha256": digest}) + b"\n"


def _minimal_failure_report(code: str) -> bytes:
    checks = _initial_checks()
    _set_check(checks, "argument_contracts", "not_ready", code)
    return _report_bytes(checks=checks, bindings={}, capacities={}, inputs={})


def parse_native_linux_final_gate_readiness_v2(
    payload: bytes,
    *,
    expected_report_sha256: str,
    expected_wire_sha256: str,
) -> NativeLinuxFinalGateReadinessV2:
    """Parse one canonical, ready-only report under semantic and wire pins."""

    _require_sha256(expected_report_sha256, name="expected_report_sha256")
    _require_sha256(expected_wire_sha256, name="expected_wire_sha256")
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > READINESS_REPORT_MAX_BYTES
        or hashlib.sha256(payload).hexdigest() != expected_wire_sha256
        or not payload.endswith(b"\n")
        or payload.count(b"\n") != 1
    ):
        raise NativeLinuxFinalGatePreflightError(
            "readiness_wire_mismatch", "readiness wire did not match its exact pin"
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_json_shape(value)
    except (RecursionError, UnicodeError, ValueError):
        raise NativeLinuxFinalGatePreflightError(
            "readiness_invalid", "readiness report is not strict canonical JSON"
        ) from None
    if (
        type(value) is not dict
        or frozenset(value) != _READINESS_ROOT_KEYS
        or _canonical_json(value) + b"\n" != payload
        or value.get("contract_version") != 2
        or value.get("kind") != READINESS_REPORT_KIND
        or value.get("preflight_version") != NATIVE_LINUX_FINAL_GATE_PREFLIGHT_VERSION
        or value.get("status") != "ready"
        or type(value.get("bindings")) is not dict
        or frozenset(value["bindings"]) != _READINESS_BINDING_KEYS
        or type(value.get("capacities")) is not dict
        or type(value.get("inputs")) is not dict
        or frozenset(value["inputs"]) != frozenset({"test", "train"})
        or type(value.get("checks")) is not list
        or len(value["checks"]) != len(_CHECK_NAMES)
    ):
        raise NativeLinuxFinalGatePreflightError(
            "readiness_invalid", "readiness report contract did not close"
        )
    for expected_name, check in zip(_CHECK_NAMES, value["checks"], strict=True):
        if (
            type(check) is not dict
            or frozenset(check) != frozenset({"code", "name", "status"})
            or check.get("name") != expected_name
            or check.get("status") != "ready"
            or type(check.get("code")) is not str
            or not check["code"]
        ):
            raise NativeLinuxFinalGatePreflightError(
                "readiness_not_ready", "readiness checks did not all close"
            )
    embedded = _require_sha256(value.get("report_sha256"), name="report_sha256")
    core = {name: item for name, item in value.items() if name != "report_sha256"}
    calculated = hashlib.sha256(
        READINESS_REPORT_DIGEST_DOMAIN + _canonical_json(core)
    ).hexdigest()
    if embedded != calculated or embedded != expected_report_sha256:
        raise NativeLinuxFinalGatePreflightError(
            "readiness_digest_mismatch", "readiness semantic digest did not match"
        )
    bindings = value["bindings"]
    try:
        runtime_binding = RuntimeBindingPinsV1(
            daemon_endpoint_sha256=bindings["daemon_endpoint_sha256"],
            docker_executable_sha256=bindings["docker_executable_sha256"],
            docker_socket_identity_sha256=bindings[
                "docker_socket_identity_sha256"
            ],
            server_observation_sha256=bindings["server_observation_sha256"],
            daemon_info_sha256=bindings["daemon_info_sha256"],
            runtime_image_id=bindings["runtime_image_id"],
            runtime_image_inspect_sha256=bindings[
                "runtime_image_inspect_sha256"
            ],
        )
        plan_sha256 = _require_sha256(
            bindings["final_gate_plan_sha256"], name="final_gate_plan_sha256"
        )
        plan_wire_sha256 = _require_sha256(
            bindings["final_gate_plan_wire_sha256"],
            name="final_gate_plan_wire_sha256",
        )
        policy_sha256 = _require_sha256(
            bindings["execution_policy_sha256"], name="execution_policy_sha256"
        )
        policy_wire_sha256 = _require_sha256(
            bindings["execution_policy_wire_sha256"],
            name="execution_policy_wire_sha256",
        )
    except (KeyError, RuntimeEvidenceError):
        raise NativeLinuxFinalGatePreflightError(
            "readiness_invalid", "readiness runtime binding is invalid"
        ) from None
    return NativeLinuxFinalGateReadinessV2(
        runtime_binding=runtime_binding,
        final_gate_plan_sha256=plan_sha256,
        final_gate_plan_wire_sha256=plan_wire_sha256,
        execution_policy_sha256=policy_sha256,
        execution_policy_wire_sha256=policy_wire_sha256,
        report_sha256=embedded,
        wire_sha256=expected_wire_sha256,
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.native_linux_final_gate_preflight",
        description="Read-only readiness gate for one fixed native-Linux 20+50 run.",
        allow_abbrev=False,
    )
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--implementation-root", type=Path, required=True)
    parser.add_argument("--scratch-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--docker-executable", type=Path, required=True)
    parser.add_argument("--docker-host", required=True)
    parser.add_argument("--runtime-image-id", required=True)
    parser.add_argument("--expected-docker-cli-sha256", required=True)
    parser.add_argument("--expected-docker-server-sha256", required=True)
    parser.add_argument("--expected-docker-info-sha256", required=True)
    parser.add_argument(
        "--expected-runtime-image-inspect-sha256", required=True
    )
    parser.add_argument("--plan-file", type=Path, required=True)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--expected-plan-wire-sha256", required=True)
    parser.add_argument("--test-sealed-batch-root", type=Path, required=True)
    parser.add_argument("--test-replay-config-root", type=Path, required=True)
    parser.add_argument("--train-sealed-batch-root", type=Path, required=True)
    parser.add_argument("--train-replay-config-root", type=Path, required=True)
    parser.add_argument("--test-key-file", type=Path, required=True)
    parser.add_argument("--train-key-file", type=Path, required=True)
    parser.add_argument("--operator-assertion-file", type=Path)
    parser.add_argument("--expected-operator-assertion-wire-sha256")
    return parser


def _validate_argument_shapes(args: argparse.Namespace) -> None:
    for name in (
        "expected_docker_cli_sha256",
        "expected_docker_server_sha256",
        "expected_docker_info_sha256",
        "expected_runtime_image_inspect_sha256",
        "expected_plan_sha256",
        "expected_plan_wire_sha256",
    ):
        _require_sha256(getattr(args, name), name=name)
    _require_image_id(args.runtime_image_id)
    if (
        type(args.docker_host) is not str
        or _UNIX_ENDPOINT_RE.fullmatch(args.docker_host) is None
    ):
        raise NativeLinuxFinalGatePreflightError(
            "invalid_argument", "Docker host must be one canonical local Unix socket"
        )
    socket_path = args.docker_host[len("unix://") :]
    if (
        not socket_path.startswith("/")
        or posixpath.normpath(socket_path) != socket_path
        or any(part in {"", ".", ".."} for part in socket_path.split("/")[1:])
    ):
        raise NativeLinuxFinalGatePreflightError(
            "invalid_argument", "Docker host must be one canonical local Unix socket"
        )
    assertion_pair = (
        args.operator_assertion_file is not None,
        args.expected_operator_assertion_wire_sha256 is not None,
    )
    if assertion_pair[0] != assertion_pair[1]:
        raise NativeLinuxFinalGatePreflightError(
            "invalid_argument", "operator assertion path and pin must be supplied together"
        )
    if assertion_pair[1]:
        _require_sha256(
            args.expected_operator_assertion_wire_sha256,
            name="expected_operator_assertion_wire_sha256",
        )


def _stable_regular_bytes(
    path: Path, *, maximum_bytes: int, private: bool
) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "input_unavailable", "trusted regular input is unavailable"
        ) from error
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum_bytes
        or before.st_uid not in {0, os.geteuid()}
        or mode & 0o022
        or (private and mode & 0o077)
    ):
        raise NativeLinuxFinalGatePreflightError(
            "unsafe_permissions", "trusted regular input permissions are unsafe"
        )
    expected = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "input_unavailable", "trusted regular input could not be opened"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            != expected
        ):
            raise NativeLinuxFinalGatePreflightError(
                "input_changed", "trusted regular input changed while opening"
            )
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise NativeLinuxFinalGatePreflightError(
                    "input_limit_exceeded", "trusted regular input exceeds its limit"
                )
        finished = os.fstat(descriptor)
        if consumed != expected[2] or (
            finished.st_dev,
            finished.st_ino,
            finished.st_size,
            finished.st_mtime_ns,
            finished.st_ctime_ns,
        ) != expected:
            raise NativeLinuxFinalGatePreflightError(
                "input_changed", "trusted regular input changed while reading"
            )
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != expected:
        raise NativeLinuxFinalGatePreflightError(
            "input_changed", "trusted regular input changed during validation"
        )
    return b"".join(chunks)


def _native_linux_bindings() -> dict[str, object]:
    release = platform.release().lower()
    if (
        os.name != "posix"
        or sys.platform != "linux"
        or platform.system() != "Linux"
        or "microsoft" in release
        or "wsl" in release
    ):
        raise NativeLinuxFinalGatePreflightError(
            "native_linux_required", "preflight requires a non-WSL native Linux host"
        )
    if any(marker.exists() for marker in _KNOWN_CONTAINER_MARKERS):
        raise NativeLinuxFinalGatePreflightError(
            "container_host_rejected", "known container host marker is present"
        )
    cgroup = _read_proc_file(Path("/proc/1/cgroup"), maximum_bytes=1024 * 1024)
    lowered_cgroup = cgroup.lower()
    if any(token in lowered_cgroup for token in _KNOWN_CGROUP_CONTAINER_TOKENS):
        raise NativeLinuxFinalGatePreflightError(
            "container_host_rejected", "known container cgroup marker is present"
        )
    machine_id = _stable_regular_bytes(
        Path("/etc/machine-id"), maximum_bytes=256, private=False
    ).strip()
    if not machine_id or len(machine_id) > 128:
        raise NativeLinuxFinalGatePreflightError(
            "host_identity_unavailable", "native Linux host identity is unavailable"
        )
    return {
        "host_identity_sha256": hashlib.sha256(
            HOST_IDENTITY_DIGEST_DOMAIN + machine_id
        ).hexdigest(),
        "kernel_release_sha256": hashlib.sha256(
            release.encode("utf-8")
        ).hexdigest(),
    }


def _canonical_existing_path(path: Path, *, directory: bool) -> Path:
    if type(path) is not type(Path()) or not path.is_absolute():
        raise NativeLinuxFinalGatePreflightError(
            "path_invalid", "preflight paths must be absolute"
        )
    try:
        resolved = path.resolve(strict=True)
        state = os.lstat(path)
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "path_unavailable", "required preflight path is unavailable"
        ) from error
    if resolved != path:
        raise NativeLinuxFinalGatePreflightError(
            "path_invalid", "preflight paths cannot contain symbolic links"
        )
    valid = stat.S_ISDIR(state.st_mode) if directory else stat.S_ISREG(state.st_mode)
    if not valid or stat.S_ISLNK(state.st_mode):
        raise NativeLinuxFinalGatePreflightError(
            "path_invalid", "preflight path has the wrong object type"
        )
    return resolved


def _require_directory_permissions(
    path: Path, *, private: bool, current_owner: bool
) -> None:
    state = os.lstat(path)
    mode = stat.S_IMODE(state.st_mode)
    allowed_owners = {os.geteuid()} if current_owner else {0, os.geteuid()}
    if (
        state.st_uid not in allowed_owners
        or mode & 0o022
        or (private and mode & 0o077)
        or not os.access(path, os.R_OK | os.X_OK)
    ):
        raise NativeLinuxFinalGatePreflightError(
            "unsafe_permissions", "preflight directory permissions are unsafe"
        )


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        common = os.path.commonpath((os.fspath(left), os.fspath(right)))
    except ValueError:
        return False
    return common in {os.fspath(left), os.fspath(right)}


def _physical_paths_overlap(
    mount_table: LinuxMountTableV1 | None, left: Path, right: Path
) -> bool:
    if mount_table is None:
        return False
    try:
        return linux_paths_overlap_v1(mount_table, left, right)
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "mount_evidence_invalid", "physical path mapping could not be verified"
        ) from error


def _assert_mount_table_stable(mount_table: LinuxMountTableV1 | None) -> None:
    if mount_table is None:
        return
    try:
        assert_linux_mount_table_stable_v1(mount_table)
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "mount_evidence_changed", "mount namespace changed during preflight"
        ) from error


def _same_node(left: Path, right: Path) -> bool:
    try:
        left_state = os.lstat(left)
        right_state = os.lstat(right)
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "path_unavailable", "required preflight path is unavailable"
        ) from error
    return (left_state.st_dev, left_state.st_ino) == (
        right_state.st_dev,
        right_state.st_ino,
    )


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((os.fspath(path), os.fspath(root))) == os.fspath(root)
    except ValueError:
        return False


def _disallowed_control_overlap(
    mount_table: LinuxMountTableV1 | None,
    root: Path,
    control: Path,
    *,
    allowed_nesting: frozenset[tuple[Path, Path]],
) -> bool:
    if (root, control) in allowed_nesting:
        return False
    return _paths_overlap(root, control) or _physical_paths_overlap(
        mount_table, root, control
    )


def _validate_paths(args: argparse.Namespace) -> _ValidatedPaths:
    try:
        mount_table = capture_linux_mount_table_v1()
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "mount_evidence_invalid", "mount namespace could not be bound"
        ) from error
    roots = {
        "benchmark_root": _canonical_existing_path(args.benchmark_root, directory=True),
        "control_root": _canonical_existing_path(args.control_root, directory=True),
        "implementation_root": _canonical_existing_path(
            args.implementation_root, directory=True
        ),
        "scratch_root": _canonical_existing_path(args.scratch_root, directory=True),
        "test_sealed_batch_root": _canonical_existing_path(
            args.test_sealed_batch_root, directory=True
        ),
        "test_replay_config_root": _canonical_existing_path(
            args.test_replay_config_root, directory=True
        ),
        "train_sealed_batch_root": _canonical_existing_path(
            args.train_sealed_batch_root, directory=True
        ),
        "train_replay_config_root": _canonical_existing_path(
            args.train_replay_config_root, directory=True
        ),
    }
    _require_directory_permissions(
        roots["benchmark_root"], private=False, current_owner=False
    )
    for name, path in roots.items():
        if name == "benchmark_root":
            continue
        _require_directory_permissions(
            path,
            private=(
                name in {"control_root", "scratch_root"}
                or ("_root" in name and name != "implementation_root")
            ),
            current_owner=name in {"control_root", "scratch_root"},
        )
    if not os.access(roots["scratch_root"], os.R_OK | os.W_OK | os.X_OK):
        raise NativeLinuxFinalGatePreflightError(
            "unsafe_permissions", "scratch root is not owner-writable"
        )
    try:
        with os.scandir(roots["scratch_root"]) as entries:
            if next(entries, None) is not None:
                raise NativeLinuxFinalGatePreflightError(
                    "scratch_pollution", "scratch root must be empty before preflight"
                )
    except NativeLinuxFinalGatePreflightError:
        raise
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "scratch_unavailable", "scratch root cannot be scanned"
        ) from error
    docker_executable = _canonical_existing_path(
        args.docker_executable, directory=False
    )
    plan_file = _canonical_existing_path(args.plan_file, directory=False)
    test_key_file = _canonical_existing_path(args.test_key_file, directory=False)
    train_key_file = _canonical_existing_path(args.train_key_file, directory=False)
    assertion_file = (
        _canonical_existing_path(args.operator_assertion_file, directory=False)
        if args.operator_assertion_file is not None
        else None
    )
    control_files = (
        plan_file,
        test_key_file,
        train_key_file,
        *((assertion_file,) if assertion_file is not None else ()),
    )
    if any(not _is_beneath(item, roots["control_root"]) for item in control_files):
        raise NativeLinuxFinalGatePreflightError(
            "control_boundary_invalid", "control inputs must reside below control root"
        )
    implementation_file = Path(__file__).resolve(strict=True)
    if not _is_beneath(implementation_file, roots["implementation_root"]):
        raise NativeLinuxFinalGatePreflightError(
            "implementation_boundary_invalid",
            "preflight implementation is outside the explicit implementation root",
        )
    if not args.output_root.is_absolute() or args.output_root.exists():
        raise NativeLinuxFinalGatePreflightError(
            "output_invalid", "final-gate output must be one absent absolute path"
        )
    try:
        output_parent = args.output_root.parent.resolve(strict=True)
        output_root = args.output_root.resolve(strict=False)
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "output_invalid", "final-gate output parent is unavailable"
        ) from error
    if output_parent != args.output_root.parent or output_root != args.output_root:
        raise NativeLinuxFinalGatePreflightError(
            "output_invalid", "final-gate output path cannot contain symbolic links"
        )
    _require_directory_permissions(
        output_parent, private=True, current_owner=True
    )
    root_values = tuple(roots.values())
    for index, left in enumerate(root_values):
        for right in root_values[index + 1 :]:
            if (
                _paths_overlap(left, right)
                or _same_node(left, right)
                or _physical_paths_overlap(mount_table, left, right)
            ):
                raise NativeLinuxFinalGatePreflightError(
                    "path_overlap", "trusted input roots overlap"
                )
    protected = (
        *root_values,
        docker_executable,
        *control_files,
        implementation_file,
    )
    if any(
        _paths_overlap(output_root, item)
        or _physical_paths_overlap(mount_table, output_root, item)
        for item in protected
    ):
        raise NativeLinuxFinalGatePreflightError(
            "path_overlap", "final-gate output overlaps a trusted input"
        )
    controlled_paths = (docker_executable, *control_files, implementation_file)
    allowed_nesting = frozenset(
        {
            *((roots["control_root"], item) for item in control_files),
            (roots["implementation_root"], implementation_file),
        }
    )
    if any(
        _disallowed_control_overlap(
            mount_table,
            root,
            control,
            allowed_nesting=allowed_nesting,
        )
        for root in root_values
        for control in controlled_paths
    ) or any(
        _same_node(left, right)
        or _physical_paths_overlap(mount_table, left, right)
        for index, left in enumerate(controlled_paths)
        for right in controlled_paths[index + 1 :]
    ):
        raise NativeLinuxFinalGatePreflightError(
            "path_overlap", "control files overlap or reside inside task inputs"
        )
    if test_key_file == train_key_file:
        raise NativeLinuxFinalGatePreflightError(
            "key_reuse", "test and train key paths must be distinct"
        )
    prefix = f".{output_root.name}."
    try:
        for item in os.scandir(output_parent):
            if item.name.startswith(prefix) and item.name.endswith(".staging"):
                raise NativeLinuxFinalGatePreflightError(
                    "staging_pollution", "a prior final-gate staging tree remains"
                )
    except NativeLinuxFinalGatePreflightError:
        raise
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "output_invalid", "final-gate output parent cannot be scanned"
        ) from error
    _assert_mount_table_stable(mount_table)
    return _ValidatedPaths(
        benchmark_root=roots["benchmark_root"],
        control_root=roots["control_root"],
        implementation_root=roots["implementation_root"],
        scratch_root=roots["scratch_root"],
        output_root=output_root,
        output_parent=output_parent,
        docker_executable=docker_executable,
        plan_file=plan_file,
        test_sealed_batch_root=roots["test_sealed_batch_root"],
        test_replay_config_root=roots["test_replay_config_root"],
        train_sealed_batch_root=roots["train_sealed_batch_root"],
        train_replay_config_root=roots["train_replay_config_root"],
        test_key_file=test_key_file,
        train_key_file=train_key_file,
        operator_assertion_file=assertion_file,
        mount_table=mount_table,
    )


def _load_and_bind_plan(
    paths: _ValidatedPaths, args: argparse.Namespace
) -> tuple[FinalGatePlanV1, ExecutionPolicyBindingV1, bytes]:
    payload = _stable_regular_bytes(
        paths.plan_file, maximum_bytes=FINAL_GATE_MAX_WIRE_BYTES, private=False
    )
    try:
        plan = FinalGatePlanV1.from_bytes(
            payload,
            expected_plan_sha256=args.expected_plan_sha256,
            expected_wire_sha256=args.expected_plan_wire_sha256,
        )
        policy = fixed_e4_execution_policy_v1(args.runtime_image_id)
        policy_wire = policy.to_bytes()
    except Exception:
        raise NativeLinuxFinalGatePreflightError(
            "plan_invalid", "final-gate plan did not verify"
        ) from None
    if (
        plan.execution_policy_sha256 != policy.policy_sha256
        or plan.execution_policy_wire_sha256
        != hashlib.sha256(policy_wire).hexdigest()
        or plan.test.snapshot_key_id == plan.train.snapshot_key_id
    ):
        raise NativeLinuxFinalGatePreflightError(
            "plan_binding_mismatch", "final-gate plan differs from fixed bindings"
        )
    return plan, policy, payload


def _freeze_execution_plan(value: object) -> DiscoveryBatchExecutionPlanV2:
    if type(value) is not DiscoveryBatchExecutionPlanV2:
        raise NativeLinuxFinalGatePreflightError(
            "static_plan_invalid", "static verifier returned an invalid plan"
        )
    try:
        payload = value.to_bytes()
        return DiscoveryBatchExecutionPlanV2.from_bytes(
            payload,
            expected_plan_sha256=value.plan_sha256,
            expected_wire_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except Exception:
        raise NativeLinuxFinalGatePreflightError(
            "static_plan_invalid", "static execution plan did not normalize"
        ) from None


def _assert_static_plan(
    session: object,
    *,
    public_tasks: tuple[SnapshotTaskSpec, ...],
    replay_configs: tuple[tuple[OciReplayConfigV1, OciReplayConfigV1], ...],
    split_plan: FinalGateSplitPlanV1,
    policy: ExecutionPolicyBindingV1,
) -> DiscoveryBatchExecutionPlanV2:
    if type(session) is not DiscoveryExecutionSession:
        raise NativeLinuxFinalGatePreflightError(
            "static_plan_invalid", "static verifier returned an invalid session"
        )
    execution_plan = _freeze_execution_plan(session.plan)
    batch = execution_plan.batch
    expected_count = PROFILE_TEST_TASKS if split_plan.split == "test" else PROFILE_TRAIN_TASKS
    if (
        batch.profile_id != PROFILE_ID
        or batch.profile_schema_version != PROFILE_SCHEMA_VERSION
        or batch.public_manifest_sha256 != PROFILE_MANIFEST_SHA256
        or batch.split != split_plan.split
        or batch.task_count != expected_count
        or batch.batch_manifest_sha256 != split_plan.sealed_batch_manifest_sha256
        or batch.attestation_key_id != split_plan.snapshot_key_id
        or batch.snapshot_policy != DEFAULT_SNAPSHOT_POLICY
        or execution_plan.execution_policy != policy
        or execution_plan.execution_policy.to_bytes() != policy.to_bytes()
        or len(public_tasks) != expected_count
        or len(replay_configs) != expected_count
        or len(execution_plan.tasks) != expected_count
    ):
        raise NativeLinuxFinalGatePreflightError(
            "static_plan_mismatch", "static execution plan differs from fixed inputs"
        )
    expected_identities = tuple(
        (task.task_id, task.repo_url, task.commit, task.split, task.instruction_id)
        for task in public_tasks
    )
    observed_identities = tuple(
        (task.task_id, task.repo_url, task.commit, task.split, task.instruction_id)
        for task in batch.tasks
    )
    if expected_identities != observed_identities:
        raise NativeLinuxFinalGatePreflightError(
            "public_task_mismatch", "static batch order differs from public tasks"
        )
    for public, member, task_plan, pair in zip(
        public_tasks, batch.tasks, execution_plan.tasks, replay_configs, strict=True
    ):
        if (
            type(public) is not SnapshotTaskSpec
            or type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not OciReplayConfigV1
            or type(pair[1]) is not OciReplayConfigV1
        ):
            raise NativeLinuxFinalGatePreflightError(
                "replay_mismatch", "static replay pair has an invalid type"
            )
        d2, d3 = pair
        try:
            validate_formal_replay_pair_v1(d2, d3)
        except ReplayAuthoringError:
            raise NativeLinuxFinalGatePreflightError(
                "formal_replay_incomplete",
                "formal static replay pair is incomplete or detached",
            ) from None
        if (
            task_plan.task_id != public.task_id
            or task_plan.task_id != member.task_id
            or task_plan.snapshot_manifest_sha256 != member.snapshot_manifest_sha256
            or task_plan.snapshot_content_root != member.snapshot_content_root
            or d2.task_id != public.task_id
            or d3.task_id != public.task_id
            or d2.role != "d2"
            or d3.role != "d3"
            or d2.backend_id != REPLAY_BACKEND_ID
            or d3.backend_id != REPLAY_BACKEND_ID
            or d2.model_id != REPLAY_MODEL_ID
            or d3.model_id != REPLAY_MODEL_ID
            or task_plan.d2_replay_sha256 != d2.config_sha256
            or task_plan.d2_replay_wire_sha256 != d2.wire_sha256
            or task_plan.d3_replay_sha256 != d3.config_sha256
            or task_plan.d3_replay_wire_sha256 != d3.wire_sha256
        ):
            raise NativeLinuxFinalGatePreflightError(
                "replay_mismatch", "static plan differs from its replay pair"
            )
    return execution_plan


def _static_verify_split(
    *,
    benchmark_root: Path,
    sealed_root: Path,
    replay_root: Path,
    split_plan: FinalGateSplitPlanV1,
    key: bytearray,
    policy: ExecutionPolicyBindingV1,
) -> dict[str, object]:
    session: DiscoveryExecutionSession | None = None
    primary: BaseException | None = None
    result: dict[str, object] | None = None
    try:
        public_tasks = load_answer_free_tasks(
            benchmark_root, split=split_plan.split
        )
        expected_count = (
            PROFILE_TEST_TASKS if split_plan.split == "test" else PROFILE_TRAIN_TASKS
        )
        if (
            type(public_tasks) is not tuple
            or len(public_tasks) != expected_count
            or any(type(task) is not SnapshotTaskSpec for task in public_tasks)
        ):
            raise NativeLinuxFinalGatePreflightError(
                "public_task_mismatch", "public task reader did not close"
            )
        replay_configs = load_batch_replay_configs_v1(
            replay_root,
            expected_manifest_sha256=split_plan.replay_manifest_sha256,
            expected_manifest_wire_sha256=split_plan.replay_manifest_wire_sha256,
            expected_split=split_plan.split,
            expected_task_ids=tuple(task.task_id for task in public_tasks),
        )
        session = prepare_discovery_execution_plan_v1(
            sealed_root,
            expected_batch_manifest_sha256=split_plan.sealed_batch_manifest_sha256,
            attestation_key=key,
            expected_key_id=split_plan.snapshot_key_id,
            execution_policy=policy,
            task_replay_configs=replay_configs,
        )
        execution_plan = _assert_static_plan(
            session,
            public_tasks=public_tasks,
            replay_configs=replay_configs,
            split_plan=split_plan,
            policy=policy,
        )
        result = {
            "execution_plan_sha256": execution_plan.plan_sha256,
            "execution_plan_wire_sha256": execution_plan.wire_sha256,
            "replay_manifest_sha256": split_plan.replay_manifest_sha256,
            "replay_manifest_wire_sha256": split_plan.replay_manifest_wire_sha256,
            "sealed_batch_manifest_sha256": split_plan.sealed_batch_manifest_sha256,
            "snapshot_key_id": split_plan.snapshot_key_id,
            "task_count": expected_count,
        }
    except BaseException as error:
        primary = error
    cleanup_error: BaseException | None = None
    if session is not None:
        try:
            session.abort()
        except BaseException as error:
            cleanup_error = error
    if primary is not None:
        if isinstance(primary, (KeyboardInterrupt, SystemExit)):
            raise primary
        if isinstance(primary, NativeLinuxFinalGatePreflightError):
            raise primary
        raise NativeLinuxFinalGatePreflightError(
            "static_input_invalid", "static split verification did not close"
        ) from None
    if cleanup_error is not None:
        if isinstance(cleanup_error, (KeyboardInterrupt, SystemExit)):
            raise cleanup_error
        raise NativeLinuxFinalGatePreflightError(
            "static_cleanup_failed", "static verifier cleanup did not close"
        ) from None
    if result is None:
        raise NativeLinuxFinalGatePreflightError(
            "static_input_invalid", "static split verification produced no result"
        )
    return result


def _read_proc_file(path: Path, *, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "host_probe_failed", "native Linux host evidence is unavailable"
        ) from error
    chunks: list[bytes] = []
    consumed = 0
    try:
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise NativeLinuxFinalGatePreflightError(
                    "host_probe_failed", "native Linux host evidence is oversized"
                )
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if not payload:
        raise NativeLinuxFinalGatePreflightError(
            "host_probe_failed", "native Linux host evidence is empty"
        )
    return payload


def _decode_mount_field(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 8))

    return re.sub(r"\\([0-7]{3})", replace, value)


def _filesystem_type_for(path: Path) -> str:
    payload = _read_proc_file(Path("/proc/self/mountinfo"), maximum_bytes=4 * 1024 * 1024)
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeError:
        raise NativeLinuxFinalGatePreflightError(
            "mount_evidence_invalid", "mount evidence is not UTF-8"
        ) from None
    target = os.fspath(path)
    best: tuple[int, str] | None = None
    for line in lines:
        if " - " not in line:
            raise NativeLinuxFinalGatePreflightError(
                "mount_evidence_invalid", "mount evidence is malformed"
            )
        left, right = line.split(" - ", 1)
        left_fields = left.split(" ")
        right_fields = right.split(" ")
        if len(left_fields) < 6 or len(right_fields) < 3:
            raise NativeLinuxFinalGatePreflightError(
                "mount_evidence_invalid", "mount evidence is malformed"
            )
        mount_point = _decode_mount_field(left_fields[4])
        try:
            contains = os.path.commonpath((target, mount_point)) == mount_point
        except ValueError:
            contains = False
        if contains and (best is None or len(mount_point) > best[0]):
            best = (len(mount_point), right_fields[0])
    if best is None:
        raise NativeLinuxFinalGatePreflightError(
            "mount_evidence_invalid", "filesystem mount could not be identified"
        )
    return best[1]


def _filesystem_capacity(path: Path, *, role: str) -> _FilesystemCapacity:
    try:
        state = os.stat(path, follow_symlinks=False)
        vfs = os.statvfs(path)
        disk = shutil.disk_usage(path)
        filesystem_id = int(getattr(vfs, "f_fsid"))
        filesystem_type = _filesystem_type_for(path)
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise NativeLinuxFinalGatePreflightError(
            "storage_evidence_invalid", "filesystem capacity evidence is unavailable"
        ) from error
    if filesystem_type not in _SAFE_LOCAL_FILESYSTEMS:
        raise NativeLinuxFinalGatePreflightError(
            "storage_filesystem_unsupported",
            "a final-gate storage role is not on an approved local filesystem",
        )
    return _FilesystemCapacity(
        role=role,
        root=path,
        filesystem_type=filesystem_type,
        free_bytes=int(disk.free),
        free_inodes=int(vfs.f_favail),
        identity=(int(state.st_dev), filesystem_id),
    )


def _host_resources(
    paths: _ValidatedPaths,
) -> tuple[dict[str, object], dict[str, _FilesystemCapacity]]:
    meminfo = _read_proc_file(Path("/proc/meminfo"), maximum_bytes=1024 * 1024)
    values: dict[str, int] = {}
    try:
        for raw in meminfo.decode("ascii").splitlines():
            if ":" not in raw:
                continue
            name, remainder = raw.split(":", 1)
            fields = remainder.strip().split()
            if len(fields) == 2 and fields[1] == "kB" and fields[0].isdigit():
                values[name] = int(fields[0]) * 1024
    except (UnicodeError, ValueError):
        raise NativeLinuxFinalGatePreflightError(
            "memory_evidence_invalid", "Linux memory evidence is malformed"
        ) from None
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    cpu_count = os.cpu_count()
    if type(cpu_count) is not int or cpu_count < MIN_HOST_CPUS:
        raise NativeLinuxFinalGatePreflightError(
            "cpu_insufficient", "native Linux CPU count is below the fixed floor"
        )
    if total < MIN_TOTAL_RAM_BYTES or available < MIN_AVAILABLE_RAM_BYTES:
        raise NativeLinuxFinalGatePreflightError(
            "memory_insufficient", "native Linux RAM does not meet the fixed floor"
        )
    controllers = _read_proc_file(
        Path("/sys/fs/cgroup/cgroup.controllers"), maximum_bytes=64 * 1024
    ).split()
    if not {b"cpu", b"memory", b"pids"}.issubset(set(controllers)):
        raise NativeLinuxFinalGatePreflightError(
            "cgroup_v2_unavailable", "required cgroup v2 controllers are unavailable"
        )
    output = _filesystem_capacity(paths.output_parent, role="output")
    scratch = _filesystem_capacity(paths.scratch_root, role="scratch")
    if (
        output.free_bytes < MIN_OUTPUT_FREE_BYTES
        or output.free_inodes < MIN_OUTPUT_FREE_INODES
    ):
        raise NativeLinuxFinalGatePreflightError(
            "output_capacity_insufficient", "output filesystem capacity is below the fixed floor"
        )
    if scratch.free_bytes < MIN_SCRATCH_FREE_BYTES:
        raise NativeLinuxFinalGatePreflightError(
            "scratch_capacity_insufficient",
            "scratch filesystem capacity is below the fixed floor",
        )
    report = {
        "available_ram_bytes": available,
        "cgroup_v2_controllers": sorted(item.decode("ascii") for item in controllers),
        "host_cpu_count": cpu_count,
        "output_filesystem": output.filesystem_type,
        "output_filesystem_identity_sha256": output.identity_sha256,
        "output_free_bytes": output.free_bytes,
        "output_free_inodes": output.free_inodes,
        "scratch_filesystem": scratch.filesystem_type,
        "scratch_filesystem_identity_sha256": scratch.identity_sha256,
        "scratch_free_bytes": scratch.free_bytes,
        "total_ram_bytes": total,
    }
    return report, {"output": output, "scratch": scratch}


def _stable_executable_digest(path: Path) -> tuple[str, tuple[int, ...]]:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_cli_unavailable", "Docker CLI is unavailable"
        ) from error
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or not 1 <= before.st_size <= 128 * 1024 * 1024
        or before.st_uid not in {0, os.geteuid()}
        or mode & 0o022
        or not os.access(path, os.R_OK | os.X_OK)
    ):
        raise NativeLinuxFinalGatePreflightError(
            "docker_cli_unsafe", "Docker CLI permissions are unsafe"
        )
    expected = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        mode,
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_cli_unavailable", "Docker CLI cannot be opened"
        ) from error
    digest = hashlib.sha256()
    consumed = 0
    try:
        opened = os.fstat(descriptor)
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
            stat.S_IMODE(opened.st_mode),
        )
        if opened_identity != expected:
            raise NativeLinuxFinalGatePreflightError(
                "docker_cli_changed", "Docker CLI changed while opening"
            )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            digest.update(chunk)
        finished = os.fstat(descriptor)
        if consumed != expected[2] or (
            finished.st_dev,
            finished.st_ino,
            finished.st_size,
            finished.st_mtime_ns,
            finished.st_ctime_ns,
            stat.S_IMODE(finished.st_mode),
        ) != expected:
            raise NativeLinuxFinalGatePreflightError(
                "docker_cli_changed", "Docker CLI changed while hashing"
            )
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        stat.S_IMODE(after.st_mode),
    ) != expected:
        raise NativeLinuxFinalGatePreflightError(
            "docker_cli_changed", "Docker CLI changed during validation"
        )
    return digest.hexdigest(), expected


def _bind_docker_cli(
    path: Path, *, expected_sha256: str
) -> tuple[str, tuple[int, ...]]:
    digest, identity = _stable_executable_digest(path)
    if digest != expected_sha256:
        raise NativeLinuxFinalGatePreflightError(
            "docker_cli_pin_mismatch", "Docker CLI differs from its exact pin"
        )
    return digest, identity


def _socket_path(endpoint: str) -> Path:
    return Path(endpoint[len("unix://") :])


def _bind_docker_socket(endpoint: str) -> tuple[str, DockerSocketGuardV1]:
    path = _socket_path(endpoint)
    try:
        guard = bind_docker_socket_guard_v1(path)
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            error.code, "local Docker socket binding is unsafe"
        ) from error
    identity = guard.socket_identity
    try:
        digest = docker_socket_identity_sha256_v1(
            device=identity[0],
            inode=identity[1],
            uid=identity[2],
            gid=identity[3],
            mode=identity[4],
        )
    except RuntimeEvidenceError:
        raise NativeLinuxFinalGatePreflightError(
            "docker_socket_unsafe", "Docker socket identity is invalid"
        ) from None
    return digest, guard


def _assert_docker_socket_stable(guard: DockerSocketGuardV1 | None) -> None:
    if guard is None:
        return
    try:
        assert_docker_socket_guard_stable_v1(guard)
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_socket_changed", "Docker socket binding changed during a probe"
        ) from error


def _assert_docker_root_stable(
    guard: LinuxDirectoryGuardV1 | None,
) -> None:
    if guard is None:
        return
    try:
        assert_root_owned_directory_guard_stable_v1(guard)
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_changed", "Docker data root binding changed during a probe"
        ) from error


def _assert_docker_host_stable(
    *,
    mount_table: LinuxMountTableV1 | None,
    socket_guard: DockerSocketGuardV1 | None,
    docker_root_guard: LinuxDirectoryGuardV1 | None,
) -> None:
    _assert_mount_table_stable(mount_table)
    _assert_docker_socket_stable(socket_guard)
    _assert_docker_root_stable(docker_root_guard)


def _clean_docker_environment(executable: Path) -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(
            (os.fspath(executable.parent), "/usr/local/bin", "/usr/bin", "/bin")
        ),
        "PYTHONHASHSEED": "0",
    }


def _run_docker_bytes(
    executable: Path,
    endpoint: str,
    config_root: Path,
    arguments: tuple[str, ...],
    *,
    maximum_bytes: int,
    socket_guard: DockerSocketGuardV1 | None = None,
    docker_root_guard: LinuxDirectoryGuardV1 | None = None,
    mount_table: LinuxMountTableV1 | None = None,
) -> bytes:
    _assert_docker_host_stable(
        mount_table=mount_table,
        socket_guard=socket_guard,
        docker_root_guard=docker_root_guard,
    )
    try:
        try:
            result = run_bounded_process_v1(
                (
                    os.fspath(executable),
                    f"--host={endpoint}",
                    f"--config={config_root}",
                    *arguments,
                ),
                stdout_max_bytes=maximum_bytes,
                stderr_max_bytes=64 * 1024,
                timeout_seconds=30.0,
                env=_clean_docker_environment(executable),
            )
        except BoundedProcessError as error:
            raise NativeLinuxFinalGatePreflightError(
                "docker_probe_failed", "bounded Docker probe could not start"
            ) from error
    finally:
        _assert_docker_host_stable(
            mount_table=mount_table,
            socket_guard=socket_guard,
            docker_root_guard=docker_root_guard,
        )
    if (
        result.exit_code != 0
        or result.timed_out
        or result.stdout_overflow
        or result.stderr_overflow
        or result.stderr
    ):
        raise NativeLinuxFinalGatePreflightError(
            "docker_probe_failed", "bounded Docker probe was not clean"
        )
    return result.stdout


def _observe_docker_daemon(
    paths: _ValidatedPaths,
    args: argparse.Namespace,
    config_root: Path,
    *,
    socket_guard: DockerSocketGuardV1 | None = None,
    docker_root_guard: LinuxDirectoryGuardV1 | None = None,
) -> _DockerDaemonObservation:
    server_payload = _run_docker_bytes(
        paths.docker_executable,
        args.docker_host,
        config_root,
        ("version", "--format", "{{json .Server}}"),
        maximum_bytes=4 * 1024 * 1024,
        socket_guard=socket_guard,
        docker_root_guard=docker_root_guard,
        mount_table=paths.mount_table,
    )
    info_payload = _run_docker_bytes(
        paths.docker_executable,
        args.docker_host,
        config_root,
        ("info", "--format", "{{json .}}"),
        maximum_bytes=8 * 1024 * 1024,
        socket_guard=socket_guard,
        docker_root_guard=docker_root_guard,
        mount_table=paths.mount_table,
    )
    server = _parse_json_document(server_payload, maximum_bytes=4 * 1024 * 1024)
    info = _parse_json_document(info_payload, maximum_bytes=8 * 1024 * 1024)
    if type(server) is not dict or type(info) is not dict:
        raise NativeLinuxFinalGatePreflightError(
            "docker_identity_invalid", "Docker identity observations are invalid"
        )
    server_sha256 = docker_server_identity_sha256_v1(server)
    info_sha256 = docker_info_identity_sha256_v1(info)
    if (
        server_sha256 != args.expected_docker_server_sha256
        or info_sha256 != args.expected_docker_info_sha256
        or server.get("Os") != "linux"
        or server.get("Arch") != "amd64"
        or info.get("OSType") != "linux"
        or info.get("Architecture") != "x86_64"
    ):
        raise NativeLinuxFinalGatePreflightError(
            "docker_identity_mismatch", "Docker daemon differs from its exact pins"
        )
    return _DockerDaemonObservation(
        server_sha256=server_sha256,
        info_sha256=info_sha256,
        server=server,
        info=info,
    )


def _bind_docker_root_guard(
    observation: _DockerDaemonObservation,
) -> LinuxDirectoryGuardV1:
    try:
        docker_root = observation.info.get("DockerRootDir")
    except AttributeError:
        docker_root = None
    if type(docker_root) is not str or not docker_root.startswith("/"):
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_invalid", "Docker data root is invalid"
        )
    try:
        return bind_root_owned_directory_chain_v1(Path(docker_root))
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_unsafe",
            "Docker data root ownership or permissions are unsafe",
        ) from error


def _validate_docker_capabilities(
    observation: _DockerDaemonObservation,
    *,
    paths: _ValidatedPaths,
    args: argparse.Namespace,
    filesystem_capacities: dict[str, _FilesystemCapacity],
    docker_root_guard: LinuxDirectoryGuardV1 | None = None,
) -> dict[str, object]:
    if docker_root_guard is None and os.name == "posix" and sys.platform == "linux":
        docker_root_guard = _bind_docker_root_guard(observation)
    info = observation.info
    security = info.get("SecurityOptions")
    runtimes = info.get("Runtimes")
    seccomp = (
        type(security) is list
        and any(type(item) is str and "seccomp" in item.lower() for item in security)
        and not any(
            type(item) is str and "seccomp=unconfined" in item.lower()
            for item in security
        )
    )
    if (
        info.get("CgroupVersion") != "2"
        or info.get("DefaultRuntime") != "runc"
        or type(runtimes) is not dict
        or "runc" not in runtimes
        or not seccomp
        or info.get("Driver") not in {"overlay2", "btrfs", "zfs"}
        or type(info.get("NCPU")) is not int
        or info["NCPU"] < MIN_DAEMON_CPUS
        or type(info.get("MemTotal")) is not int
        or info["MemTotal"] < MIN_TOTAL_RAM_BYTES
    ):
        raise NativeLinuxFinalGatePreflightError(
            "docker_isolation_unavailable", "Docker isolation capabilities do not close"
        )
    docker_root = info.get("DockerRootDir")
    if type(docker_root) is not str or not docker_root.startswith("/"):
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_invalid", "Docker data root is invalid"
        )
    root = Path(docker_root)
    try:
        root = _canonical_existing_path(root, directory=True)
        if docker_root_guard is not None:
            if docker_root_guard.path != root:
                raise NativeLinuxFinalGatePreflightError(
                    "docker_storage_invalid", "Docker data root binding is detached"
                )
            assert_root_owned_directory_guard_stable_v1(docker_root_guard)
        docker_capacity = _filesystem_capacity(root, role="docker")
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_unsafe",
            "Docker data root ownership or permissions are unsafe",
        ) from error
    except NativeLinuxFinalGatePreflightError:
        raise
    except OSError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_invalid", "Docker data root cannot be inspected"
        ) from error
    if docker_capacity.free_bytes < MIN_DOCKER_FREE_BYTES:
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_insufficient", "Docker storage does not meet the fixed floor"
        )
    socket_path = _socket_path(args.docker_host)
    protected_paths = (
        paths.benchmark_root,
        paths.control_root,
        paths.implementation_root,
        paths.scratch_root,
        paths.output_root,
        paths.test_sealed_batch_root,
        paths.test_replay_config_root,
        paths.train_sealed_batch_root,
        paths.train_replay_config_root,
        paths.docker_executable,
        paths.plan_file,
        paths.test_key_file,
        paths.train_key_file,
        *(
            (paths.operator_assertion_file,)
            if paths.operator_assertion_file is not None
            else ()
        ),
    )
    if (
        _paths_overlap(root, socket_path)
        or _physical_paths_overlap(paths.mount_table, root, socket_path)
        or any(
            _paths_overlap(candidate, protected)
            or _physical_paths_overlap(paths.mount_table, candidate, protected)
            for candidate in (root, socket_path)
            for protected in protected_paths
        )
        or any(
            _same_node(root, protected)
            for protected in protected_paths
            if protected.exists()
        )
    ):
        raise NativeLinuxFinalGatePreflightError(
            "runtime_storage_overlap",
            "Docker root or socket overlaps a final-gate trust boundary",
        )
    _assert_mount_table_stable(paths.mount_table)
    if docker_root_guard is not None:
        try:
            assert_root_owned_directory_guard_stable_v1(docker_root_guard)
        except LinuxHostSecurityError as error:
            raise NativeLinuxFinalGatePreflightError(
                "docker_storage_changed", "Docker data root binding changed"
            ) from error
    all_capacities = {**filesystem_capacities, "docker": docker_capacity}
    grouped: dict[tuple[int, int], list[_FilesystemCapacity]] = {}
    for item in all_capacities.values():
        grouped.setdefault(item.identity, []).append(item)
    unique_free_bytes = sum(
        min(item.free_bytes for item in group) for group in grouped.values()
    )
    if unique_free_bytes < MIN_UNIQUE_STORAGE_FREE_BYTES:
        raise NativeLinuxFinalGatePreflightError(
            "storage_capacity_insufficient",
            "unique final-gate filesystem capacity is below 200 GiB",
        )
    roles = [
        {
            "filesystem": item.filesystem_type,
            "filesystem_identity_sha256": item.identity_sha256,
            "free_bytes": item.free_bytes,
            "role": item.role,
        }
        for item in sorted(all_capacities.values(), key=lambda value: value.role)
    ]
    return {
        "daemon_cpu_count": info["NCPU"],
        "daemon_total_ram_bytes": info["MemTotal"],
        "docker_filesystem": docker_capacity.filesystem_type,
        "docker_filesystem_identity_sha256": docker_capacity.identity_sha256,
        "docker_free_bytes": docker_capacity.free_bytes,
        "storage_roles": roles,
        "unique_filesystem_count": len(grouped),
        "unique_storage_free_bytes": unique_free_bytes,
    }


def _observe_runtime_image(
    paths: _ValidatedPaths,
    args: argparse.Namespace,
    config_root: Path,
    observation: _DockerDaemonObservation,
    *,
    socket_guard: DockerSocketGuardV1 | None = None,
    docker_root_guard: LinuxDirectoryGuardV1 | None = None,
) -> str:
    payload = _run_docker_bytes(
        paths.docker_executable,
        args.docker_host,
        config_root,
        (
            "image",
            "inspect",
            args.runtime_image_id,
            "--format",
            "{{json .}}",
        ),
        maximum_bytes=16 * 1024 * 1024,
        socket_guard=socket_guard,
        docker_root_guard=docker_root_guard,
        mount_table=paths.mount_table,
    )
    image = _parse_json_document(payload, maximum_bytes=16 * 1024 * 1024)
    if type(image) is not dict:
        raise NativeLinuxFinalGatePreflightError(
            "runtime_image_invalid", "runtime image observation is invalid"
        )
    digest = runtime_image_inspect_sha256_v1(image)
    if (
        digest != args.expected_runtime_image_inspect_sha256
        or image.get("Id") != args.runtime_image_id
        or image.get("Os") != "linux"
        or image.get("Architecture") != observation.server.get("Arch")
        or type(image.get("Config")) is not dict
    ):
        raise NativeLinuxFinalGatePreflightError(
            "runtime_image_mismatch", "runtime image differs from its exact pin"
        )
    return digest


def _observe_daemon_cleanliness(
    paths: _ValidatedPaths,
    args: argparse.Namespace,
    config_root: Path,
    observation: _DockerDaemonObservation,
    *,
    socket_guard: DockerSocketGuardV1 | None = None,
    docker_root_guard: LinuxDirectoryGuardV1 | None = None,
) -> None:
    info = observation.info
    for name in ("Containers", "ContainersRunning", "ContainersPaused", "ContainersStopped"):
        if type(info.get(name)) is not int or info[name] != 0:
            raise NativeLinuxFinalGatePreflightError(
                "daemon_not_empty", "dedicated Docker daemon contains containers"
            )
    containers = _run_docker_bytes(
        paths.docker_executable,
        args.docker_host,
        config_root,
        ("container", "ls", "--all", "--no-trunc", "--quiet"),
        maximum_bytes=1024 * 1024,
        socket_guard=socket_guard,
        docker_root_guard=docker_root_guard,
        mount_table=paths.mount_table,
    )
    polluted_images = _run_docker_bytes(
        paths.docker_executable,
        args.docker_host,
        config_root,
        (
            "image",
            "ls",
            "--no-trunc",
            "--quiet",
            "--filter",
            "label=vulngym.e3.execution",
        ),
        maximum_bytes=1024 * 1024,
        socket_guard=socket_guard,
        docker_root_guard=docker_root_guard,
        mount_table=paths.mount_table,
    )
    if containers.strip() or polluted_images.strip():
        raise NativeLinuxFinalGatePreflightError(
            "daemon_polluted", "Docker daemon contains concurrent or stale resources"
        )


def _assert_runtime_bindings_stable(
    paths: _ValidatedPaths,
    args: argparse.Namespace,
    *,
    cli_identity: tuple[int, ...],
    socket_guard: DockerSocketGuardV1,
    docker_root_guard: LinuxDirectoryGuardV1,
    config_root: Path,
    daemon: _DockerDaemonObservation,
    runtime_image_inspect_sha256: str,
) -> None:
    _assert_mount_table_stable(paths.mount_table)
    _assert_docker_socket_stable(socket_guard)
    try:
        assert_root_owned_directory_guard_stable_v1(docker_root_guard)
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_changed", "Docker data root binding changed"
        ) from error
    digest, current_cli = _stable_executable_digest(paths.docker_executable)
    _socket_digest, current_socket = _bind_docker_socket(args.docker_host)
    current_daemon = _observe_docker_daemon(
        paths,
        args,
        config_root,
        socket_guard=socket_guard,
        docker_root_guard=docker_root_guard,
    )
    current_image = _observe_runtime_image(
        paths,
        args,
        config_root,
        current_daemon,
        socket_guard=socket_guard,
        docker_root_guard=docker_root_guard,
    )
    if (
        digest != args.expected_docker_cli_sha256
        or current_cli != cli_identity
        or current_socket != socket_guard
        or current_daemon.server_sha256 != daemon.server_sha256
        or current_daemon.info_sha256 != daemon.info_sha256
        or current_image != runtime_image_inspect_sha256
    ):
        raise NativeLinuxFinalGatePreflightError(
            "runtime_binding_changed", "runtime binding changed during preflight"
        )
    _assert_mount_table_stable(paths.mount_table)
    _assert_docker_socket_stable(socket_guard)
    try:
        assert_root_owned_directory_guard_stable_v1(docker_root_guard)
    except LinuxHostSecurityError as error:
        raise NativeLinuxFinalGatePreflightError(
            "docker_storage_changed", "Docker data root binding changed"
        ) from error


def _verify_operator_assertion(
    paths: _ValidatedPaths,
    args: argparse.Namespace,
    bindings: dict[str, object],
) -> str:
    if (
        paths.operator_assertion_file is None
        or args.expected_operator_assertion_wire_sha256 is None
    ):
        raise NativeLinuxFinalGatePreflightError(
            "operator_assertion_required",
            "a separately pinned external-isolation assertion is required",
        )
    payload = _stable_regular_bytes(
        paths.operator_assertion_file, maximum_bytes=64 * 1024, private=True
    )
    wire_sha256 = hashlib.sha256(payload).hexdigest()
    if wire_sha256 != args.expected_operator_assertion_wire_sha256:
        raise NativeLinuxFinalGatePreflightError(
            "operator_assertion_pin_mismatch", "operator assertion differs from its pin"
        )
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_json_shape(value)
    except (RecursionError, UnicodeError, ValueError):
        raise NativeLinuxFinalGatePreflightError(
            "operator_assertion_invalid", "operator assertion is not strict JSON"
        ) from None
    if (
        type(value) is not dict
        or set(value) != _ASSERTION_KEYS
        or _canonical_json(value) + b"\n" != payload
        or value.get("contract_version") != 2
        or value.get("kind") != OPERATOR_ASSERTION_KIND
        or any(value.get(name) is not True for name in _ASSERTION_TRUE_FIELDS)
    ):
        raise NativeLinuxFinalGatePreflightError(
            "operator_assertion_invalid", "operator assertion contract is invalid"
        )
    for name in (
        "daemon_endpoint_sha256",
        "daemon_info_sha256",
        "docker_executable_sha256",
        "docker_socket_identity_sha256",
        "final_gate_plan_sha256",
        "final_gate_plan_wire_sha256",
        "host_identity_sha256",
        "runtime_image_inspect_sha256",
        "server_observation_sha256",
    ):
        if value.get(name) != bindings.get(name):
            raise NativeLinuxFinalGatePreflightError(
                "operator_assertion_binding_mismatch",
                "operator assertion differs from observed bindings",
            )
    if value.get("runtime_image_id") != bindings.get("runtime_image_id"):
        raise NativeLinuxFinalGatePreflightError(
            "operator_assertion_binding_mismatch",
            "operator assertion differs from observed bindings",
        )
    return wire_sha256


def _finish_failure(
    *,
    checks: list[dict[str, str]],
    current: str,
    error: BaseException,
    bindings: dict[str, object],
    capacities: dict[str, object],
    inputs: dict[str, object],
) -> bytes:
    code = (
        error.code
        if isinstance(error, NativeLinuxFinalGatePreflightError)
        else "unexpected_check_failure"
    )
    _set_check(checks, current, "not_ready", code)
    return _report_bytes(
        checks=checks, bindings=bindings, capacities=capacities, inputs=inputs
    )


def run_native_linux_final_gate_preflight_v2(args: argparse.Namespace) -> bytes:
    """Return one canonical readiness report without mutating Docker or inputs."""

    checks = _initial_checks()
    bindings: dict[str, object] = {}
    capacities: dict[str, object] = {}
    inputs: dict[str, object] = {}

    try:
        if type(args) is not argparse.Namespace:
            raise NativeLinuxFinalGatePreflightError(
                "invalid_argument", "preflight requires parsed exact arguments"
            )
        _validate_argument_shapes(args)
        _set_check(checks, "argument_contracts", "ready", "arguments_bound")
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="argument_contracts",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    try:
        bindings.update(_native_linux_bindings())
        _set_check(checks, "native_linux_host", "ready", "native_linux_bound")
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="native_linux_host",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    try:
        paths = _validate_paths(args)
        _set_check(
            checks,
            "path_and_permission_contracts",
            "ready",
            "paths_and_permissions_bound",
        )
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="path_and_permission_contracts",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    try:
        plan, policy, plan_payload = _load_and_bind_plan(paths, args)
        bindings.update(
            {
                "execution_policy_sha256": policy.policy_sha256,
                "execution_policy_wire_sha256": policy.wire_sha256,
                "final_gate_plan_sha256": plan.plan_sha256,
                "final_gate_plan_wire_sha256": hashlib.sha256(plan_payload).hexdigest(),
                "runtime_image_id": args.runtime_image_id,
            }
        )
        _set_check(checks, "final_gate_plan", "ready", "final_gate_plan_bound")
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="final_gate_plan",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    test_key_digest: bytes | None = None
    test_key: bytearray | None = None
    try:
        test_key = read_attestation_key_file_v1(paths.test_key_file)
        test_key_digest = hashlib.sha256(bytes(test_key)).digest()
        inputs["test"] = _static_verify_split(
            benchmark_root=paths.benchmark_root,
            sealed_root=paths.test_sealed_batch_root,
            replay_root=paths.test_replay_config_root,
            split_plan=plan.test,
            key=test_key,
            policy=policy,
        )
        _set_check(checks, "static_test_inputs", "ready", "static_test_closed")
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="static_test_inputs",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )
    finally:
        if test_key is not None:
            zero_secret_buffer_v1(test_key)

    train_key: bytearray | None = None
    try:
        train_key = read_attestation_key_file_v1(paths.train_key_file)
        if test_key_digest is None or hmac.compare_digest(
            test_key_digest, hashlib.sha256(bytes(train_key)).digest()
        ):
            raise NativeLinuxFinalGatePreflightError(
                "key_reuse", "test and train key material must be distinct"
            )
        inputs["train"] = _static_verify_split(
            benchmark_root=paths.benchmark_root,
            sealed_root=paths.train_sealed_batch_root,
            replay_root=paths.train_replay_config_root,
            split_plan=plan.train,
            key=train_key,
            policy=policy,
        )
        _set_check(checks, "static_train_inputs", "ready", "static_train_closed")
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="static_train_inputs",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )
    finally:
        if train_key is not None:
            zero_secret_buffer_v1(train_key)

    try:
        host_capacities, filesystem_capacities = _host_resources(paths)
        capacities.update(host_capacities)
        _set_check(checks, "host_resources", "ready", "host_resources_bound")
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="host_resources",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    try:
        cli_sha256, cli_identity = _bind_docker_cli(
            paths.docker_executable,
            expected_sha256=args.expected_docker_cli_sha256,
        )
        bindings["docker_executable_sha256"] = cli_sha256
        bindings["daemon_endpoint_sha256"] = docker_endpoint_sha256_v1(
            args.docker_host
        )
        _set_check(checks, "docker_cli", "ready", "docker_cli_bound")
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="docker_cli",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    try:
        socket_sha256, socket_guard = _bind_docker_socket(args.docker_host)
        bindings["docker_socket_identity_sha256"] = socket_sha256
        _set_check(
            checks, "docker_local_socket", "ready", "docker_local_socket_bound"
        )
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="docker_local_socket",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    try:
        with tempfile.TemporaryDirectory(
            prefix="vulngym-native-final-gate-preflight-",
            dir=paths.scratch_root,
        ) as temporary:
            config_root = Path(temporary)
            os.chmod(config_root, 0o700)
            daemon = _observe_docker_daemon(
                paths, args, config_root, socket_guard=socket_guard
            )
            bindings["server_observation_sha256"] = daemon.server_sha256
            bindings["daemon_info_sha256"] = daemon.info_sha256
            _set_check(
                checks,
                "docker_daemon_identity",
                "ready",
                "docker_daemon_bound",
            )

            docker_root_guard = _bind_docker_root_guard(daemon)
            capacities.update(
                _validate_docker_capabilities(
                    daemon,
                    paths=paths,
                    args=args,
                    filesystem_capacities=filesystem_capacities,
                    docker_root_guard=docker_root_guard,
                )
            )
            _set_check(
                checks,
                "docker_isolation_capabilities",
                "ready",
                "docker_isolation_bound",
            )

            image_sha256 = _observe_runtime_image(
                paths,
                args,
                config_root,
                daemon,
                socket_guard=socket_guard,
                docker_root_guard=docker_root_guard,
            )
            bindings["runtime_image_inspect_sha256"] = image_sha256
            _set_check(
                checks,
                "runtime_image_identity",
                "ready",
                "runtime_image_bound",
            )

            _observe_daemon_cleanliness(
                paths,
                args,
                config_root,
                daemon,
                socket_guard=socket_guard,
                docker_root_guard=docker_root_guard,
            )
            _assert_runtime_bindings_stable(
                paths,
                args,
                cli_identity=cli_identity,
                socket_guard=socket_guard,
                docker_root_guard=docker_root_guard,
                config_root=config_root,
                daemon=daemon,
                runtime_image_inspect_sha256=image_sha256,
            )
            _set_check(
                checks, "daemon_cleanliness", "ready", "daemon_clean"
            )
    except Exception as error:
        current = next(
            name
            for name in (
                "docker_daemon_identity",
                "docker_isolation_capabilities",
                "runtime_image_identity",
                "daemon_cleanliness",
            )
            if checks[_CHECK_NAMES.index(name)]["status"] != "ready"
        )
        return _finish_failure(
            checks=checks,
            current=current,
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    try:
        assertion_wire_sha256 = _verify_operator_assertion(paths, args, bindings)
        bindings["operator_assertion_wire_sha256"] = assertion_wire_sha256
        _set_check(
            checks,
            "operator_external_isolation_assertion",
            "ready",
            "externally_asserted_and_bound",
        )
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="operator_external_isolation_assertion",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    try:
        _assert_docker_host_stable(
            mount_table=paths.mount_table,
            socket_guard=socket_guard,
            docker_root_guard=docker_root_guard,
        )
    except Exception as error:
        return _finish_failure(
            checks=checks,
            current="operator_external_isolation_assertion",
            error=error,
            bindings=bindings,
            capacities=capacities,
            inputs=inputs,
        )

    return _report_bytes(
        checks=checks, bindings=bindings, capacities=capacities, inputs=inputs
    )


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        payload = run_native_linux_final_gate_preflight_v2(args)
    except NativeLinuxFinalGatePreflightError as error:
        payload = _minimal_failure_report(error.code)
    except Exception:
        payload = _minimal_failure_report("unexpected_preflight_failure")
    sys.stdout.buffer.write(payload)
    try:
        status = json.loads(payload)["status"]
    except (KeyError, TypeError, ValueError):
        return 2
    return 0 if status == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MIN_AVAILABLE_RAM_BYTES",
    "MIN_DOCKER_FREE_BYTES",
    "MIN_HOST_CPUS",
    "MIN_DAEMON_CPUS",
    "MIN_OUTPUT_FREE_BYTES",
    "MIN_SCRATCH_FREE_BYTES",
    "MIN_TOTAL_RAM_BYTES",
    "MIN_UNIQUE_STORAGE_FREE_BYTES",
    "NATIVE_LINUX_FINAL_GATE_PREFLIGHT_VERSION",
    "NativeLinuxFinalGatePreflightError",
    "OPERATOR_ASSERTION_KIND",
    "READINESS_REPORT_KIND",
    "READINESS_REPORT_MAX_BYTES",
    "docker_info_identity_sha256_v1",
    "docker_server_identity_sha256_v1",
    "main",
    "parse_native_linux_final_gate_readiness_v2",
    "runtime_image_inspect_sha256_v1",
    "NativeLinuxFinalGateReadinessV2",
    "run_native_linux_final_gate_preflight_v2",
]
