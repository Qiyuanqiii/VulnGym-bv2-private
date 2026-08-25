from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent.evaluator.e4_driver import fixed_e4_execution_policy_v1
from vulngym_agent.evaluator.final_gate import (
    FinalGatePlanV1,
    FinalGateSplitPlanV1,
)
import vulngym_agent.native_linux_final_gate_preflight as preflight


_SHA_A = "a" * 64
_SHA_B = "b" * 64
_SHA_C = "c" * 64
_SHA_D = "d" * 64
_SHA_E = "e" * 64
_SHA_F = "f" * 64
_IMAGE = "sha256:" + "1" * 64


class NativeLinuxFinalGatePreflightTests(unittest.TestCase):
    def _args(self) -> argparse.Namespace:
        return argparse.Namespace(
            benchmark_root=Path("/srv/vulngym/benchmark"),
            control_root=Path("/srv/vulngym/control"),
            implementation_root=Path("/srv/vulngym/implementation"),
            scratch_root=Path("/srv/vulngym/scratch"),
            output_root=Path("/srv/vulngym/output/gate-001"),
            docker_executable=Path("/usr/bin/docker"),
            docker_host="unix:///run/vulngym/docker.sock",
            runtime_image_id=_IMAGE,
            expected_docker_cli_sha256=_SHA_A,
            expected_docker_server_sha256=_SHA_B,
            expected_docker_info_sha256=_SHA_C,
            expected_runtime_image_inspect_sha256=_SHA_D,
            plan_file=Path("/srv/vulngym/control/final-gate-plan.json"),
            expected_plan_sha256=_SHA_E,
            expected_plan_wire_sha256=_SHA_F,
            test_sealed_batch_root=Path("/srv/vulngym/input/test-sealed"),
            test_replay_config_root=Path("/srv/vulngym/input/test-replay"),
            train_sealed_batch_root=Path("/srv/vulngym/input/train-sealed"),
            train_replay_config_root=Path("/srv/vulngym/input/train-replay"),
            test_key_file=Path("/srv/vulngym/control/secrets/test.key"),
            train_key_file=Path("/srv/vulngym/control/secrets/train.key"),
            operator_assertion_file=Path("/srv/vulngym/control/operator.json"),
            expected_operator_assertion_wire_sha256=_SHA_A,
        )

    def _paths(self) -> preflight._ValidatedPaths:
        return preflight._ValidatedPaths(
            benchmark_root=Path("/benchmark"),
            control_root=Path("/control"),
            implementation_root=Path("/implementation"),
            scratch_root=Path(tempfile.gettempdir()),
            output_root=Path("/output/gate"),
            output_parent=Path("/output"),
            docker_executable=Path("/usr/bin/docker"),
            plan_file=Path("/control/plan.json"),
            test_sealed_batch_root=Path("/test-sealed"),
            test_replay_config_root=Path("/test-replay"),
            train_sealed_batch_root=Path("/train-sealed"),
            train_replay_config_root=Path("/train-replay"),
            test_key_file=Path("/control/secrets/test.key"),
            train_key_file=Path("/control/secrets/train.key"),
            operator_assertion_file=Path("/control/operator.json"),
        )

    def _plan(self) -> tuple[FinalGatePlanV1, object, bytes]:
        policy = fixed_e4_execution_policy_v1(_IMAGE)
        test = FinalGateSplitPlanV1(
            split="test",
            task_count=20,
            sealed_batch_manifest_sha256="2" * 64,
            replay_manifest_sha256="3" * 64,
            replay_manifest_wire_sha256="4" * 64,
            snapshot_key_id="test-key",
        )
        train = FinalGateSplitPlanV1(
            split="train",
            task_count=50,
            sealed_batch_manifest_sha256="5" * 64,
            replay_manifest_sha256="6" * 64,
            replay_manifest_wire_sha256="7" * 64,
            snapshot_key_id="train-key",
        )
        plan = FinalGatePlanV1(
            execution_policy_sha256=policy.policy_sha256,
            execution_policy_wire_sha256=policy.wire_sha256,
            test=test,
            train=train,
        )
        return plan, policy, plan.to_bytes()

    @staticmethod
    def _docker_info() -> dict[str, object]:
        return {
            "Architecture": "x86_64",
            "CgroupDriver": "systemd",
            "CgroupVersion": "2",
            "ContainerdCommit": {"Expected": "one", "ID": "one"},
            "DefaultRuntime": "runc",
            "DockerRootDir": "/var/lib/docker",
            "Driver": "overlay2",
            "ID": "DAEMON:ONE",
            "InitBinary": "docker-init",
            "InitCommit": {"Expected": "two", "ID": "two"},
            "KernelVersion": "6.8.0",
            "LiveRestoreEnabled": False,
            "MemTotal": 32 * 1024**3,
            "NCPU": 8,
            "Name": "vulngym-evaluator",
            "OSType": "linux",
            "OSVersion": "24.04",
            "OperatingSystem": "Ubuntu 24.04 LTS",
            "RuncCommit": {"Expected": "three", "ID": "three"},
            "Runtimes": {"runc": {"path": "runc"}},
            "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
            "ServerVersion": "29.6.2",
        }

    @staticmethod
    def _decode(payload: bytes) -> dict[str, object]:
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise AssertionError("report is not an object")
        return value

    def test_report_is_canonical_and_semantically_bound(self) -> None:
        checks = [
            preflight._check_record(name, "ready", "closed")
            for name in preflight._CHECK_NAMES
        ]
        payload = preflight._report_bytes(
            checks=checks,
            bindings={"runtime_image_id": _IMAGE},
            capacities={"total_ram_bytes": 16 * 1024**3},
            inputs={"test": {"task_count": 20}, "train": {"task_count": 50}},
        )
        value = self._decode(payload)
        self.assertEqual(value["status"], "ready")
        self.assertEqual(
            payload,
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n",
        )
        core = {key: item for key, item in value.items() if key != "report_sha256"}
        expected = hashlib.sha256(
            preflight.READINESS_REPORT_DIGEST_DOMAIN
            + preflight._canonical_json(core)
        ).hexdigest()
        self.assertEqual(value["report_sha256"], expected)

    def test_ready_report_requires_semantic_and_wire_pins(self) -> None:
        checks = [
            preflight._check_record(name, "ready", "closed")
            for name in preflight._CHECK_NAMES
        ]
        bindings = {
            "daemon_endpoint_sha256": _SHA_A,
            "daemon_info_sha256": _SHA_B,
            "docker_executable_sha256": _SHA_C,
            "docker_socket_identity_sha256": _SHA_D,
            "execution_policy_sha256": _SHA_E,
            "execution_policy_wire_sha256": _SHA_F,
            "final_gate_plan_sha256": "1" * 64,
            "final_gate_plan_wire_sha256": "2" * 64,
            "host_identity_sha256": "3" * 64,
            "kernel_release_sha256": "4" * 64,
            "operator_assertion_wire_sha256": "5" * 64,
            "runtime_image_id": _IMAGE,
            "runtime_image_inspect_sha256": "6" * 64,
            "server_observation_sha256": "7" * 64,
        }
        payload = preflight._report_bytes(
            checks=checks,
            bindings=bindings,
            capacities={},
            inputs={"test": {"task_count": 20}, "train": {"task_count": 50}},
        )
        value = self._decode(payload)
        parsed = preflight.parse_native_linux_final_gate_readiness_v2(
            payload,
            expected_report_sha256=value["report_sha256"],
            expected_wire_sha256=hashlib.sha256(payload).hexdigest(),
        )
        self.assertEqual(parsed.runtime_binding.runtime_image_id, _IMAGE)
        for semantic, wire in (
            (_SHA_A, hashlib.sha256(payload).hexdigest()),
            (value["report_sha256"], _SHA_B),
        ):
            with self.assertRaises(
                preflight.NativeLinuxFinalGatePreflightError
            ):
                preflight.parse_native_linux_final_gate_readiness_v2(
                    payload,
                    expected_report_sha256=semantic,
                    expected_wire_sha256=wire,
                )

    def test_storage_capacity_counts_each_filesystem_once(self) -> None:
        gib = 1024**3
        paths = self._paths()
        args = self._args()
        info = self._docker_info()
        daemon = preflight._DockerDaemonObservation(
            server_sha256=_SHA_A,
            info_sha256=_SHA_B,
            server={"Os": "linux", "Arch": "amd64"},
            info=info,
        )
        output = preflight._FilesystemCapacity(
            "output", paths.output_parent, "ext4", 120 * gib, 200_000, (1, 1)
        )
        scratch = preflight._FilesystemCapacity(
            "scratch", paths.scratch_root, "ext4", 110 * gib, 200_000, (1, 1)
        )
        docker = preflight._FilesystemCapacity(
            "docker", Path("/var/lib/docker"), "xfs", 100 * gib, 200_000, (2, 2)
        )
        with (
            mock.patch.object(
                preflight,
                "_canonical_existing_path",
                return_value=Path("/var/lib/docker"),
            ),
            mock.patch.object(
                preflight, "_filesystem_capacity", return_value=docker
            ),
            mock.patch.object(preflight, "_same_node", return_value=False),
        ):
            result = preflight._validate_docker_capabilities(
                daemon,
                paths=paths,
                args=args,
                filesystem_capacities={"output": output, "scratch": scratch},
            )
        self.assertEqual(result["unique_filesystem_count"], 2)
        self.assertEqual(result["unique_storage_free_bytes"], 210 * gib)

        same = preflight._FilesystemCapacity(
            "docker", Path("/var/lib/docker"), "ext4", 100 * gib, 200_000, (1, 1)
        )
        with (
            mock.patch.object(
                preflight,
                "_canonical_existing_path",
                return_value=Path("/var/lib/docker"),
            ),
            mock.patch.object(
                preflight, "_filesystem_capacity", return_value=same
            ),
            mock.patch.object(preflight, "_same_node", return_value=False),
            self.assertRaisesRegex(
                preflight.NativeLinuxFinalGatePreflightError, "below 200 GiB"
            ),
        ):
            preflight._validate_docker_capabilities(
                daemon,
                paths=paths,
                args=args,
                filesystem_capacities={"output": output, "scratch": scratch},
            )

    def test_host_and_daemon_cpu_ram_floors_fail_closed(self) -> None:
        gib = 1024**3
        paths = self._paths()

        def host_probe(path: Path, *, maximum_bytes: int) -> bytes:
            del maximum_bytes
            if path == Path("/proc/meminfo"):
                return b"MemTotal:       16777216 kB\nMemAvailable:    6291456 kB\n"
            if path == Path("/sys/fs/cgroup/cgroup.controllers"):
                return b"cpu memory pids\n"
            raise AssertionError(path)

        for cpu_count, meminfo, expected_code in (
            (7, None, "cpu_insufficient"),
            (
                8,
                b"MemTotal:       16777215 kB\nMemAvailable:    6291456 kB\n",
                "memory_insufficient",
            ),
            (
                8,
                b"MemTotal:       16777216 kB\nMemAvailable:    6291455 kB\n",
                "memory_insufficient",
            ),
        ):
            with self.subTest(host_cpu=cpu_count, code=expected_code):
                probe = host_probe
                if meminfo is not None:
                    def probe(path: Path, *, maximum_bytes: int, payload=meminfo) -> bytes:
                        del maximum_bytes
                        if path == Path("/proc/meminfo"):
                            return payload
                        if path == Path("/sys/fs/cgroup/cgroup.controllers"):
                            return b"cpu memory pids\n"
                        raise AssertionError(path)
                with (
                    mock.patch.object(preflight, "_read_proc_file", side_effect=probe),
                    mock.patch.object(preflight.os, "cpu_count", return_value=cpu_count),
                    mock.patch.object(preflight, "_filesystem_capacity") as capacity,
                    self.assertRaises(preflight.NativeLinuxFinalGatePreflightError) as captured,
                ):
                    preflight._host_resources(paths)
                self.assertEqual(expected_code, captured.exception.code)
                capacity.assert_not_called()

        args = self._args()
        output = preflight._FilesystemCapacity(
            "output", paths.output_parent, "ext4", 120 * gib, 200_000, (1, 1)
        )
        scratch = preflight._FilesystemCapacity(
            "scratch", paths.scratch_root, "xfs", 80 * gib, 200_000, (2, 2)
        )
        for name, value in (("NCPU", 7), ("MemTotal", 16 * gib - 1)):
            info = self._docker_info()
            info[name] = value
            daemon = preflight._DockerDaemonObservation(
                server_sha256=_SHA_A,
                info_sha256=_SHA_B,
                server={"Os": "linux", "Arch": "amd64"},
                info=info,
            )
            with (
                mock.patch.object(preflight, "_canonical_existing_path") as canonical,
                self.assertRaises(preflight.NativeLinuxFinalGatePreflightError) as captured,
            ):
                preflight._validate_docker_capabilities(
                    daemon,
                    paths=paths,
                    args=args,
                    filesystem_capacities={"output": output, "scratch": scratch},
                )
            self.assertEqual("docker_isolation_unavailable", captured.exception.code)
            canonical.assert_not_called()

    def test_docker_root_or_socket_overlap_is_fail_closed(self) -> None:
        gib = 1024**3
        paths = self._paths()
        args = self._args()
        daemon = preflight._DockerDaemonObservation(
            server_sha256=_SHA_A,
            info_sha256=_SHA_B,
            server={"Os": "linux", "Arch": "amd64"},
            info=self._docker_info(),
        )
        output = preflight._FilesystemCapacity(
            "output", paths.output_parent, "ext4", 120 * gib, 200_000, (1, 1)
        )
        scratch = preflight._FilesystemCapacity(
            "scratch", paths.scratch_root, "xfs", 80 * gib, 200_000, (2, 2)
        )
        docker = preflight._FilesystemCapacity(
            "docker", Path("/var/lib/docker"), "xfs", 80 * gib, 200_000, (3, 3)
        )
        with (
            mock.patch.object(
                preflight,
                "_canonical_existing_path",
                return_value=Path("/var/lib/docker"),
            ),
            mock.patch.object(preflight, "_filesystem_capacity", return_value=docker),
            mock.patch.object(preflight, "_paths_overlap", return_value=True),
            self.assertRaises(preflight.NativeLinuxFinalGatePreflightError) as captured,
        ):
            preflight._validate_docker_capabilities(
                daemon,
                paths=paths,
                args=args,
                filesystem_capacities={"output": output, "scratch": scratch},
            )
        self.assertEqual("runtime_storage_overlap", captured.exception.code)

    def test_control_nesting_uses_an_explicit_whitelist(self) -> None:
        task_root = Path("/srv/vulngym/input/test-sealed")
        injected_docker = task_root / "bin/docker"
        self.assertTrue(
            preflight._disallowed_control_overlap(
                None,
                task_root,
                injected_docker,
                allowed_nesting=frozenset(),
            )
        )
        control_root = Path("/srv/vulngym/control")
        plan = control_root / "plan.json"
        self.assertFalse(
            preflight._disallowed_control_overlap(
                None,
                control_root,
                plan,
                allowed_nesting=frozenset({(control_root, plan)}),
            )
        )

    def test_each_docker_probe_rechecks_host_before_and_after(self) -> None:
        result = mock.Mock(
            exit_code=0,
            timed_out=False,
            stdout_overflow=False,
            stderr_overflow=False,
            stdout=b"{}\n",
            stderr=b"",
        )
        socket_guard = mock.sentinel.socket_guard
        docker_root_guard = mock.sentinel.docker_root_guard
        mount_table = mock.sentinel.mount_table
        with (
            mock.patch.object(
                preflight, "run_bounded_process_v1", return_value=result
            ),
            mock.patch.object(preflight, "_assert_mount_table_stable") as mounts,
            mock.patch.object(preflight, "_assert_docker_socket_stable") as socket,
            mock.patch.object(preflight, "_assert_docker_root_stable") as root,
        ):
            payload = preflight._run_docker_bytes(
                Path("/usr/bin/docker"),
                "unix:///run/vulngym/docker.sock",
                Path("/tmp/docker-config"),
                ("version",),
                maximum_bytes=1024,
                socket_guard=socket_guard,
                docker_root_guard=docker_root_guard,
                mount_table=mount_table,
            )
        self.assertEqual(payload, b"{}\n")
        self.assertEqual(mounts.call_args_list, [mock.call(mount_table)] * 2)
        self.assertEqual(socket.call_args_list, [mock.call(socket_guard)] * 2)
        self.assertEqual(root.call_args_list, [mock.call(docker_root_guard)] * 2)

    def test_non_native_host_fails_before_any_path_or_docker_access(self) -> None:
        args = self._args()
        with (
            mock.patch.object(
                preflight,
                "_native_linux_bindings",
                side_effect=preflight.NativeLinuxFinalGatePreflightError(
                    "native_linux_required", "not Linux"
                ),
            ),
            mock.patch.object(preflight, "_validate_paths") as paths,
            mock.patch.object(preflight, "_run_docker_bytes") as docker,
        ):
            payload = preflight.run_native_linux_final_gate_preflight_v2(args)
        value = self._decode(payload)
        self.assertEqual(value["status"], "not_ready")
        checks = {item["name"]: item for item in value["checks"]}
        self.assertEqual(checks["native_linux_host"]["code"], "native_linux_required")
        self.assertEqual(checks["path_and_permission_contracts"]["status"], "not_checked")
        paths.assert_not_called()
        docker.assert_not_called()

    def test_invalid_remote_docker_endpoint_is_rejected_first(self) -> None:
        args = self._args()
        args.docker_host = "tcp://127.0.0.1:2375"
        with mock.patch.object(preflight, "_native_linux_bindings") as native:
            payload = preflight.run_native_linux_final_gate_preflight_v2(args)
        value = self._decode(payload)
        self.assertEqual(value["status"], "not_ready")
        self.assertEqual(value["checks"][0]["code"], "invalid_argument")
        native.assert_not_called()

    def test_static_test_failure_never_reads_train_key_or_docker(self) -> None:
        args = self._args()
        plan, policy, wire = self._plan()
        test_key = bytearray(b"T" * 40)
        with (
            mock.patch.object(
                preflight,
                "_native_linux_bindings",
                return_value={"host_identity_sha256": _SHA_A},
            ),
            mock.patch.object(preflight, "_validate_paths", return_value=self._paths()),
            mock.patch.object(
                preflight,
                "_load_and_bind_plan",
                return_value=(plan, policy, wire),
            ),
            mock.patch.object(
                preflight,
                "read_attestation_key_file_v1",
                return_value=test_key,
            ) as key_reader,
            mock.patch.object(
                preflight,
                "_static_verify_split",
                side_effect=preflight.NativeLinuxFinalGatePreflightError(
                    "static_input_invalid", "invalid"
                ),
            ) as static_reader,
            mock.patch.object(preflight, "_bind_docker_cli") as docker,
        ):
            payload = preflight.run_native_linux_final_gate_preflight_v2(args)
        value = self._decode(payload)
        self.assertEqual(value["status"], "not_ready")
        self.assertEqual(key_reader.call_count, 1)
        self.assertEqual(static_reader.call_count, 1)
        self.assertEqual(bytes(test_key), bytes(40))
        docker.assert_not_called()

    def test_all_mechanical_checks_and_bound_assertion_can_be_ready(self) -> None:
        args = self._args()
        plan, policy, wire = self._plan()
        test_key = bytearray(b"T" * 40)
        train_key = bytearray(b"R" * 40)
        daemon = preflight._DockerDaemonObservation(
            server_sha256=_SHA_B,
            info_sha256=_SHA_C,
            server={"Os": "linux", "Arch": "amd64"},
            info={"OSType": "linux", "Architecture": "x86_64"},
        )
        split_results = (
            {"task_count": 20, "execution_plan_sha256": "8" * 64},
            {"task_count": 50, "execution_plan_sha256": "9" * 64},
        )
        with (
            mock.patch.object(
                preflight,
                "_native_linux_bindings",
                return_value={
                    "host_identity_sha256": _SHA_E,
                    "kernel_release_sha256": _SHA_F,
                },
            ),
            mock.patch.object(preflight, "_validate_paths", return_value=self._paths()),
            mock.patch.object(
                preflight,
                "_load_and_bind_plan",
                return_value=(plan, policy, wire),
            ),
            mock.patch.object(
                preflight,
                "read_attestation_key_file_v1",
                side_effect=(test_key, train_key),
            ) as key_reader,
            mock.patch.object(
                preflight,
                "_static_verify_split",
                side_effect=split_results,
            ) as static_reader,
            mock.patch.object(
                preflight,
                "_host_resources",
                return_value=(
                    {"total_ram_bytes": preflight.MIN_TOTAL_RAM_BYTES},
                    {},
                ),
            ),
            mock.patch.object(
                preflight,
                "_bind_docker_cli",
                return_value=(_SHA_A, (1, 2, 3)),
            ),
            mock.patch.object(
                preflight,
                "_bind_docker_socket",
                return_value=(_SHA_D, (4, 5, 6)),
            ),
            mock.patch.object(
                preflight,
                "_bind_docker_root_guard",
                return_value=mock.sentinel.docker_root_guard,
            ),
            mock.patch.object(
                preflight, "_observe_docker_daemon", return_value=daemon
            ),
            mock.patch.object(
                preflight,
                "_validate_docker_capabilities",
                return_value={"docker_free_bytes": preflight.MIN_DOCKER_FREE_BYTES},
            ),
            mock.patch.object(
                preflight, "_observe_runtime_image", return_value=_SHA_D
            ),
            mock.patch.object(preflight, "_observe_daemon_cleanliness"),
            mock.patch.object(preflight, "_assert_runtime_bindings_stable"),
            mock.patch.object(
                preflight, "_assert_docker_host_stable"
            ) as final_stable,
            mock.patch.object(
                preflight, "_verify_operator_assertion", return_value=_SHA_A
            ),
        ):
            payload = preflight.run_native_linux_final_gate_preflight_v2(args)
            value = self._decode(payload)
            self.assertEqual(value["status"], "ready")
            self.assertTrue(
                all(item["status"] == "ready" for item in value["checks"])
            )
            self.assertEqual(
                static_reader.call_args_list[0].kwargs["split_plan"].split,
                "test",
            )
            self.assertEqual(
                static_reader.call_args_list[1].kwargs["split_plan"].split,
                "train",
            )
            self.assertEqual(bytes(test_key), bytes(40))
            self.assertEqual(bytes(train_key), bytes(40))
            self.assertEqual(final_stable.call_count, 1)

            drift_test_key = bytearray(b"U" * 40)
            drift_train_key = bytearray(b"V" * 40)
            key_reader.side_effect = (drift_test_key, drift_train_key)
            static_reader.side_effect = split_results
            final_stable.side_effect = preflight.NativeLinuxFinalGatePreflightError(
                "mount_evidence_changed", "mount namespace changed"
            )
            drift = self._decode(
                preflight.run_native_linux_final_gate_preflight_v2(args)
            )
            self.assertEqual(drift["status"], "not_ready")
            assertion_check = next(
                item
                for item in drift["checks"]
                if item["name"] == "operator_external_isolation_assertion"
            )
            self.assertEqual(
                assertion_check["code"], "mount_evidence_changed"
            )
            self.assertEqual(bytes(drift_test_key), bytes(40))
            self.assertEqual(bytes(drift_train_key), bytes(40))

    def test_operator_assertion_is_exact_canonical_and_fully_bound(self) -> None:
        args = self._args()
        paths = self._paths()
        bindings = {
            "daemon_endpoint_sha256": _SHA_A,
            "daemon_info_sha256": _SHA_B,
            "docker_executable_sha256": _SHA_C,
            "docker_socket_identity_sha256": _SHA_D,
            "final_gate_plan_sha256": _SHA_E,
            "final_gate_plan_wire_sha256": _SHA_F,
            "host_identity_sha256": "1" * 64,
            "runtime_image_id": _IMAGE,
            "runtime_image_inspect_sha256": "2" * 64,
            "server_observation_sha256": "3" * 64,
        }
        assertion = {
            "contract_version": 2,
            "kind": preflight.OPERATOR_ASSERTION_KIND,
            **bindings,
            "exclusive_docker_daemon": True,
            "exclusive_native_linux_host": True,
            "host_egress_disabled_for_gate": True,
            "no_concurrent_docker_clients": True,
            "scoring_gold_physically_isolated": True,
        }
        payload = preflight._canonical_json(assertion) + b"\n"
        args.expected_operator_assertion_wire_sha256 = hashlib.sha256(payload).hexdigest()
        with mock.patch.object(
            preflight, "_stable_regular_bytes", return_value=payload
        ):
            actual = preflight._verify_operator_assertion(paths, args, bindings)
        self.assertEqual(actual, hashlib.sha256(payload).hexdigest())

        assertion["exclusive_docker_daemon"] = False
        invalid = preflight._canonical_json(assertion) + b"\n"
        args.expected_operator_assertion_wire_sha256 = hashlib.sha256(invalid).hexdigest()
        with (
            mock.patch.object(preflight, "_stable_regular_bytes", return_value=invalid),
            self.assertRaisesRegex(
                preflight.NativeLinuxFinalGatePreflightError,
                "operator assertion contract is invalid",
            ),
        ):
            preflight._verify_operator_assertion(paths, args, bindings)

    def test_duplicate_docker_json_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            preflight.NativeLinuxFinalGatePreflightError,
            "invalid JSON",
        ):
            preflight._parse_json_document(
                b'{"Os":"linux","Os":"windows"}\n', maximum_bytes=1024
            )

    def test_daemon_observation_binds_server_and_info_pins(self) -> None:
        args = self._args()
        paths = self._paths()
        server = {"ApiVersion": "1.55", "Arch": "amd64", "Os": "linux", "Version": "29"}
        info = self._docker_info()
        args.expected_docker_server_sha256 = hashlib.sha256(
            preflight._canonical_json(server)
        ).hexdigest()
        args.expected_docker_info_sha256 = preflight.docker_info_identity_sha256_v1(
            info
        )
        with mock.patch.object(
            preflight,
            "_run_docker_bytes",
            side_effect=(
                preflight._canonical_json(server) + b"\n",
                preflight._canonical_json(info) + b"\n",
            ),
        ):
            result = preflight._observe_docker_daemon(
                paths, args, Path("/tmp/config")
            )
        self.assertEqual(result.server, server)
        self.assertEqual(result.info, info)

    def test_docker_info_identity_excludes_volatile_counts_and_time(self) -> None:
        first = self._docker_info()
        first.update({"Containers": 0, "Images": 2, "SystemTime": "now"})
        second = dict(first)
        second.update({"Containers": 7, "Images": 99, "SystemTime": "later"})
        self.assertEqual(
            preflight.docker_info_identity_sha256_v1(first),
            preflight.docker_info_identity_sha256_v1(second),
        )
        second["KernelVersion"] = "6.9.0"
        self.assertNotEqual(
            preflight.docker_info_identity_sha256_v1(first),
            preflight.docker_info_identity_sha256_v1(second),
        )

    def test_missing_operator_assertion_is_explicitly_not_ready(self) -> None:
        args = self._args()
        paths = self._paths()
        paths = preflight._ValidatedPaths(
            **{
                field: getattr(paths, field)
                for field in paths.__dataclass_fields__
                if field != "operator_assertion_file"
            },
            operator_assertion_file=None,
        )
        args.operator_assertion_file = None
        args.expected_operator_assertion_wire_sha256 = None
        with self.assertRaisesRegex(
            preflight.NativeLinuxFinalGatePreflightError,
            "separately pinned",
        ):
            preflight._verify_operator_assertion(paths, args, {})


if __name__ == "__main__":
    unittest.main()
