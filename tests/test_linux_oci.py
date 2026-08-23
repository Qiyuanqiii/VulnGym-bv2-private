from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pickle
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import vulngym_agent.evaluator.linux_oci as linux_oci
from vulngym_agent.evaluator.bounded_process import BoundedProcessResultV1
from vulngym_agent.evaluator.contracts import ExecutionPolicyBindingV1


def _sha(marker: int) -> str:
    return f"{marker:064x}"


def _json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


_FIXTURE_SOURCE_ROOT = Path(os.path.abspath("e3-fixture-source"))
_FIXTURE_RUNTIME_ROOT = Path(os.path.abspath("e3-fixture-runtime"))
_FIXTURE_WRONG_SOURCE_ROOT = Path(os.path.abspath("e3-fixture-wrong-source"))


class LinuxOciTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ExecutionPolicyBindingV1(
            runtime_image_id="sha256:" + "a" * 64,
            d2_backend_id="replay",
            d2_model_id="offline-d2",
            d2_config_sha256=_sha(1),
            d3_backend_id="replay",
            d3_model_id="offline-d3",
            d3_config_sha256=_sha(2),
            snapshot_policy_sha256=_sha(3),
            d2_budget_sha256=_sha(4),
            d3_budget_sha256=_sha(5),
            tree_limits_sha256=_sha(6),
        )
        self.lease = mock.Mock(spec=linux_oci._ExecutableLease)
        self.lease.execution_spec.return_value = (None, (), "NUL")
        self.executable = linux_oci._ExecutableBinding(
            "C:\\Docker\\docker.exe",
            _sha(7),
            (1, 2, 3, 4, 5),
            self.lease,
        )
        self.server = {
            "Version": "29.6.2",
            "ApiVersion": "1.55",
            "Os": "linux",
            "Arch": "amd64",
        }
        self.image = {
            "Id": self.policy.runtime_image_id,
            "Os": "linux",
            "Architecture": "amd64",
            "RepoTags": ["vulngym/evaluator:test"],
            "RepoDigests": [],
            "Config": {
                "Entrypoint": [
                    "/usr/local/bin/python3",
                    "-I",
                    "-B",
                    "-m",
                    "vulngym_agent.evaluator.oci_worker_entry",
                ],
                "Cmd": [],
                "User": "65532:65532",
                "WorkingDir": "/opt/vulngym",
                "Labels": {
                    "org.opencontainers.image.title": "VulnGym isolated evaluator worker",
                    "org.opencontainers.image.version": "source-discovery-isolated-worker-v1",
                },
            },
            "RootFS": {
                "Type": "layers",
                "Layers": ["sha256:" + "8" * 64, "sha256:" + "9" * 64],
            },
        }

    def _runtime(self):
        with mock.patch.object(
            linux_oci, "_bind_executable", return_value=self.executable
        ), mock.patch.object(
            linux_oci,
            "_resolve_local_docker_endpoint",
            return_value="npipe:////./pipe/docker_engine",
        ), mock.patch.object(
            linux_oci,
            "_run_probe",
            side_effect=(_json(self.server), _json(self.image)),
        ):
            return linux_oci.verify_linux_oci_runtime_v1(
                self.executable.path, execution_policy=self.policy
            )

    def test_runtime_verification_binds_linux_image_and_is_opaque(self) -> None:
        runtime = self._runtime()
        self.assertEqual(runtime.execution_policy, self.policy)
        self.assertEqual(runtime.server_arch, "amd64")
        self.assertEqual(
            runtime.docker_endpoint, "npipe:////./pipe/docker_engine"
        )
        self.assertEqual(runtime.docker_executable_sha256, _sha(7))
        self.assertEqual(
            runtime.server_sha256,
            hashlib.sha256(linux_oci._canonical_json(self.server)).hexdigest(),
        )
        with self.assertRaises(TypeError):
            pickle.dumps(runtime)

    def test_runtime_rejects_non_linux_and_image_substitution(self) -> None:
        bad_server = {**self.server, "Os": "windows"}
        with mock.patch.object(
            linux_oci, "_bind_executable", return_value=self.executable
        ), mock.patch.object(
            linux_oci,
            "_resolve_local_docker_endpoint",
            return_value="npipe:////./pipe/docker_engine",
        ), mock.patch.object(
            linux_oci,
            "_run_probe",
            side_effect=(_json(bad_server), _json(self.image)),
        ):
            with self.assertRaisesRegex(
                linux_oci.LinuxOciProviderError, "supported Linux"
            ):
                linux_oci.verify_linux_oci_runtime_v1(
                    self.executable.path, execution_policy=self.policy
                )
        bad_image = {**self.image, "Id": "sha256:" + "b" * 64}
        with mock.patch.object(
            linux_oci, "_bind_executable", return_value=self.executable
        ), mock.patch.object(
            linux_oci,
            "_resolve_local_docker_endpoint",
            return_value="npipe:////./pipe/docker_engine",
        ), mock.patch.object(
            linux_oci,
            "_run_probe",
            side_effect=(_json(self.server), _json(bad_image)),
        ):
            with self.assertRaises(linux_oci.LinuxOciProviderError) as caught:
                linux_oci.verify_linux_oci_runtime_v1(
                    self.executable.path, execution_policy=self.policy
                )
            self.assertEqual(caught.exception.code, "image_mismatch")

    def test_create_argv_is_fixed_and_task_values_cannot_supply_commands(self) -> None:
        runtime = self._runtime()
        name = "vulngym-e3-" + "1" * 32
        execution_image_id = "sha256:" + "b" * 64
        execute = linux_oci.build_worker_container_create_argv_v1(
            runtime,
            container_name=name,
            mode="execute",
            execution_image_id=execution_image_id,
        )
        self.assertEqual(execute[-2:], (execution_image_id, "execute"))
        self.assertIn("--network=none", execute)
        self.assertIn("--read-only", execute)
        self.assertIn("--cap-drop=ALL", execute)
        self.assertIn("--security-opt=no-new-privileges=true", execute)
        self.assertIn("--user=65532:65532", execute)
        self.assertNotIn("--mount", execute)
        self.assertFalse(any("volume" in item for item in execute))
        self.assertFalse(any("entrypoint" in item for item in execute))
        with self.assertRaises(linux_oci.LinuxOciProviderError):
            linux_oci.build_worker_container_create_argv_v1(
                runtime,
                container_name=name,
                mode="execute;sh",
                execution_image_id=execution_image_id,
            )
        materialize = linux_oci.build_worker_container_create_argv_v1(
            runtime,
            container_name=name,
            mode="materialize",
            source_root=_FIXTURE_SOURCE_ROOT,
            runtime_input_root=_FIXTURE_RUNTIME_ROOT,
        )
        self.assertEqual(materialize[-1], "materialize")
        self.assertIn("--user=65532:65532", materialize)
        self.assertNotIn("--read-only", materialize)
        self.assertEqual(sum("--mount" == item for item in materialize), 2)

    def _inspect(self, runtime, *, mode: str = "execute") -> dict[str, object]:
        policy = runtime.execution_policy
        name = "vulngym-e3-" + "1" * 32
        execution_image_id = "sha256:" + "b" * 64
        execution_label = "vulngym-e3-" + "2" * 32
        image_id = policy.runtime_image_id if mode == "materialize" else execution_image_id
        labels = {
            "org.opencontainers.image.title": "VulnGym isolated evaluator worker",
            "org.opencontainers.image.version": "source-discovery-isolated-worker-v1",
            "vulngym.e3.container": name,
        }
        if mode == "execute":
            labels["vulngym.e3.execution"] = execution_label
        hostname = "vulngym-materializer" if mode == "materialize" else "vulngym-worker"
        mounts = (
            [
                {
                    "Type": "bind",
                    "Source": os.fspath(_FIXTURE_SOURCE_ROOT),
                    "Destination": "/input-source",
                    "Mode": "",
                    "RW": False,
                    "Propagation": "rprivate",
                },
                {
                    "Type": "bind",
                    "Source": os.fspath(_FIXTURE_RUNTIME_ROOT),
                    "Destination": "/input-runtime",
                    "Mode": "",
                    "RW": False,
                    "Propagation": "rprivate",
                },
            ]
            if mode == "materialize"
            else []
        )
        host_mounts = (
            [
                {
                    "Type": "bind",
                    "Source": os.fspath(_FIXTURE_SOURCE_ROOT),
                    "Target": "/input-source",
                    "ReadOnly": True,
                    "BindOptions": {
                        "Propagation": "rprivate",
                        "ReadOnlyForceRecursive": True,
                    },
                },
                {
                    "Type": "bind",
                    "Source": os.fspath(_FIXTURE_RUNTIME_ROOT),
                    "Target": "/input-runtime",
                    "ReadOnly": True,
                    "BindOptions": {
                        "Propagation": "rprivate",
                        "ReadOnlyForceRecursive": True,
                    },
                },
            ]
            if mode == "materialize"
            else []
        )
        return {
            "Id": "3" * 64,
            "Name": "/" + name,
            "Image": image_id,
            "Config": {
                "Image": image_id,
                "User": "65532:65532",
                "Hostname": hostname,
                "WorkingDir": "/tmp",
                "Entrypoint": [
                    "/usr/local/bin/python3",
                    "-I",
                    "-B",
                    "-m",
                    "vulngym_agent.evaluator.oci_worker_entry",
                ],
                "Cmd": [mode],
                "AttachStdin": False,
                "AttachStdout": True,
                "AttachStderr": True,
                "Tty": False,
                "OpenStdin": False,
                "StdinOnce": False,
                "Healthcheck": {"Test": ["NONE"]},
                "Volumes": None,
                "ExposedPorts": None,
                "Labels": labels,
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": mode == "execute",
                "Privileged": False,
                "PublishAllPorts": False,
                "AutoRemove": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "GroupAdd": None,
                "SecurityOpt": ["no-new-privileges=true"],
                "PidsLimit": policy.pids_limit,
                "Memory": policy.memory_bytes,
                "MemorySwap": policy.memory_bytes,
                "CpuPeriod": 100000,
                "CpuQuota": policy.cpu_millis * 100,
                "IpcMode": "none",
                "CgroupnsMode": "private",
                "PidMode": "",
                "UTSMode": "",
                "UsernsMode": "",
                "Runtime": "runc",
                "RestartPolicy": {"Name": "no"},
                "LogConfig": {"Type": "none"},
                "Ulimits": [
                    {
                        "Name": "nofile",
                        "Hard": policy.open_files_limit,
                        "Soft": policy.open_files_limit,
                    }
                ],
                "Devices": [],
                "DeviceCgroupRules": None,
                "DeviceRequests": None,
                "Binds": None,
                "Mounts": host_mounts,
                "PortBindings": {},
                "Links": None,
                "Dns": [],
                "DnsOptions": [],
                "DnsSearch": [],
                "ExtraHosts": None,
                "OomKillDisable": None,
                "Init": None,
                "CgroupParent": "",
                "MaskedPaths": [
                    "/proc/acpi",
                    "/proc/asound",
                    "/proc/interrupts",
                    "/proc/kcore",
                    "/proc/keys",
                    "/proc/latency_stats",
                    "/proc/sched_debug",
                    "/proc/scsi",
                    "/proc/timer_list",
                    "/proc/timer_stats",
                    "/sys/devices/virtual/powercap",
                    "/sys/firmware",
                ],
                "ReadonlyPaths": [
                    "/proc/bus",
                    "/proc/fs",
                    "/proc/irq",
                    "/proc/sys",
                    "/proc/sysrq-trigger",
                ],
                "Tmpfs": {
                    "/tmp": (
                        "rw,noexec,nosuid,nodev,"
                        f"size={policy.tmpfs_bytes},mode=0700,uid=65532,gid=65532"
                    )
                },
            },
            "Mounts": mounts,
            "NetworkSettings": {
                "SandboxID": "",
                "SandboxKey": "",
                "Ports": {},
                "Networks": {
                    "none": {
                        "IPAMConfig": None,
                        "Links": None,
                        "Aliases": None,
                        "DriverOpts": None,
                        "GwPriority": 0,
                        "NetworkID": "",
                        "EndpointID": "",
                        "Gateway": "",
                        "IPAddress": "",
                        "MacAddress": "",
                        "IPPrefixLen": 0,
                        "IPv6Gateway": "",
                        "GlobalIPv6Address": "",
                        "GlobalIPv6PrefixLen": 0,
                        "DNSNames": None,
                    }
                },
            },
        }

    def test_inspect_is_strict_and_normalizes_host_paths(self) -> None:
        runtime = self._runtime()
        name = "vulngym-e3-" + "1" * 32
        execution_label = "vulngym-e3-" + "2" * 32
        execution_image_id = "sha256:" + "b" * 64
        normalized = linux_oci.normalized_container_inspect_v1(
            _json(self._inspect(runtime)),
            runtime=runtime,
            container_name=name,
            mode="execute",
            execution_image_id=execution_image_id,
            execution_image_label=execution_label,
        )
        self.assertEqual(normalized["container_id"], "3" * 64)
        self.assertEqual(normalized["mounts"], [])
        self.assertRegex(
            linux_oci.container_inspect_sha256_v1(normalized), r"^[0-9a-f]{64}$"
        )
        tampered = self._inspect(runtime)
        tampered["HostConfig"]["NetworkMode"] = "bridge"  # type: ignore[index]
        with self.assertRaises(linux_oci.LinuxOciProviderError) as caught:
            linux_oci.normalized_container_inspect_v1(
                _json(tampered),
                runtime=runtime,
                container_name=name,
                mode="execute",
                execution_image_id=execution_image_id,
                execution_image_label=execution_label,
            )
        self.assertEqual(caught.exception.code, "invalid_container")

        config_drifted = self._inspect(runtime)
        config_drifted["Config"]["Hostname"] = "unexpected"  # type: ignore[index]
        with self.assertRaises(linux_oci.LinuxOciProviderError) as captured:
            linux_oci.normalized_container_inspect_v1(
                _json(config_drifted),
                runtime=runtime,
                container_name=name,
                mode="execute",
                execution_image_id=execution_image_id,
                execution_image_label=execution_label,
            )
        self.assertEqual(
            str(captured.exception), "container hostname configuration drifted"
        )

        drifts = (
            ("CapAdd", ["SYS_ADMIN"]),
            ("GroupAdd", ["0"]),
            ("PidMode", "host"),
            ("UsernsMode", "host"),
            ("DeviceRequests", [{"Driver": ""}]),
            ("SecurityOpt", ["no-new-privileges=true", "seccomp=unconfined"]),
            ("Tmpfs", {}),
            ("MaskedPaths", []),
            ("ReadonlyPaths", []),
        )
        for field_name, replacement in drifts:
            with self.subTest(field_name=field_name):
                drifted = json.loads(json.dumps(self._inspect(runtime)))
                drifted["HostConfig"][field_name] = replacement
                with self.assertRaises(linux_oci.LinuxOciProviderError) as captured:
                    linux_oci.normalized_container_inspect_v1(
                        _json(drifted),
                        runtime=runtime,
                        container_name=name,
                        mode="execute",
                        execution_image_id=execution_image_id,
                        execution_image_label=execution_label,
                    )
                self.assertEqual(captured.exception.code, "invalid_container")

        extra_network = json.loads(json.dumps(self._inspect(runtime)))
        extra_network["NetworkSettings"]["Networks"]["bridge"] = {}
        with self.assertRaises(linux_oci.LinuxOciProviderError):
            linux_oci.normalized_container_inspect_v1(
                _json(extra_network),
                runtime=runtime,
                container_name=name,
                mode="execute",
                execution_image_id=execution_image_id,
                execution_image_label=execution_label,
            )

        network_content_drift = json.loads(json.dumps(self._inspect(runtime)))
        network_content_drift["NetworkSettings"]["Networks"]["none"][
            "IPAddress"
        ] = "192.0.2.1"
        with self.assertRaises(linux_oci.LinuxOciProviderError):
            linux_oci.normalized_container_inspect_v1(
                _json(network_content_drift),
                runtime=runtime,
                container_name=name,
                mode="execute",
                execution_image_id=execution_image_id,
                execution_image_label=execution_label,
            )

    def test_inspect_binds_all_pinned_base_image_labels(self) -> None:
        base_labels = self.image["Config"]["Labels"]
        base_labels["runner.example/build"] = "fixed-build-metadata"
        runtime = self._runtime()
        name = "vulngym-e3-" + "1" * 32
        execution_label = "vulngym-e3-" + "2" * 32
        execution_image_id = "sha256:" + "b" * 64
        observed = self._inspect(runtime)
        observed["Config"]["Labels"]["runner.example/build"] = (
            "fixed-build-metadata"
        )
        normalized = linux_oci.normalized_container_inspect_v1(
            _json(observed),
            runtime=runtime,
            container_name=name,
            mode="execute",
            execution_image_id=execution_image_id,
            execution_image_label=execution_label,
        )
        self.assertEqual(normalized["container_id"], "3" * 64)

        observed["Config"]["Labels"]["runner.example/build"] = "changed"
        with self.assertRaises(linux_oci.LinuxOciProviderError) as captured:
            linux_oci.normalized_container_inspect_v1(
                _json(observed),
                runtime=runtime,
                container_name=name,
                mode="execute",
                execution_image_id=execution_image_id,
                execution_image_label=execution_label,
            )
        self.assertEqual(
            str(captured.exception), "container labels configuration drifted"
        )

    def test_materializer_mounts_bind_exact_sources_and_force_recursive_readonly(
        self,
    ) -> None:
        runtime = self._runtime()
        name = "vulngym-e3-" + "1" * 32
        source_root = _FIXTURE_SOURCE_ROOT
        runtime_root = _FIXTURE_RUNTIME_ROOT
        normalized = linux_oci.normalized_container_inspect_v1(
            _json(self._inspect(runtime, mode="materialize")),
            runtime=runtime,
            container_name=name,
            mode="materialize",
            source_root=source_root,
            runtime_input_root=runtime_root,
        )
        self.assertTrue(normalized["recursive_readonly_bind"])
        normalized_json = json.dumps(normalized)
        for host_path in (source_root, runtime_root):
            escaped_host_path = json.dumps(os.fspath(host_path))[1:-1]
            self.assertNotIn(escaped_host_path, normalized_json)

        for location, index, field, replacement in (
            ("Mounts", 0, "Source", os.fspath(_FIXTURE_WRONG_SOURCE_ROOT)),
            ("HostConfig", 0, "Source", os.fspath(_FIXTURE_WRONG_SOURCE_ROOT)),
            (
                "HostConfig",
                0,
                "BindOptions",
                {"Propagation": "rprivate", "ReadOnlyForceRecursive": False},
            ),
        ):
            with self.subTest(location=location, field=field):
                drifted = json.loads(json.dumps(self._inspect(runtime, mode="materialize")))
                records = (
                    drifted["Mounts"]
                    if location == "Mounts"
                    else drifted["HostConfig"]["Mounts"]
                )
                records[index][field] = replacement
                with self.assertRaises(linux_oci.LinuxOciProviderError) as caught:
                    linux_oci.normalized_container_inspect_v1(
                        _json(drifted),
                        runtime=runtime,
                        container_name=name,
                        mode="materialize",
                        source_root=source_root,
                        runtime_input_root=runtime_root,
                    )
                self.assertEqual(caught.exception.code, "invalid_container")

    def test_inspect_accepts_exact_legacy_empty_network_shape(self) -> None:
        runtime = self._runtime()
        name = "vulngym-e3-" + "1" * 32
        execution_label = "vulngym-e3-" + "2" * 32
        execution_image_id = "sha256:" + "b" * 64
        legacy = self._inspect(runtime)
        network = legacy["NetworkSettings"]
        network.update(
            {
                "Bridge": "",
                "EndpointID": "",
                "Gateway": "",
                "GlobalIPv6Address": "",
                "GlobalIPv6PrefixLen": 0,
                "HairpinMode": False,
                "IPAddress": "",
                "IPPrefixLen": 0,
                "IPv6Gateway": "",
                "LinkLocalIPv6Address": "",
                "LinkLocalIPv6PrefixLen": 0,
                "MacAddress": "",
                "SecondaryIPAddresses": None,
                "SecondaryIPv6Addresses": None,
            }
        )
        legacy["HostConfig"]["MaskedPaths"].reverse()
        normalized = linux_oci.normalized_container_inspect_v1(
            _json(legacy),
            runtime=runtime,
            container_name=name,
            mode="execute",
            execution_image_id=execution_image_id,
            execution_image_label=execution_label,
        )
        self.assertEqual(normalized["network_mode"], "none")

        for field_name, replacement in (
            ("HairpinMode", True),
            ("SecondaryIPAddresses", []),
            ("Bridge", "docker0"),
        ):
            with self.subTest(field_name=field_name):
                drifted = json.loads(json.dumps(legacy))
                drifted["NetworkSettings"][field_name] = replacement
                with self.assertRaisesRegex(
                    linux_oci.LinuxOciProviderError,
                    "network policy drifted",
                ):
                    linux_oci.normalized_container_inspect_v1(
                        _json(drifted),
                        runtime=runtime,
                        container_name=name,
                        mode="execute",
                        execution_image_id=execution_image_id,
                        execution_image_label=execution_label,
                    )

    def _derived_image(self) -> dict[str, object]:
        labels = dict(self.image["Config"]["Labels"])  # type: ignore[index]
        labels.update(
            {
                "vulngym.e3.container": "vulngym-e3-" + "1" * 32,
                "vulngym.e3.execution": "vulngym-e3-" + "2" * 32,
            }
        )
        labels.update(linux_oci._SCRUBBED_DERIVED_IMAGE_LABELS)
        return {
            "Id": "sha256:" + "b" * 64,
            "Parent": self.policy.runtime_image_id,
            "Container": "3" * 64,
            "RepoTags": [],
            "RepoDigests": [],
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {
                "Entrypoint": [
                    "/usr/local/bin/python3",
                    "-I",
                    "-B",
                    "-m",
                    "vulngym_agent.evaluator.oci_worker_entry",
                ],
                "Cmd": ["materialize"],
                "User": "65532:65532",
                "WorkingDir": "/tmp",
                "Hostname": "vulngym-materializer",
                "Labels": labels,
                "Volumes": None,
                "ExposedPorts": None,
            },
            "RootFS": {
                "Type": "layers",
                "Layers": [
                    *self.image["RootFS"]["Layers"],  # type: ignore[index]
                    "sha256:" + "c" * 64,
                ],
            },
        }

    def test_derived_image_is_untagged_and_adds_exactly_one_layer(self) -> None:
        runtime = self._runtime()
        normalized = linux_oci._normalized_execution_image_inspect_v1(
            _json(self._derived_image()),
            runtime=runtime,
            image_id="sha256:" + "b" * 64,
            label="vulngym-e3-" + "2" * 32,
            materializer_container_id="3" * 64,
            materializer_name="vulngym-e3-" + "1" * 32,
            base_image=self.image,
        )
        self.assertEqual(normalized["base_layer_count"], 2)
        self.assertEqual(normalized["repo_tags"], [])
        tampered = self._derived_image()
        tampered["RepoTags"] = ["forbidden:tag"]
        with self.assertRaises(linux_oci.LinuxOciProviderError) as caught:
            linux_oci._normalized_execution_image_inspect_v1(
                _json(tampered),
                runtime=runtime,
                image_id="sha256:" + "b" * 64,
                label="vulngym-e3-" + "2" * 32,
                materializer_container_id="3" * 64,
                materializer_name="vulngym-e3-" + "1" * 32,
                base_image=self.image,
            )
        self.assertEqual(caught.exception.code, "invalid_image")

    def test_create_spec_binds_derived_image_and_has_no_execution_mounts(self) -> None:
        runtime = self._runtime()
        image_id = "sha256:" + "b" * 64
        execute = linux_oci.container_create_spec_sha256_v1(
            runtime, mode="execute", execution_image_id=image_id
        )
        materialize = linux_oci.container_create_spec_sha256_v1(
            runtime, mode="materialize"
        )
        self.assertRegex(execute, r"^[0-9a-f]{64}$")
        self.assertNotEqual(execute, materialize)
        with self.assertRaises(linux_oci.LinuxOciProviderError):
            linux_oci.container_create_spec_sha256_v1(runtime, mode="execute")

    def test_diff_allows_only_generation_changes_and_execute_is_truly_empty(self) -> None:
        runtime = self._runtime()
        materializer_pre = linux_oci.normalized_container_inspect_v1(
            _json(self._inspect(runtime, mode="materialize")),
            runtime=runtime,
            container_name="vulngym-e3-" + "1" * 32,
            mode="materialize",
            source_root=_FIXTURE_SOURCE_ROOT,
            runtime_input_root=_FIXTURE_RUNTIME_ROOT,
        )
        materializer = linux_oci._WorkerContainerV1(
            linux_oci._RUNTIME_TOKEN,
            runtime=runtime,
            container_id="3" * 64,
            name="vulngym-e3-" + "1" * 32,
            mode="materialize",
            execution_image_id=self.policy.runtime_image_id,
            execution_image_label=None,
            source_root=_FIXTURE_SOURCE_ROOT,
            runtime_input_root=_FIXTURE_RUNTIME_ROOT,
            pre_inspect=materializer_pre,
        )
        clean = BoundedProcessResultV1(
            exit_code=0,
            stdout=(
                b"A /input-runtime\nA /input-source\nC /vulngym\n"
                b"A /vulngym/source\nA /vulngym/runtime\n"
            ),
            stderr=b"",
            timed_out=False,
            stdout_overflow=False,
            stderr_overflow=False,
        )
        with mock.patch.object(linux_oci, "_runtime_command", return_value=clean):
            digest, empty = linux_oci._container_diff_v1(materializer)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertFalse(empty)
        escaped = BoundedProcessResultV1(
            exit_code=0,
            stdout=b"C /vulngym\nA /etc/escape\n",
            stderr=b"",
            timed_out=False,
            stdout_overflow=False,
            stderr_overflow=False,
        )
        with mock.patch.object(linux_oci, "_runtime_command", return_value=escaped):
            with self.assertRaises(linux_oci.LinuxOciProviderError):
                linux_oci._container_diff_v1(materializer)

        execute_pre = linux_oci.normalized_container_inspect_v1(
            _json(self._inspect(runtime)),
            runtime=runtime,
            container_name="vulngym-e3-" + "1" * 32,
            mode="execute",
            execution_image_id="sha256:" + "b" * 64,
            execution_image_label="vulngym-e3-" + "2" * 32,
        )
        execute = linux_oci._WorkerContainerV1(
            linux_oci._RUNTIME_TOKEN,
            runtime=runtime,
            container_id="3" * 64,
            name="vulngym-e3-" + "1" * 32,
            mode="execute",
            execution_image_id="sha256:" + "b" * 64,
            execution_image_label="vulngym-e3-" + "2" * 32,
            source_root=None,
            runtime_input_root=None,
            pre_inspect=execute_pre,
        )
        empty_result = BoundedProcessResultV1(
            exit_code=0,
            stdout=b"",
            stderr=b"",
            timed_out=False,
            stdout_overflow=False,
            stderr_overflow=False,
        )
        with mock.patch.object(
            linux_oci, "_runtime_command", return_value=empty_result
        ):
            _digest, empty = linux_oci._container_diff_v1(execute)
        self.assertTrue(empty)

    def test_worker_protocol_error_is_exact_and_path_free(self) -> None:
        payload = {
            "code": "runtime_mount_probe_failed",
            "contract_version": 1,
            "kind": "vulngym.oci-worker-error.v1",
            "mode": "materialize",
        }
        result = BoundedProcessResultV1(
            2, b"", _json(payload), False, False, False
        )
        self.assertEqual(
            linux_oci._worker_protocol_error_code_v1(
                result, mode="materialize"
            ),
            "runtime_mount_probe_failed",
        )
        for stderr in (
            json.dumps(payload).encode() + b"\n",
            _json({**payload, "host_path": "C:\\secret"}),
            _json({**payload, "contract_version": True}),
            _json({**payload, "mode": "execute"}),
        ):
            with self.subTest(stderr=stderr):
                changed = BoundedProcessResultV1(
                    2, b"", stderr, False, False, False
                )
                self.assertIsNone(
                    linux_oci._worker_protocol_error_code_v1(
                        changed, mode="materialize"
                    )
                )

    @unittest.skipUnless(os.name == "posix", "requires POSIX openat semantics")
    def test_posix_source_copy_rejects_swapped_ancestor(self) -> None:
        payload = b"pinned-source\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            target_root = root / "target"
            outside = root / "outside"
            for directory in (source_root / "src", target_root / "src", outside):
                directory.mkdir(parents=True)
            (source_root / "src" / "app.py").write_bytes(payload)
            outside_payload = b"external-source\n"
            (outside / "app.py").write_bytes(outside_payload)
            record = SimpleNamespace(
                path="src/app.py",
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
            source_directory = source_root / "src"
            held_directory = source_root / "src-held"
            original_open = linux_oci._open_posix_directory_chain_v1
            attacked = False

            def swap_before_open(path: Path, components: tuple[str, ...]):
                nonlocal attacked
                if path == source_root and components == ("src",) and not attacked:
                    attacked = True
                    source_directory.rename(held_directory)
                    source_directory.symlink_to(outside, target_is_directory=True)
                    try:
                        return original_open(path, components)
                    finally:
                        source_directory.unlink()
                        held_directory.rename(source_directory)
                return original_open(path, components)

            with mock.patch.object(
                linux_oci,
                "_open_posix_directory_chain_v1",
                side_effect=swap_before_open,
            ):
                with self.assertRaises(
                    linux_oci.LinuxOciProviderError
                ) as captured:
                    linux_oci._copy_source_record_v1(
                        source_root, target_root, record
                    )
            self.assertTrue(attacked)
            self.assertEqual(captured.exception.code, "runtime_input_failed")
            self.assertFalse((target_root / "src" / "app.py").exists())
            self.assertEqual((outside / "app.py").read_bytes(), outside_payload)

    def test_staging_cleanup_failure_is_runtime_uncertain(self) -> None:
        cleanup = mock.Mock(side_effect=OSError("cleanup failed"))
        context = SimpleNamespace(cleanup=cleanup)
        primary = RuntimeError("primary failure")
        with self.assertRaises(linux_oci.LinuxOciProviderError) as captured:
            linux_oci._close_materializer_staging_v1(context, primary)
        self.assertEqual(captured.exception.code, "cleanup_uncertain")
        self.assertTrue(captured.exception.runtime_uncertain)
        self.assertIs(captured.exception.__cause__, primary)
        cleanup.assert_called_once_with()

        successful_cleanup = mock.Mock()
        context = SimpleNamespace(cleanup=successful_cleanup)
        with self.assertRaises(RuntimeError) as propagated:
            linux_oci._close_materializer_staging_v1(context, primary)
        self.assertIs(propagated.exception, primary)
        successful_cleanup.assert_called_once_with()

    def test_attached_start_uses_exact_policy_wall_time_for_both_modes(self) -> None:
        runtime = self._runtime()
        name = "vulngym-e3-" + "1" * 32
        result = BoundedProcessResultV1(0, b"", b"", False, False, False)
        cases = (
            (
                "materialize",
                self.policy.runtime_image_id,
                None,
                _FIXTURE_SOURCE_ROOT,
                _FIXTURE_RUNTIME_ROOT,
            ),
            ("execute", "sha256:" + "b" * 64, "vulngym-e3-" + "2" * 32, None, None),
        )
        for mode, image_id, label, source_root, runtime_root in cases:
            with self.subTest(mode=mode):
                inspect = linux_oci.normalized_container_inspect_v1(
                    _json(self._inspect(runtime, mode=mode)),
                    runtime=runtime,
                    container_name=name,
                    mode=mode,
                    execution_image_id=(image_id if mode == "execute" else None),
                    execution_image_label=label,
                    source_root=source_root,
                    runtime_input_root=runtime_root,
                )
                container = linux_oci._WorkerContainerV1(
                    linux_oci._RUNTIME_TOKEN,
                    runtime=runtime,
                    container_id="3" * 64,
                    name=name,
                    mode=mode,
                    execution_image_id=image_id,
                    execution_image_label=label,
                    source_root=source_root,
                    runtime_input_root=runtime_root,
                    pre_inspect=inspect,
                )
                with mock.patch.object(
                    linux_oci, "_runtime_command", return_value=result
                ) as command:
                    linux_oci._start_worker_container_v1(container)
                self.assertEqual(
                    command.call_args.kwargs["timeout_seconds"],
                    float(self.policy.wall_time_seconds),
                )

    def test_create_failure_reconciles_by_exact_name_without_trusting_label(
        self,
    ) -> None:
        runtime = self._runtime()
        name = "vulngym-e3-" + "1" * 32
        container_id = "3" * 64
        tampered = self._inspect(runtime, mode="materialize")
        tampered["Config"]["Labels"]["vulngym.e3.container"] = (
            "vulngym-e3-" + "9" * 32
        )

        def completed(stdout: bytes) -> BoundedProcessResultV1:
            return BoundedProcessResultV1(0, stdout, b"", False, False, False)

        responses = (
            completed((container_id + "\n").encode("ascii")),
            completed(_json(tampered)),
            completed((container_id + "\n").encode("ascii")),
            completed((container_id + "\n").encode("ascii")),
            completed(b""),
        )
        with mock.patch.object(
            linux_oci.secrets, "token_hex", return_value="1" * 32
        ), mock.patch.object(
            linux_oci, "_runtime_command", side_effect=responses
        ) as command:
            with self.assertRaises(linux_oci.LinuxOciProviderError) as caught:
                linux_oci._create_worker_container_v1(
                    runtime,
                    mode="materialize",
                    source_root=_FIXTURE_SOURCE_ROOT,
                    runtime_input_root=_FIXTURE_RUNTIME_ROOT,
                )
        self.assertEqual(caught.exception.code, "invalid_container")
        lookup = command.call_args_list[2].args[1]
        self.assertIn(f"name=^/{name}$", lookup)
        self.assertFalse(any("label=" in item for item in lookup))
        self.assertEqual(
            command.call_args_list[3].args[1],
            ("container", "rm", "--force", container_id),
        )

    def test_create_failure_with_ambiguous_exact_name_is_cleanup_uncertain(
        self,
    ) -> None:
        runtime = self._runtime()
        container_id = "3" * 64
        tampered = self._inspect(runtime, mode="materialize")
        tampered["Config"]["Labels"]["vulngym.e3.container"] = (
            "vulngym-e3-" + "9" * 32
        )

        def completed(stdout: bytes) -> BoundedProcessResultV1:
            return BoundedProcessResultV1(0, stdout, b"", False, False, False)

        responses = (
            completed((container_id + "\n").encode("ascii")),
            completed(_json(tampered)),
            completed(((container_id + "\n") + ("4" * 64) + "\n").encode("ascii")),
        )
        with mock.patch.object(
            linux_oci.secrets, "token_hex", return_value="1" * 32
        ), mock.patch.object(linux_oci, "_runtime_command", side_effect=responses):
            with self.assertRaises(linux_oci.LinuxOciProviderError) as caught:
                linux_oci._create_worker_container_v1(
                    runtime,
                    mode="materialize",
                    source_root=_FIXTURE_SOURCE_ROOT,
                    runtime_input_root=_FIXTURE_RUNTIME_ROOT,
                )
        self.assertEqual(caught.exception.code, "cleanup_uncertain")
        self.assertTrue(caught.exception.runtime_uncertain)

    def test_strict_json_rejects_duplicate_keys_and_constants(self) -> None:
        with self.assertRaises(linux_oci.LinuxOciProviderError):
            linux_oci._strict_json_document(b'{"a":1,"a":2}\n', name="probe")
        with self.assertRaises(linux_oci.LinuxOciProviderError):
            linux_oci._strict_json_document(b'{"a":NaN}\n', name="probe")

    def test_only_local_daemon_endpoints_are_accepted(self) -> None:
        self.assertEqual(
            linux_oci._local_docker_endpoint(
                "npipe:////./pipe/dockerDesktopLinuxEngine"
            ),
            "npipe:////./pipe/dockerDesktopLinuxEngine",
        )
        self.assertEqual(
            linux_oci._local_docker_endpoint("unix:///var/run/docker.sock"),
            "unix:///var/run/docker.sock",
        )
        for endpoint in (
            "tcp://127.0.0.1:2375",
            "ssh://builder",
            "http://localhost",
            "unix:///var/run/../docker.sock",
            "npipe:////./pipe/docker/other",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(
                linux_oci.LinuxOciProviderError
            ) as caught:
                linux_oci._local_docker_endpoint(endpoint)
            self.assertEqual(caught.exception.code, "unsupported_runtime")

    def test_runtime_command_pins_endpoint_and_ignores_docker_environment(self) -> None:
        runtime = self._runtime()
        result = BoundedProcessResultV1(0, b"ok", b"", False, False, False)
        with mock.patch.object(
            linux_oci, "run_bounded_process_v1", return_value=result
        ) as run:
            self.assertIs(linux_oci._runtime_command(runtime, ("version",)), result)
        argv = run.call_args.args[0]
        self.assertEqual(
            argv[:4],
            (
                self.executable.path,
                "--host=npipe:////./pipe/docker_engine",
                "--config=NUL",
                "version",
            ),
        )
        env = run.call_args.kwargs["env"]
        for name in (
            "DOCKER_CONFIG",
            "DOCKER_CONTEXT",
            "DOCKER_HOST",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "HOME",
            "USERPROFILE",
        ):
            self.assertNotIn(name, env)

    @unittest.skipUnless(os.name == "nt", "requires Windows mandatory sharing")
    def test_windows_binding_denies_write_and_replace_through_start(self) -> None:
        source = Path(os.environ["SYSTEMROOT"]) / "System32" / "whoami.exe"
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "docker.exe"
            replacement = Path(temporary) / "replacement.exe"
            shutil.copy2(source, target)
            shutil.copy2(source, replacement)
            binding = linux_oci._bind_executable(target)
            self.assertIsNotNone(binding.lease)
            try:
                with self.assertRaises(OSError):
                    target.open("r+b")
                with self.assertRaises(OSError):
                    os.replace(replacement, target)
                execution_path, inherited_fds, _config_path = (
                    binding.execution_spec()
                )
                result = linux_oci.run_bounded_process_v1(
                    (binding.path,),
                    stdout_max_bytes=4096,
                    stderr_max_bytes=4096,
                    timeout_seconds=10,
                    env=linux_oci._clean_runtime_environment(target),
                    executable=execution_path,
                    inherited_fds=inherited_fds,
                )
                self.assertEqual(result.exit_code, 0)
                self.assertTrue(result.stdout.strip())
            finally:
                if binding.lease is not None:
                    binding.lease.close()
            os.replace(replacement, target)

    @unittest.skipUnless(
        sys.platform == "linux" and Path("/proc/self/fd").is_dir(),
        "requires Linux sealed memfd execution",
    )
    def test_linux_binding_executes_sealed_bytes_after_path_replace(self) -> None:
        source = Path("/bin/echo").resolve()
        replacement_source = Path("/bin/false").resolve()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "docker"
            replacement = Path(temporary) / "replacement"
            shutil.copy2(source, target)
            shutil.copy2(replacement_source, replacement)
            binding = linux_oci._bind_executable(target)
            self.assertIsNotNone(binding.lease)
            os.replace(replacement, target)
            try:
                execution_path, inherited_fds, _config_path = (
                    binding.execution_spec()
                )
                result = linux_oci.run_bounded_process_v1(
                    (binding.path, "bound-by-sealed-memfd"),
                    stdout_max_bytes=4096,
                    stderr_max_bytes=4096,
                    timeout_seconds=10,
                    env=linux_oci._clean_runtime_environment(target),
                    executable=execution_path,
                    inherited_fds=inherited_fds,
                )
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(result.stdout, b"bound-by-sealed-memfd\n")
                if binding.lease is not None:
                    with self.assertRaises(OSError):
                        os.write(binding.lease._descriptor, b"tamper")
            finally:
                if binding.lease is not None:
                    binding.lease.close()


if __name__ == "__main__":
    unittest.main()
