from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import unittest

from vulngym_agent.evaluator.runtime_evidence import (
    DockerServerIdentityV1,
    RUNTIME_EVIDENCE_DIGEST_DOMAIN,
    RUNTIME_EVIDENCE_MAX_JSON_DEPTH,
    RUNTIME_EVIDENCE_MAX_JSON_NODES,
    RUNTIME_EVIDENCE_MAX_WIRE_BYTES,
    RuntimeEvidenceError,
    RuntimeEvidenceV1,
    RuntimeIsolationV1,
    RuntimeResourceLimitsV1,
    runtime_evidence_wire_sha256_v1,
)


def _sha(marker: int | bytes) -> str:
    if type(marker) is bytes:
        return hashlib.sha256(marker).hexdigest()
    return f"{marker:064x}"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _wire(value: object) -> bytes:
    return _canonical(value) + b"\n"


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = DockerServerIdentityV1(
            operating_system="linux",
            architecture="amd64",
            engine_version="29.6.2",
            api_version="1.53",
            docker_executable_sha256=_sha(1),
            daemon_endpoint_sha256=_sha(22),
            server_observation_sha256=_sha(23),
        )
        self.isolation = RuntimeIsolationV1()
        self.resources = RuntimeResourceLimitsV1()
        self.evidence = RuntimeEvidenceV1(
            docker_server=self.server,
            isolation=self.isolation,
            resources=self.resources,
            runtime_image_id="sha256:" + "a" * 64,
            runtime_image_inspect_sha256=_sha(24),
            execution_image_id="sha256:" + "b" * 64,
            execution_image_inspect_sha256=_sha(16),
            execution_policy_sha256=_sha(2),
            task_plan_sha256=_sha(3),
            task_id="VG-TEST-0123456789ABCDEF0123",
            snapshot_id="VGS-0123456789ABCDEF0123456789ABCDEF",
            snapshot_manifest_sha256=_sha(4),
            snapshot_content_root=_sha(5),
            handoff_sha256=_sha(6),
            handoff_wire_sha256=_sha(7),
            source_generation_sha256=_sha(8),
            runtime_config_sha256=_sha(9),
            materializer_container_create_spec_sha256=_sha(17),
            materializer_container_pre_inspect_sha256=_sha(18),
            materializer_container_post_inspect_sha256=_sha(19),
            materializer_container_diff_sha256=_sha(20),
            materializer_container_identity_sha256=_sha(21),
            container_create_spec_sha256=_sha(10),
            container_pre_inspect_sha256=_sha(11),
            container_post_inspect_sha256=_sha(12),
            container_identity_sha256=_sha(13),
            run_sha256=_sha(14),
            run_wire_sha256=_sha(15),
            run_wire_size=4096,
            stderr_sha256=_sha(b""),
            stderr_size=0,
            exit_code=0,
            timed_out=False,
            oom_killed=False,
            restart_count=0,
            container_diff_empty=True,
            cleanup_complete=True,
        )

    def _parse(self, payload: bytes, *, content: str | None = None):
        return RuntimeEvidenceV1.from_bytes(
            payload,
            expected_evidence_sha256=(
                self.evidence.evidence_sha256 if content is None else content
            ),
            expected_wire_sha256=runtime_evidence_wire_sha256_v1(payload),
        )

    def test_roundtrip_is_one_canonical_line_and_has_separate_domains(self) -> None:
        payload = self.evidence.to_bytes()
        parsed = self._parse(payload)
        self.assertEqual(parsed, self.evidence)
        self.assertEqual(parsed.to_bytes(), payload)
        self.assertEqual(payload.count(b"\n"), 1)
        self.assertTrue(payload.endswith(b"\n"))

        core = self.evidence.to_dict()
        del core["evidence_sha256"]
        expected_content = hashlib.sha256(
            RUNTIME_EVIDENCE_DIGEST_DOMAIN + _canonical(core)
        ).hexdigest()
        expected_wire = hashlib.sha256(payload).hexdigest()
        self.assertEqual(self.evidence.evidence_sha256, expected_content)
        self.assertEqual(self.evidence.wire_sha256, expected_wire)
        self.assertNotEqual(self.evidence.evidence_sha256, self.evidence.wire_sha256)

    def test_all_required_execution_bindings_are_serialized(self) -> None:
        value = self.evidence.to_dict()
        for field_name in (
            "provider",
            "provider_version",
            "worker_version",
            "runtime_image_id",
            "runtime_image_inspect_sha256",
            "execution_image_id",
            "execution_image_inspect_sha256",
            "docker_server",
            "execution_policy_sha256",
            "task_plan_sha256",
            "task_id",
            "snapshot_id",
            "snapshot_manifest_sha256",
            "snapshot_content_root",
            "handoff_sha256",
            "handoff_wire_sha256",
            "source_generation_sha256",
            "runtime_config_sha256",
            "materializer_container_create_spec_sha256",
            "materializer_container_pre_inspect_sha256",
            "materializer_container_post_inspect_sha256",
            "materializer_container_diff_sha256",
            "materializer_container_identity_sha256",
            "container_create_spec_sha256",
            "container_pre_inspect_sha256",
            "container_post_inspect_sha256",
            "container_identity_sha256",
            "run_sha256",
            "run_wire_sha256",
            "run_wire_size",
            "exit_code",
            "timed_out",
            "oom_killed",
            "restart_count",
            "container_diff_empty",
            "cleanup_complete",
            "stderr_sha256",
            "stderr_size",
            "isolation",
            "resources",
        ):
            self.assertIn(field_name, value)
        self.assertEqual(value["docker_server"]["operating_system"], "linux")
        self.assertIn("daemon_endpoint_sha256", value["docker_server"])
        self.assertIn("server_observation_sha256", value["docker_server"])
        self.assertEqual(value["isolation"]["network_mode"], "none")
        self.assertEqual(value["isolation"]["rootfs_mode"], "read-only")
        self.assertEqual(
            value["isolation"]["source_delivery_mode"],
            "content-addressed-image-read-only",
        )

    def test_success_only_terminal_state_is_enforced(self) -> None:
        cases = (
            {"exit_code": 1},
            {"exit_code": True},
            {"timed_out": True},
            {"timed_out": 0},
            {"oom_killed": True},
            {"oom_killed": 0},
            {"restart_count": 1},
            {"restart_count": False},
            {"container_diff_empty": False},
            {"container_diff_empty": 1},
            {"cleanup_complete": False},
            {"cleanup_complete": 1},
            {"stderr_size": 1, "stderr_sha256": _sha(b"x")},
            {"stderr_sha256": _sha(99)},
            {"run_wire_size": 0},
            {"status": "failed"},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(
                RuntimeEvidenceError
            ) as captured:
                replace(self.evidence, **changes)
            self.assertIn(captured.exception.code, {"invalid_binding", "invalid_contract"})

    def test_linux_nonroot_and_fixed_isolation_are_unrepresentable_when_weakened(self) -> None:
        with self.assertRaises(RuntimeEvidenceError):
            replace(self.server, operating_system="windows")

        cases = (
            {"user_id": 0},
            {"user_id": 12345},
            {"user_id": True},
            {"group_id": 0},
            {"group_id": 12345},
            {"network_mode": "bridge"},
            {"rootfs_mode": "read-write"},
            {"source_delivery_mode": "read-write"},
            {"capabilities_mode": "default"},
            {"no_new_privileges": False},
            {"no_new_privileges": 1},
            {"user_mode": "root"},
            {"ipc_mode": "private"},
            {"cgroupns_mode": "host"},
            {"seccomp_mode": "unconfined"},
            {"runtime_input_delivery_mode": "read-write"},
            {"log_driver_mode": "json-file"},
            {"tmpfs_mode": "rw"},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(
                RuntimeEvidenceError
            ):
                replace(self.isolation, **changes)

    def test_resource_types_bounds_and_output_binding_are_strict(self) -> None:
        for changes in (
            {"wall_time_seconds": True},
            {"memory_bytes": 1},
            {"cpu_millis": 99},
            {"pids_limit": 7},
            {"open_files_limit": 31},
            {"stdout_max_bytes": 0},
            {"stderr_max_bytes": 0},
            {"tmpfs_bytes": 1024},
        ):
            with self.subTest(changes=changes), self.assertRaises(
                RuntimeEvidenceError
            ):
                replace(self.resources, **changes)

        tiny_stdout = replace(self.resources, stdout_max_bytes=10)
        with self.assertRaisesRegex(RuntimeEvidenceError, "clean success"):
            replace(self.evidence, resources=tiny_stdout, run_wire_size=11)

    def test_nested_values_require_exact_types_and_exact_keys(self) -> None:
        with self.assertRaisesRegex(RuntimeEvidenceError, "exact type"):
            replace(self.evidence, docker_server=self.server.to_dict())

        value = self.evidence.to_dict()
        value["unexpected"] = "C:/private/should-not-appear"
        payload = _wire(value)
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(payload)
        self.assertEqual(captured.exception.code, "invalid_contract")
        self.assertNotIn("C:/private", str(captured.exception))

        value = self.evidence.to_dict()
        value["resources"]["cpu_millis"] = True
        payload = _wire(value)
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(payload)
        self.assertEqual(captured.exception.code, "limit_exceeded")

    def test_content_and_wire_tampering_are_rejected(self) -> None:
        payload = self.evidence.to_bytes()
        with self.assertRaises(RuntimeEvidenceError) as captured:
            RuntimeEvidenceV1.from_bytes(
                payload,
                expected_evidence_sha256=self.evidence.evidence_sha256,
                expected_wire_sha256="f" * 64,
            )
        self.assertEqual(captured.exception.code, "digest_mismatch")

        value = self.evidence.to_dict()
        value["evidence_sha256"] = "f" * 64
        tampered = _wire(value)
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(tampered)
        self.assertEqual(captured.exception.code, "digest_mismatch")

        value = self.evidence.to_dict()
        value["run_sha256"] = "f" * 64
        tampered = _wire(value)
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(tampered)
        self.assertEqual(captured.exception.code, "noncanonical_json")

    def test_noncanonical_duplicate_and_multiline_json_are_rejected(self) -> None:
        pretty = json.dumps(self.evidence.to_dict(), indent=2).encode("utf-8") + b"\n"
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(pretty)
        self.assertEqual(captured.exception.code, "noncanonical_json")

        duplicate = b'{"evidence_sha256":"' + b"0" * 64 + (
            b'","evidence_sha256":"' + b"0" * 64 + b'"}\n'
        )
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(duplicate, content="0" * 64)
        self.assertEqual(captured.exception.code, "noncanonical_json")

        multiline = self.evidence.to_bytes() + b"\n"
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(multiline)
        self.assertEqual(captured.exception.code, "noncanonical_json")

        constant = b'{"value":NaN}\n'
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(constant)
        self.assertEqual(captured.exception.code, "noncanonical_json")

    def test_wire_byte_depth_and_node_limits_are_enforced_before_contract_use(self) -> None:
        oversized = b"x" * RUNTIME_EVIDENCE_MAX_WIRE_BYTES + b"\n"
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(oversized)
        self.assertEqual(captured.exception.code, "limit_exceeded")

        nested: object = 0
        for _ in range(RUNTIME_EVIDENCE_MAX_JSON_DEPTH + 1):
            nested = [nested]
        too_deep = _wire({"value": nested})
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(too_deep)
        self.assertEqual(captured.exception.code, "limit_exceeded")

        too_many_nodes = _wire(
            {"value": [0] * (RUNTIME_EVIDENCE_MAX_JSON_NODES + 1)}
        )
        with self.assertRaises(RuntimeEvidenceError) as captured:
            self._parse(too_many_nodes)
        self.assertEqual(captured.exception.code, "limit_exceeded")

    def test_arguments_and_errors_are_exact_and_path_free(self) -> None:
        with self.assertRaises(RuntimeEvidenceError) as captured:
            RuntimeEvidenceV1.from_bytes(
                bytearray(self.evidence.to_bytes()),
                expected_evidence_sha256=self.evidence.evidence_sha256,
                expected_wire_sha256=self.evidence.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_argument")

        with self.assertRaises(RuntimeEvidenceError) as captured:
            RuntimeEvidenceV1.from_bytes(
                self.evidence.to_bytes(),
                expected_evidence_sha256=True,
                expected_wire_sha256=self.evidence.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_argument")

        secret_path = "C:/Users/private/docker.exe"
        with self.assertRaises(RuntimeEvidenceError) as captured:
            replace(self.server, engine_version=secret_path)
        self.assertNotIn(secret_path, str(captured.exception))


if __name__ == "__main__":
    unittest.main()
