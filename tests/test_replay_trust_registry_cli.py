from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from vulngym_agent.replay_authoring_receipt import ReplayTrustRegistryV2
import vulngym_agent.replay_trust_registry_cli as registry_cli


SLOTS = registry_cli.TRUST_KEY_SLOTS


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


class ReplayTrustRegistryCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private = self.root / "private"
        self.public = self.root / "public"
        self.private.mkdir(mode=0o700)
        self.public.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _invoke(self, arguments: list[str]) -> tuple[int, bytes, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = registry_cli.main(arguments)
        return status, stdout.getvalue().encode("utf-8"), stderr.getvalue()

    def _slot_paths(self, index: int) -> tuple[Path, Path]:
        purpose, role = SLOTS[index]
        stem = f"{index}-{purpose}-{role}"
        return self.private / f"{stem}.key", self.public / f"{stem}.json"

    def _generate(self, index: int) -> tuple[Path, Path, bytes]:
        purpose, role = SLOTS[index]
        private_path, registration_path = self._slot_paths(index)
        status, stdout, stderr = self._invoke(
            [
                "generate-slot",
                "--purpose",
                purpose,
                "--role",
                role,
                "--key-id",
                f"official-{purpose}-{role}",
                "--private-key-file",
                str(private_path),
                "--registration-file",
                str(registration_path),
            ]
        )
        self.assertEqual((status, stderr), (0, ""))
        self.assertEqual(len(private_path.read_bytes()), 32)
        registration = registration_path.read_bytes()
        self.assertEqual(_canonical(json.loads(registration)), registration)
        summary = json.loads(stdout)
        self.assertEqual(
            summary["registration_wire_sha256"],
            hashlib.sha256(registration).hexdigest(),
        )
        return private_path, registration_path, stdout

    def _provision(self) -> tuple[list[Path], list[Path], Path, dict[str, object]]:
        private_paths: list[Path] = []
        registration_paths: list[Path] = []
        for index in range(len(SLOTS)):
            private_path, registration_path, _stdout = self._generate(index)
            private_paths.append(private_path)
            registration_paths.append(registration_path)
        registry_path = self.public / "registry.json"
        arguments = ["assemble-registry", "--registry-file", str(registry_path)]
        for path in registration_paths:
            arguments.extend(("--registration-file", str(path)))
        status, stdout, stderr = self._invoke(arguments)
        self.assertEqual((status, stderr), (0, ""))
        summary = json.loads(stdout)
        registry_payload = registry_path.read_bytes()
        registry = ReplayTrustRegistryV2.from_bytes(
            registry_payload,
            expected_sha256=summary["registry_sha256"],
            expected_wire_sha256=summary["registry_wire_sha256"],
        )
        self.assertEqual(
            summary["public_key_fingerprints"],
            [item.public_key_fingerprint for item in registry.keys],
        )
        return private_paths, registration_paths, registry_path, summary

    def _verify_arguments(
        self,
        *,
        index: int,
        private_path: Path,
        registry_path: Path,
        summary: dict[str, object],
    ) -> list[str]:
        purpose, role = SLOTS[index]
        return [
            "verify-slot",
            "--purpose",
            purpose,
            "--role",
            role,
            "--key-id",
            f"official-{purpose}-{role}",
            "--private-key-file",
            str(private_path),
            "--trust-registry-file",
            str(registry_path),
            "--expected-trust-registry-sha256",
            str(summary["registry_sha256"]),
            "--expected-trust-registry-wire-sha256",
            str(summary["registry_wire_sha256"]),
        ]

    def test_generate_assemble_and_verify_emit_only_public_pins(self) -> None:
        private_paths, registrations, registry_path, summary = self._provision()
        for index, private_path in enumerate(private_paths):
            status, stdout, stderr = self._invoke(
                self._verify_arguments(
                    index=index,
                    private_path=private_path,
                    registry_path=registry_path,
                    summary=summary,
                )
            )
            self.assertEqual((status, stderr), (0, ""))
            self.assertEqual(json.loads(stdout), summary)

        all_output = b"".join(path.read_bytes() for path in registrations)
        all_output += registry_path.read_bytes() + _canonical(summary)
        for private_path in private_paths:
            secret = private_path.read_bytes()
            self.assertNotIn(secret.hex().encode("ascii"), all_output)
            self.assertNotIn(base64.b64encode(secret), all_output)

    def test_outputs_are_no_replace(self) -> None:
        private_path, registration_path, _stdout = self._generate(0)
        private_before = private_path.read_bytes()
        registration_before = registration_path.read_bytes()
        purpose, role = SLOTS[0]
        status, stdout, stderr = self._invoke(
            [
                "generate-slot",
                "--purpose",
                purpose,
                "--role",
                role,
                "--key-id",
                "replacement-key",
                "--private-key-file",
                str(private_path),
                "--registration-file",
                str(registration_path),
            ]
        )
        self.assertEqual(status, 2)
        self.assertEqual(stdout, b"")
        self.assertIn("error[output_exists]", stderr)
        self.assertEqual(private_path.read_bytes(), private_before)
        self.assertEqual(registration_path.read_bytes(), registration_before)

        registration_paths = [registration_path]
        for index in range(1, len(SLOTS)):
            _private_path, generated_registration, _stdout = self._generate(index)
            registration_paths.append(generated_registration)
        registry_path = self.public / "registry.json"
        first_assembly = [
            "assemble-registry",
            "--registry-file",
            str(registry_path),
        ]
        for path in registration_paths:
            first_assembly.extend(("--registration-file", str(path)))
        status, _stdout, stderr = self._invoke(first_assembly)
        self.assertEqual((status, stderr), (0, ""))
        registry_before = registry_path.read_bytes()
        arguments = ["assemble-registry", "--registry-file", str(registry_path)]
        for path in registration_paths:
            arguments.extend(("--registration-file", str(path)))
        status, stdout, stderr = self._invoke(arguments)
        self.assertEqual(status, 2)
        self.assertEqual(stdout, b"")
        self.assertIn("error[output_exists]", stderr)
        self.assertEqual(registry_path.read_bytes(), registry_before)

    def test_wrong_order_and_duplicate_public_key_are_rejected(self) -> None:
        registrations = [self._generate(index)[1] for index in range(len(SLOTS))]
        wrong_order = [registrations[1], registrations[0], *registrations[2:]]
        output = self.public / "wrong-order-registry.json"
        arguments = ["assemble-registry", "--registry-file", str(output)]
        for path in wrong_order:
            arguments.extend(("--registration-file", str(path)))
        status, stdout, stderr = self._invoke(arguments)
        self.assertEqual((status, stdout), (2, b""))
        self.assertIn("error[slot_mismatch]", stderr)
        self.assertFalse(output.exists())

        duplicate = json.loads(registrations[0].read_bytes())
        duplicate["purpose"], duplicate["role"] = SLOTS[1]
        duplicate["key_id"] = "unique-id-for-duplicated-public-key"
        registrations[1].write_bytes(_canonical(duplicate))
        registrations[1].chmod(0o600)
        output = self.public / "duplicate-key-registry.json"
        arguments = ["assemble-registry", "--registry-file", str(output)]
        for path in registrations:
            arguments.extend(("--registration-file", str(path)))
        status, stdout, stderr = self._invoke(arguments)
        self.assertEqual((status, stdout), (2, b""))
        self.assertIn("error[trust_registry_rejected]", stderr)
        self.assertFalse(output.exists())

    def test_verify_rejects_pin_role_and_malformed_key_without_leaking(self) -> None:
        private_paths, _registrations, registry_path, summary = self._provision()
        arguments = self._verify_arguments(
            index=0,
            private_path=private_paths[0],
            registry_path=registry_path,
            summary=summary,
        )
        semantic_index = arguments.index("--expected-trust-registry-sha256") + 1
        arguments[semantic_index] = "0" * 64
        status, stdout, stderr = self._invoke(arguments)
        self.assertEqual((status, stdout), (2, b""))
        self.assertIn("error[trust_registry_pin_mismatch]", stderr)

        arguments = self._verify_arguments(
            index=0,
            private_path=private_paths[0],
            registry_path=registry_path,
            summary=summary,
        )
        wire_index = (
            arguments.index("--expected-trust-registry-wire-sha256") + 1
        )
        arguments[wire_index] = "f" * 64
        status, stdout, stderr = self._invoke(arguments)
        self.assertEqual((status, stdout), (2, b""))
        self.assertIn("error[trust_registry_pin_mismatch]", stderr)

        arguments = self._verify_arguments(
            index=1,
            private_path=private_paths[0],
            registry_path=registry_path,
            summary=summary,
        )
        status, stdout, stderr = self._invoke(arguments)
        self.assertEqual((status, stdout), (2, b""))
        self.assertIn("error[key_fingerprint_mismatch]", stderr)

        malformed = self.private / "malformed.key"
        malformed.write_bytes(b"malformed-private-key")
        malformed.chmod(0o600)
        arguments = self._verify_arguments(
            index=0,
            private_path=malformed,
            registry_path=registry_path,
            summary=summary,
        )
        status, stdout, stderr = self._invoke(arguments)
        self.assertEqual((status, stdout), (2, b""))
        self.assertIn("error[invalid_key]", stderr)
        self.assertNotIn(malformed.read_text(), stderr)

    def test_verify_rejects_hardlinked_private_key(self) -> None:
        private_paths, _registrations, registry_path, summary = self._provision()
        hardlink = self.private / "hardlink.key"
        try:
            os.link(private_paths[0], hardlink)
        except (NotImplementedError, OSError):
            self.skipTest("hard links are unavailable on this filesystem")
        status, stdout, stderr = self._invoke(
            self._verify_arguments(
                index=0,
                private_path=hardlink,
                registry_path=registry_path,
                summary=summary,
            )
        )
        self.assertEqual((status, stdout), (2, b""))
        self.assertIn("error[unsafe_path]", stderr)

    def test_optimized_mode_happy_path_and_invalid_slot_fail_closed(self) -> None:
        registration_paths: list[Path] = []
        private_paths: list[Path] = []
        for index, (purpose, role) in enumerate(SLOTS):
            private_path, registration_path = self._slot_paths(index)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-O",
                    "-B",
                    "-m",
                    "vulngym_agent.replay_trust_registry_cli",
                    "generate-slot",
                    "--purpose",
                    purpose,
                    "--role",
                    role,
                    "--key-id",
                    f"official-{purpose}-{role}",
                    "--private-key-file",
                    str(private_path),
                    "--registration-file",
                    str(registration_path),
                ],
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                capture_output=True,
            )
            self.assertEqual((completed.returncode, completed.stderr), (0, b""))
            private_paths.append(private_path)
            registration_paths.append(registration_path)

        registry_path = self.public / "optimized-registry.json"
        command = [
            sys.executable,
            "-O",
            "-B",
            "-m",
            "vulngym_agent.replay_trust_registry_cli",
            "assemble-registry",
            "--registry-file",
            str(registry_path),
        ]
        for path in registration_paths:
            command.extend(("--registration-file", str(path)))
        assembled = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            capture_output=True,
        )
        self.assertEqual((assembled.returncode, assembled.stderr), (0, b""))
        summary = json.loads(assembled.stdout)
        verified = subprocess.run(
            [
                sys.executable,
                "-O",
                "-B",
                "-m",
                "vulngym_agent.replay_trust_registry_cli",
                *self._verify_arguments(
                    index=5,
                    private_path=private_paths[5],
                    registry_path=registry_path,
                    summary=summary,
                ),
            ],
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            capture_output=True,
        )
        self.assertEqual((verified.returncode, verified.stderr), (0, b""))

        rejected_private = self.private / "rejected.key"
        rejected_public = self.public / "rejected.json"
        rejected = subprocess.run(
            [
                sys.executable,
                "-O",
                "-B",
                "-m",
                "vulngym_agent.replay_trust_registry_cli",
                "generate-slot",
                "--purpose",
                "actor-approval",
                "--role",
                "test",
                "--key-id",
                "invalid-cross-purpose-slot",
                "--private-key-file",
                str(rejected_private),
                "--registration-file",
                str(rejected_public),
            ],
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            capture_output=True,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, b"")
        self.assertIn(b"error[invalid_slot]", rejected.stderr)
        self.assertFalse(rejected_private.exists())
        self.assertFalse(rejected_public.exists())

    def test_publication_uncertain_uses_committed_exit_code(self) -> None:
        purpose, role = SLOTS[0]
        arguments = [
            "generate-slot",
            "--purpose",
            purpose,
            "--role",
            role,
            "--key-id",
            "official-uncertain-key",
            "--private-key-file",
            str(self.private / "uncertain.key"),
            "--registration-file",
            str(self.public / "uncertain.json"),
        ]
        error = registry_cli.ReplayTrustRegistryCliError(
            "publication_uncertain",
            "created output could not be removed",
            committed=True,
        )
        with mock.patch.object(registry_cli, "_run_generate", side_effect=error):
            status, stdout, stderr = self._invoke(arguments)
        self.assertEqual(status, registry_cli.EXIT_COMMITTED_UNCERTAIN)
        self.assertEqual(stdout, b"")
        self.assertEqual(
            stderr,
            "error[publication_uncertain]: trust registry provisioning failed\n",
        )

    def test_stdout_failure_after_generate_and_assemble_uses_exit_11(self) -> None:
        purpose, role = SLOTS[0]
        private_path, registration_path = self._slot_paths(0)
        generate_arguments = [
            "generate-slot",
            "--purpose",
            purpose,
            "--role",
            role,
            "--key-id",
            f"official-{purpose}-{role}",
            "--private-key-file",
            str(private_path),
            "--registration-file",
            str(registration_path),
        ]
        with mock.patch.object(
            registry_cli, "_write_stdout", side_effect=OSError("broken stdout")
        ):
            status, stdout, stderr = self._invoke(generate_arguments)
        self.assertEqual(status, registry_cli.EXIT_COMMITTED_UNCERTAIN)
        self.assertEqual(stdout, b"")
        self.assertEqual(
            stderr,
            "error[publication_uncertain]: trust registry provisioning failed\n",
        )
        self.assertEqual(len(private_path.read_bytes()), 32)
        self.assertTrue(registration_path.is_file())

        registration_paths = [registration_path]
        for index in range(1, len(SLOTS)):
            registration_paths.append(self._generate(index)[1])
        registry_path = self.public / "stdout-failed-registry.json"
        assemble_arguments = [
            "assemble-registry",
            "--registry-file",
            str(registry_path),
        ]
        for path in registration_paths:
            assemble_arguments.extend(("--registration-file", str(path)))
        with mock.patch.object(
            registry_cli, "_write_stdout", side_effect=SystemExit(9)
        ):
            status, stdout, stderr = self._invoke(assemble_arguments)
        self.assertEqual(status, registry_cli.EXIT_COMMITTED_UNCERTAIN)
        self.assertEqual(stdout, b"")
        self.assertEqual(
            stderr,
            "error[publication_uncertain]: trust registry provisioning failed\n",
        )
        self.assertTrue(registry_path.is_file())

    def test_failure_immediately_after_registry_commit_uses_exit_11(self) -> None:
        registration_paths = [
            self._generate(index)[1] for index in range(len(SLOTS))
        ]
        registry_path = self.public / "parent-exit-registry.json"
        arguments = [
            "assemble-registry",
            "--registry-file",
            str(registry_path),
        ]
        for path in registration_paths:
            arguments.extend(("--registration-file", str(path)))

        original_write = registry_cli._write_exclusive

        def fail_after_registry_publish(*args: object, **kwargs: object) -> object:
            result = original_write(*args, **kwargs)
            if kwargs.get("mutation_state") is not None:
                raise KeyboardInterrupt
            return result

        with mock.patch.object(
            registry_cli,
            "_write_exclusive",
            new=fail_after_registry_publish,
        ):
            status, stdout, stderr = self._invoke(arguments)
        self.assertEqual(status, registry_cli.EXIT_COMMITTED_UNCERTAIN)
        self.assertEqual(stdout, b"")
        self.assertEqual(
            stderr,
            "error[publication_uncertain]: trust registry provisioning failed\n",
        )
        self.assertTrue(registry_path.is_file())

    def test_write_descriptor_close_failure_cleans_created_outputs(self) -> None:
        purpose, role = SLOTS[0]
        private_path, registration_path = self._slot_paths(0)
        arguments = [
            "generate-slot",
            "--purpose",
            purpose,
            "--role",
            role,
            "--key-id",
            "close-failure-key",
            "--private-key-file",
            str(private_path),
            "--registration-file",
            str(registration_path),
        ]
        original_open = registry_cli.os.open
        original_close = registry_cli.os.close
        write_descriptors: set[int] = set()

        def track_write_descriptor(
            path: object, flags: int, *args: object, **kwargs: object
        ) -> int:
            descriptor = original_open(path, flags, *args, **kwargs)
            if flags & os.O_WRONLY and flags & os.O_CREAT:
                write_descriptors.add(descriptor)
            return descriptor

        def close_then_fail(descriptor: int) -> None:
            original_close(descriptor)
            if descriptor in write_descriptors:
                write_descriptors.remove(descriptor)
                raise OSError("injected close failure")

        with (
            mock.patch.object(registry_cli.os, "open", new=track_write_descriptor),
            mock.patch.object(registry_cli.os, "close", new=close_then_fail),
        ):
            status, stdout, stderr = self._invoke(arguments)
        self.assertEqual(status, registry_cli.EXIT_REJECTED)
        self.assertEqual(stdout, b"")
        self.assertEqual(
            stderr,
            "error[input_rejected]: trust registry provisioning failed\n",
        )
        self.assertFalse(private_path.exists())
        self.assertFalse(registration_path.exists())

    def test_private_read_close_failure_zeroes_the_loaded_buffer(self) -> None:
        private_path = self.private / "read-close-failure.key"
        private_path.write_bytes(b"s" * 32)
        private_path.chmod(0o600)
        observed = bytearray(b"s" * 32)
        descriptor_holder: dict[str, int] = {}
        original_read = registry_cli._read_descriptor
        original_close = registry_cli.os.close

        def capture_read(descriptor: int, *, maximum_bytes: int) -> bytearray:
            descriptor_holder["value"] = descriptor
            loaded = original_read(descriptor, maximum_bytes=maximum_bytes)
            observed[:] = loaded
            return observed

        def fail_target_close(descriptor: int) -> None:
            original_close(descriptor)
            if descriptor == descriptor_holder.get("value"):
                raise OSError("injected read close failure")

        with (
            mock.patch.object(registry_cli, "_read_descriptor", new=capture_read),
            mock.patch.object(registry_cli.os, "close", new=fail_target_close),
        ):
            with self.assertRaises(OSError):
                registry_cli._read_stable_regular(
                    private_path,
                    minimum_bytes=32,
                    maximum_bytes=32,
                    private=True,
                )
        self.assertEqual(observed, bytearray(32))


if __name__ == "__main__":
    unittest.main()
