from __future__ import annotations

import argparse
import dis
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest import mock

import vulngym_agent.final_gate_cli as cli
from vulngym_agent.evaluator.final_gate import (
    FinalGatePlanV1,
    FinalGateReceiptV1,
    FinalGateSplitPlanV1,
    FinalGateSplitReceiptClosureV1,
)
from vulngym_agent.evaluator.final_gate_runner import FinalGateRunnerError
from vulngym_agent.evaluator.e4_driver import fixed_e4_execution_policy_v1
from vulngym_agent.evaluator.runtime_evidence import (
    RuntimeBindingPinsV1,
    docker_endpoint_sha256_v1,
)
from vulngym_agent.native_linux_final_gate_preflight import (
    NativeLinuxFinalGateReadinessV2,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _absolute_fixture_path(*parts: str) -> Path:
    root = Path("C:/") if os.name == "nt" else Path("/")
    return root.joinpath(*parts)


class _FakeAttempt:
    def __init__(self) -> None:
        self._payload = b'{"kind":"attempt","status":"failed_clean"}\n'
        self.report_sha256 = _sha("attempt-semantic")
        self.wire_sha256 = hashlib.sha256(self._payload).hexdigest()

    def to_bytes(self) -> bytes:
        return self._payload


class _FatalSignal(BaseException):
    pass


class FinalGateCliTests(unittest.TestCase):
    def test_readme_formal_run_command_includes_runtime_readiness_pins(self) -> None:
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(
            encoding="utf-8"
        )
        marker = "python -m vulngym_agent.final_gate_cli run"
        command = readme.split(marker, 1)[1].split("```", 1)[0]
        for required in (
            "--docker-host unix:///run/vulngym/docker.sock",
            "--readiness-file /srv/vulngym/control/readiness-report.json",
            "--expected-readiness-sha256 <64-lowercase-hex>",
            "--expected-readiness-wire-sha256 <64-lowercase-hex>",
            "--test-key-file /srv/vulngym/control/secrets/test.key",
            "--train-key-file /srv/vulngym/control/secrets/train.key",
        ):
            with self.subTest(required=required):
                self.assertIn(required, command)
        self.assertIn(
            "[native-Linux final-gate runbook](docs/native_linux_final_gate_runbook.md)",
            readme,
        )

    def setUp(self) -> None:
        self.plan = self._plan()
        self.receipt = self._receipt(self.plan)
        self.readiness = NativeLinuxFinalGateReadinessV2(
            runtime_binding=RuntimeBindingPinsV1(
                daemon_endpoint_sha256=docker_endpoint_sha256_v1(
                    "unix:///run/vulngym/docker.sock"
                ),
                docker_executable_sha256=_sha("docker-cli"),
                docker_socket_identity_sha256=_sha("docker-socket"),
                server_observation_sha256=_sha("docker-server"),
                daemon_info_sha256=_sha("docker-info"),
                runtime_image_id="sha256:" + "a" * 64,
                runtime_image_inspect_sha256=_sha("runtime-image"),
            ),
            final_gate_plan_sha256=self.plan.plan_sha256,
            final_gate_plan_wire_sha256=self.plan.wire_sha256,
            execution_policy_sha256=self.plan.execution_policy_sha256,
            execution_policy_wire_sha256=self.plan.execution_policy_wire_sha256,
            report_sha256=_sha("readiness-report"),
            wire_sha256=_sha("readiness-wire"),
        )

    @staticmethod
    def _split_plan(split: str) -> FinalGateSplitPlanV1:
        return FinalGateSplitPlanV1(
            split=split,
            task_count=20 if split == "test" else 50,
            sealed_batch_manifest_sha256=_sha(f"{split}:sealed"),
            replay_manifest_sha256=_sha(f"{split}:replay:semantic"),
            replay_manifest_wire_sha256=_sha(f"{split}:replay:wire"),
            snapshot_key_id=f"snapshot-key-{split}",
        )

    def _plan(self) -> FinalGatePlanV1:
        policy = fixed_e4_execution_policy_v1("sha256:" + "a" * 64)
        return FinalGatePlanV1(
            execution_policy_sha256=policy.policy_sha256,
            execution_policy_wire_sha256=policy.wire_sha256,
            test=self._split_plan("test"),
            train=self._split_plan("train"),
        )

    @staticmethod
    def _closure(
        split: str, plan: FinalGatePlanV1
    ) -> FinalGateSplitReceiptClosureV1:
        split_plan = plan.test if split == "test" else plan.train
        count = split_plan.task_count
        return FinalGateSplitReceiptClosureV1(
            split=split,
            split_plan_sha256=split_plan.split_plan_sha256,
            split_plan_wire_sha256=split_plan.wire_sha256,
            e4_receipt_sha256=_sha(f"{split}:e4:semantic"),
            e4_receipt_wire_sha256=_sha(f"{split}:e4:wire"),
            execution_policy_sha256=plan.execution_policy_sha256,
            execution_policy_wire_sha256=plan.execution_policy_wire_sha256,
            execution_plan_sha256=_sha(f"{split}:execution:semantic"),
            execution_plan_wire_sha256=_sha(f"{split}:execution:wire"),
            artifact_index_sha256=_sha(f"{split}:artifact-index"),
            projection_manifest_sha256=_sha(f"{split}:projection"),
            task_count=count,
            finalized_task_count=count,
            deferred_task_count=0,
            candidate_count=count * 2,
            finding_count=count,
            aggregate_file_sha256=(
                None if split == "test" else _sha("train:aggregate")
            ),
        )

    def _receipt(self, plan: FinalGatePlanV1) -> FinalGateReceiptV1:
        return FinalGateReceiptV1(
            plan=plan,
            test=self._closure("test", plan),
            train=self._closure("train", plan),
        )

    def _run_argv(self) -> list[str]:
        return [
            "run",
            "--benchmark-root",
            "benchmark-root",
            "--output-root",
            "final-output",
            "--docker-executable",
            str(_absolute_fixture_path("docker", "docker.exe")),
            "--docker-host",
            "unix:///run/vulngym/docker.sock",
            "--runtime-image-id",
            "sha256:" + "a" * 64,
            "--readiness-file",
            "readiness.json",
            "--expected-readiness-sha256",
            _sha("readiness-report"),
            "--expected-readiness-wire-sha256",
            _sha("readiness-wire"),
            "--plan-file",
            "final-plan.json",
            "--expected-plan-sha256",
            self.plan.plan_sha256,
            "--expected-plan-wire-sha256",
            self.plan.wire_sha256,
            "--test-sealed-batch-root",
            "test-sealed",
            "--test-replay-config-root",
            "test-replay",
            "--train-sealed-batch-root",
            "train-sealed",
            "--train-replay-config-root",
            "train-replay",
            "--test-key-file",
            "test.key",
            "--train-key-file",
            "train.key",
        ]

    def _run_args(self) -> argparse.Namespace:
        return cli._parser().parse_args(self._run_argv())

    def _verify_argv(self) -> list[str]:
        return [
            "verify-output",
            "--output-root",
            "committed-output",
            "--benchmark-root",
            "benchmark-root",
            "--expected-receipt-sha256",
            self.receipt.receipt_sha256,
            "--expected-wire-sha256",
            self.receipt.wire_sha256,
        ]

    @staticmethod
    def _capture_main(argv: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with mock.patch.object(cli.sys, "stdout", output):
            status = cli.main(argv)
        return status, output.getvalue()

    def _run_patches(
        self,
        *,
        test_key: bytearray,
        train_key: bytearray,
        runner_return: object = None,
        runner_side_effect: BaseException | None = None,
    ):
        return (
            mock.patch.object(cli, "_preflight_run_paths", return_value=None),
            mock.patch.object(
                cli, "_read_final_gate_plan_file_v1", return_value=self.plan
            ),
            mock.patch.object(
                cli, "_read_readiness_file_v2", return_value=self.readiness
            ),
            mock.patch.object(
                cli,
                "read_attestation_key_file_v1",
                side_effect=(test_key, train_key),
            ),
            mock.patch.object(
                cli,
                "run_e4_final_gate_v1",
                return_value=runner_return,
                side_effect=runner_side_effect,
            ),
        )

    def test_parser_exposes_only_fixed_run_and_verify_inputs(self) -> None:
        parser = cli._parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        self.assertEqual({"run", "verify-output"}, set(subparsers.choices))
        run_options = {
            option
            for action in subparsers.choices["run"]._actions
            for option in action.option_strings
        }
        self.assertEqual(
            {
                "-h",
                "--help",
                "--benchmark-root",
                "--output-root",
                "--docker-executable",
                "--docker-host",
                "--runtime-image-id",
                "--readiness-file",
                "--expected-readiness-sha256",
                "--expected-readiness-wire-sha256",
                "--plan-file",
                "--expected-plan-sha256",
                "--expected-plan-wire-sha256",
                "--test-sealed-batch-root",
                "--test-replay-config-root",
                "--train-sealed-batch-root",
                "--train-replay-config-root",
                "--test-key-file",
                "--train-key-file",
            },
            run_options,
        )
        forbidden = {
            "--backend",
            "--backend-id",
            "--model",
            "--model-id",
            "--memory-bytes",
            "--network-mode",
            "--top-k",
            "--wall-time-seconds",
            "--max-attempts",
        }
        self.assertTrue(run_options.isdisjoint(forbidden))

    def test_malicious_scalars_and_nonexact_paths_precede_all_path_and_key_io(
        self,
    ) -> None:
        scalar_cases = (
            ("expected_plan_sha256", "A" * 64),
            ("expected_plan_wire_sha256", "short"),
            ("runtime_image_id", "python:latest"),
        )
        for name, value in scalar_cases:
            with self.subTest(name=name):
                args = self._run_args()
                setattr(args, name, value)
                preflight = mock.Mock()
                plan_reader = mock.Mock()
                key_reader = mock.Mock()
                with (
                    mock.patch.object(cli, "_preflight_run_paths", preflight),
                    mock.patch.object(
                        cli, "_read_final_gate_plan_file_v1", plan_reader
                    ),
                    mock.patch.object(
                        cli, "read_attestation_key_file_v1", key_reader
                    ),
                    self.assertRaises(cli.FinalGateCliError) as captured,
                ):
                    cli._run(args)
                self.assertEqual("invalid_argument", captured.exception.code)
                preflight.assert_not_called()
                plan_reader.assert_not_called()
                key_reader.assert_not_called()

        args = self._run_args()
        args.benchmark_root = "not-an-exact-Path"
        preflight = mock.Mock()
        key_reader = mock.Mock()
        with (
            mock.patch.object(cli, "_preflight_run_paths", preflight),
            mock.patch.object(cli, "read_attestation_key_file_v1", key_reader),
            self.assertRaises(cli.FinalGateCliError) as captured,
        ):
            cli._run(args)
        self.assertEqual("invalid_argument", captured.exception.code)
        preflight.assert_not_called()
        key_reader.assert_not_called()

        args = self._run_args()
        args.docker_executable = Path(" docker ")
        preflight = mock.Mock()
        key_reader = mock.Mock()
        with (
            mock.patch.object(cli, "_preflight_run_paths", preflight),
            mock.patch.object(cli, "read_attestation_key_file_v1", key_reader),
            self.assertRaises(cli.FinalGateCliError) as captured,
        ):
            cli._run(args)
        self.assertEqual("invalid_argument", captured.exception.code)
        preflight.assert_not_called()
        key_reader.assert_not_called()

    def test_runtime_policy_mismatch_rejects_before_key_reads(self) -> None:
        args = self._run_args()
        args.runtime_image_id = "sha256:" + "b" * 64
        key_reader = mock.Mock()
        runner = mock.Mock()
        with (
            mock.patch.object(cli, "_preflight_run_paths", return_value=None),
            mock.patch.object(
                cli, "_read_final_gate_plan_file_v1", return_value=self.plan
            ),
            mock.patch.object(cli, "read_attestation_key_file_v1", key_reader),
            mock.patch.object(cli, "run_e4_final_gate_v1", runner),
            self.assertRaises(cli.FinalGateCliError) as captured,
        ):
            cli._run(args)
        self.assertEqual("policy_mismatch", captured.exception.code)
        key_reader.assert_not_called()
        runner.assert_not_called()

    def test_readiness_pin_or_binding_bypass_rejects_before_key_reads(self) -> None:
        detached = NativeLinuxFinalGateReadinessV2(
            runtime_binding=self.readiness.runtime_binding,
            final_gate_plan_sha256=_sha("detached-plan"),
            final_gate_plan_wire_sha256=self.readiness.final_gate_plan_wire_sha256,
            execution_policy_sha256=self.readiness.execution_policy_sha256,
            execution_policy_wire_sha256=self.readiness.execution_policy_wire_sha256,
            report_sha256=self.readiness.report_sha256,
            wire_sha256=self.readiness.wire_sha256,
        )
        cases = (
            cli.FinalGateCliError(
                "readiness_input_rejected", "readiness wire pin mismatch"
            ),
            detached,
        )
        for result in cases:
            with self.subTest(result=type(result).__name__):
                key_reader = mock.Mock()
                runner = mock.Mock()
                with (
                    mock.patch.object(
                        cli, "_preflight_run_paths", return_value=None
                    ),
                    mock.patch.object(
                        cli, "_read_final_gate_plan_file_v1", return_value=self.plan
                    ),
                    mock.patch.object(
                        cli,
                        "_read_readiness_file_v2",
                        return_value=(None if isinstance(result, BaseException) else result),
                        side_effect=(result if isinstance(result, BaseException) else None),
                    ),
                    mock.patch.object(
                        cli, "read_attestation_key_file_v1", key_reader
                    ),
                    mock.patch.object(cli, "run_e4_final_gate_v1", runner),
                    self.assertRaises(cli.FinalGateCliError) as captured,
                ):
                    cli._run(self._run_args())
                self.assertIn(
                    captured.exception.code,
                    {"readiness_input_rejected", "readiness_binding_mismatch"},
                )
                key_reader.assert_not_called()
                runner.assert_not_called()

    def test_path_preflight_and_plan_read_finish_before_either_key_read(self) -> None:
        timeline: list[str] = []
        test_key = bytearray(b"T" * 40)
        train_key = bytearray(b"R" * 40)

        def preflight(_args: argparse.Namespace) -> None:
            timeline.append("paths")

        def plan_reader(*_args: object, **_kwargs: object) -> FinalGatePlanV1:
            timeline.append("plan")
            return self.plan

        def readiness_reader(*_args: object, **_kwargs: object):
            timeline.append("readiness")
            return self.readiness

        def key_reader(_path: Path) -> bytearray:
            timeline.append("key")
            return test_key if timeline.count("key") == 1 else train_key

        with (
            mock.patch.object(cli, "_preflight_run_paths", side_effect=preflight),
            mock.patch.object(
                cli,
                "_read_final_gate_plan_file_v1",
                side_effect=plan_reader,
            ),
            mock.patch.object(
                cli,
                "_read_readiness_file_v2",
                side_effect=readiness_reader,
            ),
            mock.patch.object(
                cli, "read_attestation_key_file_v1", side_effect=key_reader
            ),
            mock.patch.object(
                cli, "run_e4_final_gate_v1", return_value=self.receipt
            ),
        ):
            result = cli._run(self._run_args())
        self.assertIs(result, self.receipt)
        self.assertEqual(
            timeline, ["paths", "plan", "readiness", "key", "key"]
        )
        self.assertEqual(test_key, bytearray(40))
        self.assertEqual(train_key, bytearray(40))

    def test_mount_table_binding_is_forwarded_to_the_runner(self) -> None:
        mount_table = cli.LinuxMountTableV1(payload=b"bound\n", entries=())
        test_key = bytearray(b"T" * 40)
        train_key = bytearray(b"R" * 40)
        with (
            mock.patch.object(
                cli, "_preflight_run_paths", return_value=mount_table
            ),
            mock.patch.object(cli, "_assert_mount_table_stable") as stable,
            mock.patch.object(
                cli, "_read_final_gate_plan_file_v1", return_value=self.plan
            ),
            mock.patch.object(
                cli, "_read_readiness_file_v2", return_value=self.readiness
            ),
            mock.patch.object(
                cli,
                "read_attestation_key_file_v1",
                side_effect=(test_key, train_key),
            ),
            mock.patch.object(
                cli, "run_e4_final_gate_v1", return_value=self.receipt
            ) as runner,
        ):
            self.assertIs(cli._run(self._run_args()), self.receipt)
        self.assertIs(
            runner.call_args.kwargs["expected_mount_table"], mount_table
        )
        self.assertEqual(stable.call_args_list, [mock.call(mount_table)] * 4)

    def test_overlap_rejects_before_plan_or_key_reads(self) -> None:
        plan_reader = mock.Mock()
        key_reader = mock.Mock()
        with (
            mock.patch.object(
                cli,
                "_directory_identity_snapshot",
                return_value=(
                    ((1, 1), frozenset({(1, 1)})),
                    ((1, 2), frozenset({(1, 2)})),
                    ((1, 3), frozenset({(1, 3)})),
                    ((1, 4), frozenset({(1, 4)})),
                    ((1, 5), frozenset({(1, 5)})),
                ),
            ),
            mock.patch.object(cli, "paths_overlap_v1", return_value=True),
            mock.patch.object(
                cli, "_read_final_gate_plan_file_v1", plan_reader
            ),
            mock.patch.object(cli, "read_attestation_key_file_v1", key_reader),
            self.assertRaises(cli.FinalGateCliError) as captured,
        ):
            cli._run(self._run_args())
        self.assertEqual("path_overlap", captured.exception.code)
        plan_reader.assert_not_called()
        key_reader.assert_not_called()

    def test_bind_mount_alias_overlap_is_fail_closed(self) -> None:
        args = self._run_args()
        snapshot = tuple(
            ((1, index), frozenset({(1, index)})) for index in range(1, 6)
        )
        with (
            mock.patch.object(cli, "_linux_mount_table", return_value=mock.sentinel.mounts),
            mock.patch.object(cli.os, "lstat", side_effect=FileNotFoundError),
            mock.patch.object(
                cli, "_directory_identity_snapshot", return_value=snapshot
            ),
            mock.patch.object(cli, "_checked_overlap", return_value=False),
            mock.patch.object(cli, "_physical_overlap", return_value=True),
            self.assertRaises(cli.FinalGateCliError) as captured,
        ):
            cli._preflight_run_paths(args)
        self.assertEqual(captured.exception.code, "path_overlap")

    def test_existing_directory_identity_and_ancestry_aliases_are_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "input"
            child = parent / "nested"
            child.mkdir(parents=True)
            with self.assertRaises(cli.FinalGateCliError) as captured:
                cli._directory_identity_snapshot((parent, Path(str(parent))))
            self.assertEqual("path_overlap", captured.exception.code)

            with self.assertRaises(cli.FinalGateCliError) as captured:
                cli._directory_identity_snapshot((parent, child))
            self.assertEqual("path_overlap", captured.exception.code)

    def test_existing_output_rejects_before_any_plan_or_key_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self._run_args()
            args.output_root = Path(temporary)
            plan_reader = mock.Mock()
            key_reader = mock.Mock()
            with (
                mock.patch.object(
                    cli, "_read_final_gate_plan_file_v1", plan_reader
                ),
                mock.patch.object(
                    cli, "read_attestation_key_file_v1", key_reader
                ),
                self.assertRaises(cli.FinalGateCliError) as captured,
            ):
                cli._run(args)
            self.assertEqual("output_exists", captured.exception.code)
            plan_reader.assert_not_called()
            key_reader.assert_not_called()

    def test_two_key_buffers_zero_on_success_exception_ki_and_systemexit(self) -> None:
        outcomes: tuple[object, ...] = (
            self.receipt,
            RuntimeError("private-path"),
            KeyboardInterrupt(),
            SystemExit(9),
        )
        for outcome in outcomes:
            with self.subTest(outcome=type(outcome).__name__):
                test_key = bytearray(b"A" * 40)
                train_key = bytearray(b"B" * 40)
                side_effect = outcome if isinstance(outcome, BaseException) else None
                patches = self._run_patches(
                    test_key=test_key,
                    train_key=train_key,
                    runner_return=(None if side_effect is not None else outcome),
                    runner_side_effect=side_effect,
                )
                with patches[0], patches[1], patches[2], patches[3], patches[4]:
                    if side_effect is None:
                        self.assertIs(outcome, cli._run(self._run_args()))
                    else:
                        with self.assertRaises(type(outcome)):
                            cli._run(self._run_args())
                self.assertEqual(test_key, bytearray(40))
                self.assertEqual(train_key, bytearray(40))

    def test_key_buffers_must_be_independent_and_partial_read_is_cleared(self) -> None:
        shared = bytearray(b"S" * 40)
        with (
            mock.patch.object(cli, "_preflight_run_paths", return_value=None),
            mock.patch.object(
                cli, "_read_final_gate_plan_file_v1", return_value=self.plan
            ),
            mock.patch.object(
                cli, "_read_readiness_file_v2", return_value=self.readiness
            ),
            mock.patch.object(
                cli,
                "read_attestation_key_file_v1",
                side_effect=(shared, shared),
            ),
            mock.patch.object(cli, "run_e4_final_gate_v1") as runner,
            self.assertRaises(cli.FinalGateCliError) as captured,
        ):
            cli._run(self._run_args())
        self.assertEqual("trusted_key_rejected", captured.exception.code)
        self.assertEqual(shared, bytearray(40))
        runner.assert_not_called()

        first = bytearray(b"F" * 40)
        with (
            mock.patch.object(cli, "_preflight_run_paths", return_value=None),
            mock.patch.object(
                cli, "_read_final_gate_plan_file_v1", return_value=self.plan
            ),
            mock.patch.object(
                cli, "_read_readiness_file_v2", return_value=self.readiness
            ),
            mock.patch.object(
                cli,
                "read_attestation_key_file_v1",
                side_effect=(first, RuntimeError("second key path")),
            ),
            self.assertRaises(RuntimeError),
        ):
            cli._run(self._run_args())
        self.assertEqual(first, bytearray(40))

    def test_plan_loader_uses_bounded_private_file_and_external_double_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "final-gate-plan.json"
            path.write_bytes(self.plan.to_bytes())
            if os.name == "posix":
                os.chmod(path, 0o600)
            result = cli._read_final_gate_plan_file_v1(
                path,
                expected_plan_sha256=self.plan.plan_sha256,
                expected_wire_sha256=self.plan.wire_sha256,
            )
            self.assertEqual(result, self.plan)

            for label, semantic, wire in (
                (
                    "semantic",
                    _sha("wrong-plan"),
                    self.plan.wire_sha256,
                ),
                (
                    "wire",
                    self.plan.plan_sha256,
                    _sha("wrong-plan-wire"),
                ),
            ):
                with self.subTest(pin=label):
                    with self.assertRaises(cli.FinalGateCliError) as captured:
                        cli._read_final_gate_plan_file_v1(
                            path,
                            expected_plan_sha256=semantic,
                            expected_wire_sha256=wire,
                        )
                    self.assertEqual(
                        "plan_input_rejected", captured.exception.code
                    )

            if os.name == "posix":
                os.chmod(path, 0o640)
                with self.assertRaises(cli.FinalGateCliError) as captured:
                    cli._read_final_gate_plan_file_v1(
                        path,
                        expected_plan_sha256=self.plan.plan_sha256,
                        expected_wire_sha256=self.plan.wire_sha256,
                    )
                self.assertEqual(
                    "plan_input_rejected", captured.exception.code
                )
                os.chmod(path, 0o600)

            external = root / "external.json"
            external.write_bytes(self.plan.to_bytes())
            if os.name == "posix":
                os.chmod(external, 0o600)
            hardlink = root / "hardlinked-plan.json"
            try:
                os.link(external, hardlink)
            except (NotImplementedError, OSError):
                return
            with self.assertRaises(cli.FinalGateCliError) as captured:
                cli._read_final_gate_plan_file_v1(
                    hardlink,
                    expected_plan_sha256=self.plan.plan_sha256,
                    expected_wire_sha256=self.plan.wire_sha256,
                )
            self.assertEqual("plan_input_rejected", captured.exception.code)

    def test_run_success_emits_canonical_path_free_summary(self) -> None:
        with mock.patch.object(cli, "_run", return_value=self.receipt):
            status, payload = self._capture_main(self._run_argv())
        self.assertEqual(cli.EXIT_SUCCESS, status)
        summary = json.loads(payload)
        self.assertEqual("closed", summary["status"])
        self.assertEqual(self.receipt.receipt_sha256, summary["receipt_sha256"])
        self.assertEqual(20, summary["test"]["task_count"])
        self.assertEqual(50, summary["train"]["task_count"])
        self.assertEqual(
            self.receipt.train.aggregate_file_sha256,
            summary["train"]["aggregate_file_sha256"],
        )
        for forbidden in (
            "final-output",
            "benchmark-root",
            "test.key",
            "train.key",
            "gold",
            "score",
        ):
            self.assertNotIn(forbidden, payload.casefold())
        self.assertEqual(
            payload,
            json.dumps(
                summary,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
        )

    def test_postcommit_summary_exception_and_baseexception_exit_11(self) -> None:
        for failure in (RuntimeError("summary"), KeyboardInterrupt()):
            with (
                self.subTest(failure=type(failure).__name__),
                mock.patch.object(cli, "_run", return_value=self.receipt),
                mock.patch.object(
                    cli, "_success_summary_v1", side_effect=failure
                ),
            ):
                status, payload = self._capture_main(self._run_argv())
            self.assertEqual(status, cli.EXIT_COMMITTED_UNCERTAIN)
            self.assertEqual(json.loads(payload)["status"], "committed_uncertain")

    def test_postcommit_persistent_broken_pipe_still_returns_exit_11(self) -> None:
        with (
            mock.patch.object(cli, "_run", return_value=self.receipt),
            mock.patch.object(
                cli, "_write_stdout_bytes", side_effect=BrokenPipeError
            ) as writer,
        ):
            status = cli.main(self._run_argv())
        self.assertEqual(status, cli.EXIT_COMMITTED_UNCERTAIN)
        self.assertEqual(writer.call_count, 2)

    def test_run_return_store_opcode_interrupt_keeps_committed_state(self) -> None:
        target_offset = next(
            instruction.offset
            for instruction in dis.get_instructions(cli.main)
            if instruction.opname == "STORE_FAST" and instruction.argval == "result"
        )
        triggered = False

        def committed_run(_args, *, commit_callback):
            commit_callback("committed")
            return self.receipt

        def interrupt(frame, event, argument):
            del argument
            nonlocal triggered
            if frame.f_code is cli.main.__code__:
                frame.f_trace_opcodes = True
                if event == "opcode" and frame.f_lasti == target_offset:
                    triggered = True
                    sys.settrace(None)
                    raise KeyboardInterrupt()
            return interrupt

        previous_trace = sys.gettrace()
        with mock.patch.object(cli, "_run", side_effect=committed_run):
            sys.settrace(interrupt)
            try:
                status, payload = self._capture_main(self._run_argv())
            finally:
                sys.settrace(previous_trace)
        self.assertTrue(triggered)
        self.assertEqual(status, cli.EXIT_COMMITTED_UNCERTAIN)
        self.assertEqual(json.loads(payload)["status"], "committed_uncertain")

    def test_rigid_postrename_baseexception_with_broken_pipe_exits_11(self) -> None:
        class RigidFatal(BaseException):
            def __setattr__(self, _name, _value):
                raise TypeError("rigid exception")

        def rename_may_have_committed(_args, *, commit_callback):
            commit_callback("possible")
            raise RigidFatal("post-rename failure")

        with (
            mock.patch.object(cli, "_run", side_effect=rename_may_have_committed),
            mock.patch.object(
                cli, "_write_stdout_bytes", side_effect=BrokenPipeError
            ) as writer,
        ):
            status = cli.main(self._run_argv())
        self.assertEqual(status, cli.EXIT_COMMITTED_UNCERTAIN)
        self.assertEqual(writer.call_count, 1)

    def test_attempt_report_is_written_as_raw_canonical_bytes_with_exit_10(self) -> None:
        report = _FakeAttempt()
        with (
            mock.patch.object(cli, "DiscoveryBatchAttemptReportV2", _FakeAttempt),
            mock.patch.object(cli, "_run", return_value=report),
        ):
            status, payload = self._capture_main(self._run_argv())
        self.assertEqual(cli.EXIT_ATTEMPT_FAILED, status)
        self.assertEqual(report.to_bytes().decode("utf-8"), payload)
        self.assertNotIn("receipt_sha256", payload)

    def test_attempt_report_failure_remains_uncommitted(self) -> None:
        report = _FakeAttempt()
        with (
            mock.patch.object(cli, "DiscoveryBatchAttemptReportV2", _FakeAttempt),
            mock.patch.object(cli, "_run", return_value=report),
            mock.patch.object(
                cli, "_attempt_report_bytes", side_effect=KeyboardInterrupt
            ),
        ):
            status, payload = self._capture_main(self._run_argv())
        self.assertEqual(status, cli.EXIT_INTERRUPTED)
        self.assertEqual(json.loads(payload)["status"], "interrupted")

    def test_verify_output_passes_double_pins_and_emits_same_summary(self) -> None:
        with (
            mock.patch.object(
                cli,
                "_directory_identity_snapshot",
                return_value=(
                    ((1, 1), frozenset({(1, 1)})),
                    ((1, 2), frozenset({(1, 2)})),
                ),
            ),
            mock.patch.object(cli, "paths_overlap_v1", return_value=False),
            mock.patch.object(
                cli,
                "read_committed_e4_final_gate_v1",
                return_value=self.receipt,
            ) as reader,
        ):
            status, payload = self._capture_main(self._verify_argv())
        self.assertEqual(cli.EXIT_SUCCESS, status)
        reader.assert_called_once_with(
            Path("committed-output"),
            expected_receipt_sha256=self.receipt.receipt_sha256,
            expected_wire_sha256=self.receipt.wire_sha256,
            benchmark_root=Path("benchmark-root"),
        )
        summary = json.loads(payload)
        self.assertEqual(self.receipt.receipt_sha256, summary["receipt_sha256"])
        self.assertNotIn("committed-output", payload)
        self.assertNotIn("benchmark-root", payload)

    def test_exit_classes_and_errors_never_leak_paths(self) -> None:
        secret = r"C:\private\operator\final-output"
        committed_interrupt = KeyboardInterrupt()
        committed_interrupt.committed = True
        cases = (
            (
                FinalGateRunnerError(
                    "publication_uncertain", secret, committed=True
                ),
                cli.EXIT_COMMITTED_UNCERTAIN,
                "committed_uncertain",
            ),
            (
                FinalGateRunnerError("run_rejected", secret),
                cli.EXIT_REJECTED,
                "rejected",
            ),
            (KeyboardInterrupt(), cli.EXIT_INTERRUPTED, "interrupted"),
            (
                committed_interrupt,
                cli.EXIT_COMMITTED_UNCERTAIN,
                "committed_uncertain",
            ),
            (_FatalSignal(), cli.EXIT_INTERRUPTED, "interrupted"),
        )
        for error, expected_exit, expected_status in cases:
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(cli, "_run", side_effect=error):
                    status, payload = self._capture_main(self._run_argv())
                self.assertEqual(expected_exit, status)
                self.assertEqual(expected_status, json.loads(payload)["status"])
                self.assertNotIn(secret, payload)
                self.assertNotIn("Traceback", payload)


if __name__ == "__main__":
    unittest.main()
