from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import vulngym_agent.e4_cli as cli
from vulngym_agent.evaluator.e4_driver import E4DriverError
from vulngym_agent.evaluator.publication_reader import (
    E4PublicationReaderError,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _FakeSuccess:
    def __init__(
        self,
        split: str = "test",
        *,
        receipt_sha256: str | None = None,
        wire_sha256: str | None = None,
    ) -> None:
        count = 20 if split == "test" else 50
        policy = SimpleNamespace(
            policy_sha256=_sha(f"{split}:policy"),
            wire_sha256=_sha(f"{split}:policy-wire"),
        )
        batch = SimpleNamespace(split=split, task_count=count)
        plan = SimpleNamespace(
            batch=batch,
            execution_policy=policy,
            plan_sha256=_sha(f"{split}:plan"),
            wire_sha256=_sha(f"{split}:plan-wire"),
        )
        self.execution_receipt = SimpleNamespace(
            plan=plan,
            artifact_index_sha256=_sha(f"{split}:artifact-index"),
        )
        self.receipt_sha256 = receipt_sha256 or _sha(f"{split}:receipt")
        self.wire_sha256 = wire_sha256 or _sha(f"{split}:receipt-wire")


class _FakeAttempt:
    def __init__(self) -> None:
        self._payload = b'{"kind":"attempt","status":"failed_clean"}\n'
        self.report_sha256 = _sha("attempt-report")
        self.wire_sha256 = hashlib.sha256(self._payload).hexdigest()

    def to_bytes(self) -> bytes:
        return self._payload


class _FatalSignal(BaseException):
    pass


class E4CliTests(unittest.TestCase):
    def _run_argv(self, *, split: str = "test") -> list[str]:
        return [
            "run-split",
            "--benchmark-root",
            "benchmark-root",
            "--sealed-batch-root",
            "sealed-root",
            "--replay-config-root",
            "replay-root",
            "--output-root",
            "success-output",
            "--split",
            split,
            "--expected-sealed-batch-manifest-sha256",
            _sha("sealed"),
            "--expected-replay-manifest-sha256",
            _sha("replay"),
            "--expected-replay-manifest-wire-sha256",
            _sha("replay-wire"),
            "--key-file",
            "key.bin",
            "--snapshot-key-id",
            "snapshot-key",
            "--runtime-image-id",
            "sha256:" + "a" * 64,
            "--docker-executable",
            "docker",
        ]

    def _run_args(self, *, split: str = "test") -> argparse.Namespace:
        return cli._parser().parse_args(self._run_argv(split=split))

    def _capture_main(self, argv: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with mock.patch.object(cli.sys, "stdout", output):
            status = cli.main(argv)
        return status, output.getvalue()

    def test_dispatches_test_split_and_emits_path_free_success_summary(self) -> None:
        key = bytearray(b"K" * 40)
        success = _FakeSuccess("test")
        with (
            mock.patch.object(cli, "E4BatchSuccessReceiptV2", _FakeSuccess),
            mock.patch.object(cli, "paths_overlap_v1", return_value=False) as overlap,
            mock.patch.object(
                cli, "read_attestation_key_file_v1", return_value=key
            ),
            mock.patch.object(
                cli, "run_e4_discovery_split_v1", return_value=success
            ) as driver,
        ):
            status, payload = self._capture_main(self._run_argv())

        self.assertEqual(cli.EXIT_SUCCESS, status)
        self.assertEqual(bytearray(40), key)
        overlap.assert_called_once_with(
            Path("success-output"),
            Path("key.bin"),
            left_exists=False,
            right_directory=False,
        )
        self.assertEqual("test", driver.call_args.kwargs["split"])
        self.assertEqual(
            _sha("sealed"),
            driver.call_args.kwargs[
                "expected_sealed_batch_manifest_sha256"
            ],
        )
        self.assertEqual(
            _sha("replay-wire"),
            driver.call_args.kwargs[
                "expected_replay_manifest_wire_sha256"
            ],
        )
        summary = json.loads(payload)
        self.assertEqual("succeeded", summary["status"])
        self.assertEqual("test", summary["split"])
        self.assertEqual(20, summary["task_count"])
        self.assertEqual(success.receipt_sha256, summary["receipt_sha256"])
        self.assertNotIn("success-output", payload)
        self.assertNotIn("key.bin", payload)
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

    def test_key_is_zeroed_after_success_exception_and_base_exception(self) -> None:
        for outcome in (object(), RuntimeError("secret-path"), _FatalSignal()):
            with self.subTest(outcome=type(outcome).__name__):
                key = bytearray(b"Q" * 40)
                with (
                    mock.patch.object(cli, "paths_overlap_v1", return_value=False),
                    mock.patch.object(
                        cli,
                        "read_attestation_key_file_v1",
                        return_value=key,
                    ),
                    mock.patch.object(
                        cli,
                        "run_e4_discovery_split_v1",
                        side_effect=(
                            outcome
                            if isinstance(outcome, BaseException)
                            else None
                        ),
                        return_value=(
                            outcome
                            if not isinstance(outcome, BaseException)
                            else None
                        ),
                    ),
                ):
                    if isinstance(outcome, BaseException):
                        with self.assertRaises(type(outcome)):
                            cli._run_split(self._run_args())
                    else:
                        self.assertIs(outcome, cli._run_split(self._run_args()))
                self.assertEqual(bytearray(40), key)

    def test_parser_exposes_only_the_fixed_commands_and_run_inputs(self) -> None:
        parser = cli._parser()
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        self.assertEqual(
            {"run-split", "verify-output"}, set(subparsers.choices)
        )
        run = subparsers.choices["run-split"]
        options = {
            option
            for action in run._actions
            for option in action.option_strings
        }
        self.assertEqual(
            {
                "--help",
                "-h",
                "--benchmark-root",
                "--sealed-batch-root",
                "--replay-config-root",
                "--output-root",
                "--split",
                "--expected-sealed-batch-manifest-sha256",
                "--expected-replay-manifest-sha256",
                "--expected-replay-manifest-wire-sha256",
                "--key-file",
                "--snapshot-key-id",
                "--runtime-image-id",
                "--docker-executable",
            },
            options,
        )
        forbidden = {
            "--backend",
            "--backend-id",
            "--model",
            "--model-id",
            "--max-attempts",
            "--memory-bytes",
            "--network-mode",
            "--top-k",
            "--wall-time-seconds",
        }
        self.assertTrue(options.isdisjoint(forbidden))

    def test_runtime_failure_is_sanitized_without_path_key_or_traceback(self) -> None:
        secret = r"C:\operators\private\attestation.key"
        with mock.patch.object(
            cli,
            "paths_overlap_v1",
            side_effect=OSError(f"cannot inspect {secret}"),
        ):
            status, payload = self._capture_main(self._run_argv())
        self.assertEqual(cli.EXIT_REJECTED, status)
        self.assertNotIn(secret, payload)
        self.assertNotIn("attestation", payload)
        self.assertNotIn("Traceback", payload)
        self.assertEqual("rejected", json.loads(payload)["status"])

    def test_output_key_overlap_rejects_before_reading_the_key(self) -> None:
        reader = mock.Mock()
        driver = mock.Mock()
        with (
            mock.patch.object(cli, "paths_overlap_v1", return_value=True),
            mock.patch.object(cli, "read_attestation_key_file_v1", reader),
            mock.patch.object(cli, "run_e4_discovery_split_v1", driver),
        ):
            status, payload = self._capture_main(self._run_argv())
        self.assertEqual(cli.EXIT_REJECTED, status)
        self.assertEqual("path_overlap", json.loads(payload)["code"])
        self.assertNotIn("success-output", payload)
        self.assertNotIn("key.bin", payload)
        reader.assert_not_called()
        driver.assert_not_called()

    def test_malformed_run_scalars_reject_before_paths_key_or_driver(self) -> None:
        mutations = (
            ("expected_sealed_batch_manifest_sha256", "A" * 64),
            ("expected_replay_manifest_sha256", "short"),
            ("expected_replay_manifest_wire_sha256", "g" * 64),
            ("runtime_image_id", "python:latest"),
            ("snapshot_key_id", "invalid key id"),
        )
        for name, value in mutations:
            with self.subTest(name=name):
                args = self._run_args()
                setattr(args, name, value)
                overlap = mock.Mock()
                reader = mock.Mock()
                driver = mock.Mock()
                with (
                    mock.patch.object(cli, "paths_overlap_v1", overlap),
                    mock.patch.object(
                        cli, "read_attestation_key_file_v1", reader
                    ),
                    mock.patch.object(
                        cli, "run_e4_discovery_split_v1", driver
                    ),
                    self.assertRaises(cli.E4CliError) as captured,
                ):
                    cli._run_split(args)
                self.assertEqual("invalid_argument", captured.exception.code)
                overlap.assert_not_called()
                reader.assert_not_called()
                driver.assert_not_called()

    def test_failed_attempt_writes_raw_canonical_report_and_no_success_summary(self) -> None:
        key = bytearray(b"R" * 40)
        report = _FakeAttempt()
        with (
            mock.patch.object(
                cli, "DiscoveryBatchAttemptReportV2", _FakeAttempt
            ),
            mock.patch.object(cli, "paths_overlap_v1", return_value=False),
            mock.patch.object(
                cli, "read_attestation_key_file_v1", return_value=key
            ),
            mock.patch.object(
                cli, "run_e4_discovery_split_v1", return_value=report
            ),
            mock.patch.object(
                cli, "read_committed_e4_discovery_execution_v1"
            ) as reader,
        ):
            status, payload = self._capture_main(self._run_argv())
        self.assertEqual(cli.EXIT_ATTEMPT_FAILED, status)
        self.assertEqual(bytearray(40), key)
        self.assertEqual(report.to_bytes().decode("utf-8"), payload)
        self.assertNotIn("receipt_sha256", payload)
        reader.assert_not_called()

    def test_verify_output_passes_both_external_pins_and_emits_same_summary(self) -> None:
        semantic = _sha("external-e4-semantic")
        wire = _sha("external-e4-wire")
        success = _FakeSuccess(
            "train", receipt_sha256=semantic, wire_sha256=wire
        )
        argv = [
            "verify-output",
            "--output-root",
            "committed-output",
            "--expected-receipt-sha256",
            semantic,
            "--expected-wire-sha256",
            wire,
        ]
        with (
            mock.patch.object(cli, "E4BatchSuccessReceiptV2", _FakeSuccess),
            mock.patch.object(
                cli,
                "read_committed_e4_discovery_execution_v1",
                return_value=success,
            ) as reader,
        ):
            status, payload = self._capture_main(argv)
        self.assertEqual(cli.EXIT_SUCCESS, status)
        reader.assert_called_once_with(
            Path("committed-output"),
            expected_receipt_sha256=semantic,
            expected_wire_sha256=wire,
        )
        summary = json.loads(payload)
        self.assertEqual("train", summary["split"])
        self.assertEqual(50, summary["task_count"])
        self.assertEqual(semantic, summary["receipt_sha256"])
        self.assertEqual(wire, summary["receipt_wire_sha256"])
        self.assertNotIn("committed-output", payload)

    def test_verify_output_rejects_detached_or_wrong_exact_reader_return(self) -> None:
        semantic = _sha("external-e4-semantic")
        wire = _sha("external-e4-wire")
        argv = [
            "verify-output",
            "--output-root",
            "committed-output",
            "--expected-receipt-sha256",
            semantic,
            "--expected-wire-sha256",
            wire,
        ]
        detached = _FakeSuccess("test")
        for returned in (detached, object()):
            with self.subTest(returned=type(returned).__name__):
                with (
                    mock.patch.object(
                        cli, "E4BatchSuccessReceiptV2", _FakeSuccess
                    ),
                    mock.patch.object(
                        cli,
                        "read_committed_e4_discovery_execution_v1",
                        return_value=returned,
                    ),
                ):
                    status, payload = self._capture_main(argv)
                self.assertEqual(cli.EXIT_COMMITTED_UNCERTAIN, status)
                summary = json.loads(payload)
                self.assertEqual("committed_uncertain", summary["status"])
                self.assertEqual("publication_mismatch", summary["code"])
                self.assertNotIn("receipt_wire_sha256", payload)

    def test_committed_uncertainty_has_a_distinct_sanitized_exit(self) -> None:
        secret = r"D:\unpublished\operator-output"
        verify_argv = [
            "verify-output",
            "--output-root",
            secret,
            "--expected-receipt-sha256",
            _sha("semantic"),
            "--expected-wire-sha256",
            _sha("wire"),
        ]
        with mock.patch.object(
            cli,
            "read_committed_e4_discovery_execution_v1",
            side_effect=E4PublicationReaderError(
                "publication_invalid", f"changed at {secret}"
            ),
        ):
            status, payload = self._capture_main(verify_argv)
        self.assertEqual(cli.EXIT_COMMITTED_UNCERTAIN, status)
        self.assertEqual("committed_uncertain", json.loads(payload)["status"])
        self.assertNotIn(secret, payload)
        self.assertNotIn("Traceback", payload)

        with mock.patch.object(
            cli,
            "_run_split",
            side_effect=E4DriverError(
                "publication_unverified", "hidden path", committed=True
            ),
        ):
            status, payload = self._capture_main(self._run_argv())
        self.assertEqual(cli.EXIT_COMMITTED_UNCERTAIN, status)
        self.assertEqual("committed_uncertain", json.loads(payload)["status"])
        self.assertNotIn("hidden path", payload)


if __name__ == "__main__":
    unittest.main()
