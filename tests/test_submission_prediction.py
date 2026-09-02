from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vulngym_agent import submission_prediction as submission_module
from vulngym_agent import submission_prediction_cli as submission_cli_module
from vulngym_agent.orchestrator import (
    ClosedLoopOrchestrator,
    ProductionDeferredDraft,
    ReplayRecord,
    VerifiedSubmissionPredictions,
    VerifiedTaskPrediction,
    canonical_sha256,
    read_verified_submission_predictions,
    write_closed_loop_artifacts,
)
from vulngym_agent.submission_prediction import (
    SUBMISSION_PREDICTION_FILES,
    SubmissionPredictionError,
    read_submission_predictions,
    verify_submission_predictions,
    write_submission_predictions,
)
from vulngym_agent.submission_prediction_cli import main
from tests import test_orchestrator as orchestrator_fixtures
from tests.producer_context_support import FixedProducerContextFactory


@unittest.skipUnless(os.name == "posix", "submission export requires POSIX")
class SubmissionPredictionTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = orchestrator_fixtures.ClosedLoopOrchestratorTests()
        fixture.setUp()
        self.fixture = fixture
        self.entry = fixture.entry
        self.task = fixture.task

    def _manual_review(self):
        outcome, _ = self.fixture._run(
            orchestrator_fixtures._FakeProducer(self.entry),
            [
                orchestrator_fixtures._report(
                    self.entry, {"trace": "uncertain"}, label="uncertain"
                )
            ],
        )
        self.assertEqual(outcome.status, "manual_review")
        return outcome

    def _deferred(self):
        class Producer:
            def generate(self, task, context):
                return ProductionDeferredDraft(
                    stage="task_contract",
                    reason_code="missing_public_fact",
                    missing_information=("public advisory is incomplete",),
                )

            def repair(self, *args, **kwargs):
                raise AssertionError("repair must not run")

        def no_validator(task):
            raise AssertionError("validator must not run")

        return ClosedLoopOrchestrator(
            Producer(), no_validator, FixedProducerContextFactory()
        ).run(self.task)

    def _source_replay(self, parent: Path, outcome):
        replay = parent / "source-replay"
        manifest = write_closed_loop_artifacts(
            replay, [ReplayRecord(7, self.task, outcome)]
        )
        predictions = read_verified_submission_predictions(
            replay, expected_dataset_sha256=manifest.dataset_sha256
        )
        return replay, manifest, predictions

    def test_manual_review_exports_one_complete_honest_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, predictions = self._source_replay(
                root, self._manual_review()
            )
            output = root / "submission"

            manifest = write_submission_predictions(
                output,
                replay,
                expected_source_replay_dataset_sha256=(
                    source_manifest.dataset_sha256
                ),
                expected_task_count=1,
                protected_paths=(replay,),
            )

            self.assertEqual(
                {item.name for item in output.iterdir()},
                set(SUBMISSION_PREDICTION_FILES),
            )
            self.assertEqual(manifest.task_count, 1)
            self.assertEqual(dict(manifest.status_counts), {"manual_review": 1})
            self.assertEqual(dict(manifest.verdict_counts), {"uncertain": 1})
            self.assertEqual(
                manifest.source_replay_dataset_sha256,
                source_manifest.dataset_sha256,
            )
            entry = json.loads(
                (output / "entries.jsonl").read_text(encoding="utf-8")
            )
            report = json.loads(
                (output / "validation.jsonl").read_text(encoding="utf-8")
            )
            self.assertEqual(entry["verify"], 0)
            self.assertEqual(report["verdict"], "uncertain")
            self.assertEqual(entry["entry_id"], report["entry_id"])
            self.assertEqual(entry["report_id"], report["report_id"])

            checked = read_submission_predictions(
                output,
                expected_source_replay_dataset_sha256=(
                    source_manifest.dataset_sha256
                ),
                expected_task_count=1,
                expected_submission_sha256=manifest.submission_sha256,
            )
            self.assertEqual(
                canonical_sha256(checked.entries[0]), canonical_sha256(self.entry)
            )
            self.assertEqual(checked.validations[0].verdict, "uncertain")

    def test_incomplete_deferred_task_is_rejected_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._deferred()
            )
            output = root / "submission"

            with self.assertRaisesRegex(
                SubmissionPredictionError, "without a candidate/report pair"
            ):
                write_submission_predictions(
                    output,
                    replay,
                    expected_source_replay_dataset_sha256=(
                        source_manifest.dataset_sha256
                    ),
                    expected_task_count=1,
                )

            self.assertFalse(output.exists())
            self.assertFalse(
                any(
                    item.name.startswith(".submission-predictions-")
                    for item in root.iterdir()
                )
            )

    def test_public_writer_rejects_a_self_asserted_projection_object(self) -> None:
        outcome = self._manual_review()
        entry = deepcopy(self.entry)
        entry["project"] = "attacker/self-asserted"
        prediction = VerifiedTaskPrediction(
            task_id=self.task.task_id,
            input_line=7,
            status="manual_review",
            entry=entry,
            validation=outcome.report,
        )
        predictions = VerifiedSubmissionPredictions(
            dataset_sha256="a" * 64,
            tasks=(prediction,),
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "submission"
            with self.assertRaisesRegex(
                SubmissionPredictionError, "source replay directory is invalid"
            ):
                write_submission_predictions(
                    output,
                    predictions,
                    expected_source_replay_dataset_sha256="a" * 64,
                    expected_task_count=1,
                )
            self.assertFalse(output.exists())

    def test_count_source_pin_existing_output_and_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._manual_review()
            )
            with self.assertRaisesRegex(
                SubmissionPredictionError, "task count differs"
            ):
                write_submission_predictions(
                    root / "wrong-count",
                    replay,
                    expected_source_replay_dataset_sha256=(
                        source_manifest.dataset_sha256
                    ),
                    expected_task_count=2,
                )

            output = root / "submission"
            manifest = write_submission_predictions(
                output,
                replay,
                expected_source_replay_dataset_sha256=(
                    source_manifest.dataset_sha256
                ),
                expected_task_count=1,
            )
            with self.assertRaisesRegex(
                SubmissionPredictionError, "already exists"
            ):
                write_submission_predictions(
                    output,
                    replay,
                    expected_source_replay_dataset_sha256=(
                        source_manifest.dataset_sha256
                    ),
                    expected_task_count=1,
                )
            with self.assertRaisesRegex(
                SubmissionPredictionError, "manifest binding differs"
            ):
                read_submission_predictions(
                    output,
                    expected_source_replay_dataset_sha256="f" * 64,
                    expected_task_count=1,
                    expected_submission_sha256=manifest.submission_sha256,
                )
            path = output / "entries.jsonl"
            raw = path.read_bytes()
            path.write_bytes(raw.replace(b'"verify":0', b'"verify":1'))
            with self.assertRaises(SubmissionPredictionError):
                read_submission_predictions(
                    output,
                    expected_source_replay_dataset_sha256=(
                        source_manifest.dataset_sha256
                    ),
                    expected_task_count=1,
                    expected_submission_sha256=manifest.submission_sha256,
                )

    def test_formal_verify_rejects_integrity_valid_self_signed_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outcome = self._manual_review()
            replay, source_manifest, _ = self._source_replay(root, outcome)
            forged_entry = deepcopy(self.entry)
            forged_entry["project"] = "attacker/self-asserted"
            forged = VerifiedSubmissionPredictions(
                dataset_sha256=source_manifest.dataset_sha256,
                tasks=(
                    VerifiedTaskPrediction(
                        task_id=self.task.task_id,
                        input_line=7,
                        status="manual_review",
                        entry=forged_entry,
                        validation=outcome.report,
                    ),
                ),
            )
            payloads, forged_manifest = submission_module._build_payloads(
                forged, expected_task_count=1
            )
            output = root / "self-signed"
            output.mkdir(mode=0o700)
            for name, payload in payloads.items():
                (output / name).write_bytes(payload)

            integrity_only = read_submission_predictions(
                output,
                expected_source_replay_dataset_sha256=(
                    source_manifest.dataset_sha256
                ),
                expected_task_count=1,
                expected_submission_sha256=forged_manifest.submission_sha256,
            )
            self.assertEqual(
                integrity_only.entries[0]["project"], "attacker/self-asserted"
            )
            with self.assertRaisesRegex(
                SubmissionPredictionError, "pinned source replay"
            ):
                verify_submission_predictions(
                    output,
                    replay,
                    expected_source_replay_dataset_sha256=(
                        source_manifest.dataset_sha256
                    ),
                    expected_task_count=1,
                    expected_submission_sha256=(
                        forged_manifest.submission_sha256
                    ),
                )

    def test_rename_that_commits_then_raises_is_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._manual_review()
            )
            output = root / "submission"
            real_rename = submission_module._rename_noreplace

            def committed_then_raises(*args, **kwargs):
                real_rename(*args, **kwargs)
                raise OSError("injected post-commit exception")

            with patch.object(
                submission_module,
                "_rename_noreplace",
                side_effect=committed_then_raises,
            ):
                manifest = write_submission_predictions(
                    output,
                    replay,
                    expected_source_replay_dataset_sha256=(
                        source_manifest.dataset_sha256
                    ),
                    expected_task_count=1,
                )
            self.assertTrue(output.is_dir())
            self.assertEqual(manifest.task_count, 1)

    def test_staging_name_replacement_is_classified_committed_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._manual_review()
            )
            output = root / "submission"
            displaced = root / "displaced-original-staging"
            real_rename = submission_module._rename_noreplace

            def replace_staging_then_rename(*args, **kwargs):
                staging = next(root.glob(".submission-predictions-*"))
                os.rename(staging, displaced)
                os.mkdir(staging)
                real_rename(*args, **kwargs)

            with patch.object(
                submission_module,
                "_rename_noreplace",
                side_effect=replace_staging_then_rename,
            ):
                with self.assertRaises(SubmissionPredictionError) as raised:
                    write_submission_predictions(
                        output,
                        replay,
                        expected_source_replay_dataset_sha256=(
                            source_manifest.dataset_sha256
                        ),
                        expected_task_count=1,
                    )
            self.assertEqual(raised.exception.code, "publication_uncertain")
            self.assertTrue(raised.exception.committed)
            self.assertTrue(output.is_dir())
            self.assertTrue(displaced.is_dir())

    def test_failure_after_final_check_preserves_the_entire_staging_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._manual_review()
            )
            output = root / "submission"
            displaced = root / "transaction-entry"
            caller_payload = b"caller-owned-replacement\n"
            observed_staging: Path | None = None

            def replace_file_then_fail(*args, **kwargs):
                nonlocal observed_staging
                _ = args, kwargs
                observed_staging = next(
                    root.glob(".submission-predictions-*")
                )
                os.replace(
                    observed_staging / "entries.jsonl", displaced
                )
                (observed_staging / "entries.jsonl").write_bytes(
                    caller_payload
                )
                raise OSError("injected precommit failure")

            with patch.object(
                submission_module,
                "_rename_noreplace",
                side_effect=replace_file_then_fail,
            ), patch.object(
                submission_module.os,
                "unlink",
                side_effect=AssertionError("failure cleanup must not unlink"),
            ):
                with self.assertRaises(SubmissionPredictionError) as raised:
                    write_submission_predictions(
                        output,
                        replay,
                        expected_source_replay_dataset_sha256=(
                            source_manifest.dataset_sha256
                        ),
                        expected_task_count=1,
                    )
            self.assertEqual(raised.exception.code, "publication_failed")
            self.assertFalse(raised.exception.committed)
            self.assertIsNotNone(observed_staging)
            if observed_staging is None:
                self.fail("staging directory was not observed")
            self.assertTrue(observed_staging.is_dir())
            self.assertEqual(
                (observed_staging / "entries.jsonl").read_bytes(),
                caller_payload,
            )
            self.assertTrue((observed_staging / "validation.jsonl").is_file())
            self.assertTrue(
                (observed_staging / "submission_manifest.json").is_file()
            )
            self.assertTrue(displaced.is_file())
            self.assertFalse(output.exists())

    def test_directory_close_failure_preserves_publication_classification(
        self,
    ) -> None:
        with patch.object(
            submission_module.os,
            "close",
            side_effect=OSError("injected close failure"),
        ) as close:
            with self.assertRaises(SubmissionPredictionError) as raised:
                submission_module._close_directory_descriptors(
                    (101, 102, None),
                    committed=True,
                    preserve_active_failure=False,
                )
        self.assertEqual(close.call_count, 2)
        self.assertEqual(raised.exception.code, "publication_uncertain")
        self.assertTrue(raised.exception.committed)

        with patch.object(
            submission_module.os,
            "close",
            side_effect=OSError("injected close failure"),
        ) as close:
            submission_module._close_directory_descriptors(
                (201, None),
                committed=False,
                preserve_active_failure=True,
            )
        self.assertEqual(close.call_count, 1)

    def test_mock_bind_alias_identity_overlap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._manual_review()
            )
            output = root / "submission"
            actual = submission_module._capture_trusted_path_guard(
                replay, require_directory=True
            )
            parent_identity = submission_module._directory_binding(
                os.lstat(root)
            )
            aliased = submission_module._TrustedPathGuard(
                path=actual.path,
                is_directory=True,
                directory_chain=actual.directory_chain,
                object_identity=(
                    parent_identity[0],
                    parent_identity[1],
                    *actual.object_identity[2:],
                ),
            )
            with patch.object(
                submission_module,
                "_capture_trusted_path_guards",
                return_value=(aliased,),
            ):
                with self.assertRaises(SubmissionPredictionError) as raised:
                    write_submission_predictions(
                        output,
                        replay,
                        expected_source_replay_dataset_sha256=(
                            source_manifest.dataset_sha256
                        ),
                        expected_task_count=1,
                    )
            self.assertEqual(raised.exception.code, "path_overlap")
            self.assertFalse(output.exists())

    def test_file_name_replacement_during_bound_open_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._manual_review()
            )
            output = root / "submission"
            manifest = write_submission_predictions(
                output,
                replay,
                expected_source_replay_dataset_sha256=(
                    source_manifest.dataset_sha256
                ),
                expected_task_count=1,
            )
            replacement = root / "replacement-entry"
            replacement.write_bytes((output / "entries.jsonl").read_bytes())
            real_open = submission_module.os.open
            replaced = False

            def replacing_open(path, flags, *args, **kwargs):
                nonlocal replaced
                if not replaced and Path(os.fspath(path)).name == "entries.jsonl":
                    replaced = True
                    os.replace(replacement, output / "entries.jsonl")
                return real_open(path, flags, *args, **kwargs)

            with patch.object(
                submission_module.os, "open", side_effect=replacing_open
            ):
                with self.assertRaisesRegex(
                    SubmissionPredictionError, "changed during open"
                ):
                    read_submission_predictions(
                        output,
                        expected_source_replay_dataset_sha256=(
                            source_manifest.dataset_sha256
                        ),
                        expected_task_count=1,
                        expected_submission_sha256=manifest.submission_sha256,
                    )
            self.assertTrue(replaced)

    def test_cli_export_and_pinned_verify_emit_path_free_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._manual_review()
            )
            output = root / "submission"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(
                    [
                        "export",
                        "--replay-dir",
                        str(replay),
                        "--replay-dataset-sha256",
                        source_manifest.dataset_sha256,
                        "--output-dir",
                        str(output),
                        "--expected-task-count",
                        "1",
                    ]
                )
            self.assertEqual(code, 0, stderr.getvalue())
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["operation"], "export")
            self.assertEqual(summary["task_count"], 1)
            self.assertNotIn(str(root), stdout.getvalue())

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(
                    [
                        "verify",
                        "--submission-dir",
                        str(output),
                        "--replay-dir",
                        str(replay),
                        "--source-replay-dataset-sha256",
                        source_manifest.dataset_sha256,
                        "--submission-sha256",
                        summary["submission_sha256"],
                        "--expected-task-count",
                        "1",
                    ]
                )
            self.assertEqual(code, 0, stderr.getvalue())
            self.assertEqual(json.loads(stdout.getvalue())["operation"], "verify")

    def test_cli_output_interrupt_after_export_is_committed_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, _ = self._source_replay(
                root, self._manual_review()
            )
            output = root / "submission"
            stderr = io.StringIO()
            with patch.object(
                submission_cli_module,
                "_canonical_stdout",
                side_effect=KeyboardInterrupt,
            ), redirect_stderr(stderr):
                code = main(
                    [
                        "export",
                        "--replay-dir",
                        str(replay),
                        "--replay-dataset-sha256",
                        source_manifest.dataset_sha256,
                        "--output-dir",
                        str(output),
                        "--expected-task-count",
                        "1",
                    ]
                )
            self.assertEqual(code, submission_cli_module.EXIT_COMMITTED_UNCERTAIN)
            self.assertIn("committed_uncertain", stderr.getvalue())
            self.assertTrue(output.is_dir())

    def test_cli_help_and_argument_error_preserve_argparse_exit_codes(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("usage:", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main([])
        self.assertEqual(code, 2)
        self.assertIn("arguments rejected", stderr.getvalue())
        self.assertNotIn("operation_failed", stderr.getvalue())


class SubmissionPredictionCliStateTests(unittest.TestCase):
    @staticmethod
    def _export_arguments() -> list[str]:
        return [
            "export",
            "--replay-dir",
            "synthetic-replay",
            "--replay-dataset-sha256",
            "a" * 64,
            "--output-dir",
            "synthetic-output",
            "--expected-task-count",
            "1",
        ]

    @staticmethod
    def _manifest() -> SimpleNamespace:
        return SimpleNamespace(
            source_replay_dataset_sha256="a" * 64,
            submission_sha256="b" * 64,
            task_count=1,
            status_counts={"finalized": 1},
            verdict_counts={"correct": 1},
        )

    def test_prepublication_bare_failures_are_not_reported_committed(self) -> None:
        for failure in (
            MemoryError("injected memory failure"),
            RuntimeError("injected runtime failure"),
            SystemExit(7),
        ):
            with self.subTest(failure=type(failure).__name__):
                stderr = io.StringIO()
                with patch.object(
                    submission_cli_module,
                    "write_submission_predictions",
                    side_effect=failure,
                ), redirect_stderr(stderr):
                    code = main(self._export_arguments())
                self.assertEqual(code, submission_cli_module.EXIT_REJECTED)
                self.assertNotIn("committed_uncertain", stderr.getvalue())

    def test_postpublication_system_exit_is_committed_uncertain(self) -> None:
        stderr = io.StringIO()
        with patch.object(
            submission_cli_module,
            "write_submission_predictions",
            return_value=self._manifest(),
        ), patch.object(
            submission_cli_module,
            "_canonical_stdout",
            side_effect=SystemExit(0),
        ), redirect_stderr(stderr):
            code = main(self._export_arguments())
        self.assertEqual(code, submission_cli_module.EXIT_COMMITTED_UNCERTAIN)
        self.assertIn("error[committed_uncertain]", stderr.getvalue())

    def test_postpublication_domain_error_is_committed_uncertain(self) -> None:
        stderr = io.StringIO()
        with patch.object(
            submission_cli_module,
            "write_submission_predictions",
            return_value=self._manifest(),
        ), patch.object(
            submission_cli_module,
            "_canonical_stdout",
            side_effect=SubmissionPredictionError(
                "synthetic_summary_failure", "injected after publication"
            ),
        ), redirect_stderr(stderr):
            code = main(self._export_arguments())
        self.assertEqual(code, submission_cli_module.EXIT_COMMITTED_UNCERTAIN)
        self.assertIn("error[committed_uncertain]", stderr.getvalue())

    def test_help_and_argument_errors_remain_argparse_statuses(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("usage:", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main([])
        self.assertEqual(code, 2)
        self.assertIn("arguments rejected", stderr.getvalue())


@unittest.skipIf(os.name == "posix", "non-POSIX fail-closed contract")
class SubmissionPredictionNonPosixTests(unittest.TestCase):
    def test_export_fails_before_reading_source_or_changing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "submission"
            with patch.object(
                submission_module,
                "_read_source_predictions",
                side_effect=AssertionError("source must not be read"),
            ), patch.object(
                submission_module,
                "_publish_payloads",
                side_effect=AssertionError("output must not be changed"),
            ):
                with self.assertRaises(SubmissionPredictionError) as raised:
                    write_submission_predictions(
                        output,
                        root / "missing-replay",
                        expected_source_replay_dataset_sha256="a" * 64,
                        expected_task_count=1,
                    )
            self.assertEqual(raised.exception.code, "platform_unsupported")
            self.assertFalse(raised.exception.committed)
            self.assertFalse(output.exists())

    def test_cli_rejects_export_but_still_dispatches_verify(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(SubmissionPredictionCliStateTests._export_arguments())
        self.assertEqual(code, submission_cli_module.EXIT_REJECTED)
        self.assertIn("error[platform_unsupported]", stderr.getvalue())

        bundle = SimpleNamespace(
            manifest=SubmissionPredictionCliStateTests._manifest()
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.object(
            submission_cli_module,
            "verify_submission_predictions",
            return_value=bundle,
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "verify",
                    "--submission-dir",
                    "synthetic-submission",
                    "--replay-dir",
                    "synthetic-replay",
                    "--source-replay-dataset-sha256",
                    "a" * 64,
                    "--submission-sha256",
                    "b" * 64,
                    "--expected-task-count",
                    "1",
                ]
            )
        self.assertEqual(code, submission_cli_module.EXIT_SUCCESS)
        self.assertEqual(json.loads(stdout.getvalue())["operation"], "verify")
        self.assertEqual(stderr.getvalue(), "")

    def test_read_only_formal_verify_remains_available(self) -> None:
        fixture = SubmissionPredictionTests()
        fixture.setUp()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            replay, source_manifest, predictions = fixture._source_replay(
                root, fixture._manual_review()
            )
            payloads, manifest = submission_module._build_payloads(
                predictions, expected_task_count=1
            )
            submission = root / "submission"
            submission.mkdir(mode=0o700)
            for name, payload in payloads.items():
                (submission / name).write_bytes(payload)

            verified = verify_submission_predictions(
                submission,
                replay,
                expected_source_replay_dataset_sha256=(
                    source_manifest.dataset_sha256
                ),
                expected_task_count=1,
                expected_submission_sha256=manifest.submission_sha256,
            )
        self.assertEqual(verified.manifest.to_dict(), manifest.to_dict())


if __name__ == "__main__":
    unittest.main()
