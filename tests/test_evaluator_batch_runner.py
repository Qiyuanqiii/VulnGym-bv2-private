from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest import mock

import tests.test_evaluator_supervisor as supervisor_tests
import vulngym_agent.evaluator.batch_runner as runner_module
import vulngym_agent.evaluator.linux_oci as linux_oci
from vulngym_agent.evaluator.batch_runner import (
    BatchRunnerError,
    DiscoveryBatchAttemptReportV1,
    TaskAttemptOutcomeV1,
    run_prepared_discovery_batch_v1,
)
from vulngym_agent.evaluator.e4_receipt import E4SuccessReceiptAuthorityV1
from vulngym_agent.evaluator.supervisor import (
    EvaluatorSupervisorError,
    prepare_discovery_execution_plan_v1,
)


def _sha(marker: int) -> str:
    return f"{marker:064x}"


def _canonical_wire(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


class EvaluatorBatchRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_type = supervisor_tests.EvaluatorSupervisorTests
        fixture_type.setUpClass()
        cls.fixture_type = fixture_type
        cls.fixture = fixture_type(methodName="runTest")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_type.tearDownClass()

    def _session(self):
        verifier, builder = self.fixture._prepare(self.fixture.summary)
        with verifier, builder:
            return prepare_discovery_execution_plan_v1(
                self.fixture.batch_root,
                expected_batch_manifest_sha256=self.fixture.summary.manifest_sha256,
                attestation_key=supervisor_tests.KEY,
                expected_key_id=supervisor_tests.KEY_ID,
                execution_policy=self.fixture.execution_policy,
                task_replay_configs=self.fixture.replay_configs,
            )

    @staticmethod
    def _runtime(policy):
        return linux_oci.VerifiedLinuxOciRuntimeV1(
            linux_oci._RUNTIME_TOKEN,
            executable=object(),
            env={},
            endpoint="npipe:////./pipe/docker_engine",
            server={
                "Version": "29.6.2",
                "ApiVersion": "1.55",
                "Arch": "amd64",
            },
            server_sha256=_sha(9001),
            image_config={},
            image_inspect_sha256=_sha(9002),
            policy=policy,
        )

    @staticmethod
    def _pending(task_plan, marker: int):
        return SimpleNamespace(
            task_plan=task_plan,
            run=SimpleNamespace(run_sha256=_sha(marker)),
            run_wire_sha256=_sha(marker + 1),
            discovery_result_sha256=_sha(marker + 2),
            runtime_evidence_sha256=_sha(marker + 3),
        )

    def test_all_success_runs_in_plan_order_and_only_publishes(self) -> None:
        session = self._session()
        plan = session.plan
        runtime = self._runtime(plan.execution_policy)
        plans = {task.task_id: task for task in plan.tasks}
        provider_order: list[str] = []
        accepted_order: list[str] = []

        def provider(actual_runtime, launch, *, d2_replay, d3_replay):
            self.assertIs(actual_runtime, runtime)
            task_id = launch.task_plan.task_id
            self.assertEqual(d2_replay.task_id, task_id)
            self.assertEqual(d3_replay.task_id, task_id)
            provider_order.append(task_id)
            return SimpleNamespace(task_id=task_id)

        def accept(actual_session, *, completion):
            self.assertIs(actual_session, session)
            accepted_order.append(completion.task_id)
            position = provider_order.index(completion.task_id)
            return self._pending(plans[completion.task_id], 10_000 + position * 10)

        runtime_reverifier = mock.Mock()
        token = object()
        published_receipt = object()
        with (
            mock.patch.object(
                runner_module,
                "accept_discovery_worker_output_v1",
                side_effect=accept,
            ) as accept_call,
            mock.patch.object(
                runner_module,
                "close_failed_discovery_execution_v1",
            ) as close_failed,
            mock.patch.object(
                runner_module,
                "postverify_discovery_execution_v1",
                return_value=token,
            ) as postverify,
            mock.patch.object(
                runner_module,
                "_publish_scheduled_postverified_discovery_execution_v1",
                return_value=published_receipt,
            ) as publish,
        ):
            result = run_prepared_discovery_batch_v1(
                session,
                runtime,
                "unused-output",
                provider=provider,
                runtime_reverifier=runtime_reverifier,
            )

        expected_order = [task.task_id for task in plan.tasks]
        self.assertIs(result, published_receipt)
        self.assertEqual(provider_order, expected_order)
        self.assertEqual(accepted_order, expected_order)
        self.assertEqual(accept_call.call_count, len(plan.tasks))
        self.assertEqual(runtime_reverifier.call_count, len(plan.tasks))
        runtime_reverifier.assert_has_calls(
            [mock.call(runtime) for _ in plan.tasks]
        )
        close_failed.assert_not_called()
        postverify.assert_called_once_with(session)
        publish.assert_called_once()
        published_token, authority, published_output = publish.call_args.args
        self.assertIs(published_token, token)
        self.assertIs(type(authority), E4SuccessReceiptAuthorityV1)
        self.assertEqual(published_output, "unused-output")
        session.abort()

    def test_clean_allowlisted_failure_at_first_middle_or_last_continues_and_closes(
        self,
    ) -> None:
        cases = (
            (0, "evidence_failed"),
            (10, "generation_failed"),
            (19, "worker_failed"),
        )
        for failure_position, failure_code in cases:
            with self.subTest(
                failure_position=failure_position, failure_code=failure_code
            ):
                session = self._session()
                plan = session.plan
                runtime = self._runtime(plan.execution_policy)
                plans = {task.task_id: task for task in plan.tasks}
                failed_id = plan.tasks[failure_position].task_id
                provider_order: list[str] = []
                accepted_order: list[str] = []
                events: list[tuple[str, str | None]] = []
                current_task_id: str | None = None

                def provider(actual_runtime, launch, *, d2_replay, d3_replay):
                    nonlocal current_task_id
                    self.assertIs(actual_runtime, runtime)
                    current_task_id = launch.task_plan.task_id
                    provider_order.append(current_task_id)
                    events.append(("provider", current_task_id))
                    if current_task_id == failed_id:
                        raise linux_oci.LinuxOciProviderError(
                            failure_code, "clean task failure"
                        )
                    return SimpleNamespace(task_id=current_task_id)

                def reverify(actual_runtime):
                    self.assertIs(actual_runtime, runtime)
                    events.append(("reverify", current_task_id))

                def accept(actual_session, *, completion):
                    self.assertIs(actual_session, session)
                    accepted_order.append(completion.task_id)
                    events.append(("accept", completion.task_id))
                    position = provider_order.index(completion.task_id)
                    return self._pending(
                        plans[completion.task_id], 20_000 + position * 10
                    )

                def close(actual_session):
                    self.assertIs(actual_session, session)
                    events.append(("close", None))
                    return SimpleNamespace(
                        plan=plan,
                        accepted_task_ids=tuple(accepted_order),
                    )

                with (
                    mock.patch.object(
                        runner_module,
                        "accept_discovery_worker_output_v1",
                        side_effect=accept,
                    ) as accept_call,
                    mock.patch.object(
                        runner_module,
                        "close_failed_discovery_execution_v1",
                        side_effect=close,
                    ) as close_failed,
                    mock.patch.object(
                        runner_module, "postverify_discovery_execution_v1"
                    ) as postverify,
                    mock.patch.object(
                        runner_module,
                        "_publish_scheduled_postverified_discovery_execution_v1",
                    ) as publish,
                ):
                    report = run_prepared_discovery_batch_v1(
                        session,
                        runtime,
                        "unused-output",
                        provider=provider,
                        runtime_reverifier=reverify,
                    )

                expected_order = [task.task_id for task in plan.tasks]
                self.assertIsInstance(report, DiscoveryBatchAttemptReportV1)
                self.assertEqual(report.status, "failed_clean")
                self.assertTrue(report.snapshot_reverified)
                self.assertEqual(provider_order, expected_order)
                self.assertEqual(len(accepted_order), len(plan.tasks) - 1)
                self.assertNotIn(failed_id, accepted_order)
                self.assertEqual(accept_call.call_count, len(plan.tasks) - 1)
                self.assertEqual(
                    sum(event == "reverify" for event, _ in events),
                    len(plan.tasks),
                )
                close_failed.assert_called_once_with(session)
                self.assertEqual(events[-1], ("close", None))
                self.assertEqual(
                    tuple(item.status for item in report.outcomes).count("failed"),
                    1,
                )
                failed = report.outcomes[failure_position]
                self.assertEqual(failed.failure_code, failure_code)
                self.assertTrue(failed.cleanup_complete)
                self.assertTrue(failed.runtime_reverified)
                self.assertNotIn("not_run", {item.status for item in report.outcomes})
                postverify.assert_not_called()
                publish.assert_not_called()
                session.abort()

    def test_cleanup_or_runtime_uncertainty_stops_and_marks_remainder_not_run(
        self,
    ) -> None:
        for failure_code, runtime_uncertain in (
            ("cleanup_uncertain", True),
            ("worker_failed", True),
        ):
            with self.subTest(
                failure_code=failure_code, runtime_uncertain=runtime_uncertain
            ):
                session = self._session()
                plan = session.plan
                runtime = self._runtime(plan.execution_policy)
                plans = {task.task_id: task for task in plan.tasks}
                poison_position = 4
                poison_id = plan.tasks[poison_position].task_id
                provider_order: list[str] = []

                def provider(_runtime, launch, *, d2_replay, d3_replay):
                    task_id = launch.task_plan.task_id
                    provider_order.append(task_id)
                    if task_id == poison_id:
                        raise linux_oci.LinuxOciProviderError(
                            failure_code,
                            "runtime state is uncertain",
                            runtime_uncertain=runtime_uncertain,
                        )
                    return SimpleNamespace(task_id=task_id)

                def accept(_session, *, completion):
                    position = provider_order.index(completion.task_id)
                    return self._pending(
                        plans[completion.task_id], 30_000 + position * 10
                    )

                runtime_reverifier = mock.Mock()
                with (
                    mock.patch.object(
                        runner_module,
                        "accept_discovery_worker_output_v1",
                        side_effect=accept,
                    ),
                    mock.patch.object(
                        runner_module, "close_failed_discovery_execution_v1"
                    ) as close_failed,
                    mock.patch.object(
                        runner_module, "postverify_discovery_execution_v1"
                    ) as postverify,
                    mock.patch.object(
                        runner_module,
                        "_publish_scheduled_postverified_discovery_execution_v1",
                    ) as publish,
                ):
                    report = run_prepared_discovery_batch_v1(
                        session,
                        runtime,
                        "unused-output",
                        provider=provider,
                        runtime_reverifier=runtime_reverifier,
                    )

                self.assertEqual(report.status, "runtime_poisoned")
                self.assertFalse(report.snapshot_reverified)
                self.assertEqual(
                    provider_order,
                    [task.task_id for task in plan.tasks[: poison_position + 1]],
                )
                self.assertEqual(
                    runtime_reverifier.call_count, poison_position
                )
                self.assertEqual(
                    report.outcomes[poison_position].failure_code, failure_code
                )
                self.assertEqual(
                    [item.status for item in report.outcomes[poison_position + 1 :]],
                    ["not_run"] * (len(plan.tasks) - poison_position - 1),
                )
                self.assertEqual(session.state, "aborted")
                close_failed.assert_not_called()
                postverify.assert_not_called()
                publish.assert_not_called()

    def test_runtime_reverify_failure_stops_before_accepting_or_dispatching_more(
        self,
    ) -> None:
        for provider_fails, expected_code in (
            (False, "runtime_changed"),
            (True, "runtime_reverify_failed"),
        ):
            with self.subTest(provider_fails=provider_fails):
                session = self._session()
                plan = session.plan
                runtime = self._runtime(plan.execution_policy)
                provider_calls: list[str] = []

                def provider(_runtime, launch, *, d2_replay, d3_replay):
                    provider_calls.append(launch.task_plan.task_id)
                    if provider_fails:
                        raise linux_oci.LinuxOciProviderError(
                            "worker_failed", "clean provider failure"
                        )
                    return SimpleNamespace(task_id=launch.task_plan.task_id)

                def reverify(_runtime):
                    raise linux_oci.LinuxOciProviderError(
                        "runtime_changed", "runtime reverify failed"
                    )

                with (
                    mock.patch.object(
                        runner_module, "accept_discovery_worker_output_v1"
                    ) as accept,
                    mock.patch.object(
                        runner_module, "close_failed_discovery_execution_v1"
                    ) as close_failed,
                    mock.patch.object(
                        runner_module, "postverify_discovery_execution_v1"
                    ) as postverify,
                    mock.patch.object(
                        runner_module,
                        "_publish_scheduled_postverified_discovery_execution_v1",
                    ) as publish,
                ):
                    report = run_prepared_discovery_batch_v1(
                        session,
                        runtime,
                        "unused-output",
                        provider=provider,
                        runtime_reverifier=reverify,
                    )

                self.assertEqual(provider_calls, [plan.tasks[0].task_id])
                self.assertEqual(report.status, "runtime_poisoned")
                self.assertEqual(report.outcomes[0].failure_code, expected_code)
                self.assertFalse(report.outcomes[0].runtime_reverified)
                self.assertEqual(
                    [item.status for item in report.outcomes[1:]],
                    ["not_run"] * (len(plan.tasks) - 1),
                )
                accept.assert_not_called()
                close_failed.assert_not_called()
                postverify.assert_not_called()
                publish.assert_not_called()
                self.assertEqual(session.state, "aborted")

    def test_duplicate_launch_is_rejected_by_the_supervisor(self) -> None:
        session = self._session()
        task_id = session.plan.tasks[0].task_id
        launch, d2_replay, d3_replay = session.claim_task_execution(task_id)
        self.assertEqual(launch.task_plan.task_id, task_id)
        self.assertEqual(d2_replay.task_id, task_id)
        self.assertEqual(d3_replay.task_id, task_id)
        with self.assertRaises(EvaluatorSupervisorError) as captured:
            session.claim_task_execution(task_id)
        self.assertEqual(captured.exception.code, "duplicate_launch")
        session.abort()

    def test_attempt_report_roundtrip_and_rejects_extra_key_or_reordering(
        self,
    ) -> None:
        session = self._session()
        plan = session.plan
        outcomes = tuple(
            TaskAttemptOutcomeV1(
                task_plan_sha256=task.plan_sha256,
                task_id=task.task_id,
                status="failed",
                failure_code="worker_failed",
                cleanup_complete=True,
                runtime_reverified=True,
            )
            for task in plan.tasks
        )
        report = DiscoveryBatchAttemptReportV1(
            plan=plan,
            status="failed_clean",
            snapshot_reverified=True,
            outcomes=outcomes,
        )
        payload = report.to_bytes()
        self.assertEqual(
            DiscoveryBatchAttemptReportV1.from_bytes(
                payload,
                expected_report_sha256=report.report_sha256,
                expected_wire_sha256=report.wire_sha256,
            ),
            report,
        )

        extra = json.loads(payload)
        extra["unexpected"] = False
        extra_payload = _canonical_wire(extra)
        with self.assertRaises(BatchRunnerError) as captured:
            DiscoveryBatchAttemptReportV1.from_bytes(
                extra_payload,
                expected_report_sha256=report.report_sha256,
                expected_wire_sha256=hashlib.sha256(extra_payload).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "invalid_contract")

        reordered = json.loads(payload)
        reordered["outcomes"][0], reordered["outcomes"][1] = (
            reordered["outcomes"][1],
            reordered["outcomes"][0],
        )
        reordered_payload = _canonical_wire(reordered)
        with self.assertRaises(BatchRunnerError) as captured:
            DiscoveryBatchAttemptReportV1.from_bytes(
                reordered_payload,
                expected_report_sha256=report.report_sha256,
                expected_wire_sha256=hashlib.sha256(reordered_payload).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

        invalid_clean = tuple(
            TaskAttemptOutcomeV1(
                task_plan_sha256=task.plan_sha256,
                task_id=task.task_id,
                status="failed",
                failure_code="policy_mismatch",
                cleanup_complete=True,
                runtime_reverified=True,
            )
            for task in plan.tasks
        )
        with self.assertRaises(BatchRunnerError) as captured:
            DiscoveryBatchAttemptReportV1(
                plan=plan,
                status="failed_clean",
                snapshot_reverified=True,
                outcomes=invalid_clean,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")
        session.abort()


if __name__ == "__main__":
    unittest.main()
