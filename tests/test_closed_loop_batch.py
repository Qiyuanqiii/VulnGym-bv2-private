from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
from typing import Any, Iterable, Mapping
import unittest
from unittest.mock import patch

from vulngym_agent.agents.model_runtime import AttemptModelRuntime, ModelRequest
from vulngym_agent.agents.t1_validator import T1ValidationOutcome
from vulngym_agent.closed_loop_cli import (
    BatchInputRecord,
    ExactReplayBackend,
    ExactReplayFixture,
    ExactReplayMismatch,
    EXIT_FATAL,
    LocalT1ValidatorFactory,
    TaskInputLimitExceeded,
    _iter_task_stream,
    _run_artifact_cli_batch,
    iter_task_jsonl,
    load_exact_replay_backend,
    load_trusted_repo_map,
    main,
    run_closed_loop_batch,
)
from vulngym_agent.models import FieldValidation, ValidationReport
from vulngym_agent.orchestrator import (
    Budget,
    ClosedLoopOrchestrator,
    ClosedLoopOutcome,
    ProductionDraft,
    RunTask,
)
from vulngym_agent.orchestrator.producer_context import ProducerExecutionContext
from tests.producer_context_support import FixedProducerContextFactory


ROOT = Path(__file__).resolve().parents[1]


def _entry() -> dict[str, Any]:
    value = json.loads(
        (ROOT / "data" / "entries.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    value["verify"] = 0
    return value


def _task(
    input_line: int,
    *,
    task_id: str | None = None,
    entry_id: str | None = None,
) -> RunTask:
    entry = _entry()
    return RunTask(
        task_id=task_id or f"task:batch-{input_line}",
        report_id=entry["report_id"],
        entry_id=entry_id or f"entry-{input_line:05d}",
        inputs={
            "contract_version": 1,
            "input_line": input_line,
            "repo_url": entry["repo_url"],
            "package": {
                "advisory": "advisories/report.json",
                "references": [],
                "patches": ["patches/fix.patch"],
            },
            "hints": {
                "project": entry["project"],
                "fix_commits": [],
                "source_paths": [entry["critical_operation"]["file"]],
                "entry_symbols": [],
                "critical_mode": "auto",
            },
        },
    )


class _DraftProducer:
    def __init__(self, candidate: Mapping[str, Any], *, fail: bool = False) -> None:
        self._candidate = deepcopy(dict(candidate))
        self._fail = fail

    def generate(
        self, task: RunTask, context: ProducerExecutionContext
    ) -> ProductionDraft:
        context.call_model("MODEL-batch-plan", "plan", {"round": 0})
        if self._fail:
            raise RuntimeError("producer test failure")
        context.call_model(
            "MODEL-batch-semantic", "semantic_judge", {"round": 0}
        )
        context.call_model("MODEL-batch-reflection", "reflection", {"round": 0})
        return ProductionDraft(self._candidate)

    def repair(self, *args: Any, **kwargs: Any) -> ProductionDraft:
        raise AssertionError("test outcome must not request repair")


class _OneReportFactory:
    def __init__(self, task: RunTask, verdict: str) -> None:
        self._task = task
        self._verdict = verdict

    def __call__(self, task: RunTask) -> object:
        if task is not self._task:
            raise AssertionError("validator did not receive the original task")
        verdict = self._verdict
        expected_line = task.inputs["input_line"]

        class Validator:
            def validate(
                self, candidate: Any, *, input_line: int | None = None
            ) -> T1ValidationOutcome:
                if input_line != expected_line:
                    raise AssertionError("validator received the wrong input line")
                return T1ValidationOutcome(
                    ValidationReport(
                        report_id=task.report_id,
                        entry_id=task.entry_id,
                        input_line=input_line,
                        verdict=verdict,
                        fields={
                            "schema": FieldValidation(
                                status=verdict,
                                confidence=1.0 if verdict == "correct" else 0.5,
                                evidence=f"fixture:{verdict}",
                            )
                        },
                        summary=f"fixture {verdict}",
                    ),
                    (),
                )

        return Validator()


def _outcome(task: RunTask, verdict: str) -> ClosedLoopOutcome:
    candidate = _entry()
    candidate["report_id"] = task.report_id
    candidate["entry_id"] = task.entry_id
    return ClosedLoopOrchestrator(
        _DraftProducer(candidate),
        _OneReportFactory(task, verdict),
        FixedProducerContextFactory(),
    ).run(task)


def _failed_outcome(task: RunTask) -> ClosedLoopOutcome:
    return ClosedLoopOrchestrator(
        _DraftProducer(_entry(), fail=True),
        _OneReportFactory(task, "correct"),
        FixedProducerContextFactory(),
    ).run(task)


class _SequenceRunner:
    def __init__(self, values: Mapping[str, ClosedLoopOutcome | Exception]) -> None:
        self._values = dict(values)
        self.finalized = 0

    def run(self, task: RunTask) -> ClosedLoopOutcome:
        value = self._values[task.task_id]
        if isinstance(value, Exception):
            raise value
        return value

    def finalize_batch(self) -> None:
        self.finalized += 1


class ClosedLoopInputTests(unittest.TestCase):
    def test_static_total_size_gate_rejects_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "too-large.jsonl"
            path.write_bytes(b"x" * 65)
            with patch.object(
                Path,
                "open",
                side_effect=AssertionError("oversized file must not be opened"),
            ):
                with self.assertRaises(TaskInputLimitExceeded):
                    list(iter_task_jsonl(path, max_task_bytes=64))

    def test_live_total_size_gate_stops_a_growing_custom_stream(self) -> None:
        class GrowingStream(io.BytesIO):
            def __init__(self, value: bytes) -> None:
                super().__init__(value)
                self.bytes_returned = 0

            def readline(self, size: int = -1) -> bytes:
                value = super().readline(size)
                self.bytes_returned += len(value)
                return value

        stream = GrowingStream(b"x" * 100)
        records: list[BatchInputRecord] = []
        with self.assertRaises(TaskInputLimitExceeded):
            records.extend(
                _iter_task_stream(
                    stream,
                    max_input_line_bytes=8,
                    max_task_bytes=16,
                    declared_size=8,
                )
            )

        self.assertEqual(records, [])
        self.assertEqual(stream.bytes_returned, 17)

    def test_strict_jsonl_binds_task_input_line_to_physical_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tasks.jsonl"
            first = _task(1).to_dict()
            fourth = _task(99, task_id="task:bad-line").to_dict()
            path.write_bytes(
                json.dumps(first, ensure_ascii=False).encode("utf-8")
                + b"\n\n"
                + b'{"task_id":"duplicate","task_id":"again"}\n'
                + json.dumps(fourth).encode("utf-8")
            )

            records = list(iter_task_jsonl(path))

        self.assertEqual(len(records), 4)
        self.assertEqual(records[0].task, _task(1))
        self.assertEqual(records[1].error_code, "blank_input_line")
        self.assertEqual(records[2].error_code, "invalid_json")
        self.assertEqual(records[3].error_code, "input_line_mismatch")
        self.assertRegex(records[2].raw_sha256, r"^[0-9a-f]{64}$")

    def test_oversized_line_is_drained_hashed_and_next_line_survives(self) -> None:
        valid = json.dumps(_task(2).to_dict(), ensure_ascii=False).encode("utf-8")
        limit = len(valid) + 10
        oversized = b'{"untrusted":"' + b"x" * (limit + 200) + b'"}\n'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tasks.jsonl"
            path.write_bytes(oversized + valid)

            records = list(iter_task_jsonl(path, max_input_line_bytes=limit))

        self.assertEqual(records[0].error_code, "input_line_too_large")
        self.assertEqual(records[0].raw_sha256, sha256(oversized).hexdigest())
        self.assertEqual(records[1].task, _task(2))

    def test_final_unterminated_line_is_parsed(self) -> None:
        task = _task(1)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tasks.jsonl"
            path.write_bytes(json.dumps(task.to_dict()).encode("utf-8"))
            records = list(iter_task_jsonl(path))
        self.assertEqual([item.task for item in records], [task])


class ExactReplayBackendTests(unittest.TestCase):
    @staticmethod
    def request(task_id: str) -> ModelRequest:
        return ModelRequest(
            task_id=task_id,
            attempt=0,
            policy_scope="t2.initial",
            stage="plan",
            model_call_id="MODEL-plan",
            backend_id="exact-replay",
            model_id="offline-v1",
            payload={"same": "payload"},
        )

    @staticmethod
    def fixture(
        request: ModelRequest,
        *,
        status: str = "success",
        response: Mapping[str, Any] | None = None,
        error_code: str | None = None,
    ) -> ExactReplayFixture:
        return ExactReplayFixture.from_request(
            request,
            status=status,
            response={"ok": True} if response is None and status == "success" else response,
            error_code=error_code,
        )

    def test_same_payload_cannot_cross_task_identity(self) -> None:
        first = self.request("task:A")
        second = self.request("task:B")
        self.assertEqual(first.request_sha256, second.request_sha256)
        self.assertNotEqual(first.operation, second.operation)
        backend = ExactReplayBackend([self.fixture(first)])

        with self.assertRaises(ExactReplayMismatch):
            backend.invoke(second)
        self.assertEqual(backend.invoke(first), {"ok": True})
        with self.assertRaises(ExactReplayMismatch):
            backend.assert_complete()

    def test_each_fixture_must_be_consumed_exactly_once(self) -> None:
        request = self.request("task:once")
        backend = ExactReplayBackend([self.fixture(request)])
        self.assertEqual(backend.invoke(request), {"ok": True})
        with self.assertRaises(ExactReplayMismatch):
            backend.invoke(request)
        with self.assertRaises(ExactReplayMismatch):
            backend.assert_complete()

        unused = ExactReplayBackend([self.fixture(request)])
        with self.assertRaises(ExactReplayMismatch):
            unused.assert_complete()

    def test_registered_response_is_deeply_detached_and_frozen(self) -> None:
        request = self.request("task:immutable")
        aliased: dict[str, Any] = {"values": []}
        response = {
            "nested": {"values": [1, 2]},
            "tuple": (aliased,),
        }
        fixture = self.fixture(request, response=response)
        backend = ExactReplayBackend([fixture])
        response["nested"]["values"].append(999)
        aliased["values"].append("mutated")

        returned = backend.invoke(request)
        self.assertEqual(
            returned,
            {"nested": {"values": [1, 2]}, "tuple": [{"values": []}]},
        )
        returned["nested"]["values"].append(3)
        self.assertEqual(fixture.response["nested"]["values"], (1, 2))
        self.assertEqual(fixture.response["tuple"][0]["values"], ())
        backend.assert_complete()

    def test_runtime_swallowing_a_replay_miss_still_fails_batch_closure(self) -> None:
        registered = self.request("task:registered")
        actual = self.request("task:actual")
        backend = ExactReplayBackend([self.fixture(registered)])
        runtime = AttemptModelRuntime(
            task_id=actual.task_id,
            attempt=actual.attempt,
            policy_scope=actual.policy_scope,
            budget=Budget(),
            backend=backend,
        )

        result = runtime.call(actual.model_call_id, actual.stage, actual.payload)

        self.assertEqual(result.status, "error")
        self.assertEqual(result.error_code, "backend_error")
        with self.assertRaises(ExactReplayMismatch):
            backend.assert_complete()

    def test_blocked_and_error_results_are_deterministic_consumed_fixtures(self) -> None:
        for status, error_code in (
            ("blocked", "fixture_blocked"),
            ("error", "backend_error"),
        ):
            with self.subTest(status=status):
                request = self.request(f"task:{status}")
                backend = ExactReplayBackend(
                    [
                        self.fixture(
                            request,
                            status=status,
                            response=None,
                            error_code=error_code,
                        )
                    ]
                )
                runtime = AttemptModelRuntime(
                    task_id=request.task_id,
                    attempt=request.attempt,
                    policy_scope=request.policy_scope,
                    budget=Budget(),
                    backend=backend,
                )
                result = runtime.call(
                    request.model_call_id, request.stage, request.payload
                )
                self.assertEqual(result.status, status)
                self.assertEqual(result.error_code, error_code)
                backend.assert_complete()

    def test_loader_accepts_no_request_payload_and_rejects_extra_fields(self) -> None:
        request = self.request("task:file")
        document = {
            "contract_version": 2,
            "backend_id": "exact-replay",
            "model_id": "offline-v1",
            "responses": [
                {
                    "task_id": request.task_id,
                    "attempt": request.attempt,
                    "policy_scope": request.policy_scope,
                    "stage": request.stage,
                    "model_call_id": request.model_call_id,
                    "backend_id": request.backend_id,
                    "model_id": request.model_id,
                    "request_sha256": request.request_sha256,
                    "status": "success",
                    "response": {"answer": 1},
                    "error_code": None,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "replay.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            backend = load_exact_replay_backend(path)
            self.assertEqual(backend.invoke(request), {"answer": 1})
            backend.assert_complete()

            document["responses"][0]["request"] = {"prompt": "forbidden"}
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_exact_replay_backend(path)

    def test_task_scope_delimiter_collision_uses_discrete_identity(self) -> None:
        first = ModelRequest(
            task_id="task:x:0",
            attempt=1,
            policy_scope="scope",
            stage="plan",
            model_call_id="MODEL-plan",
            backend_id="exact-replay",
            model_id="offline-v1",
            payload={"same": "payload"},
        )
        second = ModelRequest(
            task_id="task:x",
            attempt=0,
            policy_scope="1:scope",
            stage="plan",
            model_call_id="MODEL-plan",
            backend_id="exact-replay",
            model_id="offline-v1",
            payload={"same": "payload"},
        )
        self.assertEqual(first.operation, second.operation)
        backend = ExactReplayBackend(
            [
                self.fixture(first, response={"selected": "first"}),
                self.fixture(second, response={"selected": "second"}),
            ]
        )

        self.assertEqual(backend.invoke(second), {"selected": "second"})
        self.assertEqual(backend.invoke(first), {"selected": "first"})
        backend.assert_complete()

    def test_backend_model_delimiter_collision_cannot_reassign_fixture(self) -> None:
        registered = ModelRequest(
            task_id="task:model-components",
            attempt=0,
            policy_scope="t2.initial",
            stage="plan",
            model_call_id="MODEL-plan",
            backend_id="vendor:a",
            model_id="model",
            payload={"same": "payload"},
        )
        reassigned = ModelRequest(
            task_id="task:model-components",
            attempt=0,
            policy_scope="t2.initial",
            stage="plan",
            model_call_id="MODEL-plan",
            backend_id="vendor",
            model_id="a:model",
            payload={"same": "payload"},
        )
        self.assertEqual(registered.operation, reassigned.operation)
        backend = ExactReplayBackend(
            [self.fixture(registered)],
            backend_id=registered.backend_id,
            model_id=registered.model_id,
        )

        with self.assertRaises(ExactReplayMismatch):
            backend.invoke(reassigned)
        self.assertEqual(backend.invoke(registered), {"ok": True})
        with self.assertRaises(ExactReplayMismatch):
            backend.assert_complete()

        with self.assertRaisesRegex(ValueError, "must match the backend"):
            ExactReplayBackend(
                [self.fixture(reassigned)],
                backend_id=registered.backend_id,
                model_id=registered.model_id,
            )


class ClosedLoopBatchRunnerTests(unittest.TestCase):
    def test_only_finalized_correct_entry_is_emitted(self) -> None:
        finalized_task = _task(1, task_id="task:final")
        manual_task = _task(2, task_id="task:manual")
        failed_task = _task(3, task_id="task:failed")
        runner = _SequenceRunner(
            {
                finalized_task.task_id: _outcome(finalized_task, "correct"),
                manual_task.task_id: _outcome(manual_task, "uncertain"),
                failed_task.task_id: _failed_outcome(failed_task),
            }
        )
        invalid = BatchInputRecord(
            4, sha256(b"invalid\n").hexdigest(), error_code="invalid_json"
        )
        events: list[Any] = []

        summary, manifest = run_closed_loop_batch(
            [
                BatchInputRecord(1, sha256(b"one").hexdigest(), task=finalized_task),
                BatchInputRecord(2, sha256(b"two").hexdigest(), task=manual_task),
                BatchInputRecord(3, sha256(b"three").hexdigest(), task=failed_task),
                invalid,
            ],
            runner,
            write_artifacts=lambda values: (events.extend(values), "manifest")[1],
        )

        self.assertEqual(manifest, "manifest")
        self.assertEqual(events[0].outcome.status, "finalized")
        self.assertEqual(
            [getattr(item, "input_line") for item in events], [1, 2, 3, 4]
        )
        self.assertEqual(summary.finalized, 1)
        self.assertEqual(summary.manual_review, 1)
        self.assertEqual(summary.failed, 1)
        self.assertEqual(summary.input_failures, 1)
        self.assertEqual(summary.exit_code, 1)
        self.assertEqual(runner.finalized, 1)

    def test_manual_review_is_normal_unless_strict_mode_is_enabled(self) -> None:
        task = _task(1, task_id="task:manual-only")
        outcome = _outcome(task, "uncertain")

        normal, _ = run_closed_loop_batch(
            [BatchInputRecord(1, sha256(b"one").hexdigest(), task=task)],
            _SequenceRunner({task.task_id: outcome}),
            write_artifacts=lambda values: tuple(values),
        )
        strict, _ = run_closed_loop_batch(
            [BatchInputRecord(1, sha256(b"one").hexdigest(), task=task)],
            _SequenceRunner({task.task_id: outcome}),
            write_artifacts=lambda values: tuple(values),
            require_all_finalized=True,
        )

        self.assertEqual(normal.exit_code, 0)
        self.assertEqual(strict.exit_code, 1)

    def test_task_exception_is_isolated_and_later_task_runs(self) -> None:
        first = _task(1, task_id="task:raises")
        second = _task(2, task_id="task:after")
        runner = _SequenceRunner(
            {
                first.task_id: RuntimeError("contains C:\\secret\\path"),
                second.task_id: _outcome(second, "uncertain"),
            }
        )
        events: list[Any] = []

        summary, _ = run_closed_loop_batch(
            [
                BatchInputRecord(1, sha256(b"first").hexdigest(), task=first),
                BatchInputRecord(2, sha256(b"second").hexdigest(), task=second),
            ],
            runner,
            write_artifacts=lambda values: events.extend(values),
        )

        self.assertEqual(summary.tasks_run, 2)
        self.assertEqual(summary.input_failures, 1)
        self.assertEqual(summary.manual_review, 1)
        self.assertNotIn("secret", repr(events))

    def test_record_limit_emits_one_correlated_failure_and_stops(self) -> None:
        first = _task(1)
        second = _task(2)
        runner = _SequenceRunner({first.task_id: _outcome(first, "uncertain")})
        events: list[Any] = []
        summary, _ = run_closed_loop_batch(
            [
                BatchInputRecord(1, sha256(b"first").hexdigest(), task=first),
                BatchInputRecord(2, sha256(b"second").hexdigest(), task=second),
            ],
            runner,
            write_artifacts=lambda values: events.extend(values),
            max_records=1,
        )
        self.assertTrue(summary.record_limit_reached)
        self.assertEqual(summary.records_seen, 2)
        self.assertEqual(summary.tasks_run, 1)
        self.assertEqual(events[-1].error_code, "record_limit")

    def test_duplicate_task_and_entry_id_are_rejected_before_second_run(self) -> None:
        first = _task(1, task_id="task:duplicate")
        duplicate_task = _task(2, task_id="task:duplicate")
        first_outcome = _outcome(first, "uncertain")
        runner = _SequenceRunner({first.task_id: first_outcome})
        events: list[Any] = []
        summary, _ = run_closed_loop_batch(
            [
                BatchInputRecord(1, sha256(b"first").hexdigest(), task=first),
                BatchInputRecord(
                    2, sha256(b"duplicate-task").hexdigest(), task=duplicate_task
                ),
            ],
            runner,
            write_artifacts=lambda values: events.extend(values),
        )
        self.assertEqual(summary.tasks_run, 1)
        self.assertEqual(events[-1].error_code, "duplicate_task_id")

        one = _task(1, task_id="task:one")
        same_entry = _task(2, task_id="task:two", entry_id=one.entry_id)
        runner = _SequenceRunner({one.task_id: _outcome(one, "uncertain")})
        events = []
        summary, _ = run_closed_loop_batch(
            [
                BatchInputRecord(1, sha256(b"one").hexdigest(), task=one),
                BatchInputRecord(2, sha256(b"two").hexdigest(), task=same_entry),
            ],
            runner,
            write_artifacts=lambda values: events.extend(values),
        )
        self.assertEqual(summary.tasks_run, 1)
        self.assertEqual(events[-1].error_code, "duplicate_entry_id")


class TrustedConfigurationTests(unittest.TestCase):
    def test_repo_map_is_exact_absolute_and_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            config = root / "repos.json"
            config.write_text(
                json.dumps(
                    {
                        "contract_version": 1,
                        "repositories": [
                            {
                                "repo_url": "https://github.com/owner/project",
                                "path": str(repo.resolve()),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = load_trusted_repo_map(config)
            self.assertEqual(result["https://github.com/owner/project"], repo.resolve())
            with self.assertRaises(TypeError):
                result["https://github.com/other/repo"] = repo  # type: ignore[index]

    def test_t1_factory_returns_a_fresh_validator_without_model_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_root = root / "packages"
            repo = root / "repo"
            package_root.mkdir()
            repo.mkdir()
            task = _task(1)
            factory = LocalT1ValidatorFactory(
                package_root, {task.inputs["repo_url"]: repo}
            )
            first = factory(task)
            second = factory(task)

        self.assertIsNot(first, second)
        self.assertNotIn("backend", repr(first.__dict__))
        self.assertNotIn("replay", repr(first.__dict__))

    def test_package_and_repository_capability_roots_must_be_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_parent = root / "package-parent"
            nested_repo = package_parent / "repo"
            package_parent.mkdir()
            nested_repo.mkdir()
            with self.assertRaisesRegex(ValueError, "disjoint"):
                LocalT1ValidatorFactory(
                    package_parent,
                    {"https://github.com/owner/project": nested_repo},
                )

            repo_parent = root / "repo-parent"
            nested_package = repo_parent / "packages"
            repo_parent.mkdir()
            nested_package.mkdir()
            with self.assertRaisesRegex(ValueError, "disjoint"):
                LocalT1ValidatorFactory(
                    nested_package,
                    {"https://github.com/owner/other": repo_parent},
                )


class ClosedLoopCliTransactionTests(unittest.TestCase):
    def test_main_total_task_limit_is_fatal_and_publishes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tasks = root / "tasks.jsonl"
            replay = root / "replay.json"
            repo_map_file = root / "repos.json"
            package_root = root / "packages"
            repo = root / "repo"
            output = root / "result"
            tasks.write_bytes(b"x" * 65)
            package_root.mkdir()
            repo.mkdir()
            replay.write_text(
                json.dumps(
                    {
                        "contract_version": 2,
                        "backend_id": "exact-replay",
                        "model_id": "offline-v1",
                        "responses": [],
                    }
                ),
                encoding="utf-8",
            )
            repo_map_file.write_text(
                json.dumps(
                    {
                        "contract_version": 1,
                        "repositories": [
                            {
                                "repo_url": "https://github.com/owner/project",
                                "path": str(repo.resolve()),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with patch("sys.stdout", stdout):
                code = main(
                    [
                        "--tasks",
                        str(tasks),
                        "--replay-responses",
                        str(replay),
                        "--repo-map",
                        str(repo_map_file),
                        "--package-root",
                        str(package_root),
                        "--output-dir",
                        str(output),
                        "--max-task-bytes",
                        "64",
                    ]
                )

            summary = json.loads(stdout.getvalue())
            self.assertFalse(output.exists())

        self.assertEqual(code, EXIT_FATAL)
        self.assertEqual(summary["error_code"], "task_input_limit_exceeded")

    def test_main_runs_an_empty_offline_batch_without_a_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tasks = root / "tasks.jsonl"
            replay = root / "replay.json"
            repo_map_file = root / "repos.json"
            package_root = root / "packages"
            repo = root / "repo"
            output = root / "result"
            tasks.write_bytes(b"")
            package_root.mkdir()
            repo.mkdir()
            replay.write_text(
                json.dumps(
                    {
                        "contract_version": 2,
                        "backend_id": "exact-replay",
                        "model_id": "offline-v1",
                        "responses": [],
                    }
                ),
                encoding="utf-8",
            )
            repo_map_file.write_text(
                json.dumps(
                    {
                        "contract_version": 1,
                        "repositories": [
                            {
                                "repo_url": "https://github.com/owner/project",
                                "path": str(repo.resolve()),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with patch("sys.stdout", stdout):
                code = main(
                    [
                        "--tasks",
                        str(tasks),
                        "--replay-responses",
                        str(replay),
                        "--repo-map",
                        str(repo_map_file),
                        "--package-root",
                        str(package_root),
                        "--output-dir",
                        str(output),
                    ]
                )

            summary = json.loads(stdout.getvalue())
            self.assertTrue((output / "entries.jsonl").is_file())
            self.assertEqual((output / "entries.jsonl").read_bytes(), b"")

        self.assertEqual(code, 0)
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["records_seen"], 0)

    def test_writer_transaction_publishes_entries_only_for_finalized_correct(self) -> None:
        finalized_task = _task(1, task_id="task:published")
        manual_task = _task(2, task_id="task:reviewed")
        runner = _SequenceRunner(
            {
                finalized_task.task_id: _outcome(finalized_task, "correct"),
                manual_task.task_id: _outcome(manual_task, "uncertain"),
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "tasks.jsonl"
            protected.write_text("fixture\n", encoding="utf-8")
            output = root / "result"
            summary = _run_artifact_cli_batch(
                output_dir=output,
                protected_paths=(protected,),
                records=[
                    BatchInputRecord(
                        1, sha256(b"first").hexdigest(), task=finalized_task
                    ),
                    BatchInputRecord(
                        2, sha256(b"second").hexdigest(), task=manual_task
                    ),
                ],
                runner=runner,
                max_records=10,
                require_all_finalized=False,
            )

            entry_lines = (output / "entries.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertTrue((output / "run_manifest.jsonl").is_file())

        self.assertEqual(summary.entries_written, 1)
        self.assertEqual(len(entry_lines), 1)
        self.assertEqual(set(json.loads(entry_lines[0])), set(_entry()))

    def test_exact_replay_failure_does_not_publish_outer_directory(self) -> None:
        class RejectingRunner:
            def run(self, task: RunTask) -> ClosedLoopOutcome:
                raise AssertionError("invalid input must not run")

            def finalize_batch(self) -> None:
                raise ExactReplayMismatch("unused=1")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "input.jsonl"
            protected.write_text("bad\n", encoding="utf-8")
            output = root / "result"
            record = BatchInputRecord(
                1, sha256(b"bad\n").hexdigest(), error_code="invalid_json"
            )

            with self.assertRaises(ExactReplayMismatch):
                _run_artifact_cli_batch(
                    output_dir=output,
                    protected_paths=(protected,),
                    records=[record],
                    runner=RejectingRunner(),
                    max_records=10,
                    require_all_finalized=False,
                )

            self.assertFalse(output.exists())
            self.assertEqual(protected.read_text(encoding="utf-8"), "bad\n")

    def test_main_fatal_summary_never_echoes_absolute_paths(self) -> None:
        secret = "C:\\private\\do-not-print"
        stdout = io.StringIO()
        with patch(
            "vulngym_agent.closed_loop_cli.Path.resolve",
            side_effect=OSError(secret),
        ), patch("sys.stdout", stdout):
            code = main(
                [
                    "--tasks",
                    "tasks.jsonl",
                    "--replay-responses",
                    "replay.json",
                    "--repo-map",
                    "repos.json",
                    "--package-root",
                    "packages",
                    "--output-dir",
                    "output",
                ]
            )
        self.assertEqual(code, EXIT_FATAL)
        self.assertNotIn(secret, stdout.getvalue())
        self.assertEqual(json.loads(stdout.getvalue())["status"], "fatal")


if __name__ == "__main__":
    unittest.main()
