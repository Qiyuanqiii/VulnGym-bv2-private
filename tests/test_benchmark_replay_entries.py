from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields, replace
import json
from pathlib import Path
import tempfile
from typing import Any, Iterator
import unittest
from unittest.mock import patch

from vulngym_agent.orchestrator import (
    ClosedLoopOrchestrator,
    ProductionDeferredDraft,
    ReplayArtifactError,
    ReplayRecord,
    RunTask,
    VerifiedFormalEntries,
    VerifiedTaskEntries,
    canonical_json,
    read_verified_formal_entries,
    write_closed_loop_artifacts,
)
from vulngym_agent.orchestrator import replay as replay_module
from tests import test_orchestrator as orchestrator_fixtures
from tests.producer_context_support import FixedProducerContextFactory


class VerifiedReplayEntriesTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = orchestrator_fixtures.ClosedLoopOrchestratorTests()
        fixture.setUp()
        self.entry = fixture.entry
        self.task = fixture.task
        self._fixture = fixture

    def _finalized(self) -> Any:
        outcome, _ = self._fixture._run(
            orchestrator_fixtures._FakeProducer(self.entry),
            [orchestrator_fixtures._report(self.entry, {"schema": "correct"})],
        )
        return outcome

    def _finalized_for(
        self, entry: dict[str, Any], task: RunTask, input_line: int
    ) -> Any:
        report = replace(
            orchestrator_fixtures._report(entry, {"schema": "correct"}),
            input_line=input_line,
        )
        validator_factory = orchestrator_fixtures._SequenceValidatorFactory(
            [report], task
        )
        return ClosedLoopOrchestrator(
            orchestrator_fixtures._FakeProducer(entry),
            validator_factory,
            FixedProducerContextFactory(),
        ).run(task)

    @staticmethod
    def _deferred_for(task: RunTask) -> Any:
        class Producer:
            def generate(self, task: Any, context: Any) -> ProductionDeferredDraft:
                return ProductionDeferredDraft(
                    stage="task_contract",
                    reason_code="missing_public_fact",
                    missing_information=("public advisory is incomplete",),
                )

            def repair(self, *args: Any, **kwargs: Any) -> None:
                raise AssertionError("repair must not run")

        def no_validator(task: Any) -> Any:
            raise AssertionError("validator must not run")

        return ClosedLoopOrchestrator(
            Producer(), no_validator, FixedProducerContextFactory()
        ).run(task)

    def test_returns_only_immutable_entries_digest_and_state_task_ids(
        self,
    ) -> None:
        outcome = self._finalized()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            manifest = write_closed_loop_artifacts(
                output, [ReplayRecord(7, self.task, outcome)]
            )

            verified = read_verified_formal_entries(
                output, expected_dataset_sha256=manifest.dataset_sha256
            )

        self.assertIsInstance(verified, VerifiedFormalEntries)
        self.assertEqual(
            tuple(item.name for item in fields(verified)),
            ("dataset_sha256", "tasks", "input_failure_count"),
        )
        self.assertEqual(verified.dataset_sha256, manifest.dataset_sha256)
        self.assertEqual(verified.input_failure_count, 0)
        self.assertEqual(verified.task_ids, (self.task.task_id,))
        self.assertIsInstance(verified.tasks[0], VerifiedTaskEntries)
        self.assertEqual(verified.tasks[0].status, "finalized")
        self.assertEqual(verified.tasks[0].entries, verified.entries)
        self.assertEqual(len(verified.entries), 1)
        self.assertEqual(set(verified.entries[0]), set(self.entry))
        self.assertIs(type(verified.entries[0]["verify"]), int)
        self.assertEqual(verified.entries[0]["verify"], 0)
        with self.assertRaises(TypeError):
            verified.entries[0]["verify"] = 1  # type: ignore[index]
        with self.assertRaises(TypeError):
            verified.entries[0]["critical_operation"]["line"] = 1  # type: ignore[index]
        with self.assertRaises(FrozenInstanceError):
            verified.dataset_sha256 = "0" * 64  # type: ignore[misc]

    def test_mixed_finalized_and_deferred_tasks_keep_explicit_entry_ownership(
        self,
    ) -> None:
        deferred_task = RunTask(
            task_id="task:closed-loop-deferred",
            report_id=self.entry["report_id"],
            entry_id="entry-00002",
            inputs={"input_line": 8, "package": {"advisory": "deferred.json"}},
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(
                output,
                [
                    ReplayRecord(7, self.task, self._finalized()),
                    ReplayRecord(8, deferred_task, self._deferred_for(deferred_task)),
                ],
            )

            verified = read_verified_formal_entries(output)

        by_task = {task.task_id: task for task in verified.tasks}
        self.assertEqual(set(by_task), {self.task.task_id, deferred_task.task_id})
        self.assertEqual(by_task[self.task.task_id].status, "finalized")
        self.assertEqual(len(by_task[self.task.task_id].entries), 1)
        self.assertEqual(
            by_task[self.task.task_id].entries[0]["entry_id"],
            self.entry["entry_id"],
        )
        self.assertEqual(by_task[deferred_task.task_id].status, "manual_review")
        self.assertEqual(by_task[deferred_task.task_id].entries, ())
        self.assertEqual(len(verified.entries), 1)

    def test_binding_types_reject_missing_or_multiply_owned_entries(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one"):
            VerifiedTaskEntries(
                task_id="task:missing-entry",
                status="finalized",
                entries=(),
            )
        with self.assertRaisesRegex(ValueError, "non-finalized"):
            VerifiedTaskEntries(
                task_id="task:unexpected-entry",
                status="manual_review",
                entries=(self.entry,),
            )
        first = VerifiedTaskEntries(
            task_id="task:owner-one",
            status="finalized",
            entries=(self.entry,),
        )
        second = VerifiedTaskEntries(
            task_id="task:owner-two",
            status="finalized",
            entries=(self.entry,),
        )
        with self.assertRaisesRegex(ValueError, "unique|multiple"):
            VerifiedFormalEntries(
                dataset_sha256="a" * 64,
                tasks=(first, second),
            )

    def test_protected_paths_are_forwarded_to_the_complete_replay_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            protected = Path(temporary) / "sealed-root"
            protected.mkdir()
            entry = deepcopy(self.entry)
            entry["vuln_title"] = f"accidental disclosure from {protected}"
            outcome = self._finalized_for(entry, self.task, 7)
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(output, [ReplayRecord(7, self.task, outcome)])

            with self.assertRaisesRegex(ReplayArtifactError, "configured local path"):
                read_verified_formal_entries(
                    output, protected_paths=(protected,)
                )

    def test_entries_file_is_opened_once_and_is_not_reopened_after_verification(
        self,
    ) -> None:
        outcome = self._finalized()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(output, [ReplayRecord(7, self.task, outcome)])
            opened: list[str] = []
            original = replay_module._safe_binary_reader

            @contextmanager
            def counting_reader(*args: Any, **kwargs: Any) -> Iterator[Any]:
                path = args[0]
                opened.append(path.name)
                with original(*args, **kwargs) as handle:
                    yield handle

            with patch.object(replay_module, "_safe_binary_reader", counting_reader):
                verified = read_verified_formal_entries(output)

        self.assertEqual(len(verified.entries), 1)
        self.assertEqual(opened.count("entries.jsonl"), 1)

    def test_expected_dataset_digest_is_strict_and_fail_closed(self) -> None:
        outcome = self._finalized()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(output, [ReplayRecord(7, self.task, outcome)])
            with self.assertRaisesRegex(ReplayArtifactError, "does not match"):
                read_verified_formal_entries(
                    output, expected_dataset_sha256="0" * 64
                )
            with self.assertRaisesRegex(ReplayArtifactError, "lower-case SHA-256"):
                read_verified_formal_entries(
                    output, expected_dataset_sha256="A" * 64
                )

    def test_duplicate_published_entry_identity_is_rejected(self) -> None:
        second_entry = deepcopy(self.entry)
        second_entry["entry_id"] = "entry-00002"
        second_task = RunTask(
            task_id="task:closed-loop-002",
            report_id=second_entry["report_id"],
            entry_id=second_entry["entry_id"],
            inputs={"input_line": 8, "package": {"advisory": "item-2.json"}},
        )
        second_outcome = self._finalized_for(second_entry, second_task, 8)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(
                output,
                [
                    ReplayRecord(7, self.task, self._finalized()),
                    ReplayRecord(8, second_task, second_outcome),
                ],
            )
            entry_path = output / "entries.jsonl"
            values = [
                json.loads(line)
                for line in entry_path.read_text(encoding="utf-8").splitlines()
            ]
            values[1]["entry_id"] = values[0]["entry_id"]
            entry_path.write_text(
                "".join(canonical_json(value) + "\n" for value in values),
                encoding="utf-8",
                newline="",
            )

            with self.assertRaisesRegex(ReplayArtifactError, "duplicate entry_id"):
                read_verified_formal_entries(output)

    def test_injected_entry_for_nonfinalized_run_is_rejected(self) -> None:
        deferred = self._deferred_for(self.task)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(output, [ReplayRecord(7, self.task, deferred)])
            (output / "entries.jsonl").write_text(
                canonical_json(self.entry) + "\n", encoding="utf-8", newline=""
            )

            with self.assertRaises(ReplayArtifactError):
                read_verified_formal_entries(output)


if __name__ == "__main__":
    unittest.main()
