from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any
import unittest

from jsonschema.validators import validator_for
from referencing import Registry, Resource

from vulngym_agent.models import EvidenceItem
from vulngym_agent.orchestrator import (
    ClosedLoopOrchestrator,
    InputFailureRecord,
    ProductionDeferredDraft,
    REPLAY_FILES,
    ReplayArtifactError,
    ReplayLimits,
    ReplayRecord,
    RunTask,
    canonical_json,
    canonical_sha256,
    read_closed_loop_artifacts,
    verify_closed_loop_artifacts,
    write_closed_loop_artifacts,
)
from tests.producer_context_support import FixedProducerContextFactory
from tests import test_orchestrator as orchestrator_fixtures


ROOT = Path(__file__).resolve().parents[1]


class ClosedLoopReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = orchestrator_fixtures.ClosedLoopOrchestratorTests()
        fixture.setUp()
        self.entry = fixture.entry
        self.task = fixture.task
        self._fixture = fixture

    def _finalized(
        self,
        *,
        assumptions: tuple[str, ...] = (),
        evidence: tuple[EvidenceItem, ...] = (),
    ) -> Any:
        outcome, _ = self._fixture._run(
            orchestrator_fixtures._FakeProducer(
                self.entry,
                assumptions=assumptions,
                evidence_by_round=[evidence],
            ),
            [orchestrator_fixtures._report(self.entry, {"schema": "correct"})],
        )
        return outcome

    def _repair_finalized(self) -> Any:
        repaired = deepcopy(self.entry)
        repaired["vuln_title"] = "Replay repaired title"
        outcome, _ = self._fixture._run(
            orchestrator_fixtures._FakeProducer(self.entry, [repaired]),
            [
                orchestrator_fixtures._report(
                    self.entry, {"vuln_title": "incorrect"}, label="bad"
                ),
                orchestrator_fixtures._report(
                    repaired, {"vuln_title": "correct"}, label="good"
                ),
            ],
        )
        return outcome

    def _deferred(self) -> Any:
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
        ).run(self.task)

    def _finalized_for_task(self, task: RunTask, input_line: int) -> Any:
        report = replace(
            orchestrator_fixtures._report(
                self.entry, {"schema": "correct"}
            ),
            input_line=input_line,
        )
        validator_factory = orchestrator_fixtures._SequenceValidatorFactory(
            [report], task
        )
        return ClosedLoopOrchestrator(
            orchestrator_fixtures._FakeProducer(self.entry),
            validator_factory,
            FixedProducerContextFactory(),
        ).run(task)

    def test_stream_writer_read_verify_and_exact_entries(self) -> None:
        outcome = self._repair_finalized()
        events = (
            item
            for item in (
                ReplayRecord(7, self.task, outcome),
                InputFailureRecord(
                    input_line=8,
                    error_code="malformed_json",
                    raw_sha256="a" * 64,
                ),
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            manifest = write_closed_loop_artifacts(output, events)

            self.assertEqual(set(REPLAY_FILES), {item.name for item in output.iterdir()})
            self.assertEqual(manifest.input_records, 2)
            self.assertEqual(manifest.outcome_records, 1)
            self.assertEqual(manifest.input_failures, 1)
            self.assertEqual(manifest.entry_count, 1)
            self.assertEqual(manifest.formal_validation_count, 1)
            self.assertEqual(manifest.validation_attempt_count, 2)
            entry = json.loads((output / "entries.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(len(entry), 15)
            self.assertEqual(canonical_sha256(entry), canonical_sha256(outcome.entry))
            formal_validation = json.loads(
                (output / "validation.jsonl").read_text(encoding="utf-8")
            )
            self.assertEqual(
                canonical_sha256(formal_validation), canonical_sha256(outcome.report)
            )

            bundle = read_closed_loop_artifacts(output)
            self.assertEqual(bundle.manifest.dataset_sha256, manifest.dataset_sha256)
            self.assertEqual(
                [item["input_line"] for item in bundle.root_records], [7, 8]
            )
            checked = verify_closed_loop_artifacts(
                output,
                expected_events=iter(
                    (
                        ReplayRecord(7, self.task, outcome),
                        InputFailureRecord(8, "malformed_json", "a" * 64),
                    )
                ),
            )
            self.assertEqual(checked.dataset_sha256, manifest.dataset_sha256)

    def test_deferred_and_failed_runs_keep_state_roots_without_entries(self) -> None:
        deferred = self._deferred()
        failed, _ = self._fixture._run(
            orchestrator_fixtures._FakeProducer(self.entry, fail_generate=True), []
        )
        # The tasks must be globally unique, so exercise the two terminal
        # topologies in separate transactions.
        for label, outcome, expected_deferred in (
            ("deferred", deferred, 1),
            ("failed", failed, 0),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "artifacts"
                manifest = write_closed_loop_artifacts(
                    output, [ReplayRecord(7, self.task, outcome)]
                )
                bundle = read_closed_loop_artifacts(output)
                self.assertEqual(manifest.entry_count, 0)
                self.assertEqual(
                    manifest.formal_validation_count,
                    0 if outcome.report is None else 1,
                )
                self.assertEqual(bundle.record_counts["states.jsonl"], 1)
                self.assertEqual(
                    bundle.record_counts["deferred.jsonl"], expected_deferred
                )
                self.assertEqual(bundle.root_records[0]["root_kind"], "state")

    def test_sensitive_text_is_omitted_but_benign_path_text_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            protected = base / "private-package"
            protected.mkdir()
            evidence = EvidenceItem(
                evidence_id="EV-REPLAY-PUBLIC",
                report_id=self.entry["report_id"],
                entry_id=self.entry["entry_id"],
                source_type="advisory",
                snippet="Public endpoint /api/v1/items is relevant.",
            )
            outcome = self._finalized(
                assumptions=(f"secret assumption at {protected}",),
                evidence=(evidence,),
            )
            output = base / "artifacts"
            write_closed_loop_artifacts(
                output,
                [ReplayRecord(7, self.task, outcome)],
                protected_paths=(protected,),
            )
            text = "".join(
                path.read_text(encoding="utf-8")
                for path in output.iterdir()
                if path.suffix == ".jsonl"
            )
            self.assertIn("/api/v1/items", text)
            self.assertNotIn("secret assumption", text)
            self.assertNotIn(str(protected), text)
            self.assertNotIn('"prompt"', text)
            self.assertNotIn('"response"', text)
            self.assertNotIn("assumptions", text)

    def test_exact_protected_root_and_absolute_file_field_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            protected = base / "repo-root"
            protected.mkdir()
            leaked = EvidenceItem(
                evidence_id="EV-REPLAY-LEAK",
                report_id=self.entry["report_id"],
                entry_id=self.entry["entry_id"],
                source_type="advisory",
                snippet=f"loaded from {protected}",
            )
            with self.assertRaisesRegex(ReplayArtifactError, "configured local path"):
                write_closed_loop_artifacts(
                    base / "leak-output",
                    [
                        ReplayRecord(
                            7, self.task, self._finalized(evidence=(leaked,))
                        )
                    ],
                    protected_paths=(protected,),
                )
            self.assertFalse((base / "leak-output").exists())

            absolute = EvidenceItem(
                evidence_id="EV-REPLAY-ABSOLUTE",
                report_id=self.entry["report_id"],
                entry_id=self.entry["entry_id"],
                source_type="source",
                snippet="bounded source excerpt",
                file="C:\\private\\repo\\source.py",
                line_start=1,
                line_end=1,
            )
            with self.assertRaisesRegex(ReplayArtifactError, "repository-relative"):
                write_closed_loop_artifacts(
                    base / "absolute-output",
                    [ReplayRecord(7, self.task, self._finalized(evidence=(absolute,)))],
                )
            self.assertFalse((base / "absolute-output").exists())

    def test_order_duplicate_task_limits_and_output_conflicts_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "unordered"
            with self.assertRaisesRegex(ReplayArtifactError, "strictly ordered"):
                write_closed_loop_artifacts(
                    output,
                    [
                        InputFailureRecord(2, "bad_line", "2" * 64),
                        InputFailureRecord(1, "bad_line", "1" * 64),
                    ],
                )
            self.assertFalse(output.exists())
            self.assertFalse(any(".unordered.staging-" in item.name for item in base.iterdir()))

            limited = base / "limited"
            with self.assertRaisesRegex(ReplayArtifactError, "max_input_records"):
                write_closed_loop_artifacts(
                    limited,
                    [
                        InputFailureRecord(1, "bad_line", "1" * 64),
                        InputFailureRecord(2, "bad_line", "2" * 64),
                    ],
                    limits=ReplayLimits(max_input_records=1),
                )
            self.assertFalse(limited.exists())

            duplicate_task = base / "duplicate-task"
            with self.assertRaisesRegex(ReplayArtifactError, "globally unique"):
                write_closed_loop_artifacts(
                    duplicate_task,
                    [
                        InputFailureRecord(
                            1, "bad_line", "1" * 64, task_id="task:duplicate"
                        ),
                        InputFailureRecord(
                            2, "bad_line", "2" * 64, task_id="task:duplicate"
                        ),
                    ],
                )
            self.assertFalse(duplicate_task.exists())

            second_task = RunTask(
                task_id="task:closed-loop-duplicate-entry",
                report_id=self.task.report_id,
                entry_id=self.task.entry_id,
                inputs={"input_line": 8, "package": {"advisory": "item.json"}},
            )
            duplicate_entry = base / "duplicate-entry"
            with self.assertRaisesRegex(ReplayArtifactError, "entry_id"):
                write_closed_loop_artifacts(
                    duplicate_entry,
                    [
                        ReplayRecord(7, self.task, self._finalized()),
                        ReplayRecord(
                            8,
                            second_task,
                            self._finalized_for_task(second_task, 8),
                        ),
                    ],
                )
            self.assertFalse(duplicate_entry.exists())

            existing = base / "existing"
            existing.mkdir()
            with self.assertRaises(FileExistsError):
                write_closed_loop_artifacts(existing, ())

    def test_tampering_and_expected_outcome_mismatch_are_rejected(self) -> None:
        outcome = self._finalized()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(
                output, [ReplayRecord(7, self.task, outcome)]
            )
            state_path = output / "states.jsonl"
            value = json.loads(state_path.read_text(encoding="utf-8"))
            value["payload"]["changed_fields"] = ["vuln_title"]
            # Keep canonical JSONL while intentionally leaving the old digest.
            state_path.write_text(canonical_json(value) + "\n", encoding="utf-8")
            with self.assertRaises(ReplayArtifactError):
                read_closed_loop_artifacts(output)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(
                output,
                [InputFailureRecord(1, "malformed_json", "1" * 64)],
            )
            with self.assertRaisesRegex(ReplayArtifactError, "expected event stream"):
                verify_closed_loop_artifacts(
                    output,
                    expected_events=[
                        InputFailureRecord(1, "malformed_json", "2" * 64)
                    ],
                )

    def test_reader_rejects_oversized_lines_before_unbounded_allocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "oversized"
            write_closed_loop_artifacts(
                output, [InputFailureRecord(1, "bad_line", "1" * 64)]
            )
            (output / "errors.jsonl").write_bytes(b"{" + b"x" * 512 + b"}\n")
            with self.assertRaisesRegex(ReplayArtifactError, "oversized line"):
                read_closed_loop_artifacts(
                    output,
                    limits=ReplayLimits(max_line_bytes=256, max_total_bytes=4096),
                )

    def test_reader_rejects_linked_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "artifacts"
            write_closed_loop_artifacts(output, ())
            outside = base / "outside.jsonl"
            outside.write_bytes(b"")
            linked_file = output / "tool_calls.jsonl"
            linked_file.unlink()
            try:
                linked_file.symlink_to(outside)
            except OSError as error:
                self.skipTest(f"file symlinks are unavailable: {error}")
            with self.assertRaisesRegex(
                ReplayArtifactError, "regular non-link artifact file"
            ):
                read_closed_loop_artifacts(output)

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "artifacts"
            write_closed_loop_artifacts(output, ())
            linked_root = base / "linked-root"
            try:
                linked_root.symlink_to(output, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            with self.assertRaisesRegex(
                ReplayArtifactError, "symlink, junction, or reparse"
            ):
                read_closed_loop_artifacts(linked_root)

    def test_all_noncanonical_git_file_spellings_are_rejected(self) -> None:
        for index, invalid in enumerate(
            ("C:secret.py", "dir\\file.py", "-option", "/absolute.py", "a/../b.py"),
            start=1,
        ):
            with self.subTest(path=invalid), tempfile.TemporaryDirectory() as temporary:
                evidence = EvidenceItem(
                    evidence_id=f"EV-REPLAY-PATH-{index}",
                    report_id=self.entry["report_id"],
                    entry_id=self.entry["entry_id"],
                    source_type="source",
                    snippet="bounded source excerpt",
                    file=invalid,
                    line_start=1,
                    line_end=1,
                )
                output = Path(temporary) / "artifacts"
                with self.assertRaisesRegex(
                    ReplayArtifactError, "repository-relative"
                ):
                    write_closed_loop_artifacts(
                        output,
                        [
                            ReplayRecord(
                                7,
                                self.task,
                                self._finalized(evidence=(evidence,)),
                            )
                        ],
                    )
                self.assertFalse(output.exists())

    def test_schema_accepts_every_emitted_line(self) -> None:
        outcome = self._finalized()
        schema_path = ROOT / "schemas" / "closed_loop_replay.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        entry_schema = json.loads(
            (ROOT / "schemas" / "entry.schema.json").read_text(encoding="utf-8")
        )
        validation_schema = json.loads(
            (ROOT / "schemas" / "validation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        registry = Registry().with_resources(
            [
                (schema["$id"], Resource.from_contents(schema)),
                (entry_schema["$id"], Resource.from_contents(entry_schema)),
                (
                    validation_schema["$id"],
                    Resource.from_contents(validation_schema),
                ),
            ]
        )
        validator_class = validator_for(schema)
        validator_class.check_schema(schema)
        validator = validator_class(schema, registry=registry)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            write_closed_loop_artifacts(
                output,
                [
                    ReplayRecord(7, self.task, outcome),
                    InputFailureRecord(8, "malformed_json", hashlib.sha256(b"{").hexdigest()),
                ],
            )
            for path in output.iterdir():
                for line in path.read_text(encoding="utf-8").splitlines():
                    validator.validate(json.loads(line))


if __name__ == "__main__":
    unittest.main()
