from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Mapping
import unittest

from jsonschema.validators import validator_for
from referencing import Registry, Resource

from vulngym_agent.adapters import ENTRY_FIELDS
from vulngym_agent.agents import T2Producer
from vulngym_agent.models import EvidenceItem, FieldValidation, ValidationReport
from vulngym_agent.orchestrator import (
    ProductionOutcome,
    RepairInstruction,
    RepairPlan,
    RunTask,
    ToolCallRecord,
    build_repair_plan,
    canonical_json,
    canonical_sha256,
    dependent_field_closure,
)
from vulngym_agent.orchestrator.budget import Budget


ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class _FakeProducer:
    def __init__(self, candidate: Mapping[str, Any]) -> None:
        self._candidate = candidate

    def generate(self, task: RunTask, budget: Budget) -> ProductionOutcome:
        return ProductionOutcome(self._candidate)

    def repair(
        self,
        task: RunTask,
        previous_entry: Mapping[str, Any],
        plan: RepairPlan,
        budget: Budget,
    ) -> ProductionOutcome:
        return ProductionOutcome(previous_entry)


class RepairPlanContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entry = json.loads(
            (ROOT / "data" / "entries.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        cls.entry["verify"] = 0
        cls.report_id = cls.entry["report_id"]
        cls.entry_id = cls.entry["entry_id"]

    def _validation(self, *incorrect: str) -> ValidationReport:
        fields: dict[str, FieldValidation] = {}
        for name in incorrect:
            fields[name] = FieldValidation(
                status="incorrect",
                confidence=1.0,
                evidence=f"{name} failed deterministic validation.",
                evidence_refs=(f"EV-REPAIR-{name.upper()}",),
                suggested_fix=self.entry[name],
            )
        if not fields:
            fields["repo_url"] = FieldValidation(
                status="uncertain",
                confidence=0.5,
                evidence="Repository ownership cannot yet be established.",
            )
        return ValidationReport(
            report_id=self.report_id,
            entry_id=self.entry_id,
            verdict="incorrect" if incorrect else "uncertain",
            fields=fields,
            summary="One bounded validation result.",
        )

    def _task(self) -> RunTask:
        return RunTask(
            task_id="task:repair-001",
            report_id=self.report_id,
            entry_id=self.entry_id,
            inputs={"package": {"advisory": "advisories/item.json"}},
        )

    def test_dependency_closure_matches_declared_rules(self) -> None:
        self.assertEqual(
            dependent_field_closure(("repo_url",)),
            (
                "commit",
                "critical_operation",
                "entry_point",
                "project",
                "trace",
            ),
        )
        self.assertEqual(
            dependent_field_closure(("commit",)),
            ("critical_operation", "entry_point", "trace"),
        )
        self.assertEqual(
            dependent_field_closure(("entry_point",)), ("trace",)
        )
        self.assertEqual(
            dependent_field_closure(("critical_operation",)), ("trace",)
        )
        self.assertEqual(
            dependent_field_closure(("report_id",)),
            ("source_link", "vuln_ids"),
        )
        self.assertEqual(
            dependent_field_closure(("repo_url", "trace")),
            ("commit", "critical_operation", "entry_point", "project"),
        )

    def test_build_plan_partitions_all_fields_and_hashes_every_lock(self) -> None:
        validation = self._validation("repo_url", "report_id")
        plan = build_repair_plan(
            task=self._task(),
            previous_candidate=self.entry,
            validation=validation,
            repair_iteration=1,
            failure_codes={
                "repo_url": ("repo_mismatch",),
                "report_id": ("advisory_mismatch",),
            },
            required_checks={
                "repo_url": ("git:remote",),
                "report_id": ("advisory:id",),
            },
            allowed_tools={"repo_url": ("git",), "report_id": ("advisory",)},
            global_actions=("Use only local evidence.",),
        )

        self.assertEqual(plan.repair_fields, ("repo_url", "report_id"))
        self.assertEqual(
            plan.dependent_fields,
            (
                "commit",
                "critical_operation",
                "entry_point",
                "project",
                "source_link",
                "trace",
                "vuln_ids",
            ),
        )
        self.assertEqual(
            set(plan.repair_fields)
            | set(plan.dependent_fields)
            | set(plan.locked_fields),
            set(ENTRY_FIELDS),
        )
        self.assertFalse(set(plan.repair_fields) & set(plan.dependent_fields))
        self.assertEqual(set(plan.locked_field_hashes), set(plan.locked_fields))
        self.assertEqual(
            plan.previous_candidate_sha256, canonical_sha256(self.entry)
        )
        self.assertEqual(
            plan.validation_sha256, canonical_sha256(validation.to_dict())
        )

    def test_locked_field_check_allows_dependencies_but_detects_other_changes(
        self,
    ) -> None:
        validation = self._validation("repo_url")
        plan = build_repair_plan(
            task=self._task(),
            previous_candidate=self.entry,
            validation=validation,
            repair_iteration=1,
        )
        candidate = deepcopy(self.entry)
        candidate["project"] = "dependent-project"
        candidate["trace"] = []
        self.assertEqual(plan.locked_field_changes(candidate), ())

        candidate["origin"] = "changed locked value"
        self.assertEqual(plan.locked_field_changes(candidate), ("origin",))
        with self.assertRaisesRegex(ValueError, "locked fields"):
            plan.assert_locked_fields(candidate)

    def test_plan_round_trip_is_stable_and_schema_valid(self) -> None:
        validation = self._validation("commit")
        plan = build_repair_plan(
            task=self._task(),
            previous_candidate=self.entry,
            validation=validation,
            repair_iteration=2,
        )
        encoded = plan.to_json()
        decoded = RepairPlan.from_dict(json.loads(encoded))

        self.assertEqual(decoded.to_dict(), plan.to_dict())
        self.assertEqual(decoded.to_json(), encoded)
        schema = _load_json(ROOT / "schemas" / "repair_plan.schema.json")
        validator_type = validator_for(schema)
        validator_type.check_schema(schema)
        errors = sorted(
            validator_type(schema).iter_errors(plan.to_dict()),
            key=lambda item: list(item.absolute_path),
        )
        self.assertEqual(errors, [])

    def test_plan_rejects_non_partition_and_wrong_dependency_closure(self) -> None:
        validation = self._validation("commit")
        plan = build_repair_plan(
            task=self._task(),
            previous_candidate=self.entry,
            validation=validation,
            repair_iteration=1,
        )
        values = plan.to_dict()
        values["dependent_fields"] = []
        values["locked_fields"] = [
            name for name in ENTRY_FIELDS if name != "commit"
        ]
        values["locked_field_hashes"].update(
            {
                name: canonical_sha256(self.entry[name])
                for name in values["locked_fields"]
            }
        )
        with self.assertRaisesRegex(ValueError, "dependency closure"):
            RepairPlan.from_dict(values)

        values = plan.to_dict()
        values["locked_fields"].append("commit")
        values["locked_field_hashes"]["commit"] = canonical_sha256(
            self.entry["commit"]
        )
        with self.assertRaisesRegex(ValueError, "disjoint"):
            RepairPlan.from_dict(values)

    def test_repair_iteration_and_instruction_keys_are_bounded(self) -> None:
        validation = self._validation("commit")
        plan = build_repair_plan(
            task=self._task(),
            previous_candidate=self.entry,
            validation=validation,
            repair_iteration=1,
        )
        for invalid in (0, 3, True):
            with self.subTest(invalid=invalid):
                values = plan.to_dict()
                values["repair_iteration"] = invalid
                with self.assertRaises(ValueError):
                    RepairPlan.from_dict(values)

        values = plan.to_dict()
        values["instructions"] = {}
        with self.assertRaisesRegex(ValueError, "instructions keys"):
            RepairPlan.from_dict(values)

    def test_uncertain_or_pseudo_field_only_report_does_not_broaden_repair(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "no incorrect official"):
            build_repair_plan(
                task=self._task(),
                previous_candidate=self.entry,
                validation=self._validation(),
                repair_iteration=1,
            )

        validation = ValidationReport(
            report_id=self.report_id,
            entry_id=self.entry_id,
            verdict="incorrect",
            fields={
                "schema": FieldValidation(
                    status="incorrect",
                    confidence=1,
                    evidence="Malformed row.",
                )
            },
            summary="Schema failed.",
        )
        with self.assertRaisesRegex(ValueError, "no incorrect official"):
            build_repair_plan(
                task=self._task(),
                previous_candidate=self.entry,
                validation=validation,
                repair_iteration=1,
            )

    def test_task_identity_anchors_a_report_id_repair(self) -> None:
        wrong_report_id = "GHSA-2222-3333-4444"
        candidate = deepcopy(self.entry)
        candidate["report_id"] = wrong_report_id
        validation = ValidationReport(
            report_id=wrong_report_id,
            entry_id=self.entry_id,
            verdict="incorrect",
            fields={
                "report_id": FieldValidation(
                    status="incorrect",
                    confidence=1,
                    evidence="Candidate advisory ID differs from the task package.",
                    suggested_fix=self.report_id,
                )
            },
            summary="The candidate identity needs repair.",
        )
        plan = build_repair_plan(
            task=self._task(),
            previous_candidate=candidate,
            validation=validation,
            repair_iteration=1,
        )
        self.assertEqual(plan.report_id, self.report_id)
        self.assertEqual(plan.entry_id, self.entry_id)
        self.assertEqual(plan.repair_fields, ("report_id",))
        self.assertEqual(plan.previous_candidate_sha256, canonical_sha256(candidate))

    def test_run_task_is_immutable_json_and_round_trips(self) -> None:
        original = {"b": [2, {"x": "值"}], "a": 1}
        task = RunTask(task_id="task-immutable", inputs=original)
        original["a"] = 99
        self.assertEqual(task.inputs["a"], 1)
        with self.assertRaises(TypeError):
            task.inputs["new"] = "forbidden"  # type: ignore[index]
        restored = RunTask.from_dict(task.to_dict())
        self.assertEqual(restored.to_dict(), task.to_dict())
        self.assertEqual(restored.to_json(), task.to_json())

    def test_canonical_digest_is_order_independent_and_rejects_nan(self) -> None:
        left = {"z": [1, 2], "a": {"文": "值"}}
        right = {"a": {"文": "值"}, "z": [1, 2]}
        self.assertEqual(canonical_json(left), canonical_json(right))
        self.assertEqual(canonical_sha256(left), canonical_sha256(right))
        with self.assertRaisesRegex(ValueError, "finite"):
            canonical_sha256({"bad": float("nan")})

    def test_production_outcome_enforces_formal_entry_and_sidecar_separation(
        self,
    ) -> None:
        entry = deepcopy(self.entry)
        entry["verify"] = False
        evidence = EvidenceItem(
            evidence_id="EV-PRODUCER-1",
            report_id=self.report_id,
            entry_id=self.entry_id,
            source_type="schema",
            snippet="The producer emitted the formal field set.",
        )
        tool_call = ToolCallRecord(
            tool_call_id="TOOL-1",
            tool_name="local.git",
            arguments_sha256="a" * 64,
            status="success",
            result_sha256="b" * 64,
        )
        outcome = ProductionOutcome(
            candidate=entry,
            evidence=(evidence,),
            tool_calls=(tool_call,),
            assumptions=("Reachability still needs T1 review.",),
        )
        self.assertEqual(set(outcome.candidate), set(ENTRY_FIELDS))
        self.assertIs(type(outcome.candidate["verify"]), int)
        self.assertEqual(outcome.candidate["verify"], 0)
        self.assertNotIn("evidence", outcome.candidate)
        self.assertNotIn("tool_calls", outcome.candidate)
        self.assertNotIn("assumptions", outcome.candidate)
        restored = ProductionOutcome.from_dict(outcome.to_dict())
        self.assertEqual(restored.to_dict(), outcome.to_dict())

        contaminated = deepcopy(self.entry)
        contaminated["reasoning"] = "must stay in sidecar"
        with self.assertRaisesRegex(ValueError, "exactly the 15"):
            ProductionOutcome(contaminated)

        invalid = deepcopy(self.entry)
        invalid["entry_point"]["line"] = 0
        with self.assertRaises(ValueError):
            ProductionOutcome(invalid)

    def test_t2_protocol_accepts_a_deterministic_fake(self) -> None:
        producer = _FakeProducer(self.entry)
        self.assertIsInstance(producer, T2Producer)
        outcome = producer.generate(self._task(), Budget())
        self.assertEqual(set(outcome.candidate), set(ENTRY_FIELDS))

    def test_run_state_schema_is_self_validating_and_excludes_raw_sidecars(
        self,
    ) -> None:
        schemas = {
            name: _load_json(ROOT / "schemas" / name)
            for name in (
                "entry.schema.json",
                "validation.schema.json",
                "repair_plan.schema.json",
                "run_state.schema.json",
            )
        }
        registry = Registry().with_resources(
            (
                schema["$id"],
                Resource.from_contents(schema),
            )
            for schema in schemas.values()
        )
        schema = schemas["run_state.schema.json"]
        validator_type = validator_for(schema)
        validator_type.check_schema(schema)

        validation = self._validation("commit")
        plan = build_repair_plan(
            task=self._task(),
            previous_candidate=self.entry,
            validation=validation,
            repair_iteration=1,
        )
        candidate = ProductionOutcome(self.entry).to_dict()["candidate"]
        state = {
            "task": {
                "task_id": self._task().task_id,
                "report_id": self.report_id,
                "entry_id": self.entry_id,
                "inputs_sha256": canonical_sha256(self._task().inputs),
            },
            "status": "repairing",
            "repair_iteration": 1,
            "validation_count": 1,
            "candidate": candidate,
            "candidate_sha256": canonical_sha256(candidate),
            "last_validation": validation.to_dict(),
            "active_repair_plan": plan.to_dict(),
            "budget": Budget().to_dict(),
            "production_history": [
                {
                    "attempt": 0,
                    "mode": "generated",
                    "candidate_sha256": canonical_sha256(candidate),
                    "parent_candidate_sha256": None,
                    "repair_plan_sha256": None,
                }
            ],
            "production_attempts": [
                {
                    "attempt": 0,
                    "mode": "generated",
                    "candidate_sha256": canonical_sha256(candidate),
                    "outcome_sha256": canonical_sha256(
                        ProductionOutcome(self.entry)
                    ),
                    "disposition": "accepted",
                    "parent_candidate_sha256": None,
                    "repair_plan_sha256": None,
                }
            ],
            "validation_history": [
                {
                    "attempt": 0,
                    "candidate_sha256": canonical_sha256(candidate),
                    "validation_sha256": canonical_sha256(validation),
                    "evidence_sha256": canonical_sha256([]),
                }
            ],
            "stop_reason": None,
            "termination": None,
        }
        errors = sorted(
            validator_type(schema, registry=registry).iter_errors(state),
            key=lambda item: list(item.absolute_path),
        )
        self.assertEqual(errors, [])
        serialized = json.dumps(state, sort_keys=True)
        self.assertNotIn("advisories/item.json", serialized)
        self.assertNotIn("assumptions", serialized)
        self.assertNotIn("inputs", state["task"])
        self.assertEqual(
            set(state["production_history"][0]),
            {
                "attempt",
                "mode",
                "candidate_sha256",
                "parent_candidate_sha256",
                "repair_plan_sha256",
            },
        )


if __name__ == "__main__":
    unittest.main()
