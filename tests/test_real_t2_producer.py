from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any
import unittest

from vulngym_agent.adapters import ENTRY_FIELDS
from vulngym_agent.agents.model_runtime import ModelRequest
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.agents.t1_validator import T1ValidationOutcome
from vulngym_agent.agents.t2_execution import LocalT2ContextFactory
from vulngym_agent.closed_loop_cli import LocalT1ValidatorFactory
from vulngym_agent.models import FieldValidation, ValidationReport
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.orchestrator.contracts import (
    ProductionDeferredDraft,
    ProductionDraft,
    RunTask,
    canonical_sha256,
)
from vulngym_agent.orchestrator.repair_plan import RepairPlan, build_repair_plan
from vulngym_agent.orchestrator.state_machine import (
    ClosedLoopOrchestrator,
    STOP_PRODUCER_DEFERRED,
)


REPORT_ID = "GHSA-1111-2222-3333"
ENTRY_ID = "entry-00001"
REPO_URL = "https://github.com/example/project"
SOURCE_PATH = "src/app.py"


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_plain(child) for child in value]
    return value


class _ScriptedBackend:
    """Offline stage script that can select only IDs issued in its request."""

    backend_id = "test.offline-script"
    model_id = "t2-structured-v1"

    def __init__(
        self,
        *,
        critical_mode: str = "sink",
        unknown_candidate: bool = False,
        repair_action: str = "apply",
        repair_fields: tuple[str, ...] = ("vuln_title",),
    ) -> None:
        self.critical_mode = critical_mode
        self.unknown_candidate = unknown_candidate
        self.repair_action = repair_action
        self.repair_fields = repair_fields
        self.requests: list[ModelRequest] = []

    def invoke(self, request: ModelRequest) -> Mapping[str, Any]:
        self.requests.append(request)
        if request.stage == "plan":
            return {"action": "analyze", "critical_mode": self.critical_mode}
        if request.stage == "semantic_judge":
            critical = request.payload["critical_candidates"]
            entries = request.payload["entry_candidates"]
            critical_id = critical[0]["candidate_id"]
            if self.unknown_candidate:
                critical_id = "critical-not-issued"
            return {
                "action": "select",
                "critical_candidate_id": critical_id,
                "entry_candidate_id": entries[0]["candidate_id"],
                "project": "example-project",
                "vuln_title": "Unsafe evaluation of an untrusted route value",
                "vuln_category_l1": "Injection",
                "vuln_category_l2": "Code Injection",
            }
        if request.stage == "repair":
            if self.repair_action == "defer":
                return {"action": "defer", "repair_fields": []}
            return {
                "action": "apply",
                "repair_fields": list(self.repair_fields),
            }
        if request.stage == "reflection":
            return {"action": "emit"}
        raise AssertionError(f"unexpected model stage: {request.stage}")


class _OneReportValidatorFactory:
    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        self.calls = 0

    def __call__(self, task: RunTask) -> object:
        outer = self

        class _Validator:
            def validate(
                self, candidate: Any, *, input_line: int | None = None
            ) -> T1ValidationOutcome:
                del candidate, input_line
                outer.calls += 1
                return T1ValidationOutcome(report=outer.report, evidence=())

        return _Validator()


class LocalStructuredT2ProducerTests(unittest.TestCase):
    def test_public_agent_exports_are_lazy_and_fresh_import_safe(self) -> None:
        completed = subprocess.run(
            (
                sys.executable,
                "-B",
                "-c",
                "from vulngym_agent.orchestrator import Budget; "
                "from vulngym_agent.agents import ("
                "LocalStructuredT2Producer, LocalT2ContextFactory); "
                "assert Budget and LocalStructuredT2Producer and LocalT2ContextFactory",
            ),
            cwd=Path(__file__).resolve().parents[1],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / "repo"
        self.package_root = self.root / "package"
        (self.repository / "src").mkdir(parents=True)
        (self.package_root / "advisories").mkdir(parents=True)
        (self.package_root / "patches").mkdir(parents=True)
        _git(self.repository, "init", "--quiet")
        _git(self.repository, "config", "user.name", "VulnGym Test")
        _git(
            self.repository,
            "config",
            "user.email",
            "vulngym-test@example.invalid",
        )

        vulnerable = (
            "def dangerous(user):\n"
            "    return eval(user)\n"
            "\n"
            "@app.route('/run')\n"
            "def public_route(request):\n"
            "    return dangerous(request)\n"
        )
        (self.repository / SOURCE_PATH).write_text(vulnerable, encoding="utf-8")
        _git(self.repository, "add", "--", SOURCE_PATH)
        _git(self.repository, "commit", "--quiet", "-m", "vulnerable")
        self.vulnerable_commit = _git(self.repository, "rev-parse", "HEAD")

        fixed = (
            "def dangerous(user):\n"
            "    if not user.isdigit():\n"
            "        return None\n"
            "    return int(user)\n"
            "\n"
            "@app.route('/run')\n"
            "def public_route(request):\n"
            "    return dangerous(request)\n"
        )
        (self.repository / SOURCE_PATH).write_text(fixed, encoding="utf-8")
        _git(self.repository, "add", "--", SOURCE_PATH)
        _git(self.repository, "commit", "--quiet", "-m", "fix")
        self.fix_commit = _git(self.repository, "rev-parse", "HEAD")

        patch = _git(
            self.repository,
            "diff",
            "--no-ext-diff",
            self.vulnerable_commit,
            self.fix_commit,
            "--",
            SOURCE_PATH,
        )
        (self.package_root / "patches" / "fix.patch").write_text(
            patch + "\n", encoding="utf-8"
        )
        self._write_advisory((self.fix_commit,))

    def _write_advisory(self, fix_commits: tuple[str, ...]) -> None:
        advisory = {
            "ghsa_id": REPORT_ID,
            "cve": "CVE-2026-12345",
            "fix_commits": list(fix_commits),
            "source_link": f"https://github.com/advisories/{REPORT_ID}",
            "summary": "Unsafe eval permits code execution from a public route.",
        }
        (self.package_root / "advisories" / "item.json").write_text(
            json.dumps(advisory, sort_keys=True), encoding="utf-8"
        )

    def _replace_fix_with_benign_change(self) -> None:
        prior = self.fix_commit
        source_file = self.repository / SOURCE_PATH
        source_file.write_text(
            "# security metadata only\n" + source_file.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        _git(self.repository, "add", "--", SOURCE_PATH)
        _git(self.repository, "commit", "--quiet", "-m", "metadata only")
        self.vulnerable_commit = prior
        self.fix_commit = _git(self.repository, "rev-parse", "HEAD")
        patch = _git(
            self.repository,
            "diff",
            "--no-ext-diff",
            self.vulnerable_commit,
            self.fix_commit,
            "--",
            SOURCE_PATH,
        )
        (self.package_root / "patches" / "fix.patch").write_text(
            patch + "\n", encoding="utf-8"
        )
        self._write_advisory((self.fix_commit,))

    def _task(self, *, critical_mode: str = "sink") -> RunTask:
        return RunTask(
            task_id="task:real-t2-001",
            report_id=REPORT_ID,
            entry_id=ENTRY_ID,
            inputs={
                "contract_version": 1,
                "input_line": 1,
                "repo_url": REPO_URL,
                "package": {
                    "advisory": "advisories/item.json",
                    "references": [],
                    "patches": ["patches/fix.patch"],
                },
                "hints": {
                    "project": "example-project",
                    "fix_commits": [self.fix_commit],
                    "source_paths": [SOURCE_PATH],
                    "entry_symbols": ["public_route", "dangerous"],
                    "critical_mode": critical_mode,
                },
            },
        )

    def _factory(self, backend: _ScriptedBackend) -> LocalT2ContextFactory:
        return LocalT2ContextFactory(
            self.package_root,
            {REPO_URL: self.repository},
            backend,
        )

    def _generate(
        self,
        backend: _ScriptedBackend,
        *,
        task: RunTask | None = None,
    ) -> tuple[
        ProductionDraft | ProductionDeferredDraft,
        Any,
        LocalT2ContextFactory,
    ]:
        active_task = task or self._task()
        budget = Budget(Limits(max_llm_calls=8, max_tool_calls=40))
        factory = self._factory(backend)
        controller = factory.create(
            active_task,
            attempt=0,
            mode="generate",
            plan=None,
            budget=budget,
        )
        producer = LocalStructuredT2Producer()
        draft = producer.generate(active_task, controller.producer_context)
        projection = controller.finalize()
        return draft, projection, factory

    def _title_plan(
        self,
        task: RunTask,
        previous: Mapping[str, Any],
        suggested_fix: str,
        *,
        allow_required_tools: bool = True,
    ) -> RepairPlan:
        validation = ValidationReport(
            report_id=REPORT_ID,
            entry_id=ENTRY_ID,
            input_line=1,
            verdict="incorrect",
            fields={
                "vuln_title": FieldValidation(
                    status="incorrect",
                    confidence=1.0,
                    evidence="The title is not specific to the verified sink.",
                    evidence_refs=(),
                    suggested_fix=suggested_fix,
                )
            },
            summary="One title repair is required.",
        )
        allowed_tools = None
        if not allow_required_tools:
            allowed_tools = {"vuln_title": ()}
        return build_repair_plan(
            task=task,
            previous_candidate=previous,
            validation=validation,
            repair_iteration=1,
            allowed_tools=allowed_tools,
        )

    def test_generate_from_real_git_emits_complete_evidence_bound_draft(self) -> None:
        backend = _ScriptedBackend()
        draft, projection, _ = self._generate(backend)

        self.assertIsInstance(draft, ProductionDraft)
        assert isinstance(draft, ProductionDraft)
        candidate = _plain(draft.candidate)
        self.assertEqual(set(candidate), set(ENTRY_FIELDS))
        self.assertEqual(len(candidate), 15)
        self.assertEqual(candidate["commit"], self.vulnerable_commit)
        self.assertEqual(candidate["trace"], [])
        self.assertIs(type(candidate["verify"]), int)
        self.assertEqual(candidate["verify"], 0)
        self.assertEqual(
            projection.model_stages,
            ("plan", "semantic_judge", "reflection"),
        )

        semantic = next(
            request for request in backend.requests if request.stage == "semantic_judge"
        )
        issued_critical = semantic.payload["critical_candidates"]
        issued_entries = semantic.payload["entry_candidates"]
        self.assertTrue(issued_critical)
        self.assertTrue(issued_entries)
        self.assertTrue(
            all(item["candidate_id"].startswith("critical-") for item in issued_critical)
        )
        self.assertTrue(
            all(item["candidate_id"].startswith("entry-") for item in issued_entries)
        )
        self.assertEqual(
            candidate["critical_operation"], _plain(issued_critical[0]["location"])
        )
        self.assertEqual(
            candidate["entry_point"], _plain(issued_entries[0]["location"])
        )

        portable = json.dumps(
            {"draft": draft.to_dict(), "projection": projection.to_dict()},
            ensure_ascii=False,
            sort_keys=True,
        )
        self.assertNotIn(str(self.package_root), portable)
        self.assertNotIn(str(self.repository), portable)
        self.assertNotIn("package_root", portable)
        self.assertNotIn("repo_path", portable)

    def test_full_entry_lane_runs_real_t2_into_real_t1_with_in_memory_sidecars(
        self,
    ) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional developer dependency
            self.skipTest("jsonschema is not installed")

        backend = _ScriptedBackend()
        task = self._task()
        outcome = ClosedLoopOrchestrator(
            LocalStructuredT2Producer(),
            LocalT1ValidatorFactory(
                self.package_root,
                {REPO_URL: self.repository},
            ),
            self._factory(backend),
            limits=Limits(
                max_llm_calls=8,
                max_tool_calls=80,
                max_repair_iterations=0,
            ),
        ).run(task)

        self.assertEqual(outcome.status, "manual_review")
        self.assertIsNotNone(outcome.entry)
        self.assertIsNotNone(outcome.report)
        self.assertEqual(len(outcome.production_outcomes), 1)
        self.assertEqual(len(outcome.validation_outcomes), 1)
        self.assertEqual(
            outcome.state.stop_reason,
            "validation_uncertain",
        )

        candidate = _plain(outcome.entry)
        self.assertEqual(set(candidate), set(ENTRY_FIELDS))
        self.assertEqual(candidate["commit"], self.vulnerable_commit)
        self.assertIs(type(candidate["verify"]), int)
        self.assertEqual(candidate["verify"], 0)
        self.assertEqual(
            candidate,
            _plain(outcome.production_outcomes[0].candidate),
        )

        validation = outcome.validation_outcomes[0]
        self.assertEqual(outcome.report, validation.report)
        report = validation.report.to_dict()
        evidence = [item.to_dict() for item in validation.evidence]
        self.assertTrue(evidence)
        schema_root = Path(__file__).resolve().parents[1] / "schemas"
        entry_schema = json.loads(
            (schema_root / "entry.schema.json").read_text(encoding="utf-8")
        )
        validation_schema = json.loads(
            (schema_root / "validation.schema.json").read_text(encoding="utf-8")
        )
        evidence_schema = json.loads(
            (schema_root / "evidence.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(entry_schema).validate(candidate)
        Draft202012Validator(validation_schema).validate(report)
        evidence_validator = Draft202012Validator(evidence_schema)
        for item in evidence:
            evidence_validator.validate(item)

        self.assertEqual(report["report_id"], candidate["report_id"])
        self.assertEqual(report["entry_id"], candidate["entry_id"])
        self.assertEqual(report["input_line"], task.inputs["input_line"])
        self.assertTrue(set(ENTRY_FIELDS).issubset(report["fields"]))
        for name in ("entry_id", "repo_url", "report_id", "origin", "verify"):
            with self.subTest(field=name):
                self.assertEqual(report["fields"][name]["status"], "correct")
        for item in evidence:
            self.assertEqual(item["report_id"], candidate["report_id"])
            self.assertEqual(item["entry_id"], candidate["entry_id"])

        referenced = {
            evidence_id
            for field in report["fields"].values()
            for evidence_id in field.get("evidence_refs", [])
        }
        self.assertEqual(referenced, {item["evidence_id"] for item in evidence})
        self.assertEqual(report["verdict"], "uncertain")
        self.assertEqual(report["fields"]["schema"]["status"], "correct")
        self.assertEqual(
            [request.stage for request in backend.requests],
            ["plan", "semantic_judge", "reflection"],
        )

    def test_generate_defers_when_advisory_names_multiple_fix_commits(self) -> None:
        self._write_advisory((self.fix_commit, self.vulnerable_commit))
        draft, projection, _ = self._generate(_ScriptedBackend())

        self.assertIsInstance(draft, ProductionDeferredDraft)
        assert isinstance(draft, ProductionDeferredDraft)
        self.assertEqual(draft.stage, "extract_advisory")
        self.assertEqual(draft.reason_code, "ambiguous_fix_commit")
        self.assertEqual(projection.model_stages, ("plan",))

    def test_generate_defers_when_guard_exists_only_on_fixed_side(self) -> None:
        backend = _ScriptedBackend(critical_mode="guard")
        draft, projection, _ = self._generate(
            backend,
            task=self._task(critical_mode="guard"),
        )

        self.assertIsInstance(draft, ProductionDeferredDraft)
        assert isinstance(draft, ProductionDeferredDraft)
        self.assertEqual(draft.stage, "resolve_critical")
        self.assertEqual(draft.reason_code, "guard_only_exists_on_fix_side")
        self.assertEqual(projection.model_stages, ("plan",))

    def test_generate_defers_without_a_vulnerable_side_sink_candidate(self) -> None:
        self._replace_fix_with_benign_change()
        draft, projection, _ = self._generate(_ScriptedBackend())

        self.assertIsInstance(draft, ProductionDeferredDraft)
        assert isinstance(draft, ProductionDeferredDraft)
        self.assertEqual(draft.stage, "resolve_critical")
        self.assertEqual(draft.reason_code, "no_vulnerable_side_candidate")
        self.assertEqual(projection.model_stages, ("plan",))

    def test_generate_defers_when_model_selects_an_unknown_issued_id(self) -> None:
        draft, projection, _ = self._generate(
            _ScriptedBackend(unknown_candidate=True)
        )

        self.assertIsInstance(draft, ProductionDeferredDraft)
        assert isinstance(draft, ProductionDeferredDraft)
        self.assertEqual(draft.stage, "semantic_judge")
        self.assertEqual(draft.reason_code, "unknown_candidate_id")
        self.assertEqual(projection.model_stages, ("plan", "semantic_judge"))

    def test_repair_uses_only_suggested_fix_preserves_locks_and_runs_checks(self) -> None:
        task = self._task()
        generated, _, _ = self._generate(_ScriptedBackend(), task=task)
        self.assertIsInstance(generated, ProductionDraft)
        assert isinstance(generated, ProductionDraft)
        previous = _plain(generated.candidate)
        suggested = "Unsafe route evaluation enables code injection"
        plan = self._title_plan(task, previous, suggested)
        backend = _ScriptedBackend(repair_fields=("vuln_title",))
        factory = self._factory(backend)
        controller = factory.create(
            task,
            attempt=1,
            mode="repair",
            plan=plan,
            budget=Budget(Limits(max_llm_calls=4, max_tool_calls=20)),
        )

        repaired = LocalStructuredT2Producer().repair(
            task,
            previous,
            plan,
            controller.producer_context,
        )
        projection = controller.finalize()

        self.assertIsInstance(repaired, ProductionDraft)
        assert isinstance(repaired, ProductionDraft)
        candidate = _plain(repaired.candidate)
        self.assertEqual(candidate["vuln_title"], suggested)
        changed = {
            field_name
            for field_name in ENTRY_FIELDS
            if canonical_sha256(candidate[field_name])
            != canonical_sha256(previous[field_name])
        }
        self.assertEqual(changed, {"vuln_title"})
        for field_name in plan.locked_fields:
            self.assertEqual(candidate[field_name], previous[field_name])
        self.assertEqual(projection.model_stages, ("repair", "reflection"))
        self.assertTrue(
            {"read_local_advisory", "extract_advisory_fields", "validate_schema"}
            <= set(projection.tool_names)
        )

    def test_repair_defers_when_required_checks_have_no_tool_authority(self) -> None:
        task = self._task()
        generated, _, _ = self._generate(_ScriptedBackend(), task=task)
        self.assertIsInstance(generated, ProductionDraft)
        assert isinstance(generated, ProductionDraft)
        previous = _plain(generated.candidate)
        plan = self._title_plan(
            task,
            previous,
            "A checked title cannot be established",
            allow_required_tools=False,
        )
        backend = _ScriptedBackend(repair_fields=("vuln_title",))
        factory = self._factory(backend)
        controller = factory.create(
            task,
            attempt=1,
            mode="repair",
            plan=plan,
            budget=Budget(Limits(max_llm_calls=4, max_tool_calls=8)),
        )

        draft = LocalStructuredT2Producer().repair(
            task,
            previous,
            plan,
            controller.producer_context,
        )
        projection = controller.finalize()

        self.assertIsInstance(draft, ProductionDeferredDraft)
        assert isinstance(draft, ProductionDeferredDraft)
        self.assertEqual(draft.stage, "repair")
        self.assertEqual(draft.reason_code, "required_checks_unavailable")
        self.assertNotIn("read_local_advisory", projection.tool_names)
        self.assertNotIn("extract_advisory_fields", projection.tool_names)

    def test_commit_repair_defers_before_model_when_verifiers_are_unavailable(self) -> None:
        task = self._task()
        generated, _, _ = self._generate(_ScriptedBackend(), task=task)
        self.assertIsInstance(generated, ProductionDraft)
        assert isinstance(generated, ProductionDraft)
        previous = _plain(generated.candidate)
        previous_snapshot = json.dumps(previous, sort_keys=True)
        validation = ValidationReport(
            report_id=REPORT_ID,
            entry_id=ENTRY_ID,
            input_line=1,
            verdict="incorrect",
            fields={
                "commit": FieldValidation(
                    status="incorrect",
                    confidence=1.0,
                    evidence="The vulnerable revision needs deterministic proof.",
                    suggested_fix=self.fix_commit,
                )
            },
            summary="A commit repair was proposed by T1.",
        )
        plan = build_repair_plan(
            task=task,
            previous_candidate=previous,
            validation=validation,
            repair_iteration=1,
        )
        backend = _ScriptedBackend(repair_fields=("commit",))
        factory = self._factory(backend)
        controller = factory.create(
            task,
            attempt=1,
            mode="repair",
            plan=plan,
            budget=Budget(Limits(max_llm_calls=4, max_tool_calls=20)),
        )

        draft = LocalStructuredT2Producer().repair(
            task,
            previous,
            plan,
            controller.producer_context,
        )
        projection = controller.finalize()

        self.assertIsInstance(draft, ProductionDeferredDraft)
        assert isinstance(draft, ProductionDeferredDraft)
        self.assertEqual(draft.stage, "repair")
        self.assertEqual(draft.reason_code, "required_checks_unavailable")
        self.assertEqual(projection.model_stages, ())
        self.assertEqual(projection.model_calls, ())
        self.assertEqual(projection.tool_names, ())
        self.assertEqual(json.dumps(previous, sort_keys=True), previous_snapshot)
        self.assertNotIn("repair", [request.stage for request in backend.requests])

    def test_orchestrator_binds_repair_defer_topology_not_the_producer(self) -> None:
        task = self._task()
        suggested = "A more specific title supplied by T1"
        report = ValidationReport(
            report_id=REPORT_ID,
            entry_id=ENTRY_ID,
            input_line=1,
            verdict="incorrect",
            fields={
                "vuln_title": FieldValidation(
                    status="incorrect",
                    confidence=1.0,
                    evidence="Title requires a bounded repair.",
                    suggested_fix=suggested,
                )
            },
            summary="Repair the title once.",
        )
        backend = _ScriptedBackend(repair_action="defer")
        factory = self._factory(backend)
        validator_factory = _OneReportValidatorFactory(report)
        orchestrator = ClosedLoopOrchestrator(
            LocalStructuredT2Producer(),
            validator_factory,
            factory,
            limits=Limits(max_llm_calls=8, max_tool_calls=80),
        )

        outcome = orchestrator.run(task)

        self.assertEqual(outcome.status, "manual_review")
        self.assertEqual(outcome.state.stop_reason, STOP_PRODUCER_DEFERRED)
        self.assertEqual(validator_factory.calls, 1)
        self.assertEqual(len(outcome.production_outcomes), 1)
        self.assertEqual(len(outcome.repair_plans), 1)
        deferred = outcome.deferred_outcome
        self.assertIsNotNone(deferred)
        assert deferred is not None
        parent = outcome.production_outcomes[0]
        plan = outcome.repair_plans[0]
        self.assertEqual(deferred.attempt, 1)
        self.assertEqual(deferred.mode, "repair")
        self.assertEqual(
            deferred.parent_candidate_sha256,
            canonical_sha256(parent.candidate),
        )
        self.assertEqual(deferred.repair_plan_sha256, canonical_sha256(plan))
        for record in (*deferred.tool_calls, *deferred.model_calls):
            self.assertEqual(record.attempt, 1)
            self.assertEqual(record.policy_scope, "t2.repair-1")


if __name__ == "__main__":
    unittest.main()
