"""T2 production composition with a caller-configured structured model backend.

Unlike ``closed_loop_cli``, this entry point does not accept answer fixtures.
The backend factory is trusted operator configuration, never report content.
Importing a factory executes local Python code; the operator must audit that
adapter and authorize its model service separately. This module neither loads
credentials nor starts a service, and importing it performs no model calls.

The output is the existing evidence-bound batch format. ``entries.jsonl``
contains only T1-finalized entries, not every complete T2 candidate. Complete
manual-review candidates and their actual T1 reports remain in batch artifacts.
``--results-dir`` also writes operator-facing T2 candidates, T1 reports and
deferrals directly, without requiring a separate projection command. A successful batch
exit is not a semantic-accuracy certificate or proof of a real-model run.
"""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Sequence
import importlib
from pathlib import Path
import re
import sys
from typing import Any

from vulngym_agent.agents.model_runtime import (
    ModelRequest,
    ReplayStructuredModelBackend,
    StructuredModelBackend,
)
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.closed_loop_cli import (
    EXIT_FATAL,
    EXIT_INCOMPLETE,
    HARD_MAX_INPUT_LINE_BYTES,
    HARD_MAX_RECORDS,
    HARD_MAX_TASK_BYTES,
    ClosedLoopBatchError,
    ExactReplayBackend,
    TaskInputLimitExceeded,
    _LocalTaskExecution,
    _add_batch_arguments,
    _configured_directory,
    _fatal_summary,
    _positive_bounded,
    _print_summary,
    _run_artifact_cli_batch,
    iter_task_jsonl,
    load_trusted_repo_map,
)
from vulngym_agent.orchestrator import ClosedLoopOutcome, Limits, RunTask
from vulngym_agent.t2_user_results import T2UserResults


_FACTORY_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r":[A-Za-z_][A-Za-z0-9_]*\Z"
)


def _validate_backend(backend: Any) -> StructuredModelBackend:
    if (isinstance(backend, type) or not isinstance(backend, StructuredModelBackend)
            or not callable(backend.invoke)):
        raise ValueError("factory must return a StructuredModelBackend instance")
    if isinstance(backend, (ExactReplayBackend, ReplayStructuredModelBackend)):
        raise ValueError("answer fixtures belong to the exact-replay entry point")
    # Validate bounded public identifiers before they reach a CLI summary. This
    # constructs an envelope only: it never invokes or warms up the backend.
    ModelRequest(
        task_id="backend-configuration",
        attempt=0,
        policy_scope="generate",
        stage="plan",
        model_call_id="MODEL-configuration",
        backend_id=backend.backend_id,
        model_id=backend.model_id,
        payload={},
    )
    return backend


def load_backend_factory(specification: str) -> StructuredModelBackend:
    """Load an explicit trusted ``module:zero_argument_factory``.

    No dotted attribute traversal, file evaluation, automatic installation or
    credential discovery is performed. Adapters must implement their own
    bounded request timeout and have no hidden retries outside the run budget.
    """

    if not isinstance(specification, str) or not _FACTORY_RE.fullmatch(specification):
        raise ValueError("backend factory must be module:factory")
    module_name, factory_name = specification.split(":")
    factory = getattr(importlib.import_module(module_name), factory_name)
    if not callable(factory):
        raise ValueError("backend factory must be callable")
    return _validate_backend(factory())


class LocalProductionTaskRunner(_LocalTaskExecution):
    """Run fresh tasks against a structured backend, not an answer registry.

    Batch closure seals this runner without requiring a prerecorded call list.
    Existing per-call request hashes, budgets, schema checks and T1 decisions
    are unchanged. Known replay backend types are rejected, but the operator
    remains responsible for truthfully identifying custom adapters/test doubles.
    """

    __slots__ = ("_closed", "_identity", "_execution_counts", "_model_errors", "_progress", "_user_results")

    def __init__(self, *, backend: StructuredModelBackend, progress: bool = False,
                 user_results: T2UserResults | None = None,
                 context_followup: bool = False,
                 **configuration: Any) -> None:
        backend = _validate_backend(backend)
        if configuration.get("whole_line_entry_snippets", True) is not True:
            raise ValueError("production requires whole-line entry snippets")
        configuration["whole_line_entry_snippets"] = True
        if configuration.get("review_candidate_pool", True) is not True:
            raise ValueError("production requires the review candidate pool")
        configuration["review_candidate_pool"] = True
        super().__init__(backend=backend, **configuration)
        self._producer = LocalStructuredT2Producer(
            include_reflection_context=True, evidence_first_planning=True,
            include_semantic_context=True,
            include_reflection_defer_details=True,
            context_followup=context_followup,
        )
        self._identity = (backend.backend_id, backend.model_id)
        self._closed = False
        self._execution_counts: Counter[str] = Counter()
        self._model_errors: Counter[str] = Counter()
        self._progress = progress
        self._user_results = user_results

    def execution_summary(self) -> dict[str, Any]:
        """Count observed outcomes, independently of manual_review terminal state."""
        return {
            "execution_counts": {name: self._execution_counts[name] for name in (
                "complete_candidate_tasks", "t1_report_tasks", "deferred_tasks",
                "model_declared_defer_tasks", "model_problem_tasks", "non_success_model_calls")},
            "model_error_counts": dict(sorted(self._model_errors.items())),
            "model_call_counts_are_http_counts": False,
        }

    @property
    def backend_id(self) -> str:
        return self._identity[0]

    @property
    def model_id(self) -> str:
        return self._identity[1]

    def _check_identity(self) -> None:
        if (self._backend.backend_id, self._backend.model_id) != self._identity:
            raise ClosedLoopBatchError("configured backend identity changed")

    def run(self, task: RunTask) -> ClosedLoopOutcome:
        if self._closed:
            raise ClosedLoopBatchError("production batch is already closed")
        if self._user_results is not None:
            self._user_results.check_writable()
        self._check_identity()
        if self._progress:
            _print_summary({"event": "task_started", "task_id": task.task_id}, stream=sys.stderr)
        outcome = super().run(task)
        self._check_identity()
        if self._user_results is not None:
            self._user_results.record(outcome)
        self._execution_counts["complete_candidate_tasks"] += int(bool(outcome.production_outcomes))
        self._execution_counts["t1_report_tasks"] += int(bool(outcome.validation_outcomes))
        deferred = outcome.deferred_outcome
        self._execution_counts["deferred_tasks"] += int(deferred is not None)
        self._execution_counts["model_declared_defer_tasks"] += int(
            deferred is not None and deferred.reason_code == "model_deferred")
        sources = list(outcome.production_outcomes) + ([] if deferred is None else [deferred])
        calls = {c.model_call_id: c for source in sources for c in source.model_calls}
        problems = [c for c in calls.values() if c.status != "success"]
        self._execution_counts["model_problem_tasks"] += int(bool(problems))
        self._execution_counts["non_success_model_calls"] += len(problems)
        for call in problems:
            # Raw backend exception text is never available here. Still keep
            # arbitrary custom error identifiers out of the public CLI summary.
            code = call.error_code or "model_call_not_successful"
            public_code = code if re.fullmatch(r"deepseek_[a-z_]{1,70}|backend_error|invalid_model_output|model_budget_exceeded", code) else "other_model_error"
            self._model_errors[public_code] += 1
        if self._progress:
            _print_summary({"event": "task_finished", "task_id": task.task_id,
                "workflow_status": outcome.status, "complete_candidate": bool(outcome.production_outcomes),
                "model_problem": bool(problems)}, stream=sys.stderr)
        return outcome

    def finalize_batch(self) -> None:
        self._check_identity()
        if self._user_results is not None:
            self._user_results.check_writable()
        self._closed = True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vulngym_agent.t2_production_cli",
        description="Produce T2 candidates with a configured model and auxiliary T1 review.",
    )
    _add_batch_arguments(parser, exact_replay=False)
    parser.add_argument(
        "--backend-factory", required=True,
        help="trusted installed Python module:factory returning StructuredModelBackend",
    )
    parser.add_argument("--progress", action="store_true",
                        help="write task start/end metadata to stderr; stdout remains one JSON result")
    parser.add_argument("--results-dir", type=Path,
                        help="new separate directory for all complete T2 candidates, actual T1 reports and deferrals")
    parser.add_argument("--context-followup", action="store_true",
                        help="allow one requested source supplement and one extra semantic call, within existing budgets")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    user_results: T2UserResults | None = None
    try:
        max_input_line_bytes = _positive_bounded(
            "max_input_line_bytes", args.max_input_line_bytes, HARD_MAX_INPUT_LINE_BYTES
        )
        max_task_bytes = _positive_bounded(
            "max_task_bytes", args.max_task_bytes, HARD_MAX_TASK_BYTES
        )
        max_records = _positive_bounded("max_records", args.max_records, HARD_MAX_RECORDS)
        tasks_path = args.tasks.resolve(strict=True)
        repo_map_path = args.repo_map.resolve(strict=True)
        if not tasks_path.is_file() or not repo_map_path.is_file():
            raise ValueError("configured input files must be regular files")
        package_root = _configured_directory(args.package_root, name="package_root")
        repo_map = load_trusted_repo_map(repo_map_path)
        limits = Limits(
            max_llm_calls=args.max_llm_calls,
            max_tool_calls=args.max_tool_calls,
            max_repair_iterations=args.max_repair_iterations,
        )
        if args.results_dir is not None:
            user_results = T2UserResults(args.results_dir, protected_paths=(
                args.output_dir, tasks_path, repo_map_path, package_root, *repo_map.values()))
        backend = load_backend_factory(args.backend_factory)
        runner = LocalProductionTaskRunner(
            package_root=package_root, repo_map=repo_map, backend=backend, limits=limits,
            line_tolerance=args.line_tolerance,
            t1_max_file_bytes=args.t1_max_file_bytes,
            t1_max_package_bytes=args.t1_max_package_bytes,
            t1_max_package_files=args.t1_max_package_files,
            progress=args.progress,
            user_results=user_results,
            context_followup=args.context_followup,
        )
        summary = _run_artifact_cli_batch(
            output_dir=args.output_dir,
            protected_paths=(tasks_path, repo_map_path, package_root, *repo_map.values()),
            records=iter_task_jsonl(
                tasks_path, max_input_line_bytes=max_input_line_bytes,
                max_task_bytes=max_task_bytes,
            ),
            runner=runner, max_records=max_records,
            require_all_finalized=args.require_all_finalized,
        )
    except TaskInputLimitExceeded:
        if user_results is not None:
            user_results.abort()
        _print_summary(_fatal_summary("task_input_limit_exceeded"), stream=sys.stdout)
        return EXIT_FATAL
    except KeyboardInterrupt:
        if user_results is not None:
            user_results.abort()
        raise
    except Exception:
        if user_results is not None:
            user_results.abort()
        # Provider exceptions and import errors can contain paths, prompt text,
        # endpoint addresses or credentials. They are not public output.
        _print_summary(_fatal_summary("production_configuration_or_io_error"), stream=sys.stdout)
        return EXIT_FATAL
    result = summary.to_dict()
    result.update(
        model_mode="configured_backend", backend_id=runner.backend_id, model_id=runner.model_id,
        context_followup=args.context_followup,
    )
    result.update(runner.execution_summary())
    exit_code = summary.exit_code
    if result["execution_counts"]["model_problem_tasks"]:
        result["status"] = "incomplete"
        result["execution_status"] = "model_execution_incomplete"
        exit_code = EXIT_INCOMPLETE
    else:
        result["execution_status"] = "processed_not_quality_verified"
    # Adapter metadata is bounded and provider-specific; do not call an
    # arbitrary factory object's lookalike method or print its exception text.
    from vulngym_agent.agents.deepseek_backend import DeepSeekV4ProBackend
    if type(backend) is DeepSeekV4ProBackend:
        result["last_transport_failure"] = backend.last_transport_failure()
        completion_failure = backend.last_completion_failure()
        if completion_failure is not None:
            result["last_completion_failure"] = completion_failure
    result["exit_code"] = exit_code
    if user_results is not None:
        try:
            user_results.finish(result)
            result["user_results_written"] = True
        except OSError:
            user_results.abort()
            result.update(user_results_written=False, error_code="user_results_write_failed",
                          status="incomplete", exit_code=EXIT_FATAL)
            exit_code = EXIT_FATAL
    _print_summary(result, stream=sys.stdout)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["LocalProductionTaskRunner", "load_backend_factory", "main"]
