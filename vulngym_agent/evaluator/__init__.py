"""Trusted evaluator and isolated-worker boundaries for stage E.

Exports are loaded lazily so ``python -m vulngym_agent.evaluator.<entry>`` does
not import the selected entry module while Python is still initialising its
parent package.  In particular, the OCI worker treats any stderr output as a
failed execution, including the ``runpy`` warning caused by such a preload.
"""

from importlib import import_module


_EXPORTS = {
    "DEFAULT_D2_WORKER_BUDGET_LIMITS": ".worker",
    "DEFAULT_D3_WORKER_BUDGET_LIMITS": ".worker",
    "CompletedWorkerExecutionV1": ".worker_completion",
    "BATCH_ATTEMPT_REPORT_KIND": ".batch_runner",
    "BATCH_REPLAY_CONFIG_CONTRACT_VERSION": ".batch_configs",
    "BATCH_REPLAY_CONFIG_MANIFEST_KIND": ".batch_configs",
    "BatchRunnerError": ".batch_runner",
    "BatchReplayConfigError": ".batch_configs",
    "BatchReplayConfigManifestV1": ".batch_configs",
    "DISCOVERY_BATCH_EXECUTION_PLAN_KIND": ".contracts",
    "DISCOVERY_BATCH_EXECUTION_RECEIPT_KIND": ".contracts",
    "DISCOVERY_TASK_EXECUTION_PLAN_KIND": ".contracts",
    "DISCOVERY_TASK_EXECUTION_RECEIPT_KIND": ".contracts",
    "DiscoveryBatchExecutionPlanV1": ".contracts",
    "DiscoveryBatchExecutionReceiptV1": ".contracts",
    "DiscoveryBatchAttemptReportV1": ".batch_runner",
    "DiscoveryExecutionSession": ".supervisor",
    "DiscoveryTaskExecutionPlanV1": ".contracts",
    "DiscoveryTaskExecutionReceiptV1": ".contracts",
    "DockerServerIdentityV1": ".runtime_evidence",
    "EVALUATOR_CONTRACT_VERSION": ".contracts",
    "E4_BATCH_RUNNER_VERSION": ".batch_runner",
    "E4_BATCH_SUCCESS_RECEIPT_KIND": ".e4_receipt",
    "E4_PUBLICATION_READER_VERSION": ".publication_reader",
    "E4_RUNTIME_REVERIFY_POLICY": ".e4_receipt",
    "E4_SCHEDULER_VERSION": ".e4_receipt",
    "E4_SUCCESS_RECEIPT_FILENAME": ".e4_receipt",
    "E4_TASK_SUCCESS_CLOSURE_KIND": ".e4_receipt",
    "E4BatchSuccessReceiptV1": ".e4_receipt",
    "E4PublicationReaderError": ".publication_reader",
    "E4ReceiptError": ".e4_receipt",
    "E4TaskSuccessClosureV1": ".e4_receipt",
    "EVALUATOR_SUPERVISOR_VERSION": ".supervisor",
    "EXECUTION_POLICY_BINDING_KIND": ".contracts",
    "EvaluatorContractError": ".contracts",
    "EvaluatorSupervisorError": ".supervisor",
    "FailedDiscoveryExecutionClosureV1": ".supervisor",
    "ExecutionPolicyBindingV1": ".contracts",
    "ISOLATED_WORKER_ERROR_TAXONOMY_VERSION": ".worker",
    "ISOLATED_WORKER_VERSION": ".worker",
    "IsolatedWorkerError": ".worker",
    "PendingTaskExecutionV1": ".supervisor",
    "PostVerifiedDiscoveryExecutionV1": ".supervisor",
    "RuntimeEvidenceError": ".runtime_evidence",
    "RuntimeEvidenceV1": ".runtime_evidence",
    "RuntimeIsolationV1": ".runtime_evidence",
    "RuntimeResourceLimitsV1": ".runtime_evidence",
    "SNAPSHOT_BATCH_BINDING_KIND": ".contracts",
    "SnapshotBatchBindingV1": ".contracts",
    "TASK_ATTEMPT_OUTCOME_KIND": ".batch_runner",
    "TaskAttemptOutcomeV1": ".batch_runner",
    "TaskReplayConfigBindingV1": ".batch_configs",
    "WorkerTaskLaunchV1": ".supervisor",
    "WorkerCompletionError": ".worker_completion",
    "accept_discovery_worker_output_v1": ".supervisor",
    "budget_limits_sha256_v1": ".supervisor",
    "close_failed_discovery_execution_v1": ".supervisor",
    "execute_discovery_worker_v1": ".worker",
    "load_batch_replay_configs_v1": ".batch_configs",
    "postverify_discovery_execution_v1": ".supervisor",
    "prepare_discovery_execution_plan_v1": ".supervisor",
    "read_committed_e4_discovery_execution_v1": ".publication_reader",
    "run_prepared_discovery_batch_v1": ".batch_runner",
    "publish_postverified_discovery_execution_v1": ".supervisor",
    "snapshot_policy_sha256_v1": ".contracts",
    "tree_limits_sha256_v1": ".supervisor",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> object:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
