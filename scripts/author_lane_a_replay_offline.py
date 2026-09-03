"""Author a request-bound Lane A exact-replay file from reviewed decisions.

The decision document deliberately contains no request digest.  This tool runs
the real local T2 producer and the real deterministic T1 validator, observes
the actual :class:`ModelRequest` values, converts each reviewed stage decision
into an :class:`ExactReplayFixture`, and then performs a second pass through
the production ``ExactReplayBackend`` before publishing anything.

Decision contract (JSON, contract_version 1)::

    {
      "contract_version": 1,
      "tasks": [{
        "task_id": "VG-TEST-...",
        "plan": {"critical_mode": "sink"},
        "semantic_judge": {
          "critical_candidate_ordinal": 1,
          "entry_candidate_ordinal": 1,
          "project": "project",
          "vuln_title": "Specific vulnerability title",
          "vuln_category_l1": "Injection",
          "vuln_category_l2": "Command Injection"
        },
        "reflection": {"action": "emit"},
        "repairs": []
      }]
    }

Candidate ordinals are one-based positions in the runtime-issued candidate
arrays.  A repair decision, when needed, has ``attempt`` (1 or 2), a non-empty
``repair_fields`` array, and ``reflection: {"action": "emit"}``.  The selected
fields must be offered by the real T1 RepairPlan and must carry a T1
``suggested_fix``; this tool never supplies or changes repair values itself.

Only the exact replay configuration is written.  The returned/stdout summary
contains task IDs, statuses, verdicts, and digests, but no host path, request
payload, source snippet, or model response body.
"""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Final
import uuid


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulngym_agent.agents.model_runtime import ModelRequest
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.agents.t2_execution import LocalT2ContextFactory
from vulngym_agent.closed_loop_cli import (
    DEFAULT_MAX_INPUT_LINE_BYTES,
    DEFAULT_MAX_RECORDS,
    DEFAULT_MAX_TASK_BYTES,
    ExactReplayFixture,
    LocalClosedLoopTaskRunner,
    LocalT1ValidatorFactory,
    iter_task_jsonl,
    load_exact_replay_backend,
    load_trusted_repo_map,
)
from vulngym_agent.orchestrator import ClosedLoopOrchestrator, ClosedLoopOutcome, Limits
from vulngym_agent.orchestrator.contracts import RunTask, canonical_json, canonical_sha256


BACKEND_ID: Final[str] = "exact-replay"
MODEL_ID: Final[str] = "offline-v1"
DECISION_CONTRACT_VERSION: Final[int] = 1
SUMMARY_CONTRACT_VERSION: Final[int] = 1
MAX_DECISION_BYTES: Final[int] = 16 * 1024 * 1024
MAX_DECISION_TASKS: Final[int] = 100_000
MAX_ORDINAL: Final[int] = 100_000
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z"
)
_WINDOWS_ABSOLUTE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]"
)
_POSIX_ABSOLUTE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9.])/(?:[^/\s]+/)*[^/\s]+"
)
_UNC_ABSOLUTE_RE: Final[re.Pattern[str]] = re.compile(r"(?<![\\])\\\\[^\\\s]+\\")
_FILE_URI_RE: Final[re.Pattern[str]] = re.compile(r"\bfile:", re.IGNORECASE)
_PRIVATE_MARKERS: Final[frozenset[str]] = frozenset(
    {"private", "gold", "selection_lock", "source_map"}
)


class LaneAReplayAuthoringError(RuntimeError):
    """Stable, path-free failure raised by the offline authoring helper."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _normalized_marker_text(value: str) -> str:
    return value.casefold().replace("-", "_")


def _contains_private_marker(value: str) -> bool:
    normalized = _normalized_marker_text(value)
    return any(
        re.search(rf"(?:^|[^a-z0-9]){re.escape(marker)}(?:$|[^a-z0-9])", normalized)
        is not None
        for marker in _PRIVATE_MARKERS
    )


def _reject_sensitive_path(value: str | os.PathLike[str], *, name: str) -> None:
    path = Path(value)
    if any(_contains_private_marker(part) for part in path.parts):
        raise LaneAReplayAuthoringError(
            "sensitive_path", f"{name} contains a prohibited path component"
        )


def _reject_sensitive_free_text(value: str, *, name: str) -> None:
    lowered = value.casefold()
    absolute_path = (
        value.startswith(("/", "\\"))
        or _WINDOWS_ABSOLUTE_RE.search(value) is not None
        or _POSIX_ABSOLUTE_RE.search(value) is not None
        or _UNC_ABSOLUTE_RE.search(value) is not None
        or _FILE_URI_RE.search(lowered) is not None
    )
    if absolute_path or _contains_private_marker(value):
        raise LaneAReplayAuthoringError(
            "decision_sensitive", f"{name} contains prohibited material"
        )


def _strict_object(value: Any, keys: frozenset[str], *, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != keys:
        raise LaneAReplayAuthoringError("decision_invalid", f"{name} fields differ")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LaneAReplayAuthoringError(
                "decision_invalid", "decision JSON contains a duplicate key"
            )
        result[key] = value
    return result


def _text(value: Any, *, name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise LaneAReplayAuthoringError(
            "decision_invalid", f"{name} must be bounded canonical text"
        )
    _reject_sensitive_free_text(value, name=name)
    return value


def _ordinal(value: Any, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_ORDINAL:
        raise LaneAReplayAuthoringError(
            "decision_invalid", f"{name} must be a one-based bounded integer"
        )
    return value


@dataclass(frozen=True, slots=True)
class RepairDecision:
    attempt: int
    repair_fields: tuple[str, ...]
    reflection_action: str


@dataclass(frozen=True, slots=True)
class TaskDecision:
    task_id: str
    critical_mode: str
    critical_candidate_ordinal: int
    entry_candidate_ordinal: int
    project: str
    vuln_title: str
    vuln_category_l1: str
    vuln_category_l2: str
    reflection_action: str
    repairs: tuple[RepairDecision, ...]


def _parse_repair(value: Any) -> RepairDecision:
    item = _strict_object(
        value,
        frozenset({"attempt", "repair_fields", "reflection"}),
        name="repair decision",
    )
    attempt = item["attempt"]
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt not in {1, 2}:
        raise LaneAReplayAuthoringError(
            "decision_invalid", "repair attempt must be integer 1 or 2"
        )
    fields = item["repair_fields"]
    if (
        isinstance(fields, (str, bytes, Mapping, set, frozenset))
        or not isinstance(fields, Sequence)
        or not fields
    ):
        raise LaneAReplayAuthoringError(
            "decision_invalid", "repair_fields must be a non-empty ordered array"
        )
    checked_fields = tuple(fields)
    if (
        any(not isinstance(field, str) or not field for field in checked_fields)
        or len(checked_fields) != len(set(checked_fields))
    ):
        raise LaneAReplayAuthoringError(
            "decision_invalid", "repair_fields must contain unique strings"
        )
    reflection = _strict_object(
        item["reflection"], frozenset({"action"}), name="repair reflection"
    )
    if reflection["action"] != "emit":
        raise LaneAReplayAuthoringError(
            "decision_invalid", "a complete batch requires repair reflection emit"
        )
    return RepairDecision(attempt, checked_fields, "emit")


def _parse_task_decision(value: Any) -> TaskDecision:
    item = _strict_object(
        value,
        frozenset(
            {"task_id", "plan", "semantic_judge", "reflection", "repairs"}
        ),
        name="task decision",
    )
    task_id = item["task_id"]
    if not isinstance(task_id, str) or _TASK_ID_RE.fullmatch(task_id) is None:
        raise LaneAReplayAuthoringError(
            "decision_invalid", "task decision has an invalid task_id"
        )
    plan = _strict_object(item["plan"], frozenset({"critical_mode"}), name="plan")
    critical_mode = plan["critical_mode"]
    if critical_mode not in {"sink", "guard"}:
        raise LaneAReplayAuthoringError(
            "decision_invalid", "critical_mode must be sink or guard"
        )
    semantic = _strict_object(
        item["semantic_judge"],
        frozenset(
            {
                "critical_candidate_ordinal",
                "entry_candidate_ordinal",
                "project",
                "vuln_title",
                "vuln_category_l1",
                "vuln_category_l2",
            }
        ),
        name="semantic_judge",
    )
    reflection = _strict_object(
        item["reflection"], frozenset({"action"}), name="reflection"
    )
    if reflection["action"] != "emit":
        raise LaneAReplayAuthoringError(
            "decision_invalid", "a complete batch requires reflection emit"
        )
    repairs_value = item["repairs"]
    if (
        isinstance(repairs_value, (str, bytes, Mapping, set, frozenset))
        or not isinstance(repairs_value, Sequence)
    ):
        raise LaneAReplayAuthoringError(
            "decision_invalid", "repairs must be an ordered array"
        )
    repairs = tuple(_parse_repair(repair) for repair in repairs_value)
    attempts = tuple(repair.attempt for repair in repairs)
    if attempts != tuple(sorted(attempts)) or len(attempts) != len(set(attempts)):
        raise LaneAReplayAuthoringError(
            "decision_invalid", "repair attempts must be unique and ordered"
        )
    return TaskDecision(
        task_id=task_id,
        critical_mode=critical_mode,
        critical_candidate_ordinal=_ordinal(
            semantic["critical_candidate_ordinal"],
            name="critical_candidate_ordinal",
        ),
        entry_candidate_ordinal=_ordinal(
            semantic["entry_candidate_ordinal"], name="entry_candidate_ordinal"
        ),
        project=_text(semantic["project"], name="project", maximum=256),
        vuln_title=_text(
            semantic["vuln_title"], name="vuln_title", maximum=512
        ),
        vuln_category_l1=_text(
            semantic["vuln_category_l1"],
            name="vuln_category_l1",
            maximum=128,
        ),
        vuln_category_l2=_text(
            semantic["vuln_category_l2"],
            name="vuln_category_l2",
            maximum=128,
        ),
        reflection_action="emit",
        repairs=repairs,
    )


def load_decisions(path: str | os.PathLike[str]) -> tuple[dict[str, TaskDecision], str, str]:
    decision_path = Path(path)
    try:
        with decision_path.open("rb") as stream:
            payload = stream.read(MAX_DECISION_BYTES + 1)
    except OSError as error:
        raise LaneAReplayAuthoringError(
            "decision_unavailable", "decision input is unavailable"
        ) from error
    if not payload or len(payload) > MAX_DECISION_BYTES:
        raise LaneAReplayAuthoringError(
            "decision_invalid", "decision input is empty or exceeds its byte limit"
        )
    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except LaneAReplayAuthoringError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LaneAReplayAuthoringError(
            "decision_invalid", "decision input is not strict UTF-8 JSON"
        ) from error
    root = _strict_object(
        value, frozenset({"contract_version", "tasks"}), name="decision root"
    )
    if (
        type(root["contract_version"]) is not int
        or root["contract_version"] != DECISION_CONTRACT_VERSION
    ):
        raise LaneAReplayAuthoringError(
            "decision_invalid", "decision contract_version must be integer 1"
        )
    tasks = root["tasks"]
    if (
        isinstance(tasks, (str, bytes, Mapping, set, frozenset))
        or not isinstance(tasks, Sequence)
        or not tasks
        or len(tasks) > MAX_DECISION_TASKS
    ):
        raise LaneAReplayAuthoringError(
            "decision_invalid", "decision tasks must be a non-empty bounded array"
        )
    decisions: dict[str, TaskDecision] = {}
    for raw in tasks:
        decision = _parse_task_decision(raw)
        if decision.task_id in decisions:
            raise LaneAReplayAuthoringError(
                "decision_invalid", "decision task_id values must be unique"
            )
        decisions[decision.task_id] = decision
    return decisions, canonical_sha256(value), sha256(payload).hexdigest()


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_plain(child) for child in value]
    return value


def _candidate_id(payload: Mapping[str, Any], name: str, ordinal: int) -> str:
    values = payload.get(name)
    if (
        isinstance(values, (str, bytes, Mapping, set, frozenset))
        or not isinstance(values, Sequence)
        or ordinal > len(values)
    ):
        raise LaneAReplayAuthoringError(
            "candidate_ordinal_invalid", "candidate ordinal is outside the issued set"
        )
    selected = values[ordinal - 1]
    candidate_id = selected.get("candidate_id") if isinstance(selected, Mapping) else None
    if not isinstance(candidate_id, str) or not candidate_id:
        raise LaneAReplayAuthoringError(
            "candidate_set_invalid", "runtime issued an invalid candidate set"
        )
    return candidate_id


class DecisionAuthoringBackend:
    """Translate reviewed ordinal decisions into actual request-bound fixtures."""

    __slots__ = ("_consumed", "_decisions", "_failure", "_fixtures", "_task_counts")

    @property
    def backend_id(self) -> str:
        return BACKEND_ID

    @property
    def model_id(self) -> str:
        return MODEL_ID

    def __init__(self, decisions: Mapping[str, TaskDecision]) -> None:
        self._decisions = dict(decisions)
        self._fixtures: list[ExactReplayFixture] = []
        self._consumed: set[tuple[str, int, str]] = set()
        self._task_counts: Counter[str] = Counter()
        self._failure: LaneAReplayAuthoringError | None = None

    @property
    def fixtures(self) -> tuple[ExactReplayFixture, ...]:
        return tuple(self._fixtures)

    def response_count(self, task_id: str) -> int:
        return self._task_counts[task_id]

    def raise_if_failed(self) -> None:
        if self._failure is not None:
            raise self._failure

    def _repair(self, decision: TaskDecision, request: ModelRequest) -> Mapping[str, Any]:
        configured = {item.attempt: item for item in decision.repairs}.get(request.attempt)
        if configured is None:
            raise LaneAReplayAuthoringError(
                "repair_decision_missing", "T1 requested an unreviewed repair attempt"
            )
        offered = request.payload.get("repair_fields")
        if (
            isinstance(offered, (str, bytes, Mapping, set, frozenset))
            or not isinstance(offered, Sequence)
        ):
            raise LaneAReplayAuthoringError(
                "repair_request_invalid", "repair request field authority is invalid"
            )
        allowed: dict[str, bool] = {}
        for item in offered:
            if not isinstance(item, Mapping) or not isinstance(item.get("field"), str):
                raise LaneAReplayAuthoringError(
                    "repair_request_invalid", "repair request field authority is invalid"
                )
            allowed[item["field"]] = (
                item.get("has_suggested_fix") is True
                and item.get("suggested_fix") is not None
            )
        if any(not allowed.get(field, False) for field in configured.repair_fields):
            raise LaneAReplayAuthoringError(
                "repair_not_authorized",
                "repair decision selected a field without a T1 suggested fix",
            )
        return {"action": "apply", "repair_fields": list(configured.repair_fields)}

    def _response(self, request: ModelRequest) -> Mapping[str, Any]:
        decision = self._decisions.get(request.task_id)
        if decision is None:
            raise LaneAReplayAuthoringError(
                "decision_missing", "model request has no task decision"
            )
        slot = (request.task_id, request.attempt, request.stage)
        if slot in self._consumed:
            raise LaneAReplayAuthoringError(
                "decision_reused", "a task/stage decision was requested more than once"
            )
        if request.stage == "plan" and request.attempt == 0:
            allowed = request.payload.get("allowed_critical_modes")
            if (
                isinstance(allowed, (str, bytes, Mapping, set, frozenset))
                or not isinstance(allowed, Sequence)
                or decision.critical_mode not in allowed
            ):
                raise LaneAReplayAuthoringError(
                    "critical_mode_not_allowed",
                    "plan selected a critical mode outside runtime authority",
                )
            response: Mapping[str, Any] = {
                "action": "analyze",
                "critical_mode": decision.critical_mode,
            }
        elif request.stage == "semantic_judge" and request.attempt == 0:
            response = {
                "action": "select",
                "critical_candidate_id": _candidate_id(
                    request.payload,
                    "critical_candidates",
                    decision.critical_candidate_ordinal,
                ),
                "entry_candidate_id": _candidate_id(
                    request.payload,
                    "entry_candidates",
                    decision.entry_candidate_ordinal,
                ),
                "project": decision.project,
                "vuln_title": decision.vuln_title,
                "vuln_category_l1": decision.vuln_category_l1,
                "vuln_category_l2": decision.vuln_category_l2,
            }
        elif request.stage == "repair" and request.attempt in {1, 2}:
            response = self._repair(decision, request)
        elif request.stage == "reflection":
            if request.attempt == 0:
                action = decision.reflection_action
            else:
                configured = {item.attempt: item for item in decision.repairs}.get(
                    request.attempt
                )
                if configured is None:
                    raise LaneAReplayAuthoringError(
                        "repair_decision_missing",
                        "repair reflection has no reviewed decision",
                    )
                action = configured.reflection_action
            response = {"action": action}
        else:
            raise LaneAReplayAuthoringError(
                "stage_not_supported", "model requested an unsupported decision stage"
            )
        self._consumed.add(slot)
        return response

    def invoke(self, request: ModelRequest) -> Mapping[str, Any]:
        if self._failure is not None:
            raise self._failure
        try:
            response = self._response(request)
            fixture = ExactReplayFixture.from_request(
                request,
                status="success",
                response=response,
                error_code=None,
            )
        except LaneAReplayAuthoringError as error:
            self._failure = error
            raise
        self._fixtures.append(fixture)
        self._task_counts[request.task_id] += 1
        return _plain(response)

    def assert_healthy_and_complete(
        self, *, producer_deferred_task_ids: Sequence[str] = ()
    ) -> None:
        self.raise_if_failed()
        producer_deferred = set(producer_deferred_task_ids)
        expected: set[tuple[str, int, str]] = set()
        for decision in self._decisions.values():
            expected.add((decision.task_id, 0, "plan"))
            if decision.task_id in producer_deferred:
                continue
            expected.add((decision.task_id, 0, "semantic_judge"))
            expected.add((decision.task_id, 0, "reflection"))
            for repair in decision.repairs:
                expected.add((decision.task_id, repair.attempt, "repair"))
                expected.add((decision.task_id, repair.attempt, "reflection"))
        if self._consumed != expected:
            raise LaneAReplayAuthoringError(
                "decision_not_closed", "reviewed task/stage decisions were not consumed exactly"
            )


def _fixture_record(fixture: ExactReplayFixture) -> dict[str, Any]:
    return {
        "attempt": fixture.attempt,
        "backend_id": fixture.backend_id,
        "error_code": fixture.error_code,
        "model_call_id": fixture.model_call_id,
        "model_id": fixture.model_id,
        "policy_scope": fixture.policy_scope,
        "request_sha256": fixture.request_sha256,
        "response": None if fixture.response is None else _plain(fixture.response),
        "stage": fixture.stage,
        "status": fixture.status,
        "task_id": fixture.task_id,
    }


def _replay_document(fixtures: Sequence[ExactReplayFixture]) -> dict[str, Any]:
    return {
        "backend_id": BACKEND_ID,
        "contract_version": 2,
        "model_id": MODEL_ID,
        "responses": [_fixture_record(fixture) for fixture in fixtures],
    }


def _load_tasks(
    path: Path,
    *,
    max_input_line_bytes: int,
    max_task_bytes: int,
    max_records: int,
) -> tuple[RunTask, ...]:
    tasks: list[RunTask] = []
    seen_task_ids: set[str] = set()
    seen_entry_ids: set[str] = set()
    for record in iter_task_jsonl(
        path,
        max_input_line_bytes=max_input_line_bytes,
        max_task_bytes=max_task_bytes,
    ):
        if len(tasks) >= max_records:
            raise LaneAReplayAuthoringError(
                "task_limit", "task input exceeds the configured record limit"
            )
        if record.error_code is not None or record.task is None:
            raise LaneAReplayAuthoringError(
                "task_invalid", "task input contains an invalid physical record"
            )
        task = record.task
        if task.task_id in seen_task_ids or task.entry_id in seen_entry_ids:
            raise LaneAReplayAuthoringError(
                "task_invalid", "task or entry identities are duplicated"
            )
        seen_task_ids.add(task.task_id)
        assert task.entry_id is not None
        seen_entry_ids.add(task.entry_id)
        tasks.append(task)
    if not tasks:
        raise LaneAReplayAuthoringError("task_invalid", "task input is empty")
    return tuple(tasks)


def _run_authoring_pass(
    tasks: Sequence[RunTask],
    *,
    package_root: Path,
    repo_map: Mapping[str, Path],
    backend: DecisionAuthoringBackend,
    limits: Limits,
    line_tolerance: int,
    allow_producer_deferred: bool,
) -> tuple[ClosedLoopOutcome, ...]:
    producer = LocalStructuredT2Producer()
    t2_factory = LocalT2ContextFactory(package_root, repo_map, backend)
    t1_factory = LocalT1ValidatorFactory(
        package_root, repo_map, line_tolerance=line_tolerance
    )
    outcomes: list[ClosedLoopOutcome] = []
    producer_deferred_task_ids: list[str] = []
    for task in tasks:
        outcome = ClosedLoopOrchestrator(
            producer, t1_factory, t2_factory, limits=limits
        ).run(task)
        if (
            allow_producer_deferred
            and outcome.status == "manual_review"
            and outcome.deferred_outcome is not None
            and outcome.entry is None
            and outcome.report is None
        ):
            outcomes.append(outcome)
            producer_deferred_task_ids.append(task.task_id)
            continue
        if (
            outcome.status not in {"finalized", "manual_review"}
            or outcome.entry is None
            or outcome.report is None
        ):
            backend.raise_if_failed()
            raise LaneAReplayAuthoringError(
                "terminal_prediction_missing",
                "a task did not produce a terminal candidate and T1 report",
            )
        outcomes.append(outcome)
    backend.assert_healthy_and_complete(
        producer_deferred_task_ids=producer_deferred_task_ids
    )
    return tuple(outcomes)


def _run_exact_pass(
    tasks: Sequence[RunTask],
    expected: Sequence[ClosedLoopOutcome],
    *,
    package_root: Path,
    repo_map: Mapping[str, Path],
    replay_path: Path,
    limits: Limits,
    line_tolerance: int,
) -> tuple[ClosedLoopOutcome, ...]:
    backend = load_exact_replay_backend(replay_path)
    runner = LocalClosedLoopTaskRunner(
        package_root=package_root,
        repo_map=repo_map,
        backend=backend,
        limits=limits,
        line_tolerance=line_tolerance,
    )
    observed = tuple(runner.run(task) for task in tasks)
    runner.finalize_batch()
    if observed != tuple(expected):
        raise LaneAReplayAuthoringError(
            "exact_replay_diverged", "formal exact replay changed a terminal outcome"
        )
    return observed


def _publish_verified_replay(
    output_path: Path,
    payload: bytes,
    verify: Any,
) -> str:
    parent = output_path.parent.resolve(strict=True)
    target = parent / output_path.name

    def recover_existing() -> str:
        if target.is_symlink() or not target.is_file():
            raise LaneAReplayAuthoringError(
                "output_exists", "output replay path already exists"
            )
        try:
            existing = target.read_bytes()
        except OSError as error:
            raise LaneAReplayAuthoringError(
                "output_exists", "output replay path already exists"
            ) from error
        if existing != payload:
            raise LaneAReplayAuthoringError(
                "output_exists", "output replay path already exists"
            )
        try:
            verify(target)
        except BaseException as error:
            raise LaneAReplayAuthoringError(
                "publication_uncertain",
                "committed replay could not be independently verified",
            ) from error
        return "recovered"

    if os.path.lexists(target):
        return recover_existing()
    temporary = parent / f".{target.name}.authoring-{uuid.uuid4().hex}.tmp"
    committed = False
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, target)
            committed = True
        except FileExistsError:
            return recover_existing()
        except BaseException as error:
            if os.path.lexists(target):
                committed = True
                raise LaneAReplayAuthoringError(
                    "publication_uncertain",
                    "replay publication was interrupted after target creation",
                ) from error
            if isinstance(error, OSError):
                raise LaneAReplayAuthoringError(
                    "publication_failed", "verified replay could not be published"
                ) from error
            raise
        try:
            target_payload = target.read_bytes()
            temporary_payload = temporary.read_bytes()
            if target_payload != temporary_payload or target_payload != payload:
                raise LaneAReplayAuthoringError(
                    "publication_readback_mismatch",
                    "committed replay differs from its canonical payload",
                )
            verify(target)
        except BaseException as error:
            raise LaneAReplayAuthoringError(
                "publication_uncertain",
                "committed replay could not be independently verified",
            ) from error
        return "published"
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def author_lane_a_replay(
    *,
    tasks_path: str | os.PathLike[str],
    decisions_path: str | os.PathLike[str],
    repo_map_path: str | os.PathLike[str],
    package_root: str | os.PathLike[str],
    output_replay: str | os.PathLike[str],
    max_input_line_bytes: int = DEFAULT_MAX_INPUT_LINE_BYTES,
    max_task_bytes: int = DEFAULT_MAX_TASK_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_llm_calls: int = Limits().max_llm_calls,
    max_tool_calls: int = Limits().max_tool_calls,
    max_repair_iterations: int = Limits().max_repair_iterations,
    line_tolerance: int = 5,
    allow_producer_deferred: bool = False,
) -> dict[str, Any]:
    """Create and internally exact-replay one complete Lane A batch."""

    raw_paths = {
        "tasks": Path(tasks_path),
        "decisions": Path(decisions_path),
        "repo_map": Path(repo_map_path),
        "package_root": Path(package_root),
        "output_replay": Path(output_replay),
    }
    for name, path in raw_paths.items():
        _reject_sensitive_path(path, name=name)
    tasks_file = raw_paths["tasks"].resolve(strict=True)
    decisions_file = raw_paths["decisions"].resolve(strict=True)
    repo_file = raw_paths["repo_map"].resolve(strict=True)
    package = raw_paths["package_root"].resolve(strict=True)
    output = raw_paths["output_replay"]
    for name, path in {
        "tasks": tasks_file,
        "decisions": decisions_file,
        "repo_map": repo_file,
        "package_root": package,
        "output_replay_parent": output.parent.resolve(strict=True),
    }.items():
        _reject_sensitive_path(path, name=name)
    if not tasks_file.is_file() or not decisions_file.is_file() or not repo_file.is_file():
        raise LaneAReplayAuthoringError(
            "input_unavailable", "configured inputs must be regular files"
        )
    if not package.is_dir():
        raise LaneAReplayAuthoringError(
            "input_unavailable", "package_root must be a directory"
        )
    tasks = _load_tasks(
        tasks_file,
        max_input_line_bytes=max_input_line_bytes,
        max_task_bytes=max_task_bytes,
        max_records=max_records,
    )
    decisions, decisions_sha256, decisions_wire_sha256 = load_decisions(decisions_file)
    task_ids = tuple(task.task_id for task in tasks)
    if set(task_ids) != set(decisions) or len(task_ids) != len(decisions):
        raise LaneAReplayAuthoringError(
            "decision_task_mismatch", "decisions do not exactly cover task IDs"
        )
    repo_map = load_trusted_repo_map(repo_file)
    limits = Limits(
        max_llm_calls=max_llm_calls,
        max_tool_calls=max_tool_calls,
        max_repair_iterations=max_repair_iterations,
    )
    author_backend = DecisionAuthoringBackend(decisions)
    authored = _run_authoring_pass(
        tasks,
        package_root=package,
        repo_map=repo_map,
        backend=author_backend,
        limits=limits,
        line_tolerance=line_tolerance,
        allow_producer_deferred=allow_producer_deferred,
    )
    document = _replay_document(author_backend.fixtures)
    replay_payload = canonical_json(document).encode("utf-8") + b"\n"
    exact_outcomes: tuple[ClosedLoopOutcome, ...] = ()

    def verify(temporary: Path) -> None:
        nonlocal exact_outcomes
        exact_outcomes = _run_exact_pass(
            tasks,
            authored,
            package_root=package,
            repo_map=repo_map,
            replay_path=temporary,
            limits=limits,
            line_tolerance=line_tolerance,
        )

    publication_status = _publish_verified_replay(output, replay_payload, verify)
    statuses = Counter(outcome.status for outcome in exact_outcomes)
    verdicts = Counter(
        outcome.report.verdict
        for outcome in exact_outcomes
        if outcome.report is not None
    )
    task_summaries = []
    for ordinal, (task, outcome) in enumerate(zip(tasks, exact_outcomes), 1):
        entry_sha256 = (
            None if outcome.entry is None else canonical_sha256(outcome.entry)
        )
        validation_sha256 = (
            None if outcome.report is None else canonical_sha256(outcome.report)
        )
        verdict = None if outcome.report is None else outcome.report.verdict
        deferred_reason = (
            None
            if outcome.deferred_outcome is None
            else outcome.deferred_outcome.reason_code
        )
        task_summaries.append(
            {
                "deferred_reason": deferred_reason,
                "entry_sha256": entry_sha256,
                "model_response_count": author_backend.response_count(task.task_id),
                "ordinal": ordinal,
                "state_sha256": canonical_sha256(outcome.state.to_dict()),
                "status": outcome.status,
                "task_id": task.task_id,
                "validation_sha256": validation_sha256,
                "verdict": verdict,
            }
        )
    return {
        "backend_id": BACKEND_ID,
        "contract_version": SUMMARY_CONTRACT_VERSION,
        "decisions_sha256": decisions_sha256,
        "decisions_wire_sha256": decisions_wire_sha256,
        "exact_replay_verified": True,
        "model_id": MODEL_ID,
        "replay_sha256": canonical_sha256(document),
        "replay_wire_sha256": sha256(replay_payload).hexdigest(),
        "response_count": len(author_backend.fixtures),
        "status": publication_status,
        "status_counts": dict(sorted(statuses.items())),
        "task_count": len(tasks),
        "tasks": task_summaries,
        "verdict_counts": dict(sorted(verdicts.items())),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Author and verify an offline Lane A exact-replay configuration."
    )
    parser.add_argument("--tasks", required=True, type=Path)
    parser.add_argument("--decisions", required=True, type=Path)
    parser.add_argument("--repo-map", required=True, type=Path)
    parser.add_argument("--package-root", required=True, type=Path)
    parser.add_argument("--output-replay", required=True, type=Path)
    parser.add_argument(
        "--max-input-line-bytes", type=int, default=DEFAULT_MAX_INPUT_LINE_BYTES
    )
    parser.add_argument("--max-task-bytes", type=int, default=DEFAULT_MAX_TASK_BYTES)
    parser.add_argument("--max-records", type=int, default=DEFAULT_MAX_RECORDS)
    parser.add_argument("--max-llm-calls", type=int, default=Limits().max_llm_calls)
    parser.add_argument("--max-tool-calls", type=int, default=Limits().max_tool_calls)
    parser.add_argument(
        "--max-repair-iterations",
        type=int,
        default=Limits().max_repair_iterations,
    )
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--allow-producer-deferred", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        summary = author_lane_a_replay(
            tasks_path=args.tasks,
            decisions_path=args.decisions,
            repo_map_path=args.repo_map,
            package_root=args.package_root,
            output_replay=args.output_replay,
            max_input_line_bytes=args.max_input_line_bytes,
            max_task_bytes=args.max_task_bytes,
            max_records=args.max_records,
            max_llm_calls=args.max_llm_calls,
            max_tool_calls=args.max_tool_calls,
            max_repair_iterations=args.max_repair_iterations,
            line_tolerance=args.line_tolerance,
            allow_producer_deferred=args.allow_producer_deferred,
        )
    except LaneAReplayAuthoringError as error:
        sys.stderr.write(
            canonical_json(
                {
                    "contract_version": SUMMARY_CONTRACT_VERSION,
                    "error_code": error.code,
                    "status": "rejected",
                }
            )
            + "\n"
        )
        return 11 if error.code == "publication_uncertain" else 2
    except (OSError, RuntimeError, TypeError, ValueError):
        sys.stderr.write(
            canonical_json(
                {
                    "contract_version": SUMMARY_CONTRACT_VERSION,
                    "error_code": "authoring_failed",
                    "status": "rejected",
                }
            )
            + "\n"
        )
        return 2
    sys.stdout.write(canonical_json(summary) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DecisionAuthoringBackend",
    "LaneAReplayAuthoringError",
    "RepairDecision",
    "TaskDecision",
    "author_lane_a_replay",
    "load_decisions",
    "main",
]
