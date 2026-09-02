"""Independent closure receipts and the external replay authoring index.

This module is a control-plane bridge between a published single-task D2/D3
authoring pair and :mod:`vulngym_agent.replay_batch_plan_cli`.  It never
accepts or uses an answer key and never derives approval from a replay
directory alone:

* a closure observation is produced by replaying the published pair through
  the existing production offline reader;
* author, critic, and reviewer approvals bind that exact observation;
* sealing reruns the observation and requires three distinct actor identities;
* the 70-task index is derived only from approved receipts and the verified
  public task order.

Actor IDs are provenance claims, not cryptographic signatures.  The operator
must distribute the three approval steps across independently controlled
actors and retain their semantic and wire pins outside the replay directory.
All serialized values are canonical, single-line, path-free JSON.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Final, Literal

from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.harness import (
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
    load_answer_free_tasks,
)
from vulngym_agent.evaluator.oci_worker_entry import MAX_REPLAY_RESPONSES
from vulngym_agent.evaluator.replay_authoring import (
    ReplayAuthoringPendingRequestV1,
    ReplayAuthoringSummaryV1,
    inspect_replay_authoring_v1,
    read_pinned_authoring_task_v1,
)
REPLAY_CLOSURE_OBSERVATION_KIND: Final[str] = (
    "vulngym.replay-authoring-closure-observation.v1"
)
REPLAY_ACTOR_APPROVAL_KIND: Final[str] = (
    "vulngym.replay-authoring-actor-approval.v1"
)
REPLAY_CLOSURE_RECEIPT_KIND: Final[str] = (
    "vulngym.replay-authoring-closure-receipt.v1"
)
REPLAY_AUTHORING_INDEX_KIND: Final[str] = "vulngym.replay-authoring-index.v1"
REPLAY_RECEIPT_CONTRACT_VERSION: Final[int] = 1
REPLAY_RECEIPT_FILENAME_SUFFIX: Final[str] = ".receipt.json"

_OBSERVATION_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-closure-observation:v1\x00"
)
_APPROVAL_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-actor-approval:v1\x00"
)
_RECEIPT_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-closure-receipt:v1\x00"
)
_PUBLIC_TASK_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-public-task:v1\x00"
)
# This domain and the exact six-field task records are intentionally identical
# to the already deployed replay_batch_plan_cli reader contract.
_AUTHORING_INDEX_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-index:v1\x00"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_ACTOR_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z"
)
_ACTOR_ROLES: Final[tuple[str, ...]] = ("author", "critic", "reviewer")
_MAX_OBSERVATION_BYTES: Final[int] = 64 * 1024
_MAX_APPROVAL_BYTES: Final[int] = 64 * 1024
_MAX_RECEIPT_BYTES: Final[int] = 256 * 1024
_MAX_INDEX_BYTES: Final[int] = 512 * 1024


class ReplayAuthoringReceiptError(RuntimeError):
    """Stable, path-free rejection at the replay receipt boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "receipt_failed"
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    def thaw(item: object) -> object:
        if isinstance(item, Mapping):
            return {key: thaw(child) for key, child in item.items()}
        if isinstance(item, tuple):
            return [thaw(child) for child in item]
        return item

    try:
        return json.dumps(
            thaw(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise ReplayAuthoringReceiptError(
            "noncanonical_json", "receipt value is not canonical JSON"
        ) from None


def _canonical_line(value: object) -> bytes:
    return _canonical_json(value) + b"\n"


def _reject_constant(_value: str) -> None:
    raise ReplayAuthoringReceiptError(
        "noncanonical_json", "receipt JSON contains a non-finite number"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ReplayAuthoringReceiptError(
                "noncanonical_json", "receipt JSON repeats an object key"
            )
        result[key] = value
    return result


def _parse_canonical_line(payload: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > maximum_bytes
        or not payload.endswith(b"\n")
        or payload.count(b"\n") != 1
    ):
        raise ReplayAuthoringReceiptError(
            "noncanonical_json", "receipt input must be one bounded JSON line"
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ReplayAuthoringReceiptError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise ReplayAuthoringReceiptError(
            "noncanonical_json", "receipt input is not strict JSON"
        ) from None
    if type(value) is not dict or _canonical_line(value) != payload:
        raise ReplayAuthoringReceiptError(
            "noncanonical_json", "receipt input is not canonical"
        )
    return value


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ReplayAuthoringReceiptError(
            "invalid_contract", f"{name} must be lower-case SHA-256"
        )
    return value


def _require_exact_keys(
    value: object, *, keys: frozenset[str], name: str
) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        raise ReplayAuthoringReceiptError(
            "invalid_contract", f"{name} fields are invalid"
        )
    return value


def _task_split(task_id: object) -> Literal["test", "train"]:
    if type(task_id) is not str or _TASK_ID_RE.fullmatch(task_id) is None:
        raise ReplayAuthoringReceiptError(
            "invalid_contract", "task ID is invalid"
        )
    return "test" if task_id.startswith("VG-TEST-") else "train"


def public_task_sha256_v1(
    *,
    task_id: str,
    repo_url: str,
    commit: str,
    instruction_id: str,
    split: Literal["test", "train"],
) -> str:
    """Bind the public, answer-free identity shared by both task contracts."""

    if split != _task_split(task_id):
        raise ReplayAuthoringReceiptError(
            "invalid_contract", "public task split differs from its ID"
        )
    if any(type(item) is not str for item in (repo_url, commit, instruction_id)):
        raise ReplayAuthoringReceiptError(
            "invalid_contract", "public task identity is invalid"
        )
    core = {
        "commit": commit,
        "instruction_id": instruction_id,
        "repo_url": repo_url,
        "split": split,
        "task_id": task_id,
    }
    return hashlib.sha256(_PUBLIC_TASK_DOMAIN + _canonical_json(core)).hexdigest()


@dataclass(frozen=True, slots=True)
class ReplayClosureObservationV1:
    """One independently replayed, path-free observation of a D2/D3 pair."""

    task_id: str
    split: Literal["test", "train"]
    task_wire_sha256: str
    public_task_sha256: str
    d2_sha256: str
    d2_wire_sha256: str
    d3_sha256: str
    d3_wire_sha256: str
    d2_response_count: int
    d3_response_count: int
    run_sha256: str
    run_wire_sha256: str
    run_outcome: Literal["d2_deferred", "d3_deferred", "finalized"]
    candidate_count: int
    finding_count: int
    reviewer_verdict_count: int
    reviewer_accept_count: int
    reviewer_reject_count: int
    reviewer_defer_count: int
    contract_version: int = REPLAY_RECEIPT_CONTRACT_VERSION
    kind: str = REPLAY_CLOSURE_OBSERVATION_KIND
    observation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != REPLAY_RECEIPT_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_CLOSURE_OBSERVATION_KIND
            or self.split != _task_split(self.task_id)
            or type(self.run_outcome) is not str
            or self.run_outcome
            not in {"d2_deferred", "d3_deferred", "finalized"}
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure observation header is invalid"
            )
        for value, name in (
            (self.task_wire_sha256, "task_wire_sha256"),
            (self.public_task_sha256, "public_task_sha256"),
            (self.d2_sha256, "d2_sha256"),
            (self.d2_wire_sha256, "d2_wire_sha256"),
            (self.d3_sha256, "d3_sha256"),
            (self.d3_wire_sha256, "d3_wire_sha256"),
            (self.run_sha256, "run_sha256"),
            (self.run_wire_sha256, "run_wire_sha256"),
        ):
            _require_sha256(value, name=name)
        if (
            type(self.d2_response_count) is not int
            or type(self.d3_response_count) is not int
            or not 0 <= self.d2_response_count <= MAX_REPLAY_RESPONSES
            or not 0 <= self.d3_response_count <= MAX_REPLAY_RESPONSES
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "replay response counts are invalid"
            )
        counts = (
            self.candidate_count,
            self.finding_count,
            self.reviewer_verdict_count,
            self.reviewer_accept_count,
            self.reviewer_reject_count,
            self.reviewer_defer_count,
        )
        if any(type(value) is not int or not 0 <= value <= 64 for value in counts):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure outcome counts are invalid"
            )
        if (
            self.reviewer_accept_count
            + self.reviewer_reject_count
            + self.reviewer_defer_count
            != self.reviewer_verdict_count
            or self.finding_count != self.reviewer_accept_count
            or self.finding_count > self.candidate_count
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure outcome counts do not close"
            )
        if self.run_outcome == "d2_deferred" and (
            any(counts) or self.d3_response_count != 0
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "D2 deferral observation is inconsistent"
            )
        if self.run_outcome == "d3_deferred" and self.reviewer_verdict_count != 0:
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "D3 deferral exposes partial verdicts"
            )
        if self.run_outcome == "finalized" and (
            self.candidate_count != self.reviewer_verdict_count
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "finalized reviewer coverage is incomplete"
            )
        object.__setattr__(
            self,
            "observation_sha256",
            hashlib.sha256(_OBSERVATION_DOMAIN + _canonical_json(self._core_dict())).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "candidate_count": self.candidate_count,
            "contract_version": self.contract_version,
            "d2_response_count": self.d2_response_count,
            "d2_sha256": self.d2_sha256,
            "d2_wire_sha256": self.d2_wire_sha256,
            "d3_response_count": self.d3_response_count,
            "d3_sha256": self.d3_sha256,
            "d3_wire_sha256": self.d3_wire_sha256,
            "finding_count": self.finding_count,
            "kind": self.kind,
            "public_task_sha256": self.public_task_sha256,
            "reviewer_accept_count": self.reviewer_accept_count,
            "reviewer_defer_count": self.reviewer_defer_count,
            "reviewer_reject_count": self.reviewer_reject_count,
            "reviewer_verdict_count": self.reviewer_verdict_count,
            "run_outcome": self.run_outcome,
            "run_sha256": self.run_sha256,
            "run_wire_sha256": self.run_wire_sha256,
            "split": self.split,
            "task_id": self.task_id,
            "task_wire_sha256": self.task_wire_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            _OBSERVATION_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.observation_sha256 != expected:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "closure observation digest changed"
            )
        return {**self._core_dict(), "observation_sha256": self.observation_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_line(self.to_dict())

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_summary(
        cls,
        task: DiscoveryTaskInputV1,
        summary: ReplayAuthoringSummaryV1,
        *,
        task_wire_sha256: str,
    ) -> "ReplayClosureObservationV1":
        if (
            type(task) is not DiscoveryTaskInputV1
            or type(summary) is not ReplayAuthoringSummaryV1
            or summary.status != "closed"
            or summary.task_id != task.task_id
            or summary.run_sha256 is None
            or summary.run_wire_sha256 is None
            or summary.run_outcome == "not_run"
        ):
            raise ReplayAuthoringReceiptError(
                "closure_rejected", "published replay did not close"
            )
        split = _task_split(task.task_id)
        return cls(
            task_id=task.task_id,
            split=split,
            task_wire_sha256=_require_sha256(
                task_wire_sha256, name="task_wire_sha256"
            ),
            public_task_sha256=public_task_sha256_v1(
                task_id=task.task_id,
                repo_url=task.repo_url,
                commit=task.commit,
                instruction_id=task.instruction_id,
                split=split,
            ),
            d2_sha256=summary.d2_config_sha256,
            d2_wire_sha256=summary.d2_wire_sha256,
            d3_sha256=summary.d3_config_sha256,
            d3_wire_sha256=summary.d3_wire_sha256,
            d2_response_count=summary.d2_response_count,
            d3_response_count=summary.d3_response_count,
            run_sha256=summary.run_sha256,
            run_wire_sha256=summary.run_wire_sha256,
            run_outcome=summary.run_outcome,
            candidate_count=summary.candidate_count,
            finding_count=summary.finding_count,
            reviewer_verdict_count=summary.reviewer_verdict_count,
            reviewer_accept_count=summary.reviewer_accept_count,
            reviewer_reject_count=summary.reviewer_reject_count,
            reviewer_defer_count=summary.reviewer_defer_count,
        )

    @classmethod
    def from_dict(cls, value: object) -> "ReplayClosureObservationV1":
        keys = frozenset(
            {
                "candidate_count",
                "contract_version",
                "d2_response_count",
                "d2_sha256",
                "d2_wire_sha256",
                "d3_response_count",
                "d3_sha256",
                "d3_wire_sha256",
                "finding_count",
                "kind",
                "observation_sha256",
                "public_task_sha256",
                "reviewer_accept_count",
                "reviewer_defer_count",
                "reviewer_reject_count",
                "reviewer_verdict_count",
                "run_outcome",
                "run_sha256",
                "run_wire_sha256",
                "split",
                "task_id",
                "task_wire_sha256",
            }
        )
        raw = _require_exact_keys(value, keys=keys, name="closure observation")
        supplied = raw["observation_sha256"]
        result = cls(
            task_id=raw["task_id"],
            split=raw["split"],
            task_wire_sha256=raw["task_wire_sha256"],
            public_task_sha256=raw["public_task_sha256"],
            d2_sha256=raw["d2_sha256"],
            d2_wire_sha256=raw["d2_wire_sha256"],
            d3_sha256=raw["d3_sha256"],
            d3_wire_sha256=raw["d3_wire_sha256"],
            d2_response_count=raw["d2_response_count"],
            d3_response_count=raw["d3_response_count"],
            run_sha256=raw["run_sha256"],
            run_wire_sha256=raw["run_wire_sha256"],
            run_outcome=raw["run_outcome"],
            candidate_count=raw["candidate_count"],
            finding_count=raw["finding_count"],
            reviewer_verdict_count=raw["reviewer_verdict_count"],
            reviewer_accept_count=raw["reviewer_accept_count"],
            reviewer_reject_count=raw["reviewer_reject_count"],
            reviewer_defer_count=raw["reviewer_defer_count"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if supplied != result.observation_sha256:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "closure observation digest differs"
            )
        return result

    @classmethod
    def from_bytes(cls, payload: bytes) -> "ReplayClosureObservationV1":
        return cls.from_dict(
            _parse_canonical_line(payload, maximum_bytes=_MAX_OBSERVATION_BYTES)
        )


def _require_approvable(observation: ReplayClosureObservationV1) -> None:
    if (
        type(observation) is not ReplayClosureObservationV1
        or observation.run_outcome != "finalized"
        or observation.d2_response_count < 1
        or observation.d3_response_count < 1
        or observation.candidate_count < 1
        or observation.finding_count < 1
        or observation.reviewer_defer_count != 0
    ):
        raise ReplayAuthoringReceiptError(
            "approval_rejected",
            "only a non-empty finalized replay with no deferred verdict is approvable",
        )


@dataclass(frozen=True, slots=True)
class ReplayActorApprovalV1:
    """One actor's explicit approval of an exact closure observation."""

    task_id: str
    split: Literal["test", "train"]
    actor_role: Literal["author", "critic", "reviewer"]
    actor_id: str
    observation_sha256: str
    decision: Literal["approve"] = "approve"
    contract_version: int = REPLAY_RECEIPT_CONTRACT_VERSION
    kind: str = REPLAY_ACTOR_APPROVAL_KIND
    approval_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != REPLAY_RECEIPT_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_ACTOR_APPROVAL_KIND
            or self.split != _task_split(self.task_id)
            or type(self.actor_role) is not str
            or self.actor_role not in _ACTOR_ROLES
            or type(self.actor_id) is not str
            or _ACTOR_ID_RE.fullmatch(self.actor_id) is None
            or type(self.decision) is not str
            or self.decision != "approve"
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "actor approval header is invalid"
            )
        _require_sha256(self.observation_sha256, name="observation_sha256")
        object.__setattr__(
            self,
            "approval_sha256",
            hashlib.sha256(_APPROVAL_DOMAIN + _canonical_json(self._core_dict())).hexdigest(),
        )

    @classmethod
    def from_observation(
        cls,
        observation: ReplayClosureObservationV1,
        *,
        actor_role: Literal["author", "critic", "reviewer"],
        actor_id: str,
    ) -> "ReplayActorApprovalV1":
        _require_approvable(observation)
        return cls(
            task_id=observation.task_id,
            split=observation.split,
            actor_role=actor_role,
            actor_id=actor_id,
            observation_sha256=observation.observation_sha256,
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "contract_version": self.contract_version,
            "decision": self.decision,
            "kind": self.kind,
            "observation_sha256": self.observation_sha256,
            "split": self.split,
            "task_id": self.task_id,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            _APPROVAL_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.approval_sha256 != expected:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "actor approval digest changed"
            )
        return {**self._core_dict(), "approval_sha256": self.approval_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_line(self.to_dict())

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "ReplayActorApprovalV1":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {
                    "actor_id",
                    "actor_role",
                    "approval_sha256",
                    "contract_version",
                    "decision",
                    "kind",
                    "observation_sha256",
                    "split",
                    "task_id",
                }
            ),
            name="actor approval",
        )
        supplied = raw["approval_sha256"]
        result = cls(
            task_id=raw["task_id"],
            split=raw["split"],
            actor_role=raw["actor_role"],
            actor_id=raw["actor_id"],
            observation_sha256=raw["observation_sha256"],
            decision=raw["decision"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if supplied != result.approval_sha256:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "actor approval digest differs"
            )
        return result

    @classmethod
    def from_bytes(cls, payload: bytes) -> "ReplayActorApprovalV1":
        return cls.from_dict(
            _parse_canonical_line(payload, maximum_bytes=_MAX_APPROVAL_BYTES)
        )


@dataclass(frozen=True, slots=True)
class ReplayAuthoringClosureReceiptV1:
    """Three-actor approval over one freshly re-read replay closure."""

    observation: ReplayClosureObservationV1
    approvals: tuple[ReplayActorApprovalV1, ...]
    contract_version: int = REPLAY_RECEIPT_CONTRACT_VERSION
    kind: str = REPLAY_CLOSURE_RECEIPT_KIND
    receipt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != REPLAY_RECEIPT_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_CLOSURE_RECEIPT_KIND
            or type(self.observation) is not ReplayClosureObservationV1
            or type(self.approvals) is not tuple
            or len(self.approvals) != len(_ACTOR_ROLES)
            or any(type(item) is not ReplayActorApprovalV1 for item in self.approvals)
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure receipt header is invalid"
            )
        if tuple(item.actor_role for item in self.approvals) != _ACTOR_ROLES:
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure receipt approval order is invalid"
            )
        _require_approvable(self.observation)
        actor_ids = tuple(item.actor_id for item in self.approvals)
        if len(actor_ids) != 3 or len(set(actor_ids)) != 3:
            raise ReplayAuthoringReceiptError(
                "approval_rejected", "approval actor identities are not distinct"
            )
        for approval in self.approvals:
            if (
                approval.task_id != self.observation.task_id
                or approval.split != self.observation.split
                or approval.observation_sha256
                != self.observation.observation_sha256
                or approval.decision != "approve"
            ):
                raise ReplayAuthoringReceiptError(
                    "approval_rejected", "approval does not bind the closure"
                )
        object.__setattr__(
            self,
            "receipt_sha256",
            hashlib.sha256(_RECEIPT_DOMAIN + _canonical_json(self._core_dict())).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "approvals": [item.to_dict() for item in self.approvals],
            "contract_version": self.contract_version,
            "kind": self.kind,
            "observation": self.observation.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            _RECEIPT_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.receipt_sha256 != expected:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "closure receipt digest changed"
            )
        return {**self._core_dict(), "receipt_sha256": self.receipt_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_line(self.to_dict())

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "ReplayAuthoringClosureReceiptV1":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {
                    "approvals",
                    "contract_version",
                    "kind",
                    "observation",
                    "receipt_sha256",
                }
            ),
            name="closure receipt",
        )
        approvals = raw["approvals"]
        if type(approvals) is not list:
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure receipt approvals are invalid"
            )
        supplied = raw["receipt_sha256"]
        result = cls(
            observation=ReplayClosureObservationV1.from_dict(raw["observation"]),
            approvals=tuple(ReplayActorApprovalV1.from_dict(item) for item in approvals),
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if supplied != result.receipt_sha256:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "closure receipt digest differs"
            )
        return result

    @classmethod
    def from_bytes(cls, payload: bytes) -> "ReplayAuthoringClosureReceiptV1":
        return cls.from_dict(
            _parse_canonical_line(payload, maximum_bytes=_MAX_RECEIPT_BYTES)
        )


@dataclass(frozen=True, slots=True)
class ReplayAuthoringIndexTaskV1:
    split: Literal["test", "train"]
    task_id: str
    d2_sha256: str
    d2_wire_sha256: str
    d3_sha256: str
    d3_wire_sha256: str

    def __post_init__(self) -> None:
        if self.split != _task_split(self.task_id):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "authoring index task split is invalid"
            )
        for value, name in (
            (self.d2_sha256, "d2_sha256"),
            (self.d2_wire_sha256, "d2_wire_sha256"),
            (self.d3_sha256, "d3_sha256"),
            (self.d3_wire_sha256, "d3_wire_sha256"),
        ):
            _require_sha256(value, name=name)

    def to_dict(self) -> dict[str, str]:
        return {
            "d2_sha256": self.d2_sha256,
            "d2_wire_sha256": self.d2_wire_sha256,
            "d3_sha256": self.d3_sha256,
            "d3_wire_sha256": self.d3_wire_sha256,
            "split": self.split,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class ReplayAuthoringIndexV1:
    """The exact external index consumed by replay_batch_plan_cli."""

    tasks: tuple[ReplayAuthoringIndexTaskV1, ...]
    contract_version: int = REPLAY_RECEIPT_CONTRACT_VERSION
    kind: str = REPLAY_AUTHORING_INDEX_KIND
    index_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != REPLAY_RECEIPT_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_AUTHORING_INDEX_KIND
            or type(self.tasks) is not tuple
            or any(type(item) is not ReplayAuthoringIndexTaskV1 for item in self.tasks)
            or len(self.tasks) != PROFILE_TEST_TASKS + PROFILE_TRAIN_TASKS
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "authoring index header is invalid"
            )
        expected_splits = (
            ("test",) * PROFILE_TEST_TASKS
            + ("train",) * PROFILE_TRAIN_TASKS
        )
        if (
            tuple(item.split for item in self.tasks) != expected_splits
            or len({item.task_id for item in self.tasks}) != len(self.tasks)
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "authoring index task order is invalid"
            )
        object.__setattr__(
            self,
            "index_sha256",
            hashlib.sha256(
                _AUTHORING_INDEX_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "kind": self.kind,
            "tasks": [item.to_dict() for item in self.tasks],
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            _AUTHORING_INDEX_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.index_sha256 != expected:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "authoring index digest changed"
            )
        return {**self._core_dict(), "index_sha256": self.index_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_line(self.to_dict())
        if len(payload) > _MAX_INDEX_BYTES:
            raise ReplayAuthoringReceiptError(
                "limit_exceeded", "authoring index exceeds its byte limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
        getattr(value, "st_ctime_ns", 0),
    )


def _file_binding_identity(value: os.stat_result) -> tuple[int, ...]:
    """Compare a named file with its opened handle across platform APIs."""

    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
    )


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        getattr(value, "st_mtime_ns", 0),
        getattr(value, "st_ctime_ns", 0),
    )


def _require_private_directory(path: Path) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError:
        raise ReplayAuthoringReceiptError(
            "input_unavailable", "receipt directory is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or (os.name == "posix" and value.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise ReplayAuthoringReceiptError(
            "unsafe_path", "receipt directory is unsafe"
        )
    return value


def _scan_exact_directory(
    path: Path, expected_names: frozenset[str]
) -> tuple[int, ...]:
    before = _require_private_directory(path)
    try:
        with os.scandir(path) as entries:
            names = frozenset(item.name for item in entries)
    except OSError:
        raise ReplayAuthoringReceiptError(
            "input_unavailable", "receipt directory could not be enumerated"
        ) from None
    after = _require_private_directory(path)
    if _directory_identity(before) != _directory_identity(after):
        raise ReplayAuthoringReceiptError(
            "input_changed", "receipt directory changed while scanning"
        )
    if names != expected_names:
        raise ReplayAuthoringReceiptError(
            "receipt_set_mismatch", "receipt directory membership is invalid"
        )
    return _directory_identity(after)


def _read_private_regular(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        before = os.lstat(path)
    except OSError:
        raise ReplayAuthoringReceiptError(
            "input_unavailable", "receipt input file is unavailable"
        ) from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or not 1 <= before.st_size <= maximum_bytes
        or (os.name == "posix" and before.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise ReplayAuthoringReceiptError(
            "unsafe_path", "receipt input is not a bounded private regular file"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReplayAuthoringReceiptError(
            "input_unavailable", "receipt input could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        if _file_binding_identity(opened) != _file_binding_identity(before):
            raise ReplayAuthoringReceiptError(
                "input_changed", "receipt input changed before opening"
            )
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor, min(64 * 1024, maximum_bytes + 1 - consumed)
            )
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise ReplayAuthoringReceiptError(
                    "limit_exceeded", "receipt input exceeds its byte limit"
                )
            chunks.append(chunk)
        finished = os.fstat(descriptor)
        if _file_identity(finished) != _file_identity(opened) or consumed != opened.st_size:
            raise ReplayAuthoringReceiptError(
                "input_changed", "receipt input changed while reading"
            )
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError:
        raise ReplayAuthoringReceiptError(
            "input_changed", "receipt input changed after reading"
        ) from None
    if _file_identity(after) != _file_identity(before):
        raise ReplayAuthoringReceiptError(
            "input_changed", "receipt input changed after reading"
        )
    return b"".join(chunks)


def readback_published_replay_v1(
    task_file: str | os.PathLike[str],
    published_root: str | os.PathLike[str],
    sealed_bundle_root: str | os.PathLike[str],
    *,
    expected_task_wire_sha256: str,
    attestation_key: bytes | bytearray,
    expected_key_id: str,
) -> ReplayClosureObservationV1:
    """Rerun one published pair and return only its canonical closure facts."""

    expected_wire = _require_sha256(
        expected_task_wire_sha256, name="expected_task_wire_sha256"
    )
    try:
        task = read_pinned_authoring_task_v1(
            task_file, expected_wire_sha256=expected_wire
        )
        step = inspect_replay_authoring_v1(
            task,
            sealed_bundle_root,
            published_root,
            attestation_key=attestation_key,
            expected_key_id=expected_key_id,
        )
    except ReplayAuthoringReceiptError:
        raise
    except Exception:
        raise ReplayAuthoringReceiptError(
            "closure_rejected", "published replay closure could not be verified"
        ) from None
    if type(step) is ReplayAuthoringPendingRequestV1:
        raise ReplayAuthoringReceiptError(
            "closure_rejected", "published replay still has a pending request"
        )
    if type(step) is not ReplayAuthoringSummaryV1:
        raise ReplayAuthoringReceiptError(
            "closure_rejected", "published replay returned an invalid closure"
        )
    return ReplayClosureObservationV1.from_summary(
        task, step, task_wire_sha256=expected_wire
    )


def read_pinned_observation_v1(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    expected_wire_sha256: str,
) -> ReplayClosureObservationV1:
    payload = _read_private_regular(
        Path(os.path.abspath(os.fspath(path))), maximum_bytes=_MAX_OBSERVATION_BYTES
    )
    if hashlib.sha256(payload).hexdigest() != _require_sha256(
        expected_wire_sha256, name="expected_observation_wire_sha256"
    ):
        raise ReplayAuthoringReceiptError(
            "observation_pin_mismatch", "closure observation wire pin differs"
        )
    result = ReplayClosureObservationV1.from_bytes(payload)
    if result.observation_sha256 != _require_sha256(
        expected_sha256, name="expected_observation_sha256"
    ):
        raise ReplayAuthoringReceiptError(
            "observation_pin_mismatch", "closure observation semantic pin differs"
        )
    return result


def read_pinned_approval_v1(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    expected_wire_sha256: str,
) -> ReplayActorApprovalV1:
    payload = _read_private_regular(
        Path(os.path.abspath(os.fspath(path))), maximum_bytes=_MAX_APPROVAL_BYTES
    )
    if hashlib.sha256(payload).hexdigest() != _require_sha256(
        expected_wire_sha256, name="expected_approval_wire_sha256"
    ):
        raise ReplayAuthoringReceiptError(
            "approval_pin_mismatch", "actor approval wire pin differs"
        )
    result = ReplayActorApprovalV1.from_bytes(payload)
    if result.approval_sha256 != _require_sha256(
        expected_sha256, name="expected_approval_sha256"
    ):
        raise ReplayAuthoringReceiptError(
            "approval_pin_mismatch", "actor approval semantic pin differs"
        )
    return result


def seal_replay_closure_receipt_v1(
    observation: ReplayClosureObservationV1,
    approvals: Sequence[ReplayActorApprovalV1],
) -> ReplayAuthoringClosureReceiptV1:
    """Seal exactly author/critic/reviewer approvals in canonical role order."""

    if type(observation) is not ReplayClosureObservationV1:
        raise ReplayAuthoringReceiptError(
            "invalid_argument", "closure observation has an invalid type"
        )
    if type(approvals) not in (tuple, list):
        raise ReplayAuthoringReceiptError(
            "invalid_argument", "approval collection has an invalid type"
        )
    by_role: dict[str, ReplayActorApprovalV1] = {}
    for approval in approvals:
        if type(approval) is not ReplayActorApprovalV1 or approval.actor_role in by_role:
            raise ReplayAuthoringReceiptError(
                "approval_rejected", "approval roles are incomplete or duplicated"
            )
        by_role[approval.actor_role] = approval
    if frozenset(by_role) != frozenset(_ACTOR_ROLES):
        raise ReplayAuthoringReceiptError(
            "approval_rejected", "all three approval roles are required"
        )
    return ReplayAuthoringClosureReceiptV1(
        observation=observation,
        approvals=tuple(by_role[role] for role in _ACTOR_ROLES),
    )


def _public_task_digest(task: object, *, split: Literal["test", "train"]) -> str:
    values = tuple(
        getattr(task, name, None)
        for name in ("task_id", "repo_url", "commit", "instruction_id")
    )
    if any(type(value) is not str for value in values):
        raise ReplayAuthoringReceiptError(
            "benchmark_rejected", "public task identity is invalid"
        )
    task_id, repo_url, commit, instruction_id = values
    return public_task_sha256_v1(
        task_id=task_id,
        repo_url=repo_url,
        commit=commit,
        instruction_id=instruction_id,
        split=split,
    )


def build_replay_authoring_index_v1(
    benchmark_root: str | os.PathLike[str],
    receipt_root: str | os.PathLike[str],
) -> ReplayAuthoringIndexV1:
    """Build the fixed index from 70 receipts, never from replay directories."""

    try:
        public_tasks = tuple(
            (split, task)
            for split in ("test", "train")
            for task in load_answer_free_tasks(benchmark_root, split=split)
        )
    except ReplayAuthoringReceiptError:
        raise
    except Exception:
        raise ReplayAuthoringReceiptError(
            "benchmark_rejected", "public benchmark order could not be verified"
        ) from None
    if (
        len(public_tasks) != PROFILE_TEST_TASKS + PROFILE_TRAIN_TASKS
        or sum(split == "test" for split, _task in public_tasks)
        != PROFILE_TEST_TASKS
        or sum(split == "train" for split, _task in public_tasks)
        != PROFILE_TRAIN_TASKS
    ):
        raise ReplayAuthoringReceiptError(
            "benchmark_rejected", "public benchmark task count is incomplete"
        )
    task_ids = tuple(getattr(task, "task_id", None) for _split, task in public_tasks)
    if (
        any(type(task_id) is not str for task_id in task_ids)
        or len(set(task_ids)) != len(task_ids)
    ):
        raise ReplayAuthoringReceiptError(
            "benchmark_rejected", "public benchmark task IDs are invalid"
        )
    root = Path(os.path.abspath(os.fspath(receipt_root)))
    expected_names = frozenset(
        f"{task_id}{REPLAY_RECEIPT_FILENAME_SUFFIX}" for task_id in task_ids
    )
    root_identity = _scan_exact_directory(root, expected_names)
    bindings: list[ReplayAuthoringIndexTaskV1] = []
    for split_value, task in public_tasks:
        split: Literal["test", "train"] = split_value  # type: ignore[assignment]
        task_id = str(getattr(task, "task_id"))
        payload = _read_private_regular(
            root / f"{task_id}{REPLAY_RECEIPT_FILENAME_SUFFIX}",
            maximum_bytes=_MAX_RECEIPT_BYTES,
        )
        receipt = ReplayAuthoringClosureReceiptV1.from_bytes(payload)
        observation = receipt.observation
        if (
            observation.task_id != task_id
            or observation.split != split
            or observation.public_task_sha256 != _public_task_digest(task, split=split)
        ):
            raise ReplayAuthoringReceiptError(
                "receipt_binding_mismatch",
                "approved receipt differs from the public task identity",
            )
        bindings.append(
            ReplayAuthoringIndexTaskV1(
                split=split,
                task_id=task_id,
                d2_sha256=observation.d2_sha256,
                d2_wire_sha256=observation.d2_wire_sha256,
                d3_sha256=observation.d3_sha256,
                d3_wire_sha256=observation.d3_wire_sha256,
            )
        )
    if _scan_exact_directory(root, expected_names) != root_identity:
        raise ReplayAuthoringReceiptError(
            "input_changed", "receipt directory changed while building the index"
        )
    return ReplayAuthoringIndexV1(tasks=tuple(bindings))


__all__ = [
    "REPLAY_ACTOR_APPROVAL_KIND",
    "REPLAY_AUTHORING_INDEX_KIND",
    "REPLAY_CLOSURE_OBSERVATION_KIND",
    "REPLAY_CLOSURE_RECEIPT_KIND",
    "REPLAY_RECEIPT_CONTRACT_VERSION",
    "REPLAY_RECEIPT_FILENAME_SUFFIX",
    "ReplayActorApprovalV1",
    "ReplayAuthoringClosureReceiptV1",
    "ReplayAuthoringIndexTaskV1",
    "ReplayAuthoringIndexV1",
    "ReplayAuthoringReceiptError",
    "ReplayClosureObservationV1",
    "build_replay_authoring_index_v1",
    "public_task_sha256_v1",
    "read_pinned_approval_v1",
    "read_pinned_observation_v1",
    "readback_published_replay_v1",
    "seal_replay_closure_receipt_v1",
]
