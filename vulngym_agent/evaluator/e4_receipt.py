"""Canonical E4 success receipt and one-shot publication authority.

The existing discovery execution receipt proves the E3 supervisor publication
transaction.  This module wraps that receipt with the fixed E4 scheduler
closure without weakening or replacing the E3 contract.  The opaque authority
is intended to cross the batch-runner/supervisor boundary in-process; hashes
remain integrity bindings rather than signatures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
import threading
from typing import Final

from vulngym_agent.evaluator.contracts import (
    DiscoveryBatchExecutionPlanV2,
    DiscoveryBatchExecutionReceiptV2,
    EvaluatorContractError,
)


E4_SCHEDULER_VERSION: Final[str] = "discovery-e4-batch-runner-v1"
E4_RUNTIME_REVERIFY_POLICY: Final[str] = "after_each_task_cleanup"
E4_SUCCESS_RECEIPT_FILENAME: Final[str] = "e4-success-receipt.json"
E4_TASK_SUCCESS_CLOSURE_KIND: Final[str] = (
    "vulngym.discovery-e4-task-success-closure.v1"
)
E4_BATCH_SUCCESS_RECEIPT_KIND: Final[str] = (
    "vulngym.discovery-e4-batch-success-receipt.v2"
)
E4_TASK_SUCCESS_CLOSURE_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym discovery E4 task success closure v1\0"
)
E4_BATCH_SUCCESS_RECEIPT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym discovery E4 batch success receipt v2\0"
)
E4_SUCCESS_RECEIPT_MAX_BYTES: Final[int] = 8 * 1024 * 1024
E4_SUCCESS_RECEIPT_MAX_JSON_NODES: Final[int] = 250_000
E4_SUCCESS_RECEIPT_MAX_JSON_DEPTH: Final[int] = 64

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_SPLIT_COUNTS: Final[dict[str, int]] = {"train": 50, "test": 20}
_AUTHORITY_ISSUER_TOKEN: Final[object] = object()


class E4ReceiptError(ValueError):
    """Stable failure for malformed, detached, or reused E4 success state."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "invalid_e4_receipt"
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise E4ReceiptError(
            "invalid_contract", "E4 success value is not canonical JSON"
        ) from None


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise E4ReceiptError("invalid_contract", f"{name} is invalid")
    return value


def _require_expected_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise E4ReceiptError("invalid_argument", f"{name} is invalid")
    return value


def _strict_object(
    value: object, *, keys: frozenset[str], name: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise E4ReceiptError(
            "invalid_contract", f"{name} has invalid exact keys"
        )
    return value


def _validate_json_shape(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if (
            count > E4_SUCCESS_RECEIPT_MAX_JSON_NODES
            or depth > E4_SUCCESS_RECEIPT_MAX_JSON_DEPTH
        ):
            raise E4ReceiptError(
                "limit_exceeded", "E4 success JSON exceeds its shape limit"
            )
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in {str, int, bool}:
            raise E4ReceiptError(
                "invalid_contract", "E4 success JSON contains an invalid value"
            )


def _parse_canonical_line(payload: bytes) -> dict[str, object]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise E4ReceiptError(
            "noncanonical_json", "E4 success wire must be one JSON line"
        )

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("constant")
            ),
            object_pairs_hook=unique_object,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise E4ReceiptError(
            "invalid_contract", "E4 success wire is invalid"
        ) from None
    _validate_json_shape(value)
    if type(value) is not dict or _canonical_json(value) + b"\n" != payload:
        raise E4ReceiptError(
            "noncanonical_json", "E4 success wire is not canonical"
        )
    return value


def _parse_pinned_canonical_line(
    payload: bytes,
    *,
    expected_wire_sha256: str,
) -> dict[str, object]:
    if type(payload) is not bytes:
        raise E4ReceiptError(
            "invalid_argument", "E4 success wire must be exact bytes"
        )
    _require_expected_sha256(
        expected_wire_sha256, name="expected_wire_sha256"
    )
    if not payload or len(payload) > E4_SUCCESS_RECEIPT_MAX_BYTES:
        raise E4ReceiptError(
            "limit_exceeded", "E4 success wire exceeds its byte limit"
        )
    if hashlib.sha256(payload).hexdigest() != expected_wire_sha256:
        raise E4ReceiptError(
            "digest_mismatch", "E4 success wire differs from its pin"
        )
    return _parse_canonical_line(payload)


def _freeze_plan(
    value: object,
) -> DiscoveryBatchExecutionPlanV2:
    if type(value) is not DiscoveryBatchExecutionPlanV2:
        raise E4ReceiptError(
            "invalid_argument", "E4 success plan has an invalid exact type"
        )
    try:
        payload = value.to_bytes()
        return DiscoveryBatchExecutionPlanV2.from_bytes(
            payload,
            expected_plan_sha256=value.plan_sha256,
            expected_wire_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except (AttributeError, EvaluatorContractError, TypeError, ValueError):
        raise E4ReceiptError(
            "invalid_binding", "E4 success plan did not normalize"
        ) from None


def _freeze_execution_receipt(
    value: object,
) -> DiscoveryBatchExecutionReceiptV2:
    if type(value) is not DiscoveryBatchExecutionReceiptV2:
        raise E4ReceiptError(
            "invalid_argument",
            "E4 success execution receipt has an invalid exact type",
        )
    try:
        payload = value.to_bytes()
        return DiscoveryBatchExecutionReceiptV2.from_bytes(
            payload,
            expected_receipt_sha256=value.receipt_sha256,
            expected_wire_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except (AttributeError, EvaluatorContractError, TypeError, ValueError):
        raise E4ReceiptError(
            "invalid_binding", "E4 success execution receipt did not normalize"
        ) from None


@dataclass(frozen=True, slots=True)
class E4TaskSuccessClosureV1:
    """Success-only scheduler closure for one exact task result."""

    task_plan_sha256: str
    task_id: str
    run_sha256: str
    run_wire_sha256: str
    discovery_result_sha256: str
    runtime_evidence_sha256: str
    cleanup_complete: bool = True
    runtime_reverified: bool = True
    status: str = "succeeded"
    contract_version: int = 1
    kind: str = E4_TASK_SUCCESS_CLOSURE_KIND
    closure_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != 1
            or type(self.kind) is not str
            or self.kind != E4_TASK_SUCCESS_CLOSURE_KIND
            or type(self.status) is not str
            or self.status != "succeeded"
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.cleanup_complete) is not bool
            or self.cleanup_complete is not True
            or type(self.runtime_reverified) is not bool
            or self.runtime_reverified is not True
        ):
            raise E4ReceiptError(
                "invalid_contract", "E4 task success closure is invalid"
            )
        for value, name in (
            (self.task_plan_sha256, "task_plan_sha256"),
            (self.run_sha256, "run_sha256"),
            (self.run_wire_sha256, "run_wire_sha256"),
            (self.discovery_result_sha256, "discovery_result_sha256"),
            (self.runtime_evidence_sha256, "runtime_evidence_sha256"),
        ):
            _require_sha256(value, name=name)
        object.__setattr__(
            self,
            "closure_sha256",
            hashlib.sha256(
                E4_TASK_SUCCESS_CLOSURE_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "cleanup_complete": self.cleanup_complete,
            "contract_version": self.contract_version,
            "discovery_result_sha256": self.discovery_result_sha256,
            "kind": self.kind,
            "run_sha256": self.run_sha256,
            "run_wire_sha256": self.run_wire_sha256,
            "runtime_evidence_sha256": self.runtime_evidence_sha256,
            "runtime_reverified": self.runtime_reverified,
            "status": self.status,
            "task_id": self.task_id,
            "task_plan_sha256": self.task_plan_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            E4_TASK_SUCCESS_CLOSURE_DIGEST_DOMAIN
            + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.closure_sha256 != expected:
            raise E4ReceiptError(
                "invalid_binding", "E4 task success closure digest changed"
            )
        return {**self._core_dict(), "closure_sha256": self.closure_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "E4TaskSuccessClosureV1":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "cleanup_complete",
                    "closure_sha256",
                    "contract_version",
                    "discovery_result_sha256",
                    "kind",
                    "run_sha256",
                    "run_wire_sha256",
                    "runtime_evidence_sha256",
                    "runtime_reverified",
                    "status",
                    "task_id",
                    "task_plan_sha256",
                }
            ),
            name="E4 task success closure",
        )
        expected = _require_sha256(
            raw["closure_sha256"], name="closure_sha256"
        )
        result = cls(
            task_plan_sha256=raw["task_plan_sha256"],
            task_id=raw["task_id"],
            run_sha256=raw["run_sha256"],
            run_wire_sha256=raw["run_wire_sha256"],
            discovery_result_sha256=raw["discovery_result_sha256"],
            runtime_evidence_sha256=raw["runtime_evidence_sha256"],
            cleanup_complete=raw["cleanup_complete"],
            runtime_reverified=raw["runtime_reverified"],
            status=raw["status"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.closure_sha256 != expected:
            raise E4ReceiptError(
                "digest_mismatch", "E4 task success closure digest differs"
            )
        return result

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_closure_sha256: str,
        expected_wire_sha256: str,
    ) -> "E4TaskSuccessClosureV1":
        _require_expected_sha256(
            expected_closure_sha256, name="expected_closure_sha256"
        )
        result = cls.from_dict(
            _parse_pinned_canonical_line(
                payload,
                expected_wire_sha256=expected_wire_sha256,
            )
        )
        if result.closure_sha256 != expected_closure_sha256:
            raise E4ReceiptError(
                "digest_mismatch", "E4 task success closure differs from its pin"
            )
        if result.to_bytes() != payload:
            raise E4ReceiptError(
                "noncanonical_json", "E4 task success closure did not close"
            )
        return result


def _freeze_success_closures(
    plan: DiscoveryBatchExecutionPlanV2,
    value: object,
) -> tuple[E4TaskSuccessClosureV1, ...]:
    if type(value) is not tuple:
        raise E4ReceiptError(
            "invalid_argument", "E4 success closures must be an exact tuple"
        )
    closures: list[E4TaskSuccessClosureV1] = []
    for supplied in value:
        if type(supplied) is not E4TaskSuccessClosureV1:
            raise E4ReceiptError(
                "invalid_argument",
                "E4 success closures must have exact element types",
            )
        wire = supplied.to_bytes()
        closures.append(
            E4TaskSuccessClosureV1.from_bytes(
                wire,
                expected_closure_sha256=supplied.closure_sha256,
                expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
            )
        )
    result = tuple(closures)
    expected_count = _SPLIT_COUNTS.get(plan.batch.split)
    if (
        expected_count is None
        or len(result) != expected_count
        or len(result) != len(plan.tasks)
    ):
        raise E4ReceiptError(
            "invalid_binding", "E4 success closures do not cover the exact split"
        )
    for task_plan, closure in zip(plan.tasks, result, strict=True):
        if (
            closure.task_id != task_plan.task_id
            or closure.task_plan_sha256 != task_plan.plan_sha256
        ):
            raise E4ReceiptError(
                "invalid_binding", "E4 success closure order differs from the plan"
            )
    if len({item.closure_sha256 for item in result}) != len(result):
        raise E4ReceiptError(
            "invalid_binding", "E4 success closures repeat an identity"
        )
    return result


@dataclass(frozen=True, slots=True)
class E4BatchSuccessReceiptV2:
    """Success-only E4 closure wrapping one exact published E3 receipt."""

    execution_receipt: DiscoveryBatchExecutionReceiptV2
    success_closures: tuple[E4TaskSuccessClosureV1, ...]
    scheduler_version: str = E4_SCHEDULER_VERSION
    max_parallelism: int = 1
    max_attempts: int = 1
    runtime_reverify_policy: str = E4_RUNTIME_REVERIFY_POLICY
    snapshot_reverified: bool = True
    status: str = "succeeded"
    contract_version: int = 2
    kind: str = E4_BATCH_SUCCESS_RECEIPT_KIND
    execution_receipt_sha256: str = field(init=False)
    execution_receipt_wire_sha256: str = field(init=False)
    receipt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.scheduler_version) is not str
            or self.scheduler_version != E4_SCHEDULER_VERSION
            or type(self.max_parallelism) is not int
            or self.max_parallelism != 1
            or type(self.max_attempts) is not int
            or self.max_attempts != 1
            or type(self.runtime_reverify_policy) is not str
            or self.runtime_reverify_policy != E4_RUNTIME_REVERIFY_POLICY
            or type(self.snapshot_reverified) is not bool
            or self.snapshot_reverified is not True
            or type(self.status) is not str
            or self.status != "succeeded"
            or type(self.contract_version) is not int
            or self.contract_version != 2
            or type(self.kind) is not str
            or self.kind != E4_BATCH_SUCCESS_RECEIPT_KIND
        ):
            raise E4ReceiptError(
                "invalid_contract", "E4 batch success header is invalid"
            )
        execution_receipt = _freeze_execution_receipt(self.execution_receipt)
        plan = execution_receipt.plan
        closures = _freeze_success_closures(plan, self.success_closures)
        for task_plan, task_receipt, closure in zip(
            plan.tasks, execution_receipt.tasks, closures, strict=True
        ):
            if (
                closure.task_plan_sha256 != task_plan.plan_sha256
                or closure.task_plan_sha256 != task_receipt.task_plan_sha256
                or closure.task_id != task_plan.task_id
                or closure.task_id != task_receipt.task_id
                or closure.run_sha256 != task_receipt.run_sha256
                or closure.run_wire_sha256 != task_receipt.run_wire_sha256
                or closure.discovery_result_sha256
                != task_receipt.discovery_result_sha256
                or closure.runtime_evidence_sha256
                != task_receipt.runtime_evidence_sha256
                or task_receipt.runtime_evidence.cleanup_complete is not True
            ):
                raise E4ReceiptError(
                    "invalid_binding",
                    "E4 task success closure is detached from the E3 receipt",
                )
        execution_wire = execution_receipt.to_bytes()
        object.__setattr__(self, "execution_receipt", execution_receipt)
        object.__setattr__(self, "success_closures", closures)
        object.__setattr__(
            self,
            "execution_receipt_sha256",
            execution_receipt.receipt_sha256,
        )
        object.__setattr__(
            self,
            "execution_receipt_wire_sha256",
            hashlib.sha256(execution_wire).hexdigest(),
        )
        object.__setattr__(
            self,
            "receipt_sha256",
            hashlib.sha256(
                E4_BATCH_SUCCESS_RECEIPT_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > E4_SUCCESS_RECEIPT_MAX_BYTES:
            raise E4ReceiptError(
                "limit_exceeded", "E4 batch success receipt is too large"
            )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "execution_receipt": self.execution_receipt.to_dict(),
            "execution_receipt_sha256": self.execution_receipt_sha256,
            "execution_receipt_wire_sha256": (
                self.execution_receipt_wire_sha256
            ),
            "kind": self.kind,
            "max_attempts": self.max_attempts,
            "max_parallelism": self.max_parallelism,
            "runtime_reverify_policy": self.runtime_reverify_policy,
            "scheduler_version": self.scheduler_version,
            "snapshot_reverified": self.snapshot_reverified,
            "status": self.status,
            "success_closures": [item.to_dict() for item in self.success_closures],
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            E4_BATCH_SUCCESS_RECEIPT_DIGEST_DOMAIN
            + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.receipt_sha256 != expected:
            raise E4ReceiptError(
                "invalid_binding", "E4 batch success receipt digest changed"
            )
        return {**self._core_dict(), "receipt_sha256": self.receipt_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_receipt_sha256: str,
        expected_wire_sha256: str,
    ) -> "E4BatchSuccessReceiptV2":
        _require_expected_sha256(
            expected_receipt_sha256, name="expected_receipt_sha256"
        )
        raw = _strict_object(
            _parse_pinned_canonical_line(
                payload,
                expected_wire_sha256=expected_wire_sha256,
            ),
            keys=frozenset(
                {
                    "contract_version",
                    "execution_receipt",
                    "execution_receipt_sha256",
                    "execution_receipt_wire_sha256",
                    "kind",
                    "max_attempts",
                    "max_parallelism",
                    "receipt_sha256",
                    "runtime_reverify_policy",
                    "scheduler_version",
                    "snapshot_reverified",
                    "status",
                    "success_closures",
                }
            ),
            name="E4 batch success receipt",
        )
        if raw["receipt_sha256"] != expected_receipt_sha256:
            raise E4ReceiptError(
                "digest_mismatch", "E4 batch success receipt differs"
            )
        raw_execution = raw["execution_receipt"]
        raw_closures = raw["success_closures"]
        if type(raw_execution) is not dict or type(raw_closures) is not list:
            raise E4ReceiptError(
                "invalid_contract", "E4 batch success nested values are invalid"
            )
        execution_sha256 = _require_sha256(
            raw["execution_receipt_sha256"],
            name="execution_receipt_sha256",
        )
        execution_wire_sha256 = _require_sha256(
            raw["execution_receipt_wire_sha256"],
            name="execution_receipt_wire_sha256",
        )
        execution_payload = _canonical_json(raw_execution) + b"\n"
        if raw_execution.get("receipt_sha256") != execution_sha256:
            raise E4ReceiptError(
                "invalid_binding", "nested E3 receipt semantic pin is detached"
            )
        try:
            execution_receipt = DiscoveryBatchExecutionReceiptV2.from_bytes(
                execution_payload,
                expected_receipt_sha256=execution_sha256,
                expected_wire_sha256=execution_wire_sha256,
            )
        except (EvaluatorContractError, TypeError, ValueError):
            raise E4ReceiptError(
                "invalid_contract", "nested E3 receipt did not pass strict parsing"
            ) from None
        result = cls(
            execution_receipt=execution_receipt,
            success_closures=tuple(
                E4TaskSuccessClosureV1.from_dict(item) for item in raw_closures
            ),
            scheduler_version=raw["scheduler_version"],
            max_parallelism=raw["max_parallelism"],
            max_attempts=raw["max_attempts"],
            runtime_reverify_policy=raw["runtime_reverify_policy"],
            snapshot_reverified=raw["snapshot_reverified"],
            status=raw["status"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if (
            result.execution_receipt_sha256 != execution_sha256
            or result.execution_receipt_wire_sha256
            != execution_wire_sha256
            or result.receipt_sha256 != expected_receipt_sha256
            or result.wire_sha256 != expected_wire_sha256
            or result.to_bytes() != payload
        ):
            raise E4ReceiptError(
                "noncanonical_json", "E4 batch success receipt did not close"
            )
        return result


class E4SuccessReceiptAuthorityV2:
    """Opaque one-use authority to wrap one exact E3 publication receipt."""

    __slots__ = (
        "__claimed",
        "__closure_pins",
        "__lock",
        "__plan_sha256",
        "__plan_wire",
    )

    def __init__(
        self,
        token: object,
        *,
        plan: DiscoveryBatchExecutionPlanV2,
        success_closures: tuple[E4TaskSuccessClosureV1, ...],
    ) -> None:
        if token is not _AUTHORITY_ISSUER_TOKEN:
            raise TypeError("E4 success receipt authorities are issuer-created")
        frozen_plan = _freeze_plan(plan)
        closures = _freeze_success_closures(frozen_plan, success_closures)
        self.__plan_sha256 = frozen_plan.plan_sha256
        self.__plan_wire = frozen_plan.to_bytes()
        self.__closure_pins = tuple(
            (item.to_bytes(), item.closure_sha256) for item in closures
        )
        self.__claimed = False
        self.__lock = threading.Lock()

    def _claim_for_execution_receipt(
        self,
        execution_receipt: DiscoveryBatchExecutionReceiptV2,
    ) -> E4BatchSuccessReceiptV2:
        if type(execution_receipt) is not DiscoveryBatchExecutionReceiptV2:
            raise E4ReceiptError(
                "invalid_argument",
                "authority claim requires an exact E3 execution receipt",
            )
        with self.__lock:
            if self.__claimed:
                raise E4ReceiptError(
                    "authority_reused",
                    "E4 success receipt authority was already claimed",
                )
            self.__claimed = True
            receipt = _freeze_execution_receipt(execution_receipt)
            try:
                plan = DiscoveryBatchExecutionPlanV2.from_bytes(
                    self.__plan_wire,
                    expected_plan_sha256=self.__plan_sha256,
                    expected_wire_sha256=hashlib.sha256(
                        self.__plan_wire
                    ).hexdigest(),
                )
                closures = tuple(
                    E4TaskSuccessClosureV1.from_bytes(
                        wire,
                        expected_closure_sha256=closure_sha256,
                        expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
                    )
                    for wire, closure_sha256 in self.__closure_pins
                )
            except (
                E4ReceiptError,
                EvaluatorContractError,
                KeyError,
                TypeError,
                ValueError,
            ):
                raise E4ReceiptError(
                    "invalid_state", "frozen E4 authority state did not normalize"
                ) from None
            if plan.to_bytes() != receipt.plan.to_bytes():
                raise E4ReceiptError(
                    "detached_receipt", "E3 receipt is detached from E4 authority"
                )
            try:
                return E4BatchSuccessReceiptV2(
                    execution_receipt=receipt,
                    success_closures=closures,
                )
            except E4ReceiptError as error:
                raise E4ReceiptError(
                    "detached_receipt",
                    "E3 receipt does not match the E4 success closures",
                ) from error

    def __reduce__(self):
        raise TypeError("E4 success receipt authorities are not serializable")


def _issue_e4_success_receipt_authority_v2(
    plan: DiscoveryBatchExecutionPlanV2,
    success_closures: tuple[E4TaskSuccessClosureV1, ...],
) -> E4SuccessReceiptAuthorityV2:
    """Issue the trusted one-use E4 authority for one exact successful plan."""

    return E4SuccessReceiptAuthorityV2(
        _AUTHORITY_ISSUER_TOKEN,
        plan=plan,
        success_closures=success_closures,
    )


def claim_e4_success_receipt_authority_v2(
    authority: E4SuccessReceiptAuthorityV2,
    execution_receipt: DiscoveryBatchExecutionReceiptV2,
) -> E4BatchSuccessReceiptV2:
    """Exact-type supervisor integration point for one E4 authority claim."""

    if type(authority) is not E4SuccessReceiptAuthorityV2:
        raise E4ReceiptError(
            "invalid_argument", "E4 success authority has an invalid exact type"
        )
    return authority._claim_for_execution_receipt(execution_receipt)


__all__ = [
    "E4_BATCH_SUCCESS_RECEIPT_KIND",
    "E4_RUNTIME_REVERIFY_POLICY",
    "E4_SCHEDULER_VERSION",
    "E4_SUCCESS_RECEIPT_FILENAME",
    "E4_SUCCESS_RECEIPT_MAX_BYTES",
    "E4_TASK_SUCCESS_CLOSURE_KIND",
    "E4BatchSuccessReceiptV2",
    "E4ReceiptError",
    "E4SuccessReceiptAuthorityV2",
    "E4TaskSuccessClosureV1",
    "claim_e4_success_receipt_authority_v2",
]
