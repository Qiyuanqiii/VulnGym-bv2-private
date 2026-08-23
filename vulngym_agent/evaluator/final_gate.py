"""Canonical, path-free contracts for the E4 20+50 final gate.

These contracts describe mechanical closure only.  ``status="closed"`` means
that the fixed execution and projection stages have supplied a complete set of
digest bindings; it does not mean that a quality threshold was met, that a
hidden test was scored, or that external provenance was authenticated.

The module deliberately contains no filesystem transaction, CLI, secret, or
gold-data interface.  A later trusted coordinator is responsible for deriving
the fields from independently verified execution and projection artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Final, Literal

from vulngym_agent.benchmark.harness import (
    MAX_DISCOVERY_TOP_K,
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
)


FINAL_GATE_CONTRACT_VERSION: Final[int] = 1
FINAL_GATE_STATUS: Final[str] = "closed"
FINAL_GATE_TOP_K: Final[int] = MAX_DISCOVERY_TOP_K
FINAL_GATE_STAGE_ORDER: Final[tuple[str, ...]] = (
    "test_execution",
    "test_projection",
    "train_execution",
    "train_projection",
)
FINAL_GATE_PLAN_FILENAME: Final[str] = "final-gate-plan.json"
FINAL_GATE_RECEIPT_FILENAME: Final[str] = "final-gate-receipt.json"
FINAL_GATE_TEST_DIRECTORY: Final[str] = "test"
FINAL_GATE_TRAIN_DIRECTORY: Final[str] = "train"
FINAL_GATE_EXECUTION_DIRECTORY: Final[str] = "execution"
FINAL_GATE_PROJECTION_DIRECTORY: Final[str] = "projection"
FINAL_GATE_ROOT_MEMBERS: Final[frozenset[str]] = frozenset(
    {
        FINAL_GATE_PLAN_FILENAME,
        FINAL_GATE_RECEIPT_FILENAME,
        FINAL_GATE_TEST_DIRECTORY,
        FINAL_GATE_TRAIN_DIRECTORY,
    }
)
FINAL_GATE_SPLIT_MEMBERS: Final[frozenset[str]] = frozenset(
    {FINAL_GATE_EXECUTION_DIRECTORY, FINAL_GATE_PROJECTION_DIRECTORY}
)

FINAL_GATE_SPLIT_PLAN_KIND: Final[str] = (
    "vulngym.discovery-e4-final-gate-split-plan.v1"
)
FINAL_GATE_PLAN_KIND: Final[str] = (
    "vulngym.discovery-e4-final-gate-plan.v1"
)
FINAL_GATE_SPLIT_RECEIPT_CLOSURE_KIND: Final[str] = (
    "vulngym.discovery-e4-final-gate-split-receipt-closure.v1"
)
FINAL_GATE_RECEIPT_KIND: Final[str] = (
    "vulngym.discovery-e4-final-gate-receipt.v1"
)

FINAL_GATE_SPLIT_PLAN_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym discovery E4 final gate split plan v1\0"
)
FINAL_GATE_PLAN_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym discovery E4 final gate plan v1\0"
)
FINAL_GATE_SPLIT_RECEIPT_CLOSURE_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym discovery E4 final gate split receipt closure v1\0"
)
FINAL_GATE_RECEIPT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym discovery E4 final gate receipt v1\0"
)

FINAL_GATE_MAX_WIRE_BYTES: Final[int] = 512 * 1024
FINAL_GATE_MAX_JSON_NODES: Final[int] = 4096
FINAL_GATE_MAX_JSON_DEPTH: Final[int] = 16

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_SPLIT_COUNTS: Final[dict[str, int]] = {
    "test": PROFILE_TEST_TASKS,
    "train": PROFILE_TRAIN_TASKS,
}


class FinalGateContractError(ValueError):
    """Stable rejection for a malformed or detached final-gate contract."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "invalid_contract"
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
        raise FinalGateContractError(
            "invalid_contract", "final-gate value is not canonical JSON"
        ) from None


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise FinalGateContractError(
            "invalid_contract", f"{name} must be lower-case SHA-256"
        )
    return value


def _require_expected_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise FinalGateContractError(
            "invalid_argument", f"{name} must be lower-case SHA-256"
        )
    return value


def _strict_object(
    value: object, *, keys: frozenset[str], name: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise FinalGateContractError(
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
            count > FINAL_GATE_MAX_JSON_NODES
            or depth > FINAL_GATE_MAX_JSON_DEPTH
        ):
            raise FinalGateContractError(
                "limit_exceeded", "final-gate JSON exceeds its shape limit"
            )
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in {str, int, bool}:
            raise FinalGateContractError(
                "invalid_contract", "final-gate JSON contains an invalid value"
            )


def _parse_pinned_canonical_line(
    payload: bytes,
    *,
    expected_wire_sha256: str,
) -> dict[str, object]:
    if type(payload) is not bytes:
        raise FinalGateContractError(
            "invalid_argument", "final-gate wire must be exact bytes"
        )
    wire_sha256 = _require_expected_sha256(
        expected_wire_sha256, name="expected_wire_sha256"
    )
    if not payload or len(payload) > FINAL_GATE_MAX_WIRE_BYTES:
        raise FinalGateContractError(
            "limit_exceeded", "final-gate wire exceeds its byte limit"
        )
    if hashlib.sha256(payload).hexdigest() != wire_sha256:
        raise FinalGateContractError(
            "digest_mismatch", "final-gate wire differs from its pin"
        )
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise FinalGateContractError(
            "noncanonical_json", "final-gate wire must be one JSON line"
        )

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise FinalGateContractError(
                    "noncanonical_json", "final-gate JSON repeats an object key"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                FinalGateContractError(
                    "noncanonical_json",
                    "final-gate JSON contains a non-finite number",
                )
            ),
        )
    except FinalGateContractError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise FinalGateContractError(
            "noncanonical_json", "final-gate wire is not strict JSON"
        ) from None
    _validate_json_shape(value)
    if type(value) is not dict or _canonical_json(value) + b"\n" != payload:
        raise FinalGateContractError(
            "noncanonical_json", "final-gate wire is not canonical"
        )
    return value


@dataclass(frozen=True, slots=True)
class FinalGateSplitPlanV1:
    """Trusted, path-free input pins for one fixed benchmark split."""

    split: Literal["test", "train"]
    task_count: int
    sealed_batch_manifest_sha256: str
    replay_manifest_sha256: str
    replay_manifest_wire_sha256: str
    snapshot_key_id: str
    contract_version: int = FINAL_GATE_CONTRACT_VERSION
    kind: str = FINAL_GATE_SPLIT_PLAN_KIND
    split_plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        expected_count = (
            _SPLIT_COUNTS.get(self.split)
            if type(self.split) is str
            else None
        )
        if (
            type(self.split) is not str
            or expected_count is None
            or type(self.task_count) is not int
            or self.task_count != expected_count
            or type(self.contract_version) is not int
            or self.contract_version != FINAL_GATE_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != FINAL_GATE_SPLIT_PLAN_KIND
            or type(self.snapshot_key_id) is not str
            or _KEY_ID_RE.fullmatch(self.snapshot_key_id) is None
        ):
            raise FinalGateContractError(
                "invalid_contract", "final-gate split plan header is invalid"
            )
        for value, name in (
            (self.sealed_batch_manifest_sha256, "sealed_batch_manifest_sha256"),
            (self.replay_manifest_sha256, "replay_manifest_sha256"),
            (self.replay_manifest_wire_sha256, "replay_manifest_wire_sha256"),
        ):
            _require_sha256(value, name=name)
        object.__setattr__(
            self,
            "split_plan_sha256",
            hashlib.sha256(
                FINAL_GATE_SPLIT_PLAN_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "kind": self.kind,
            "replay_manifest_sha256": self.replay_manifest_sha256,
            "replay_manifest_wire_sha256": self.replay_manifest_wire_sha256,
            "sealed_batch_manifest_sha256": self.sealed_batch_manifest_sha256,
            "snapshot_key_id": self.snapshot_key_id,
            "split": self.split,
            "task_count": self.task_count,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            FINAL_GATE_SPLIT_PLAN_DIGEST_DOMAIN
            + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.split_plan_sha256 != expected:
            raise FinalGateContractError(
                "invalid_binding", "final-gate split plan digest changed"
            )
        return {**self._core_dict(), "split_plan_sha256": self.split_plan_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > FINAL_GATE_MAX_WIRE_BYTES:
            raise FinalGateContractError(
                "limit_exceeded", "final-gate split plan exceeds its wire limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "FinalGateSplitPlanV1":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "contract_version",
                    "kind",
                    "replay_manifest_sha256",
                    "replay_manifest_wire_sha256",
                    "sealed_batch_manifest_sha256",
                    "snapshot_key_id",
                    "split",
                    "split_plan_sha256",
                    "task_count",
                }
            ),
            name="final-gate split plan",
        )
        expected = _require_sha256(
            raw["split_plan_sha256"], name="split_plan_sha256"
        )
        result = cls(
            split=raw["split"],
            task_count=raw["task_count"],
            sealed_batch_manifest_sha256=raw["sealed_batch_manifest_sha256"],
            replay_manifest_sha256=raw["replay_manifest_sha256"],
            replay_manifest_wire_sha256=raw["replay_manifest_wire_sha256"],
            snapshot_key_id=raw["snapshot_key_id"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.split_plan_sha256 != expected or result.to_dict() != raw:
            raise FinalGateContractError(
                "digest_mismatch", "final-gate split plan differs from its digest"
            )
        return result

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_plan_sha256: str,
        expected_wire_sha256: str,
    ) -> "FinalGateSplitPlanV1":
        semantic = _require_expected_sha256(
            expected_plan_sha256, name="expected_plan_sha256"
        )
        result = cls.from_dict(
            _parse_pinned_canonical_line(
                payload, expected_wire_sha256=expected_wire_sha256
            )
        )
        if result.split_plan_sha256 != semantic or result.to_bytes() != payload:
            raise FinalGateContractError(
                "digest_mismatch", "final-gate split plan differs from its pin"
            )
        return result


def _freeze_split_plan(value: object) -> FinalGateSplitPlanV1:
    if type(value) is not FinalGateSplitPlanV1:
        raise FinalGateContractError(
            "invalid_argument", "split plan must have an exact contract type"
        )
    wire = value.to_bytes()
    return FinalGateSplitPlanV1.from_bytes(
        wire,
        expected_plan_sha256=value.split_plan_sha256,
        expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class FinalGatePlanV1:
    """Fixed test-first authorization plan shared by both E4 split runs."""

    execution_policy_sha256: str
    execution_policy_wire_sha256: str
    test: FinalGateSplitPlanV1
    train: FinalGateSplitPlanV1
    profile_id: str = PROFILE_ID
    profile_schema_version: str = PROFILE_SCHEMA_VERSION
    public_manifest_sha256: str = PROFILE_MANIFEST_SHA256
    stage_order: tuple[str, ...] = FINAL_GATE_STAGE_ORDER
    top_k: int = FINAL_GATE_TOP_K
    contract_version: int = FINAL_GATE_CONTRACT_VERSION
    kind: str = FINAL_GATE_PLAN_KIND
    plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.profile_id) is not str
            or self.profile_id != PROFILE_ID
            or type(self.profile_schema_version) is not str
            or self.profile_schema_version != PROFILE_SCHEMA_VERSION
            or type(self.public_manifest_sha256) is not str
            or self.public_manifest_sha256 != PROFILE_MANIFEST_SHA256
            or type(self.stage_order) is not tuple
            or self.stage_order != FINAL_GATE_STAGE_ORDER
            or any(type(item) is not str for item in self.stage_order)
            or type(self.top_k) is not int
            or self.top_k != FINAL_GATE_TOP_K
            or type(self.contract_version) is not int
            or self.contract_version != FINAL_GATE_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != FINAL_GATE_PLAN_KIND
        ):
            raise FinalGateContractError(
                "invalid_contract", "final-gate plan fixed header is invalid"
            )
        _require_sha256(
            self.execution_policy_sha256, name="execution_policy_sha256"
        )
        _require_sha256(
            self.execution_policy_wire_sha256,
            name="execution_policy_wire_sha256",
        )
        test = _freeze_split_plan(self.test)
        train = _freeze_split_plan(self.train)
        if test.split != "test" or train.split != "train":
            raise FinalGateContractError(
                "invalid_binding", "final-gate split plan union is invalid"
            )
        if (
            test.sealed_batch_manifest_sha256
            == train.sealed_batch_manifest_sha256
            or test.replay_manifest_sha256 == train.replay_manifest_sha256
            or test.replay_manifest_wire_sha256
            == train.replay_manifest_wire_sha256
            or test.split_plan_sha256 == train.split_plan_sha256
        ):
            raise FinalGateContractError(
                "invalid_binding", "test and train plans reuse an input identity"
            )
        object.__setattr__(self, "test", test)
        object.__setattr__(self, "train", train)
        object.__setattr__(
            self,
            "plan_sha256",
            hashlib.sha256(
                FINAL_GATE_PLAN_DIGEST_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "execution_policy_sha256": self.execution_policy_sha256,
            "execution_policy_wire_sha256": self.execution_policy_wire_sha256,
            "kind": self.kind,
            "profile_id": self.profile_id,
            "profile_schema_version": self.profile_schema_version,
            "public_manifest_sha256": self.public_manifest_sha256,
            "stage_order": list(self.stage_order),
            "test": self.test.to_dict(),
            "top_k": self.top_k,
            "train": self.train.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            FINAL_GATE_PLAN_DIGEST_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.plan_sha256 != expected:
            raise FinalGateContractError(
                "invalid_binding", "final-gate plan digest changed"
            )
        return {**self._core_dict(), "plan_sha256": self.plan_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > FINAL_GATE_MAX_WIRE_BYTES:
            raise FinalGateContractError(
                "limit_exceeded", "final-gate plan exceeds its wire limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "FinalGatePlanV1":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "contract_version",
                    "execution_policy_sha256",
                    "execution_policy_wire_sha256",
                    "kind",
                    "plan_sha256",
                    "profile_id",
                    "profile_schema_version",
                    "public_manifest_sha256",
                    "stage_order",
                    "test",
                    "top_k",
                    "train",
                }
            ),
            name="final-gate plan",
        )
        expected = _require_sha256(raw["plan_sha256"], name="plan_sha256")
        stage_order = raw["stage_order"]
        if type(stage_order) is not list:
            raise FinalGateContractError(
                "invalid_contract", "final-gate stage order must be a JSON array"
            )
        result = cls(
            execution_policy_sha256=raw["execution_policy_sha256"],
            execution_policy_wire_sha256=raw["execution_policy_wire_sha256"],
            test=FinalGateSplitPlanV1.from_dict(raw["test"]),
            train=FinalGateSplitPlanV1.from_dict(raw["train"]),
            profile_id=raw["profile_id"],
            profile_schema_version=raw["profile_schema_version"],
            public_manifest_sha256=raw["public_manifest_sha256"],
            stage_order=tuple(stage_order),
            top_k=raw["top_k"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.plan_sha256 != expected or result.to_dict() != raw:
            raise FinalGateContractError(
                "digest_mismatch", "final-gate plan differs from its digest"
            )
        return result

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_plan_sha256: str,
        expected_wire_sha256: str,
    ) -> "FinalGatePlanV1":
        semantic = _require_expected_sha256(
            expected_plan_sha256, name="expected_plan_sha256"
        )
        result = cls.from_dict(
            _parse_pinned_canonical_line(
                payload, expected_wire_sha256=expected_wire_sha256
            )
        )
        if result.plan_sha256 != semantic or result.to_bytes() != payload:
            raise FinalGateContractError(
                "digest_mismatch", "final-gate plan differs from its pin"
            )
        return result


def _freeze_plan(value: object) -> FinalGatePlanV1:
    if type(value) is not FinalGatePlanV1:
        raise FinalGateContractError(
            "invalid_argument", "final-gate plan must have an exact contract type"
        )
    wire = value.to_bytes()
    return FinalGatePlanV1.from_bytes(
        wire,
        expected_plan_sha256=value.plan_sha256,
        expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class FinalGateSplitReceiptClosureV1:
    """Mechanical closure pins for one E4 execution and its projection."""

    split: Literal["test", "train"]
    split_plan_sha256: str
    split_plan_wire_sha256: str
    e4_receipt_sha256: str
    e4_receipt_wire_sha256: str
    execution_policy_sha256: str
    execution_policy_wire_sha256: str
    execution_plan_sha256: str
    execution_plan_wire_sha256: str
    artifact_index_sha256: str
    projection_manifest_sha256: str
    task_count: int
    finalized_task_count: int
    deferred_task_count: int
    candidate_count: int
    finding_count: int
    aggregate_file_sha256: str | None
    top_k: int = FINAL_GATE_TOP_K
    status: str = FINAL_GATE_STATUS
    contract_version: int = FINAL_GATE_CONTRACT_VERSION
    kind: str = FINAL_GATE_SPLIT_RECEIPT_CLOSURE_KIND
    closure_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        expected_count = (
            _SPLIT_COUNTS.get(self.split)
            if type(self.split) is str
            else None
        )
        counts = (
            self.task_count,
            self.finalized_task_count,
            self.deferred_task_count,
            self.candidate_count,
            self.finding_count,
        )
        if (
            type(self.split) is not str
            or expected_count is None
            or any(type(value) is not int or value < 0 for value in counts)
            or self.task_count != expected_count
            or self.finalized_task_count + self.deferred_task_count
            != self.task_count
            or self.finding_count > self.candidate_count
            or self.finding_count > self.task_count * FINAL_GATE_TOP_K
            or type(self.top_k) is not int
            or self.top_k != FINAL_GATE_TOP_K
            or type(self.status) is not str
            or self.status != FINAL_GATE_STATUS
            or type(self.contract_version) is not int
            or self.contract_version != FINAL_GATE_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != FINAL_GATE_SPLIT_RECEIPT_CLOSURE_KIND
        ):
            raise FinalGateContractError(
                "invalid_contract", "final-gate split closure is invalid"
            )
        for value, name in (
            (self.split_plan_sha256, "split_plan_sha256"),
            (self.split_plan_wire_sha256, "split_plan_wire_sha256"),
            (self.e4_receipt_sha256, "e4_receipt_sha256"),
            (self.e4_receipt_wire_sha256, "e4_receipt_wire_sha256"),
            (self.execution_policy_sha256, "execution_policy_sha256"),
            (
                self.execution_policy_wire_sha256,
                "execution_policy_wire_sha256",
            ),
            (self.execution_plan_sha256, "execution_plan_sha256"),
            (self.execution_plan_wire_sha256, "execution_plan_wire_sha256"),
            (self.artifact_index_sha256, "artifact_index_sha256"),
            (self.projection_manifest_sha256, "projection_manifest_sha256"),
        ):
            _require_sha256(value, name=name)
        if self.split == "train":
            _require_sha256(
                self.aggregate_file_sha256, name="aggregate_file_sha256"
            )
        elif self.aggregate_file_sha256 is not None:
            raise FinalGateContractError(
                "invalid_contract", "test closure cannot bind an aggregate file"
            )
        object.__setattr__(
            self,
            "closure_sha256",
            hashlib.sha256(
                FINAL_GATE_SPLIT_RECEIPT_CLOSURE_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "aggregate_file_sha256": self.aggregate_file_sha256,
            "artifact_index_sha256": self.artifact_index_sha256,
            "candidate_count": self.candidate_count,
            "contract_version": self.contract_version,
            "deferred_task_count": self.deferred_task_count,
            "e4_receipt_sha256": self.e4_receipt_sha256,
            "e4_receipt_wire_sha256": self.e4_receipt_wire_sha256,
            "execution_policy_sha256": self.execution_policy_sha256,
            "execution_policy_wire_sha256": self.execution_policy_wire_sha256,
            "execution_plan_sha256": self.execution_plan_sha256,
            "execution_plan_wire_sha256": self.execution_plan_wire_sha256,
            "finalized_task_count": self.finalized_task_count,
            "finding_count": self.finding_count,
            "kind": self.kind,
            "projection_manifest_sha256": self.projection_manifest_sha256,
            "split": self.split,
            "split_plan_sha256": self.split_plan_sha256,
            "split_plan_wire_sha256": self.split_plan_wire_sha256,
            "status": self.status,
            "task_count": self.task_count,
            "top_k": self.top_k,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            FINAL_GATE_SPLIT_RECEIPT_CLOSURE_DIGEST_DOMAIN
            + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.closure_sha256 != expected:
            raise FinalGateContractError(
                "invalid_binding", "final-gate split closure digest changed"
            )
        return {**self._core_dict(), "closure_sha256": self.closure_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > FINAL_GATE_MAX_WIRE_BYTES:
            raise FinalGateContractError(
                "limit_exceeded", "final-gate split closure exceeds its wire limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "FinalGateSplitReceiptClosureV1":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "aggregate_file_sha256",
                    "artifact_index_sha256",
                    "candidate_count",
                    "closure_sha256",
                    "contract_version",
                    "deferred_task_count",
                    "e4_receipt_sha256",
                    "e4_receipt_wire_sha256",
                    "execution_policy_sha256",
                    "execution_policy_wire_sha256",
                    "execution_plan_sha256",
                    "execution_plan_wire_sha256",
                    "finalized_task_count",
                    "finding_count",
                    "kind",
                    "projection_manifest_sha256",
                    "split",
                    "split_plan_sha256",
                    "split_plan_wire_sha256",
                    "status",
                    "task_count",
                    "top_k",
                }
            ),
            name="final-gate split closure",
        )
        expected = _require_sha256(raw["closure_sha256"], name="closure_sha256")
        result = cls(
            split=raw["split"],
            split_plan_sha256=raw["split_plan_sha256"],
            split_plan_wire_sha256=raw["split_plan_wire_sha256"],
            e4_receipt_sha256=raw["e4_receipt_sha256"],
            e4_receipt_wire_sha256=raw["e4_receipt_wire_sha256"],
            execution_policy_sha256=raw["execution_policy_sha256"],
            execution_policy_wire_sha256=raw["execution_policy_wire_sha256"],
            execution_plan_sha256=raw["execution_plan_sha256"],
            execution_plan_wire_sha256=raw["execution_plan_wire_sha256"],
            artifact_index_sha256=raw["artifact_index_sha256"],
            projection_manifest_sha256=raw["projection_manifest_sha256"],
            task_count=raw["task_count"],
            finalized_task_count=raw["finalized_task_count"],
            deferred_task_count=raw["deferred_task_count"],
            candidate_count=raw["candidate_count"],
            finding_count=raw["finding_count"],
            aggregate_file_sha256=raw["aggregate_file_sha256"],
            top_k=raw["top_k"],
            status=raw["status"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.closure_sha256 != expected or result.to_dict() != raw:
            raise FinalGateContractError(
                "digest_mismatch", "final-gate split closure differs from its digest"
            )
        return result

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_closure_sha256: str,
        expected_wire_sha256: str,
    ) -> "FinalGateSplitReceiptClosureV1":
        semantic = _require_expected_sha256(
            expected_closure_sha256, name="expected_closure_sha256"
        )
        result = cls.from_dict(
            _parse_pinned_canonical_line(
                payload, expected_wire_sha256=expected_wire_sha256
            )
        )
        if result.closure_sha256 != semantic or result.to_bytes() != payload:
            raise FinalGateContractError(
                "digest_mismatch", "final-gate split closure differs from its pin"
            )
        return result


def _freeze_split_closure(value: object) -> FinalGateSplitReceiptClosureV1:
    if type(value) is not FinalGateSplitReceiptClosureV1:
        raise FinalGateContractError(
            "invalid_argument", "split closure must have an exact contract type"
        )
    wire = value.to_bytes()
    return FinalGateSplitReceiptClosureV1.from_bytes(
        wire,
        expected_closure_sha256=value.closure_sha256,
        expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class FinalGateReceiptV1:
    """Top-level proof that all four fixed stages mechanically closed."""

    plan: FinalGatePlanV1
    test: FinalGateSplitReceiptClosureV1
    train: FinalGateSplitReceiptClosureV1
    status: str = FINAL_GATE_STATUS
    contract_version: int = FINAL_GATE_CONTRACT_VERSION
    kind: str = FINAL_GATE_RECEIPT_KIND
    plan_sha256: str = field(init=False)
    plan_wire_sha256: str = field(init=False)
    receipt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.status) is not str
            or self.status != FINAL_GATE_STATUS
            or type(self.contract_version) is not int
            or self.contract_version != FINAL_GATE_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != FINAL_GATE_RECEIPT_KIND
        ):
            raise FinalGateContractError(
                "invalid_contract", "final-gate receipt header is invalid"
            )
        plan = _freeze_plan(self.plan)
        test = _freeze_split_closure(self.test)
        train = _freeze_split_closure(self.train)
        if test.split != "test" or train.split != "train":
            raise FinalGateContractError(
                "invalid_binding", "final-gate receipt split union is invalid"
            )
        if (
            test.split_plan_sha256 != plan.test.split_plan_sha256
            or test.split_plan_wire_sha256 != plan.test.wire_sha256
            or train.split_plan_sha256 != plan.train.split_plan_sha256
            or train.split_plan_wire_sha256 != plan.train.wire_sha256
            or test.task_count != plan.test.task_count
            or train.task_count != plan.train.task_count
            or test.top_k != plan.top_k
            or train.top_k != plan.top_k
            or test.execution_policy_sha256
            != plan.execution_policy_sha256
            or train.execution_policy_sha256
            != plan.execution_policy_sha256
            or test.execution_policy_wire_sha256
            != plan.execution_policy_wire_sha256
            or train.execution_policy_wire_sha256
            != plan.execution_policy_wire_sha256
        ):
            raise FinalGateContractError(
                "invalid_binding", "final-gate closures are detached from the plan"
            )
        identity_pairs = (
            (test.e4_receipt_sha256, train.e4_receipt_sha256),
            (test.e4_receipt_wire_sha256, train.e4_receipt_wire_sha256),
            (test.execution_plan_sha256, train.execution_plan_sha256),
            (test.execution_plan_wire_sha256, train.execution_plan_wire_sha256),
            (test.artifact_index_sha256, train.artifact_index_sha256),
            (test.projection_manifest_sha256, train.projection_manifest_sha256),
            (test.closure_sha256, train.closure_sha256),
        )
        if any(left == right for left, right in identity_pairs):
            raise FinalGateContractError(
                "invalid_binding", "test and train closures reuse an output identity"
            )
        plan_wire = plan.to_bytes()
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "test", test)
        object.__setattr__(self, "train", train)
        object.__setattr__(self, "plan_sha256", plan.plan_sha256)
        object.__setattr__(
            self, "plan_wire_sha256", hashlib.sha256(plan_wire).hexdigest()
        )
        object.__setattr__(
            self,
            "receipt_sha256",
            hashlib.sha256(
                FINAL_GATE_RECEIPT_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > FINAL_GATE_MAX_WIRE_BYTES:
            raise FinalGateContractError(
                "limit_exceeded", "final-gate receipt exceeds its wire limit"
            )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "kind": self.kind,
            "plan": self.plan.to_dict(),
            "plan_sha256": self.plan_sha256,
            "plan_wire_sha256": self.plan_wire_sha256,
            "status": self.status,
            "test": self.test.to_dict(),
            "train": self.train.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            FINAL_GATE_RECEIPT_DIGEST_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.receipt_sha256 != expected:
            raise FinalGateContractError(
                "invalid_binding", "final-gate receipt digest changed"
            )
        return {**self._core_dict(), "receipt_sha256": self.receipt_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > FINAL_GATE_MAX_WIRE_BYTES:
            raise FinalGateContractError(
                "limit_exceeded", "final-gate receipt exceeds its wire limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "FinalGateReceiptV1":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "contract_version",
                    "kind",
                    "plan",
                    "plan_sha256",
                    "plan_wire_sha256",
                    "receipt_sha256",
                    "status",
                    "test",
                    "train",
                }
            ),
            name="final-gate receipt",
        )
        expected_receipt = _require_sha256(
            raw["receipt_sha256"], name="receipt_sha256"
        )
        expected_plan = _require_sha256(raw["plan_sha256"], name="plan_sha256")
        expected_plan_wire = _require_sha256(
            raw["plan_wire_sha256"], name="plan_wire_sha256"
        )
        plan = FinalGatePlanV1.from_dict(raw["plan"])
        if (
            plan.plan_sha256 != expected_plan
            or plan.wire_sha256 != expected_plan_wire
        ):
            raise FinalGateContractError(
                "invalid_binding", "embedded final-gate plan differs from its pins"
            )
        result = cls(
            plan=plan,
            test=FinalGateSplitReceiptClosureV1.from_dict(raw["test"]),
            train=FinalGateSplitReceiptClosureV1.from_dict(raw["train"]),
            status=raw["status"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.receipt_sha256 != expected_receipt or result.to_dict() != raw:
            raise FinalGateContractError(
                "digest_mismatch", "final-gate receipt differs from its digest"
            )
        return result

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_receipt_sha256: str,
        expected_wire_sha256: str,
    ) -> "FinalGateReceiptV1":
        semantic = _require_expected_sha256(
            expected_receipt_sha256, name="expected_receipt_sha256"
        )
        result = cls.from_dict(
            _parse_pinned_canonical_line(
                payload, expected_wire_sha256=expected_wire_sha256
            )
        )
        if result.receipt_sha256 != semantic or result.to_bytes() != payload:
            raise FinalGateContractError(
                "digest_mismatch", "final-gate receipt differs from its pin"
            )
        return result


__all__ = [
    "FINAL_GATE_CONTRACT_VERSION",
    "FINAL_GATE_MAX_JSON_DEPTH",
    "FINAL_GATE_MAX_JSON_NODES",
    "FINAL_GATE_MAX_WIRE_BYTES",
    "FINAL_GATE_EXECUTION_DIRECTORY",
    "FINAL_GATE_PLAN_FILENAME",
    "FINAL_GATE_PLAN_KIND",
    "FINAL_GATE_PROJECTION_DIRECTORY",
    "FINAL_GATE_RECEIPT_FILENAME",
    "FINAL_GATE_RECEIPT_KIND",
    "FINAL_GATE_ROOT_MEMBERS",
    "FINAL_GATE_SPLIT_MEMBERS",
    "FINAL_GATE_SPLIT_PLAN_KIND",
    "FINAL_GATE_SPLIT_RECEIPT_CLOSURE_KIND",
    "FINAL_GATE_STAGE_ORDER",
    "FINAL_GATE_STATUS",
    "FINAL_GATE_TEST_DIRECTORY",
    "FINAL_GATE_TOP_K",
    "FINAL_GATE_TRAIN_DIRECTORY",
    "FinalGateContractError",
    "FinalGatePlanV1",
    "FinalGateReceiptV1",
    "FinalGateSplitPlanV1",
    "FinalGateSplitReceiptClosureV1",
]
