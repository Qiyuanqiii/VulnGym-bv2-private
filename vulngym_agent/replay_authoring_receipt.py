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

Every observation, approval, and final index carries an Ed25519 signature
whose public key is fixed by an externally double-pinned trust registry.  The
six signing purposes have distinct key IDs, raw public keys, and fingerprints;
seal and formal verification never load actor/readback private keys.  The
existing snapshot HMAC remains confined to authenticating the sealed batch.
All serialized values are canonical, single-line, path-free JSON.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
import base64
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Final, Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.harness import (
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
    load_answer_free_tasks,
)
from vulngym_agent.benchmark.snapshot_batch import (
    SnapshotBatchError,
    SnapshotBatchSummary,
    verify_snapshot_batch,
)
from vulngym_agent.evaluator.oci_worker_entry import MAX_REPLAY_RESPONSES
from vulngym_agent.evaluator.replay_authoring import (
    ReplayAuthoringPendingRequestV1,
    ReplayAuthoringSummaryV1,
    inspect_replay_authoring_v1,
)
from vulngym_agent.replay_task_response_cli import (
    DiscoveryTaskSplitExportIndexV1,
    ReplayTaskResponseError,
    VerifiedDiscoveryTaskSplitExportV1,
    read_discovery_task_split_export_v1,
)
REPLAY_CLOSURE_OBSERVATION_KIND: Final[str] = (
    "vulngym.replay-authoring-closure-observation.v2"
)
REPLAY_ACTOR_APPROVAL_KIND: Final[str] = (
    "vulngym.replay-authoring-actor-approval.v2"
)
REPLAY_CLOSURE_RECEIPT_KIND: Final[str] = (
    "vulngym.replay-authoring-closure-receipt.v2"
)
REPLAY_AUTHORING_INDEX_KIND: Final[str] = "vulngym.replay-authoring-index.v2"
REPLAY_TRUST_REGISTRY_KIND: Final[str] = (
    "vulngym.replay-authoring-trust-registry.v2"
)
REPLAY_RECEIPT_CONTRACT_VERSION: Final[int] = 2
REPLAY_RECEIPT_FILENAME_SUFFIX: Final[str] = ".receipt.json"

_OBSERVATION_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-closure-observation:v2\x00"
)
_OBSERVATION_SIGNATURE_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-closure-observation-signature:v2\x00"
)
_APPROVAL_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-actor-approval:v2\x00"
)
_APPROVAL_SIGNATURE_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-actor-approval-signature:v2\x00"
)
_RECEIPT_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-closure-receipt:v2\x00"
)
_INDEX_SIGNATURE_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-index-signature:v2\x00"
)
_TRUST_REGISTRY_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-trust-registry:v2\x00"
)
_PUBLIC_TASK_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-public-task:v1\x00"
)
# This domain and the exact six-field task records are intentionally identical
# to the already deployed replay_batch_plan_cli reader contract.
_AUTHORING_INDEX_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-index:v2\x00"
)
_KEY_FINGERPRINT_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-key-fingerprint:v2\x00"
)
_ED25519_PUBLIC_KEY_FINGERPRINT_DOMAIN: Final[bytes] = (
    b"vulngym:replay-authoring-ed25519-public-key-fingerprint:v2\x00"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_ACTOR_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z"
)
_SNAPSHOT_ID_RE: Final[re.Pattern[str]] = re.compile(r"VGS-[0-9A-F]{32}\Z")
_ACTOR_ROLES: Final[tuple[str, ...]] = ("author", "critic", "reviewer")
_MAX_OBSERVATION_BYTES: Final[int] = 64 * 1024
_MAX_APPROVAL_BYTES: Final[int] = 64 * 1024
_MAX_RECEIPT_BYTES: Final[int] = 256 * 1024
_MAX_INDEX_BYTES: Final[int] = 512 * 1024
_MAX_TRUST_REGISTRY_BYTES: Final[int] = 64 * 1024
_MIN_KEY_BYTES: Final[int] = 32
_MAX_KEY_BYTES: Final[int] = 4096
_ED25519_PRIVATE_KEY_BYTES: Final[int] = 32
_ED25519_PUBLIC_KEY_BYTES: Final[int] = 32
_ED25519_SIGNATURE_BYTES: Final[int] = 64
_TRUST_KEY_SLOTS: Final[tuple[tuple[str, str], ...]] = (
    ("actor-approval", "author"),
    ("actor-approval", "critic"),
    ("actor-approval", "reviewer"),
    ("readback-attestation", "test"),
    ("readback-attestation", "train"),
    ("authoring-index", "global"),
)


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


def _require_key_id(value: object, *, name: str) -> str:
    if type(value) is not str or _ACTOR_ID_RE.fullmatch(value) is None:
        raise ReplayAuthoringReceiptError(
            "invalid_contract", f"{name} is not a canonical key ID"
        )
    return value


def _require_key(value: object, *, name: str) -> bytes | bytearray:
    if (
        type(value) not in (bytes, bytearray)
        or not _MIN_KEY_BYTES <= len(value) <= _MAX_KEY_BYTES
    ):
        raise ReplayAuthoringReceiptError(
            "invalid_key", f"{name} is not a bounded key buffer"
        )
    return cast(bytes | bytearray, value)


def replay_key_fingerprint_v2(key: bytes | bytearray) -> str:
    """Return a domain-separated identity for one registered secret key."""

    checked = _require_key(key, name="registered key")
    digest = hashlib.sha256()
    digest.update(_KEY_FINGERPRINT_DOMAIN)
    digest.update(checked)
    return digest.hexdigest()


def _decode_canonical_base64(
    value: object, *, name: str, expected_bytes: int
) -> bytes:
    if type(value) is not str:
        raise ReplayAuthoringReceiptError(
            "invalid_contract", f"{name} is not canonical base64"
        )
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ReplayAuthoringReceiptError(
            "invalid_contract", f"{name} is not canonical base64"
        ) from None
    if (
        len(decoded) != expected_bytes
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise ReplayAuthoringReceiptError(
            "invalid_contract", f"{name} is not canonical base64"
        )
    return decoded


def replay_ed25519_public_key_fingerprint_v2(
    public_key: bytes | bytearray,
) -> str:
    """Fingerprint one raw Ed25519 public key with a dedicated domain."""

    if (
        type(public_key) not in (bytes, bytearray)
        or len(public_key) != _ED25519_PUBLIC_KEY_BYTES
    ):
        raise ReplayAuthoringReceiptError(
            "invalid_key", "Ed25519 public key must contain exactly 32 bytes"
        )
    digest = hashlib.sha256()
    digest.update(_ED25519_PUBLIC_KEY_FINGERPRINT_DOMAIN)
    digest.update(public_key)
    return digest.hexdigest()


def replay_ed25519_public_key_from_private_v2(
    private_key: bytes | bytearray,
) -> bytes:
    """Derive raw public bytes from one raw 32-byte Ed25519 private key."""

    if (
        type(private_key) not in (bytes, bytearray)
        or len(private_key) != _ED25519_PRIVATE_KEY_BYTES
    ):
        raise ReplayAuthoringReceiptError(
            "invalid_key", "Ed25519 private key must contain exactly 32 bytes"
        )
    try:
        key = Ed25519PrivateKey.from_private_bytes(private_key)
        return key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    except (TypeError, ValueError):
        raise ReplayAuthoringReceiptError(
            "invalid_key", "Ed25519 private key is invalid"
        ) from None


def _sign_ed25519(
    private_key: bytes | bytearray,
    *,
    registration: "ReplayTrustKeyRegistrationV2",
    domain: bytes,
    value: object,
) -> str:
    observed_public = replay_ed25519_public_key_from_private_v2(private_key)
    if not hmac.compare_digest(observed_public, registration.public_key_bytes):
        raise ReplayAuthoringReceiptError(
            "key_fingerprint_mismatch",
            "Ed25519 private key differs from the registered public key",
        )
    try:
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
            domain + _canonical_json(value)
        )
    except (TypeError, ValueError):
        raise ReplayAuthoringReceiptError(
            "invalid_key", "Ed25519 signing key is invalid"
        ) from None
    return base64.b64encode(signature).decode("ascii")


def _verify_ed25519(
    *,
    registration: "ReplayTrustKeyRegistrationV2",
    signature: object,
    domain: bytes,
    value: object,
    code: str,
    message: str,
) -> None:
    signature_bytes = _decode_canonical_base64(
        signature,
        name="Ed25519 signature",
        expected_bytes=_ED25519_SIGNATURE_BYTES,
    )
    try:
        Ed25519PublicKey.from_public_bytes(registration.public_key_bytes).verify(
            signature_bytes,
            domain + _canonical_json(value),
        )
    except (InvalidSignature, TypeError, ValueError):
        raise ReplayAuthoringReceiptError(code, message) from None


@dataclass(frozen=True, slots=True)
class ReplayTrustKeyRegistrationV2:
    """One purpose- and role-bound Ed25519 public verification key."""

    purpose: Literal[
        "actor-approval", "readback-attestation", "authoring-index"
    ]
    role: Literal["author", "critic", "reviewer", "test", "train", "global"]
    key_id: str
    public_key: str
    public_key_fingerprint: str

    def __post_init__(self) -> None:
        if (self.purpose, self.role) not in _TRUST_KEY_SLOTS:
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "trust key purpose/role is invalid"
            )
        _require_key_id(self.key_id, name="trust key ID")
        public_key = _decode_canonical_base64(
            self.public_key,
            name="Ed25519 public key",
            expected_bytes=_ED25519_PUBLIC_KEY_BYTES,
        )
        fingerprint = _require_sha256(
            self.public_key_fingerprint, name="public_key_fingerprint"
        )
        if not hmac.compare_digest(
            replay_ed25519_public_key_fingerprint_v2(public_key), fingerprint
        ):
            raise ReplayAuthoringReceiptError(
                "key_fingerprint_mismatch",
                "registered Ed25519 public key fingerprint differs",
            )

    @property
    def public_key_bytes(self) -> bytes:
        return _decode_canonical_base64(
            self.public_key,
            name="Ed25519 public key",
            expected_bytes=_ED25519_PUBLIC_KEY_BYTES,
        )

    @classmethod
    def from_public_key(
        cls,
        *,
        purpose: Literal[
            "actor-approval", "readback-attestation", "authoring-index"
        ],
        role: Literal[
            "author", "critic", "reviewer", "test", "train", "global"
        ],
        key_id: str,
        public_key: bytes | bytearray,
    ) -> "ReplayTrustKeyRegistrationV2":
        fingerprint = replay_ed25519_public_key_fingerprint_v2(public_key)
        return cls(
            purpose=purpose,
            role=role,
            key_id=key_id,
            public_key=base64.b64encode(public_key).decode("ascii"),
            public_key_fingerprint=fingerprint,
        )

    @classmethod
    def from_dict(cls, value: object) -> "ReplayTrustKeyRegistrationV2":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {
                    "key_id",
                    "public_key",
                    "public_key_fingerprint",
                    "purpose",
                    "role",
                }
            ),
            name="trust key registration",
        )
        return cls(**raw)

    def to_dict(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "public_key": self.public_key,
            "public_key_fingerprint": self.public_key_fingerprint,
            "purpose": self.purpose,
            "role": self.role,
        }


@dataclass(frozen=True, slots=True)
class ReplayTrustRegistryV2:
    """Externally double-pinned public verification-key policy."""

    keys: tuple[ReplayTrustKeyRegistrationV2, ...]
    contract_version: int = REPLAY_RECEIPT_CONTRACT_VERSION
    kind: str = REPLAY_TRUST_REGISTRY_KIND
    registry_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != REPLAY_RECEIPT_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_TRUST_REGISTRY_KIND
            or type(self.keys) is not tuple
            or len(self.keys) != len(_TRUST_KEY_SLOTS)
            or any(type(item) is not ReplayTrustKeyRegistrationV2 for item in self.keys)
            or tuple((item.purpose, item.role) for item in self.keys)
            != _TRUST_KEY_SLOTS
            or len({item.key_id for item in self.keys}) != len(self.keys)
            or len({item.public_key_fingerprint for item in self.keys})
            != len(self.keys)
            or len({item.public_key for item in self.keys}) != len(self.keys)
        ):
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected",
                "trust registry is incomplete, reordered, or reuses a key",
            )
        object.__setattr__(
            self,
            "registry_sha256",
            hashlib.sha256(
                _TRUST_REGISTRY_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "keys": [item.to_dict() for item in self.keys],
            "kind": self.kind,
        }

    def registration(
        self, *, purpose: str, role: str
    ) -> ReplayTrustKeyRegistrationV2:
        for registration in self.keys:
            if registration.purpose == purpose and registration.role == role:
                return registration
        raise ReplayAuthoringReceiptError(
            "trust_registry_rejected", "required trust key is not registered"
        )

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            _TRUST_REGISTRY_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.registry_sha256 != expected:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "trust registry digest changed"
            )
        return {**self._core_dict(), "registry_sha256": self.registry_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_line(self.to_dict())
        if len(payload) > _MAX_TRUST_REGISTRY_BYTES:
            raise ReplayAuthoringReceiptError(
                "limit_exceeded", "trust registry exceeds its byte limit"
            )
        return payload

    @classmethod
    def from_dict(cls, value: object) -> "ReplayTrustRegistryV2":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {"contract_version", "keys", "kind", "registry_sha256"}
            ),
            name="trust registry",
        )
        keys = raw["keys"]
        supplied = raw["registry_sha256"]
        if type(keys) is not list:
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected", "trust registry keys are invalid"
            )
        result = cls(
            keys=tuple(ReplayTrustKeyRegistrationV2.from_dict(item) for item in keys),
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if supplied != result.registry_sha256:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "trust registry digest differs"
            )
        return result

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_sha256: str,
        expected_wire_sha256: str,
    ) -> "ReplayTrustRegistryV2":
        if hashlib.sha256(payload).hexdigest() != _require_sha256(
            expected_wire_sha256, name="expected_trust_registry_wire_sha256"
        ):
            raise ReplayAuthoringReceiptError(
                "trust_registry_pin_mismatch", "trust registry wire pin differs"
            )
        result = cls.from_dict(
            _parse_canonical_line(payload, maximum_bytes=_MAX_TRUST_REGISTRY_BYTES)
        )
        if result.registry_sha256 != _require_sha256(
            expected_sha256, name="expected_trust_registry_sha256"
        ):
            raise ReplayAuthoringReceiptError(
                "trust_registry_pin_mismatch", "trust registry semantic pin differs"
            )
        return result


@dataclass(frozen=True, slots=True)
class ReplaySourceBindingV2:
    """Pinned split-export and sealed-batch authority for one observation."""

    split: Literal["test", "train"]
    task_export_index_sha256: str
    task_export_index_wire_sha256: str
    tasks_sha256: str
    public_manifest_sha256: str
    sealed_batch_manifest_sha256: str
    sealed_batch_content_root: str
    sealed_batch_key_id: str
    snapshot_key_fingerprint: str
    readback_key_id: str
    readback_key_fingerprint: str
    trust_registry_sha256: str
    trust_registry_wire_sha256: str

    def __post_init__(self) -> None:
        if type(self.split) is not str or self.split not in {"test", "train"}:
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "source binding split is invalid"
            )
        for value, name in (
            (self.task_export_index_sha256, "task_export_index_sha256"),
            (
                self.task_export_index_wire_sha256,
                "task_export_index_wire_sha256",
            ),
            (self.tasks_sha256, "tasks_sha256"),
            (self.public_manifest_sha256, "public_manifest_sha256"),
            (self.sealed_batch_manifest_sha256, "sealed_batch_manifest_sha256"),
            (self.sealed_batch_content_root, "sealed_batch_content_root"),
            (self.snapshot_key_fingerprint, "snapshot_key_fingerprint"),
            (self.readback_key_fingerprint, "readback_key_fingerprint"),
            (self.trust_registry_sha256, "trust_registry_sha256"),
            (self.trust_registry_wire_sha256, "trust_registry_wire_sha256"),
        ):
            _require_sha256(value, name=name)
        _require_key_id(self.sealed_batch_key_id, name="sealed_batch_key_id")
        _require_key_id(self.readback_key_id, name="readback_key_id")
        if self.snapshot_key_fingerprint == self.readback_key_fingerprint:
            raise ReplayAuthoringReceiptError(
                "key_reuse", "snapshot and readback keys are not independent"
            )

    @classmethod
    def from_export_index(
        cls,
        index: DiscoveryTaskSplitExportIndexV1,
        *,
        task_export_index_wire_sha256: str,
        snapshot_key_fingerprint: str,
        trust_registry: ReplayTrustRegistryV2,
    ) -> "ReplaySourceBindingV2":
        if type(index) is not DiscoveryTaskSplitExportIndexV1:
            raise ReplayAuthoringReceiptError(
                "source_binding_rejected", "task export index type is invalid"
            )
        if type(trust_registry) is not ReplayTrustRegistryV2:
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected", "trust registry type is invalid"
            )
        readback = trust_registry.registration(
            purpose="readback-attestation", role=index.split
        )
        if (
            index.sealed_batch_key_id in {item.key_id for item in trust_registry.keys}
            or snapshot_key_fingerprint
            in {item.public_key_fingerprint for item in trust_registry.keys}
        ):
            raise ReplayAuthoringReceiptError(
                "key_reuse", "snapshot HMAC identity overlaps a signing identity"
            )
        return cls(
            split=index.split,
            task_export_index_sha256=index.index_sha256,
            task_export_index_wire_sha256=_require_sha256(
                task_export_index_wire_sha256,
                name="task_export_index_wire_sha256",
            ),
            tasks_sha256=index.tasks_sha256,
            public_manifest_sha256=index.public_manifest_sha256,
            sealed_batch_manifest_sha256=index.sealed_batch_manifest_sha256,
            sealed_batch_content_root=index.sealed_batch_content_root,
            sealed_batch_key_id=index.sealed_batch_key_id,
            snapshot_key_fingerprint=snapshot_key_fingerprint,
            readback_key_id=readback.key_id,
            readback_key_fingerprint=readback.public_key_fingerprint,
            trust_registry_sha256=trust_registry.registry_sha256,
            trust_registry_wire_sha256=trust_registry.wire_sha256,
        )

    @classmethod
    def from_dict(cls, value: object) -> "ReplaySourceBindingV2":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {
                    "public_manifest_sha256",
                    "readback_key_fingerprint",
                    "readback_key_id",
                    "sealed_batch_content_root",
                    "sealed_batch_key_id",
                    "sealed_batch_manifest_sha256",
                    "snapshot_key_fingerprint",
                    "split",
                    "task_export_index_sha256",
                    "task_export_index_wire_sha256",
                    "tasks_sha256",
                    "trust_registry_sha256",
                    "trust_registry_wire_sha256",
                }
            ),
            name="source binding",
        )
        return cls(**raw)

    def to_dict(self) -> dict[str, str]:
        return {
            "public_manifest_sha256": self.public_manifest_sha256,
            "readback_key_fingerprint": self.readback_key_fingerprint,
            "readback_key_id": self.readback_key_id,
            "sealed_batch_content_root": self.sealed_batch_content_root,
            "sealed_batch_key_id": self.sealed_batch_key_id,
            "sealed_batch_manifest_sha256": self.sealed_batch_manifest_sha256,
            "snapshot_key_fingerprint": self.snapshot_key_fingerprint,
            "split": self.split,
            "task_export_index_sha256": self.task_export_index_sha256,
            "task_export_index_wire_sha256": self.task_export_index_wire_sha256,
            "tasks_sha256": self.tasks_sha256,
            "trust_registry_sha256": self.trust_registry_sha256,
            "trust_registry_wire_sha256": self.trust_registry_wire_sha256,
        }


@dataclass(frozen=True, slots=True)
class ReplayActorKeyRegistrationV2:
    actor_role: Literal["author", "critic", "reviewer"]
    actor_key_id: str
    actor_key_fingerprint: str

    def __post_init__(self) -> None:
        if type(self.actor_role) is not str or self.actor_role not in _ACTOR_ROLES:
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "actor key role is invalid"
            )
        _require_key_id(self.actor_key_id, name="actor_key_id")
        _require_sha256(self.actor_key_fingerprint, name="actor_key_fingerprint")

    @classmethod
    def from_trust_registry(
        cls,
        *,
        actor_role: Literal["author", "critic", "reviewer"],
        trust_registry: ReplayTrustRegistryV2,
    ) -> "ReplayActorKeyRegistrationV2":
        if type(trust_registry) is not ReplayTrustRegistryV2:
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected", "trust registry type is invalid"
            )
        registration = trust_registry.registration(
            purpose="actor-approval", role=actor_role
        )
        return cls(
            actor_role=actor_role,
            actor_key_id=registration.key_id,
            actor_key_fingerprint=registration.public_key_fingerprint,
        )

    @classmethod
    def from_dict(cls, value: object) -> "ReplayActorKeyRegistrationV2":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {"actor_key_fingerprint", "actor_key_id", "actor_role"}
            ),
            name="actor key registration",
        )
        return cls(**raw)

    def to_dict(self) -> dict[str, str]:
        return {
            "actor_key_fingerprint": self.actor_key_fingerprint,
            "actor_key_id": self.actor_key_id,
            "actor_role": self.actor_role,
        }


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


def _closure_observation_values_v2(
    task: DiscoveryTaskInputV1,
    summary: ReplayAuthoringSummaryV1,
    *,
    task_wire_sha256: str,
    source: ReplaySourceBindingV2,
) -> dict[str, object]:
    if (
        type(task) is not DiscoveryTaskInputV1
        or type(summary) is not ReplayAuthoringSummaryV1
        or type(source) is not ReplaySourceBindingV2
        or summary.status != "closed"
        or summary.task_id != task.task_id
        or source.split != _task_split(task.task_id)
        or summary.run_sha256 is None
        or summary.run_wire_sha256 is None
        or summary.run_outcome == "not_run"
    ):
        raise ReplayAuthoringReceiptError(
            "closure_rejected", "published replay did not close"
        )
    return {
        "task_id": task.task_id,
        "split": source.split,
        "task_wire_sha256": _require_sha256(
            task_wire_sha256, name="task_wire_sha256"
        ),
        "snapshot_id": task.snapshot_id,
        "snapshot_manifest_sha256": task.snapshot_manifest_sha256,
        "snapshot_content_root": task.snapshot_content_root,
        "public_task_sha256": public_task_sha256_v1(
            task_id=task.task_id,
            repo_url=task.repo_url,
            commit=task.commit,
            instruction_id=task.instruction_id,
            split=source.split,
        ),
        "source": source,
        "d2_sha256": summary.d2_config_sha256,
        "d2_wire_sha256": summary.d2_wire_sha256,
        "d3_sha256": summary.d3_config_sha256,
        "d3_wire_sha256": summary.d3_wire_sha256,
        "d2_response_count": summary.d2_response_count,
        "d3_response_count": summary.d3_response_count,
        "run_sha256": summary.run_sha256,
        "run_wire_sha256": summary.run_wire_sha256,
        "run_outcome": summary.run_outcome,
        "candidate_count": summary.candidate_count,
        "finding_count": summary.finding_count,
        "reviewer_verdict_count": summary.reviewer_verdict_count,
        "reviewer_accept_count": summary.reviewer_accept_count,
        "reviewer_reject_count": summary.reviewer_reject_count,
        "reviewer_defer_count": summary.reviewer_defer_count,
    }


@dataclass(frozen=True, slots=True)
class ReplayClosureObservationV2:
    """One production readback authenticated to an exact sealed task export."""

    task_id: str
    split: Literal["test", "train"]
    task_wire_sha256: str
    snapshot_id: str
    snapshot_manifest_sha256: str
    snapshot_content_root: str
    public_task_sha256: str
    source: ReplaySourceBindingV2
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
    readback_signature: str
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
            or type(self.source) is not ReplaySourceBindingV2
            or self.source.split != self.split
            or type(self.snapshot_id) is not str
            or _SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None
            or type(self.run_outcome) is not str
            or self.run_outcome not in {"d2_deferred", "d3_deferred", "finalized"}
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure observation header is invalid"
            )
        for value, name in (
            (self.task_wire_sha256, "task_wire_sha256"),
            (self.snapshot_manifest_sha256, "snapshot_manifest_sha256"),
            (self.snapshot_content_root, "snapshot_content_root"),
            (self.public_task_sha256, "public_task_sha256"),
            (self.d2_sha256, "d2_sha256"),
            (self.d2_wire_sha256, "d2_wire_sha256"),
            (self.d3_sha256, "d3_sha256"),
            (self.d3_wire_sha256, "d3_wire_sha256"),
            (self.run_sha256, "run_sha256"),
            (self.run_wire_sha256, "run_wire_sha256"),
        ):
            _require_sha256(value, name=name)
        _decode_canonical_base64(
            self.readback_signature,
            name="readback signature",
            expected_bytes=_ED25519_SIGNATURE_BYTES,
        )
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
            hashlib.sha256(
                _OBSERVATION_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _unsigned_dict(self) -> dict[str, object]:
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
            "snapshot_content_root": self.snapshot_content_root,
            "snapshot_id": self.snapshot_id,
            "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            "source": self.source.to_dict(),
            "split": self.split,
            "task_id": self.task_id,
            "task_wire_sha256": self.task_wire_sha256,
        }

    def _core_dict(self) -> dict[str, object]:
        return {
            **self._unsigned_dict(),
            "readback_signature": self.readback_signature,
        }

    def verify_readback(
        self,
        *,
        trust_registry: ReplayTrustRegistryV2,
    ) -> None:
        if type(trust_registry) is not ReplayTrustRegistryV2:
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected", "trust registry type is invalid"
            )
        registration = trust_registry.registration(
            purpose="readback-attestation", role=self.split
        )
        if (
            self.source.trust_registry_sha256 != trust_registry.registry_sha256
            or self.source.trust_registry_wire_sha256 != trust_registry.wire_sha256
            or self.source.readback_key_id != registration.key_id
            or not hmac.compare_digest(
                self.source.readback_key_fingerprint,
                registration.public_key_fingerprint,
            )
            or self.source.sealed_batch_key_id
            in {item.key_id for item in trust_registry.keys}
            or self.source.snapshot_key_fingerprint
            in {item.public_key_fingerprint for item in trust_registry.keys}
        ):
            raise ReplayAuthoringReceiptError(
                "readback_authentication_failed",
                "closure observation readback attestation is invalid",
            )
        _verify_ed25519(
            registration=registration,
            signature=self.readback_signature,
            domain=_OBSERVATION_SIGNATURE_DOMAIN,
            value=self._unsigned_dict(),
            code="readback_authentication_failed",
            message="closure observation readback attestation is invalid",
        )

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
        source: ReplaySourceBindingV2,
        readback_private_key: bytes | bytearray,
        trust_registry: ReplayTrustRegistryV2,
    ) -> "ReplayClosureObservationV2":
        values = _closure_observation_values_v2(
            task,
            summary,
            task_wire_sha256=task_wire_sha256,
            source=source,
        )
        unsigned = {
            **values,
            "contract_version": REPLAY_RECEIPT_CONTRACT_VERSION,
            "kind": REPLAY_CLOSURE_OBSERVATION_KIND,
        }
        unsigned["source"] = source.to_dict()
        if (
            type(trust_registry) is not ReplayTrustRegistryV2
            or source.trust_registry_sha256 != trust_registry.registry_sha256
            or source.trust_registry_wire_sha256 != trust_registry.wire_sha256
        ):
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected", "source does not bind the trust registry"
            )
        registration = trust_registry.registration(
            purpose="readback-attestation", role=source.split
        )
        if (
            source.readback_key_id != registration.key_id
            or source.readback_key_fingerprint
            != registration.public_key_fingerprint
        ):
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected", "source readback key is not registered"
            )
        return cls(
            **values,
            readback_signature=_sign_ed25519(
                readback_private_key,
                registration=registration,
                domain=_OBSERVATION_SIGNATURE_DOMAIN,
                value=unsigned,
            ),
        )

    @classmethod
    def from_dict(cls, value: object) -> "ReplayClosureObservationV2":
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
                "readback_signature",
                "reviewer_accept_count",
                "reviewer_defer_count",
                "reviewer_reject_count",
                "reviewer_verdict_count",
                "run_outcome",
                "run_sha256",
                "run_wire_sha256",
                "snapshot_content_root",
                "snapshot_id",
                "snapshot_manifest_sha256",
                "source",
                "split",
                "task_id",
                "task_wire_sha256",
            }
        )
        raw = _require_exact_keys(value, keys=keys, name="closure observation")
        supplied = raw.pop("observation_sha256")
        source = ReplaySourceBindingV2.from_dict(raw.pop("source"))
        result = cls(source=source, **raw)
        if supplied != result.observation_sha256:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "closure observation digest differs"
            )
        return result

    @classmethod
    def from_bytes(cls, payload: bytes) -> "ReplayClosureObservationV2":
        return cls.from_dict(
            _parse_canonical_line(payload, maximum_bytes=_MAX_OBSERVATION_BYTES)
        )


def _require_approvable(observation: ReplayClosureObservationV2) -> None:
    if (
        type(observation) is not ReplayClosureObservationV2
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
class ReplayActorApprovalV2:
    """An Ed25519 actor approval over one authenticated observation."""

    task_id: str
    split: Literal["test", "train"]
    actor_role: Literal["author", "critic", "reviewer"]
    actor_key_id: str
    actor_key_fingerprint: str
    observation_sha256: str
    approval_signature: str
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
            or type(self.decision) is not str
            or self.decision != "approve"
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "actor approval header is invalid"
            )
        _require_key_id(self.actor_key_id, name="actor_key_id")
        _require_sha256(self.actor_key_fingerprint, name="actor_key_fingerprint")
        _require_sha256(self.observation_sha256, name="observation_sha256")
        _decode_canonical_base64(
            self.approval_signature,
            name="approval signature",
            expected_bytes=_ED25519_SIGNATURE_BYTES,
        )
        object.__setattr__(
            self,
            "approval_sha256",
            hashlib.sha256(
                _APPROVAL_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _unsigned_dict(self) -> dict[str, object]:
        return {
            "actor_key_fingerprint": self.actor_key_fingerprint,
            "actor_key_id": self.actor_key_id,
            "actor_role": self.actor_role,
            "contract_version": self.contract_version,
            "decision": self.decision,
            "kind": self.kind,
            "observation_sha256": self.observation_sha256,
            "split": self.split,
            "task_id": self.task_id,
        }

    def _core_dict(self) -> dict[str, object]:
        return {
            **self._unsigned_dict(),
            "approval_signature": self.approval_signature,
        }

    @classmethod
    def from_observation(
        cls,
        observation: ReplayClosureObservationV2,
        *,
        actor_role: Literal["author", "critic", "reviewer"],
        actor_private_key: bytes | bytearray,
        trust_registry: ReplayTrustRegistryV2,
    ) -> "ReplayActorApprovalV2":
        _require_approvable(observation)
        observation.verify_readback(trust_registry=trust_registry)
        trust_key = trust_registry.registration(
            purpose="actor-approval", role=actor_role
        )
        registration = ReplayActorKeyRegistrationV2.from_trust_registry(
            actor_role=actor_role, trust_registry=trust_registry
        )
        unsigned = {
            "actor_key_fingerprint": registration.actor_key_fingerprint,
            "actor_key_id": registration.actor_key_id,
            "actor_role": registration.actor_role,
            "contract_version": REPLAY_RECEIPT_CONTRACT_VERSION,
            "decision": "approve",
            "kind": REPLAY_ACTOR_APPROVAL_KIND,
            "observation_sha256": observation.observation_sha256,
            "split": observation.split,
            "task_id": observation.task_id,
        }
        return cls(
            task_id=observation.task_id,
            split=observation.split,
            actor_role=registration.actor_role,
            actor_key_id=registration.actor_key_id,
            actor_key_fingerprint=registration.actor_key_fingerprint,
            observation_sha256=observation.observation_sha256,
            approval_signature=_sign_ed25519(
                actor_private_key,
                registration=trust_key,
                domain=_APPROVAL_SIGNATURE_DOMAIN,
                value=unsigned,
            ),
        )

    def verify_actor_signature(
        self,
        *,
        trust_registry: ReplayTrustRegistryV2,
    ) -> None:
        if type(trust_registry) is not ReplayTrustRegistryV2:
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected", "trust registry type is invalid"
            )
        registration = trust_registry.registration(
            purpose="actor-approval", role=self.actor_role
        )
        if (
            self.actor_key_id != registration.key_id
            or not hmac.compare_digest(
                self.actor_key_fingerprint,
                registration.public_key_fingerprint,
            )
        ):
            raise ReplayAuthoringReceiptError(
                "approval_authentication_failed", "actor approval key is invalid"
            )
        _verify_ed25519(
            registration=registration,
            signature=self.approval_signature,
            domain=_APPROVAL_SIGNATURE_DOMAIN,
            value=self._unsigned_dict(),
            code="approval_authentication_failed",
            message="actor approval signature is invalid",
        )

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
    def from_dict(cls, value: object) -> "ReplayActorApprovalV2":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {
                    "actor_key_fingerprint",
                    "actor_key_id",
                    "actor_role",
                    "approval_signature",
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
        supplied = raw.pop("approval_sha256")
        result = cls(**raw)
        if supplied != result.approval_sha256:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "actor approval digest differs"
            )
        return result

    @classmethod
    def from_bytes(cls, payload: bytes) -> "ReplayActorApprovalV2":
        return cls.from_dict(
            _parse_canonical_line(payload, maximum_bytes=_MAX_APPROVAL_BYTES)
        )


@dataclass(frozen=True, slots=True)
class ReplayAuthoringClosureReceiptV2:
    """Three-actor approval over one freshly re-read replay closure."""

    observation: ReplayClosureObservationV2
    approvals: tuple[ReplayActorApprovalV2, ...]
    contract_version: int = REPLAY_RECEIPT_CONTRACT_VERSION
    kind: str = REPLAY_CLOSURE_RECEIPT_KIND
    receipt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != REPLAY_RECEIPT_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_CLOSURE_RECEIPT_KIND
            or type(self.observation) is not ReplayClosureObservationV2
            or type(self.approvals) is not tuple
            or len(self.approvals) != len(_ACTOR_ROLES)
            or any(type(item) is not ReplayActorApprovalV2 for item in self.approvals)
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure receipt header is invalid"
            )
        if tuple(item.actor_role for item in self.approvals) != _ACTOR_ROLES:
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "closure receipt approval order is invalid"
            )
        _require_approvable(self.observation)
        actor_ids = tuple(item.actor_key_id for item in self.approvals)
        actor_fingerprints = tuple(
            item.actor_key_fingerprint for item in self.approvals
        )
        if (
            len(set(actor_ids)) != len(_ACTOR_ROLES)
            or len(set(actor_fingerprints)) != len(_ACTOR_ROLES)
            or self.observation.source.readback_key_fingerprint
            in actor_fingerprints
            or self.observation.source.snapshot_key_fingerprint
            in actor_fingerprints
        ):
            raise ReplayAuthoringReceiptError(
                "key_reuse", "receipt authentication keys are not independent"
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
    def from_dict(cls, value: object) -> "ReplayAuthoringClosureReceiptV2":
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
            observation=ReplayClosureObservationV2.from_dict(raw["observation"]),
            approvals=tuple(ReplayActorApprovalV2.from_dict(item) for item in approvals),
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if supplied != result.receipt_sha256:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "closure receipt digest differs"
            )
        return result

    @classmethod
    def from_bytes(cls, payload: bytes) -> "ReplayAuthoringClosureReceiptV2":
        return cls.from_dict(
            _parse_canonical_line(payload, maximum_bytes=_MAX_RECEIPT_BYTES)
        )


@dataclass(frozen=True, slots=True)
class ReplayAuthoringIndexTaskV2:
    split: Literal["test", "train"]
    task_id: str
    task_wire_sha256: str
    snapshot_id: str
    receipt_sha256: str
    receipt_wire_sha256: str
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
            (self.task_wire_sha256, "task_wire_sha256"),
            (self.receipt_sha256, "receipt_sha256"),
            (self.receipt_wire_sha256, "receipt_wire_sha256"),
            (self.d2_sha256, "d2_sha256"),
            (self.d2_wire_sha256, "d2_wire_sha256"),
            (self.d3_sha256, "d3_sha256"),
            (self.d3_wire_sha256, "d3_wire_sha256"),
        ):
            _require_sha256(value, name=name)
        if type(self.snapshot_id) is not str or _SNAPSHOT_ID_RE.fullmatch(
            self.snapshot_id
        ) is None:
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "authoring index snapshot ID is invalid"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "d2_sha256": self.d2_sha256,
            "d2_wire_sha256": self.d2_wire_sha256,
            "d3_sha256": self.d3_sha256,
            "d3_wire_sha256": self.d3_wire_sha256,
            "receipt_sha256": self.receipt_sha256,
            "receipt_wire_sha256": self.receipt_wire_sha256,
            "snapshot_id": self.snapshot_id,
            "split": self.split,
            "task_id": self.task_id,
            "task_wire_sha256": self.task_wire_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> "ReplayAuthoringIndexTaskV2":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {
                    "d2_sha256",
                    "d2_wire_sha256",
                    "d3_sha256",
                    "d3_wire_sha256",
                    "receipt_sha256",
                    "receipt_wire_sha256",
                    "snapshot_id",
                    "split",
                    "task_id",
                    "task_wire_sha256",
                }
            ),
            name="authoring index task",
        )
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class ReplayAuthoringIndexSignatureV2:
    """Signature by the independently registered index authority."""

    key_id: str
    public_key_fingerprint: str
    signature: str

    def __post_init__(self) -> None:
        _require_key_id(self.key_id, name="index signer key ID")
        _require_sha256(
            self.public_key_fingerprint, name="index signer key fingerprint"
        )
        _decode_canonical_base64(
            self.signature,
            name="index signature",
            expected_bytes=_ED25519_SIGNATURE_BYTES,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "key_id": self.key_id,
            "public_key_fingerprint": self.public_key_fingerprint,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: object) -> "ReplayAuthoringIndexSignatureV2":
        raw = _require_exact_keys(
            value,
            keys=frozenset({"key_id", "public_key_fingerprint", "signature"}),
            name="authoring index signature",
        )
        return cls(**raw)


def _authoring_index_unsigned_dict(
    sources: Sequence[ReplaySourceBindingV2],
    actor_keys: Sequence[ReplayActorKeyRegistrationV2],
    tasks: Sequence[ReplayAuthoringIndexTaskV2],
    *,
    trust_registry_sha256: str,
    trust_registry_wire_sha256: str,
    index_signer_key_id: str,
    index_signer_key_fingerprint: str,
) -> dict[str, object]:
    return {
        "actor_keys": [item.to_dict() for item in actor_keys],
        "contract_version": REPLAY_RECEIPT_CONTRACT_VERSION,
        "index_signer_key_fingerprint": index_signer_key_fingerprint,
        "index_signer_key_id": index_signer_key_id,
        "kind": REPLAY_AUTHORING_INDEX_KIND,
        "sources": [item.to_dict() for item in sources],
        "tasks": [item.to_dict() for item in tasks],
        "trust_registry_sha256": trust_registry_sha256,
        "trust_registry_wire_sha256": trust_registry_wire_sha256,
    }


@dataclass(frozen=True, slots=True)
class ReplayAuthoringIndexV2:
    """Signed receipt provenance consumed by the formal batch plan."""

    sources: tuple[ReplaySourceBindingV2, ...]
    actor_keys: tuple[ReplayActorKeyRegistrationV2, ...]
    tasks: tuple[ReplayAuthoringIndexTaskV2, ...]
    trust_registry_sha256: str
    trust_registry_wire_sha256: str
    index_signature: ReplayAuthoringIndexSignatureV2
    contract_version: int = REPLAY_RECEIPT_CONTRACT_VERSION
    kind: str = REPLAY_AUTHORING_INDEX_KIND
    index_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != REPLAY_RECEIPT_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_AUTHORING_INDEX_KIND
            or type(self.sources) is not tuple
            or len(self.sources) != 2
            or any(type(item) is not ReplaySourceBindingV2 for item in self.sources)
            or type(self.actor_keys) is not tuple
            or len(self.actor_keys) != len(_ACTOR_ROLES)
            or any(
                type(item) is not ReplayActorKeyRegistrationV2
                for item in self.actor_keys
            )
            or type(self.index_signature) is not ReplayAuthoringIndexSignatureV2
            or type(self.tasks) is not tuple
            or any(type(item) is not ReplayAuthoringIndexTaskV2 for item in self.tasks)
            or len(self.tasks) != PROFILE_TEST_TASKS + PROFILE_TRAIN_TASKS
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "authoring index header is invalid"
            )
        _require_sha256(self.trust_registry_sha256, name="trust_registry_sha256")
        _require_sha256(
            self.trust_registry_wire_sha256, name="trust_registry_wire_sha256"
        )
        expected_splits = (
            ("test",) * PROFILE_TEST_TASKS
            + ("train",) * PROFILE_TRAIN_TASKS
        )
        if (
            tuple(item.split for item in self.sources) != ("test", "train")
            or tuple(item.actor_role for item in self.actor_keys) != _ACTOR_ROLES
            or len({item.actor_key_id for item in self.actor_keys})
            != len(_ACTOR_ROLES)
            or len({item.actor_key_fingerprint for item in self.actor_keys})
            != len(_ACTOR_ROLES)
            or tuple(item.split for item in self.tasks) != expected_splits
            or len({item.task_id for item in self.tasks}) != len(self.tasks)
            or len({item.snapshot_id for item in self.tasks}) != len(self.tasks)
            or len({item.receipt_wire_sha256 for item in self.tasks})
            != len(self.tasks)
            or any(
                source.trust_registry_sha256 != self.trust_registry_sha256
                or source.trust_registry_wire_sha256
                != self.trust_registry_wire_sha256
                for source in self.sources
            )
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "authoring index task/source order is invalid"
            )
        signing_identities = {
            *(item.actor_key_id for item in self.actor_keys),
            *(source.readback_key_id for source in self.sources),
        }
        signing_fingerprints = {
            *(item.actor_key_fingerprint for item in self.actor_keys),
            *(source.readback_key_fingerprint for source in self.sources),
        }
        if (
            self.index_signature.key_id in signing_identities
            or self.index_signature.public_key_fingerprint in signing_fingerprints
        ):
            raise ReplayAuthoringReceiptError(
                "key_reuse", "index signer is reused for another purpose"
            )
        object.__setattr__(
            self,
            "index_sha256",
            hashlib.sha256(
                _AUTHORING_INDEX_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _unsigned_dict(self) -> dict[str, object]:
        return _authoring_index_unsigned_dict(
            self.sources,
            self.actor_keys,
            self.tasks,
            trust_registry_sha256=self.trust_registry_sha256,
            trust_registry_wire_sha256=self.trust_registry_wire_sha256,
            index_signer_key_id=self.index_signature.key_id,
            index_signer_key_fingerprint=(
                self.index_signature.public_key_fingerprint
            ),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            **self._unsigned_dict(),
            "index_signature": self.index_signature.signature,
        }

    def verify_trust_registry(self, trust_registry: ReplayTrustRegistryV2) -> None:
        if type(trust_registry) is not ReplayTrustRegistryV2:
            raise ReplayAuthoringReceiptError(
                "trust_registry_rejected", "trust registry type is invalid"
            )
        index_key = trust_registry.registration(
            purpose="authoring-index", role="global"
        )
        expected_actors = tuple(
            ReplayActorKeyRegistrationV2.from_trust_registry(
                actor_role=cast(
                    Literal["author", "critic", "reviewer"], role
                ),
                trust_registry=trust_registry,
            )
            for role in _ACTOR_ROLES
        )
        expected_readbacks = tuple(
            trust_registry.registration(
                purpose="readback-attestation", role=split
            )
            for split in ("test", "train")
        )
        if (
            self.trust_registry_sha256 != trust_registry.registry_sha256
            or self.trust_registry_wire_sha256 != trust_registry.wire_sha256
            or self.actor_keys != expected_actors
            or self.index_signature.key_id != index_key.key_id
            or self.index_signature.public_key_fingerprint
            != index_key.public_key_fingerprint
            or any(
                source.readback_key_id != registration.key_id
                or source.readback_key_fingerprint
                != registration.public_key_fingerprint
                for source, registration in zip(self.sources, expected_readbacks)
            )
            or any(
                source.sealed_batch_key_id
                in {item.key_id for item in trust_registry.keys}
                or source.snapshot_key_fingerprint
                in {item.public_key_fingerprint for item in trust_registry.keys}
                for source in self.sources
            )
        ):
            raise ReplayAuthoringReceiptError(
                "index_authentication_failed",
                "authoring index differs from the externally pinned trust registry",
            )
        _verify_ed25519(
            registration=index_key,
            signature=self.index_signature.signature,
            domain=_INDEX_SIGNATURE_DOMAIN,
            value=self._unsigned_dict(),
            code="index_authentication_failed",
            message="authoring index signature is invalid",
        )

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

    @classmethod
    def from_dict(cls, value: object) -> "ReplayAuthoringIndexV2":
        raw = _require_exact_keys(
            value,
            keys=frozenset(
                {
                    "actor_keys",
                    "contract_version",
                    "index_sha256",
                    "index_signature",
                    "index_signer_key_fingerprint",
                    "index_signer_key_id",
                    "kind",
                    "sources",
                    "tasks",
                    "trust_registry_sha256",
                    "trust_registry_wire_sha256",
                }
            ),
            name="authoring index",
        )
        sources = raw.pop("sources")
        actor_keys = raw.pop("actor_keys")
        tasks = raw.pop("tasks")
        signature = raw.pop("index_signature")
        signer_id = raw.pop("index_signer_key_id")
        signer_fingerprint = raw.pop("index_signer_key_fingerprint")
        supplied = raw.pop("index_sha256")
        if (
            type(sources) is not list
            or type(actor_keys) is not list
            or type(tasks) is not list
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_contract", "authoring index collections are invalid"
            )
        result = cls(
            sources=tuple(ReplaySourceBindingV2.from_dict(item) for item in sources),
            actor_keys=tuple(
                ReplayActorKeyRegistrationV2.from_dict(item) for item in actor_keys
            ),
            tasks=tuple(ReplayAuthoringIndexTaskV2.from_dict(item) for item in tasks),
            trust_registry_sha256=raw["trust_registry_sha256"],
            trust_registry_wire_sha256=raw["trust_registry_wire_sha256"],
            index_signature=ReplayAuthoringIndexSignatureV2(
                key_id=signer_id,
                public_key_fingerprint=signer_fingerprint,
                signature=signature,
            ),
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if supplied != result.index_sha256:
            raise ReplayAuthoringReceiptError(
                "digest_mismatch", "authoring index digest differs"
            )
        return result

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_sha256: str,
        expected_wire_sha256: str,
    ) -> "ReplayAuthoringIndexV2":
        if hashlib.sha256(payload).hexdigest() != _require_sha256(
            expected_wire_sha256, name="expected_index_wire_sha256"
        ):
            raise ReplayAuthoringReceiptError(
                "index_pin_mismatch", "authoring index wire pin differs"
            )
        result = cls.from_dict(
            _parse_canonical_line(payload, maximum_bytes=_MAX_INDEX_BYTES)
        )
        if result.index_sha256 != _require_sha256(
            expected_sha256, name="expected_index_sha256"
        ):
            raise ReplayAuthoringReceiptError(
                "index_pin_mismatch", "authoring index semantic pin differs"
            )
        return result


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


@dataclass(frozen=True, slots=True)
class _DirectoryGuard:
    chain: tuple[tuple[Path, tuple[int, int, int]], ...]


def _directory_chain(path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    return tuple(reversed(absolute.parents)) + (absolute,)


def _guard_directory_chain(path: Path, *, final_private: bool) -> _DirectoryGuard:
    checked: list[tuple[Path, tuple[int, int, int]]] = []
    chain = _directory_chain(path)
    for index, component in enumerate(chain):
        try:
            state = os.lstat(component)
        except OSError:
            raise ReplayAuthoringReceiptError(
                "input_unavailable", "receipt directory chain is unavailable"
            ) from None
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
            or (
                final_private
                and index == len(chain) - 1
                and os.name == "posix"
                and state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            )
        ):
            raise ReplayAuthoringReceiptError(
                "unsafe_path", "receipt directory chain is unsafe"
            )
        checked.append(
            (component, (state.st_dev, state.st_ino, state.st_mode))
        )
    return _DirectoryGuard(tuple(checked))


def _assert_directory_guard(
    guard: _DirectoryGuard, *, final_private: bool
) -> None:
    if type(guard) is not _DirectoryGuard:
        raise ReplayAuthoringReceiptError(
            "invalid_argument", "receipt directory guard is invalid"
        )
    for index, (component, expected) in enumerate(guard.chain):
        try:
            state = os.lstat(component)
        except OSError:
            raise ReplayAuthoringReceiptError(
                "input_changed", "receipt directory chain changed"
            ) from None
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
            or (state.st_dev, state.st_ino, state.st_mode) != expected
            or (
                final_private
                and index == len(guard.chain) - 1
                and os.name == "posix"
                and state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            )
        ):
            raise ReplayAuthoringReceiptError(
                "input_changed", "receipt directory chain changed"
            )


def _windows_extended_path(path: Path) -> str:
    text = os.path.abspath(os.fspath(path))
    if os.name != "nt" or text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


class _WindowsDirectoryLocks:
    """Hold no-delete handles for a Windows directory ancestry."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._handles: list[int] = []

    def acquire(self) -> None:
        if os.name != "nt":
            return
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = (
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            )
            create_file.restype = ctypes.c_void_p
            invalid = ctypes.c_void_p(-1).value
            for component in _directory_chain(self._path):
                handle = create_file(
                    _windows_extended_path(component),
                    0x0080,  # FILE_READ_ATTRIBUTES
                    0x0001 | 0x0002,  # share read/write, deliberately not delete
                    None,
                    3,  # OPEN_EXISTING
                    0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
                    None,
                )
                if handle in (None, invalid):
                    raise OSError(ctypes.get_last_error(), "CreateFileW failed")
                self._handles.append(int(handle))
        except (KeyboardInterrupt, SystemExit):
            self.close()
            raise
        except Exception:
            self.close()
            raise ReplayAuthoringReceiptError(
                "unsafe_path", "Windows receipt directory could not be locked"
            ) from None

    def close(self) -> None:
        if not self._handles:
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (ctypes.c_void_p,)
        close_handle.restype = ctypes.c_int
        while self._handles:
            close_handle(ctypes.c_void_p(self._handles.pop()))


def _validate_private_regular_state(
    value: os.stat_result, *, maximum_bytes: int
) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or value.st_nlink != 1
        or not 1 <= value.st_size <= maximum_bytes
        or (os.name == "posix" and value.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise ReplayAuthoringReceiptError(
            "unsafe_path", "receipt input is not a bounded private regular file"
        )


def _read_open_descriptor(
    descriptor: int, *, expected: os.stat_result, maximum_bytes: int
) -> bytes:
    opened = os.fstat(descriptor)
    if _file_identity(opened) != _file_identity(expected):
        raise ReplayAuthoringReceiptError(
            "input_changed", "receipt input changed before reading"
        )
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        raise ReplayAuthoringReceiptError(
            "input_unavailable", "receipt input could not be positioned"
        ) from None
    chunks: list[bytes] = []
    consumed = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - consumed))
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
    return b"".join(chunks)


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
    guard = _guard_directory_chain(path.parent, final_private=False)
    try:
        before = os.lstat(path)
    except OSError:
        raise ReplayAuthoringReceiptError(
            "input_unavailable", "receipt input file is unavailable"
        ) from None
    _validate_private_regular_state(before, maximum_bytes=maximum_bytes)
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
        payload = _read_open_descriptor(
            descriptor, expected=opened, maximum_bytes=maximum_bytes
        )
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError:
        raise ReplayAuthoringReceiptError(
            "input_changed", "receipt input changed after reading"
        ) from None
    _assert_directory_guard(guard, final_private=False)
    if _file_identity(after) != _file_identity(before):
        raise ReplayAuthoringReceiptError(
            "input_changed", "receipt input changed after reading"
        )
    return payload


def read_pinned_trust_registry_v2(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    expected_wire_sha256: str,
) -> ReplayTrustRegistryV2:
    """Read the externally held public-key policy under semantic/wire pins."""

    payload = _read_private_regular(
        Path(os.path.abspath(os.fspath(path))),
        maximum_bytes=_MAX_TRUST_REGISTRY_BYTES,
    )
    return ReplayTrustRegistryV2.from_bytes(
        payload,
        expected_sha256=expected_sha256,
        expected_wire_sha256=expected_wire_sha256,
    )


def read_ed25519_private_key_file_v2(
    path: str | os.PathLike[str],
) -> bytearray:
    """Read one raw private signing key from a private, stable regular file."""

    payload = _read_private_regular(
        Path(os.path.abspath(os.fspath(path))),
        maximum_bytes=_ED25519_PRIVATE_KEY_BYTES,
    )
    if len(payload) != _ED25519_PRIVATE_KEY_BYTES:
        raise ReplayAuthoringReceiptError(
            "invalid_key", "Ed25519 private key file must contain exactly 32 bytes"
        )
    return bytearray(payload)


class _ReceiptDirectoryReader(AbstractContextManager["_ReceiptDirectoryReader"]):
    """Hold the exact receipt directory and all expected members while reading."""

    def __init__(self, root: Path, expected_names: frozenset[str]) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.expected_names = expected_names
        self._guard: _DirectoryGuard | None = None
        self._root_descriptor: int | None = None
        self._windows_locks = _WindowsDirectoryLocks(self.root)
        self._descriptors: dict[str, tuple[int, os.stat_result]] = {}
        self._payloads: dict[str, bytes] = {}
        self._root_identity: tuple[int, ...] | None = None

    def _names(self) -> frozenset[str]:
        try:
            if self._root_descriptor is not None and os.name == "posix":
                names = frozenset(os.listdir(self._root_descriptor))
            else:
                names = frozenset(item.name for item in os.scandir(self.root))
        except OSError:
            raise ReplayAuthoringReceiptError(
                "input_unavailable", "receipt directory could not be enumerated"
            ) from None
        if names != self.expected_names:
            raise ReplayAuthoringReceiptError(
                "receipt_set_mismatch", "receipt directory membership is invalid"
            )
        return names

    def _member_state(self, name: str) -> os.stat_result:
        try:
            if self._root_descriptor is not None and os.name == "posix":
                return os.stat(
                    name,
                    dir_fd=self._root_descriptor,
                    follow_symlinks=False,
                )
            return os.lstat(self.root / name)
        except OSError:
            raise ReplayAuthoringReceiptError(
                "input_unavailable", "receipt member is unavailable"
            ) from None

    def _open_member(self, name: str) -> tuple[int, os.stat_result]:
        before = self._member_state(name)
        _validate_private_regular_state(before, maximum_bytes=_MAX_RECEIPT_BYTES)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            if self._root_descriptor is not None and os.name == "posix":
                descriptor = os.open(name, flags, dir_fd=self._root_descriptor)
            else:
                descriptor = os.open(self.root / name, flags)
        except OSError:
            raise ReplayAuthoringReceiptError(
                "input_unavailable", "receipt member could not be opened"
            ) from None
        opened = os.fstat(descriptor)
        if _file_binding_identity(opened) != _file_binding_identity(before):
            os.close(descriptor)
            raise ReplayAuthoringReceiptError(
                "input_changed", "receipt member changed while opening"
            )
        return descriptor, opened

    def __enter__(self) -> "_ReceiptDirectoryReader":
        if (
            not self.expected_names
            or any(
                type(name) is not str
                or Path(name).name != name
                or name in {".", ".."}
                for name in self.expected_names
            )
        ):
            raise ReplayAuthoringReceiptError(
                "invalid_argument", "expected receipt membership is invalid"
            )
        self._guard = _guard_directory_chain(self.root, final_private=True)
        try:
            if os.name == "nt":
                self._windows_locks.acquire()
            else:
                if (
                    os.open not in os.supports_dir_fd
                    or os.stat not in os.supports_dir_fd
                    or os.listdir not in os.supports_fd
                ):
                    raise ReplayAuthoringReceiptError(
                        "unsupported_platform",
                        "secure receipt directory handles are unavailable",
                    )
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                self._root_descriptor = os.open(self.root, flags)
            root_state = (
                os.fstat(self._root_descriptor)
                if self._root_descriptor is not None
                else os.lstat(self.root)
            )
            if (
                not stat.S_ISDIR(root_state.st_mode)
                or stat.S_ISLNK(root_state.st_mode)
                or _is_reparse(root_state)
            ):
                raise ReplayAuthoringReceiptError(
                    "unsafe_path", "receipt directory handle is unsafe"
                )
            self._root_identity = _directory_identity(root_state)
            self._names()
            for name in sorted(self.expected_names):
                self._descriptors[name] = self._open_member(name)
            self._names()
            self._assert_bound()
            return self
        except BaseException:
            self.close()
            raise

    def read(self, name: str) -> bytes:
        if name not in self._descriptors:
            raise ReplayAuthoringReceiptError(
                "receipt_set_mismatch", "receipt member was not pre-opened"
            )
        descriptor, expected = self._descriptors[name]
        payload = _read_open_descriptor(
            descriptor, expected=expected, maximum_bytes=_MAX_RECEIPT_BYTES
        )
        previous = self._payloads.setdefault(name, payload)
        if previous != payload:
            raise ReplayAuthoringReceiptError(
                "input_changed", "receipt member changed across reads"
            )
        return payload

    def _assert_bound(self) -> None:
        if self._guard is None or self._root_identity is None:
            raise ReplayAuthoringReceiptError(
                "invalid_argument", "receipt directory reader is not open"
            )
        _assert_directory_guard(self._guard, final_private=True)
        root_state = (
            os.fstat(self._root_descriptor)
            if self._root_descriptor is not None
            else os.lstat(self.root)
        )
        if _directory_identity(root_state) != self._root_identity:
            raise ReplayAuthoringReceiptError(
                "input_changed", "receipt directory identity changed"
            )
        self._names()
        for name, (descriptor, expected) in self._descriptors.items():
            if _file_identity(os.fstat(descriptor)) != _file_identity(expected):
                raise ReplayAuthoringReceiptError(
                    "input_changed", "receipt member handle changed"
                )
            if _file_binding_identity(
                self._member_state(name)
            ) != _file_binding_identity(expected):
                raise ReplayAuthoringReceiptError(
                    "input_changed", "receipt member path changed"
                )

    def verify(self) -> None:
        self._assert_bound()
        for name in sorted(self.expected_names):
            self.read(name)
        self._assert_bound()

    def close(self) -> None:
        while self._descriptors:
            _name, (descriptor, _state) = self._descriptors.popitem()
            try:
                os.close(descriptor)
            except OSError:
                pass
        if self._root_descriptor is not None:
            try:
                os.close(self._root_descriptor)
            except OSError:
                pass
            self._root_descriptor = None
        self._windows_locks.close()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        _ = exc_type, exc_value, traceback
        self.close()


def read_verified_task_export_v2(
    root: str | os.PathLike[str],
    *,
    expected_index_sha256: str,
    expected_index_wire_sha256: str,
) -> VerifiedDiscoveryTaskSplitExportV1:
    try:
        return read_discovery_task_split_export_v1(
            root,
            expected_index_sha256=expected_index_sha256,
            expected_index_wire_sha256=expected_index_wire_sha256,
        )
    except ReplayAuthoringReceiptError:
        raise
    except ReplayTaskResponseError:
        raise ReplayAuthoringReceiptError(
            "task_export_rejected", "authenticated task split export was rejected"
        ) from None
    except Exception:
        raise ReplayAuthoringReceiptError(
            "task_export_rejected", "authenticated task split export could not be read"
        ) from None


def _assert_batch_export_binding(
    export: VerifiedDiscoveryTaskSplitExportV1,
    batch: SnapshotBatchSummary,
) -> None:
    if (
        type(export) is not VerifiedDiscoveryTaskSplitExportV1
        or type(batch) is not SnapshotBatchSummary
    ):
        raise ReplayAuthoringReceiptError(
            "source_binding_rejected", "source authority types are invalid"
        )
    index = export.index
    if (
        batch.split != index.split
        or batch.task_count != len(export.tasks)
        or batch.tasks_sha256 != index.tasks_sha256
        or batch.public_manifest_sha256 != index.public_manifest_sha256
        or batch.manifest_sha256 != index.sealed_batch_manifest_sha256
        or batch.batch_content_root != index.sealed_batch_content_root
        or batch.key_id != index.sealed_batch_key_id
        or tuple(item.task_id for item in batch.tasks)
        != tuple(item.task_id for item in export.tasks)
    ):
        raise ReplayAuthoringReceiptError(
            "source_binding_rejected",
            "sealed batch differs from its authenticated task export",
        )
    for task, member, pin in zip(export.tasks, batch.tasks, index.tasks):
        if (
            task.task_id != member.task_id
            or task.repo_url != member.repo_url
            or task.commit != member.commit
            or task.instruction_id != member.instruction_id
            or task.snapshot_manifest_sha256 != member.snapshot_manifest_sha256
            or task.snapshot_content_root != member.snapshot_content_root
            or task.task_id != pin.task_id
            or task.snapshot_id != pin.snapshot_id
        ):
            raise ReplayAuthoringReceiptError(
                "source_binding_rejected",
                "sealed task differs from its authenticated export",
            )


def _readback_published_replay_summary_v2(
    task_export_root: str | os.PathLike[str],
    task_id: str,
    published_root: str | os.PathLike[str],
    sealed_batch_root: str | os.PathLike[str],
    *,
    expected_task_export_index_sha256: str,
    expected_task_export_index_wire_sha256: str,
    snapshot_attestation_key: bytes | bytearray,
    expected_snapshot_key_id: str,
    expected_snapshot_key_fingerprint: str,
    trust_registry: ReplayTrustRegistryV2,
) -> tuple[
    DiscoveryTaskInputV1,
    ReplayAuthoringSummaryV1,
    str,
    ReplaySourceBindingV2,
]:

    if type(task_id) is not str or _TASK_ID_RE.fullmatch(task_id) is None:
        raise ReplayAuthoringReceiptError("invalid_argument", "task ID is invalid")
    snapshot_fingerprint = replay_key_fingerprint_v2(snapshot_attestation_key)
    if not hmac.compare_digest(
        snapshot_fingerprint,
        _require_sha256(
            expected_snapshot_key_fingerprint,
            name="expected_snapshot_key_fingerprint",
        ),
    ):
        raise ReplayAuthoringReceiptError(
            "key_fingerprint_mismatch", "snapshot key fingerprint differs"
        )
    if type(trust_registry) is not ReplayTrustRegistryV2:
        raise ReplayAuthoringReceiptError(
            "trust_registry_rejected", "trust registry type is invalid"
        )
    snapshot_key_id = _require_key_id(
        expected_snapshot_key_id, name="expected_snapshot_key_id"
    )
    export = read_verified_task_export_v2(
        task_export_root,
        expected_index_sha256=expected_task_export_index_sha256,
        expected_index_wire_sha256=expected_task_export_index_wire_sha256,
    )
    if export.index.sealed_batch_key_id != snapshot_key_id:
        raise ReplayAuthoringReceiptError(
            "source_binding_rejected", "snapshot key ID differs from task export"
        )
    try:
        batch = verify_snapshot_batch(
            sealed_batch_root,
            expected_manifest_sha256=export.index.sealed_batch_manifest_sha256,
            attestation_key=snapshot_attestation_key,
            expected_key_id=snapshot_key_id,
        )
    except SnapshotBatchError:
        raise ReplayAuthoringReceiptError(
            "sealed_batch_rejected", "sealed batch authentication failed"
        ) from None
    except Exception:
        raise ReplayAuthoringReceiptError(
            "sealed_batch_rejected", "sealed batch could not be verified"
        ) from None
    _assert_batch_export_binding(export, batch)
    try:
        ordinal = tuple(item.task_id for item in export.tasks).index(task_id)
    except ValueError:
        raise ReplayAuthoringReceiptError(
            "source_binding_rejected", "task is absent from authenticated export"
        ) from None
    task = export.tasks[ordinal]
    pin = export.index.tasks[ordinal]
    member = batch.tasks[ordinal]
    source = ReplaySourceBindingV2.from_export_index(
        export.index,
        task_export_index_wire_sha256=export.index.wire_sha256,
        snapshot_key_fingerprint=snapshot_fingerprint,
        trust_registry=trust_registry,
    )
    try:
        step = inspect_replay_authoring_v1(
            task,
            batch.batch_root.joinpath(*member.bundle_path.split("/")),
            published_root,
            attestation_key=snapshot_attestation_key,
            expected_key_id=snapshot_key_id,
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
    return task, step, pin.task_wire_sha256, source


def readback_published_replay_v2(
    task_export_root: str | os.PathLike[str],
    task_id: str,
    published_root: str | os.PathLike[str],
    sealed_batch_root: str | os.PathLike[str],
    *,
    expected_task_export_index_sha256: str,
    expected_task_export_index_wire_sha256: str,
    snapshot_attestation_key: bytes | bytearray,
    expected_snapshot_key_id: str,
    expected_snapshot_key_fingerprint: str,
    readback_private_key: bytes | bytearray,
    trust_registry: ReplayTrustRegistryV2,
) -> ReplayClosureObservationV2:
    """Authenticate source, execute production readback, and sign its facts."""

    task, summary, task_wire_sha256, source = (
        _readback_published_replay_summary_v2(
            task_export_root,
            task_id,
            published_root,
            sealed_batch_root,
            expected_task_export_index_sha256=(
                expected_task_export_index_sha256
            ),
            expected_task_export_index_wire_sha256=(
                expected_task_export_index_wire_sha256
            ),
            snapshot_attestation_key=snapshot_attestation_key,
            expected_snapshot_key_id=expected_snapshot_key_id,
            expected_snapshot_key_fingerprint=(
                expected_snapshot_key_fingerprint
            ),
            trust_registry=trust_registry,
        )
    )
    return ReplayClosureObservationV2.from_summary(
        task,
        summary,
        task_wire_sha256=task_wire_sha256,
        source=source,
        readback_private_key=readback_private_key,
        trust_registry=trust_registry,
    )


def verify_published_replay_observation_v2(
    observation: ReplayClosureObservationV2,
    task_export_root: str | os.PathLike[str],
    published_root: str | os.PathLike[str],
    sealed_batch_root: str | os.PathLike[str],
    *,
    expected_task_export_index_sha256: str,
    expected_task_export_index_wire_sha256: str,
    snapshot_attestation_key: bytes | bytearray,
    expected_snapshot_key_id: str,
    expected_snapshot_key_fingerprint: str,
    trust_registry: ReplayTrustRegistryV2,
) -> None:
    """Rerun production readback and match a public-key-signed observation."""

    if type(observation) is not ReplayClosureObservationV2:
        raise ReplayAuthoringReceiptError(
            "invalid_argument", "closure observation has an invalid type"
        )
    observation.verify_readback(trust_registry=trust_registry)
    task, summary, task_wire_sha256, source = (
        _readback_published_replay_summary_v2(
            task_export_root,
            observation.task_id,
            published_root,
            sealed_batch_root,
            expected_task_export_index_sha256=(
                expected_task_export_index_sha256
            ),
            expected_task_export_index_wire_sha256=(
                expected_task_export_index_wire_sha256
            ),
            snapshot_attestation_key=snapshot_attestation_key,
            expected_snapshot_key_id=expected_snapshot_key_id,
            expected_snapshot_key_fingerprint=(
                expected_snapshot_key_fingerprint
            ),
            trust_registry=trust_registry,
        )
    )
    expected_values = _closure_observation_values_v2(
        task,
        summary,
        task_wire_sha256=task_wire_sha256,
        source=source,
    )
    expected_unsigned = {
        **expected_values,
        "contract_version": REPLAY_RECEIPT_CONTRACT_VERSION,
        "kind": REPLAY_CLOSURE_OBSERVATION_KIND,
    }
    expected_unsigned["source"] = source.to_dict()
    if observation._unsigned_dict() != expected_unsigned:
        raise ReplayAuthoringReceiptError(
            "closure_changed",
            "signed closure observation differs from the fresh production readback",
        )


def read_pinned_observation_v2(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    expected_wire_sha256: str,
    trust_registry: ReplayTrustRegistryV2,
) -> ReplayClosureObservationV2:
    payload = _read_private_regular(
        Path(os.path.abspath(os.fspath(path))), maximum_bytes=_MAX_OBSERVATION_BYTES
    )
    if hashlib.sha256(payload).hexdigest() != _require_sha256(
        expected_wire_sha256, name="expected_observation_wire_sha256"
    ):
        raise ReplayAuthoringReceiptError(
            "observation_pin_mismatch", "closure observation wire pin differs"
        )
    result = ReplayClosureObservationV2.from_bytes(payload)
    if result.observation_sha256 != _require_sha256(
        expected_sha256, name="expected_observation_sha256"
    ):
        raise ReplayAuthoringReceiptError(
            "observation_pin_mismatch", "closure observation semantic pin differs"
        )
    result.verify_readback(trust_registry=trust_registry)
    return result


def read_pinned_approval_v2(
    path: str | os.PathLike[str],
    *,
    expected_sha256: str,
    expected_wire_sha256: str,
    trust_registry: ReplayTrustRegistryV2,
) -> ReplayActorApprovalV2:
    payload = _read_private_regular(
        Path(os.path.abspath(os.fspath(path))), maximum_bytes=_MAX_APPROVAL_BYTES
    )
    if hashlib.sha256(payload).hexdigest() != _require_sha256(
        expected_wire_sha256, name="expected_approval_wire_sha256"
    ):
        raise ReplayAuthoringReceiptError(
            "approval_pin_mismatch", "actor approval wire pin differs"
        )
    result = ReplayActorApprovalV2.from_bytes(payload)
    if result.approval_sha256 != _require_sha256(
        expected_sha256, name="expected_approval_sha256"
    ):
        raise ReplayAuthoringReceiptError(
            "approval_pin_mismatch", "actor approval semantic pin differs"
        )
    result.verify_actor_signature(trust_registry=trust_registry)
    return result


def _registration_map(
    registrations: Sequence[ReplayActorKeyRegistrationV2],
) -> dict[str, ReplayActorKeyRegistrationV2]:
    if type(registrations) not in (tuple, list):
        raise ReplayAuthoringReceiptError(
            "invalid_argument", "actor registrations have an invalid type"
        )
    result: dict[str, ReplayActorKeyRegistrationV2] = {}
    for registration in registrations:
        if (
            type(registration) is not ReplayActorKeyRegistrationV2
            or registration.actor_role in result
        ):
            raise ReplayAuthoringReceiptError(
                "approval_rejected", "actor registrations are incomplete or duplicated"
            )
        result[registration.actor_role] = registration
    if frozenset(result) != frozenset(_ACTOR_ROLES):
        raise ReplayAuthoringReceiptError(
            "approval_rejected", "all three registered actor keys are required"
        )
    if (
        len({item.actor_key_id for item in result.values()}) != len(_ACTOR_ROLES)
        or len({item.actor_key_fingerprint for item in result.values()})
        != len(_ACTOR_ROLES)
    ):
        raise ReplayAuthoringReceiptError(
            "key_reuse", "registered actor keys are not independent"
        )
    return result


def authenticate_replay_closure_receipt_v2(
    receipt: ReplayAuthoringClosureReceiptV2,
    *,
    trust_registry: ReplayTrustRegistryV2,
) -> None:
    if type(receipt) is not ReplayAuthoringClosureReceiptV2:
        raise ReplayAuthoringReceiptError(
            "invalid_argument", "closure receipt has an invalid type"
        )
    if type(trust_registry) is not ReplayTrustRegistryV2:
        raise ReplayAuthoringReceiptError(
            "trust_registry_rejected", "trust registry type is invalid"
        )
    receipt.observation.verify_readback(trust_registry=trust_registry)
    for approval in receipt.approvals:
        approval.verify_actor_signature(trust_registry=trust_registry)


def seal_replay_closure_receipt_v2(
    observation: ReplayClosureObservationV2,
    approvals: Sequence[ReplayActorApprovalV2],
    *,
    trust_registry: ReplayTrustRegistryV2,
) -> ReplayAuthoringClosureReceiptV2:
    """Verify public-key readback and actor signatures before sealing."""

    if type(observation) is not ReplayClosureObservationV2:
        raise ReplayAuthoringReceiptError(
            "invalid_argument", "closure observation has an invalid type"
        )
    if type(approvals) not in (tuple, list):
        raise ReplayAuthoringReceiptError(
            "invalid_argument", "approval collection has an invalid type"
        )
    by_role: dict[str, ReplayActorApprovalV2] = {}
    for approval in approvals:
        if type(approval) is not ReplayActorApprovalV2 or approval.actor_role in by_role:
            raise ReplayAuthoringReceiptError(
                "approval_rejected", "approval roles are incomplete or duplicated"
            )
        by_role[approval.actor_role] = approval
    if frozenset(by_role) != frozenset(_ACTOR_ROLES):
        raise ReplayAuthoringReceiptError(
            "approval_rejected", "all three approval roles are required"
        )
    receipt = ReplayAuthoringClosureReceiptV2(
        observation=observation,
        approvals=tuple(by_role[role] for role in _ACTOR_ROLES),
    )
    authenticate_replay_closure_receipt_v2(
        receipt,
        trust_registry=trust_registry,
    )
    return receipt


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


def build_replay_authoring_index_v2(
    benchmark_root: str | os.PathLike[str],
    receipt_root: str | os.PathLike[str],
    *,
    task_exports: Mapping[str, VerifiedDiscoveryTaskSplitExportV1],
    snapshot_key_fingerprints: Mapping[str, str],
    trust_registry: ReplayTrustRegistryV2,
    index_private_key: bytes | bytearray,
) -> ReplayAuthoringIndexV2:
    """Build the formal 70-task index from authenticated v2 receipts.

    ``task_exports`` must already have been verified against externally held
    semantic and wire pins.  This function deliberately accepts no raw source
    map and derives no authority from the receipt directory itself.
    """

    split_keys = frozenset({"test", "train"})
    supplied_mappings: tuple[tuple[object, str], ...] = (
        (task_exports, "task exports"),
        (snapshot_key_fingerprints, "snapshot key fingerprints"),
    )
    for value, name in supplied_mappings:
        if type(value) is not dict or frozenset(value) != split_keys:
            raise ReplayAuthoringReceiptError(
                "invalid_argument", f"{name} must contain exactly test and train"
            )
    if type(trust_registry) is not ReplayTrustRegistryV2:
        raise ReplayAuthoringReceiptError(
            "trust_registry_rejected", "trust registry type is invalid"
        )
    registrations = _registration_map(
        tuple(
            ReplayActorKeyRegistrationV2.from_trust_registry(
                actor_role=cast(
                    Literal["author", "critic", "reviewer"], role
                ),
                trust_registry=trust_registry,
            )
            for role in _ACTOR_ROLES
        )
    )
    index_registration = trust_registry.registration(
        purpose="authoring-index", role="global"
    )

    exports: dict[str, VerifiedDiscoveryTaskSplitExportV1] = {}
    sources: dict[str, ReplaySourceBindingV2] = {}
    for split in ("test", "train"):
        export = task_exports[split]
        if (
            type(export) is not VerifiedDiscoveryTaskSplitExportV1
            or export.index.split != split
        ):
            raise ReplayAuthoringReceiptError(
                "source_binding_rejected", "task export split authority is invalid"
            )
        snapshot_fingerprint = _require_sha256(
            snapshot_key_fingerprints[split],
            name=f"{split}_snapshot_key_fingerprint",
        )
        exports[split] = export
        sources[split] = ReplaySourceBindingV2.from_export_index(
            export.index,
            task_export_index_wire_sha256=export.index.wire_sha256,
            snapshot_key_fingerprint=snapshot_fingerprint,
            trust_registry=trust_registry,
        )

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
    by_split_public: dict[str, list[object]] = {"test": [], "train": []}
    for split, task in public_tasks:
        by_split_public[split].append(task)
    for split in ("test", "train"):
        export = exports[split]
        public = by_split_public[split]
        if (
            len(public) != len(export.tasks)
            or tuple(getattr(item, "task_id", None) for item in public)
            != tuple(item.task_id for item in export.tasks)
        ):
            raise ReplayAuthoringReceiptError(
                "source_binding_rejected",
                "authenticated task export differs from public task order",
            )
        for benchmark_task, exported_task, pin in zip(
            public, export.tasks, export.index.tasks
        ):
            if (
                _public_task_digest(benchmark_task, split=split)  # type: ignore[arg-type]
                != public_task_sha256_v1(
                    task_id=exported_task.task_id,
                    repo_url=exported_task.repo_url,
                    commit=exported_task.commit,
                    instruction_id=exported_task.instruction_id,
                    split=split,  # type: ignore[arg-type]
                )
                or pin.task_id != exported_task.task_id
                or pin.snapshot_id != exported_task.snapshot_id
            ):
                raise ReplayAuthoringReceiptError(
                    "source_binding_rejected",
                    "authenticated task export differs from public task identity",
                )

    root = Path(os.path.abspath(os.fspath(receipt_root)))
    expected_names = frozenset(
        f"{task_id}{REPLAY_RECEIPT_FILENAME_SUFFIX}" for task_id in task_ids
    )
    bindings: list[ReplayAuthoringIndexTaskV2] = []
    export_positions = {
        split: {
            task.task_id: (task, export.index.tasks[ordinal])
            for ordinal, task in enumerate(export.tasks)
        }
        for split, export in exports.items()
    }
    with _ReceiptDirectoryReader(root, expected_names) as reader:
        for split_value, task in public_tasks:
            split = cast(Literal["test", "train"], split_value)
            task_id = str(getattr(task, "task_id"))
            exported_task, pin = export_positions[split][task_id]
            payload = reader.read(
                f"{task_id}{REPLAY_RECEIPT_FILENAME_SUFFIX}"
            )
            receipt = ReplayAuthoringClosureReceiptV2.from_bytes(payload)
            observation = receipt.observation
            if (
                observation.task_id != task_id
                or observation.split != split
                or observation.public_task_sha256
                != _public_task_digest(task, split=split)
                or observation.source != sources[split]
                or observation.task_wire_sha256 != pin.task_wire_sha256
                or observation.snapshot_id != exported_task.snapshot_id
                or observation.snapshot_manifest_sha256
                != exported_task.snapshot_manifest_sha256
                or observation.snapshot_content_root
                != exported_task.snapshot_content_root
            ):
                raise ReplayAuthoringReceiptError(
                    "receipt_binding_mismatch",
                    "approved receipt differs from authenticated public source",
                )
            authenticate_replay_closure_receipt_v2(
                receipt,
                trust_registry=trust_registry,
            )
            bindings.append(
                ReplayAuthoringIndexTaskV2(
                    split=split,
                    task_id=task_id,
                    task_wire_sha256=observation.task_wire_sha256,
                    snapshot_id=observation.snapshot_id,
                    receipt_sha256=receipt.receipt_sha256,
                    receipt_wire_sha256=hashlib.sha256(payload).hexdigest(),
                    d2_sha256=observation.d2_sha256,
                    d2_wire_sha256=observation.d2_wire_sha256,
                    d3_sha256=observation.d3_sha256,
                    d3_wire_sha256=observation.d3_wire_sha256,
                )
            )
        reader.verify()
    ordered_sources = tuple(sources[split] for split in ("test", "train"))
    ordered_actors = tuple(registrations[role] for role in _ACTOR_ROLES)
    ordered_tasks = tuple(bindings)
    unsigned = _authoring_index_unsigned_dict(
        ordered_sources,
        ordered_actors,
        ordered_tasks,
        trust_registry_sha256=trust_registry.registry_sha256,
        trust_registry_wire_sha256=trust_registry.wire_sha256,
        index_signer_key_id=index_registration.key_id,
        index_signer_key_fingerprint=index_registration.public_key_fingerprint,
    )
    index_signature = ReplayAuthoringIndexSignatureV2(
        key_id=index_registration.key_id,
        public_key_fingerprint=index_registration.public_key_fingerprint,
        signature=_sign_ed25519(
            index_private_key,
            registration=index_registration,
            domain=_INDEX_SIGNATURE_DOMAIN,
            value=unsigned,
        ),
    )
    return ReplayAuthoringIndexV2(
        sources=ordered_sources,
        actor_keys=ordered_actors,
        tasks=ordered_tasks,
        trust_registry_sha256=trust_registry.registry_sha256,
        trust_registry_wire_sha256=trust_registry.wire_sha256,
        index_signature=index_signature,
    )


__all__ = [
    "REPLAY_ACTOR_APPROVAL_KIND",
    "REPLAY_AUTHORING_INDEX_KIND",
    "REPLAY_CLOSURE_OBSERVATION_KIND",
    "REPLAY_CLOSURE_RECEIPT_KIND",
    "REPLAY_RECEIPT_CONTRACT_VERSION",
    "REPLAY_RECEIPT_FILENAME_SUFFIX",
    "ReplayActorApprovalV2",
    "ReplayActorKeyRegistrationV2",
    "ReplayAuthoringClosureReceiptV2",
    "ReplayAuthoringIndexSignatureV2",
    "ReplayAuthoringIndexTaskV2",
    "ReplayAuthoringIndexV2",
    "ReplayAuthoringReceiptError",
    "ReplayClosureObservationV2",
    "ReplaySourceBindingV2",
    "ReplayTrustKeyRegistrationV2",
    "ReplayTrustRegistryV2",
    "authenticate_replay_closure_receipt_v2",
    "build_replay_authoring_index_v2",
    "public_task_sha256_v1",
    "read_pinned_approval_v2",
    "read_pinned_observation_v2",
    "read_pinned_trust_registry_v2",
    "read_ed25519_private_key_file_v2",
    "read_verified_task_export_v2",
    "readback_published_replay_v2",
    "replay_key_fingerprint_v2",
    "replay_ed25519_public_key_fingerprint_v2",
    "replay_ed25519_public_key_from_private_v2",
    "seal_replay_closure_receipt_v2",
    "verify_published_replay_observation_v2",
]
