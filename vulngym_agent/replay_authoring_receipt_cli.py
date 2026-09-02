"""Path-free CLI for authenticated replay closure receipts and indexes."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from typing import Final, Sequence

from vulngym_agent.replay_authoring_receipt import (
    ReplayActorApprovalV2,
    ReplayAuthoringClosureReceiptV2,
    ReplayAuthoringIndexV2,
    ReplayAuthoringReceiptError,
    ReplayClosureObservationV2,
    ReplayTrustRegistryV2,
    build_replay_authoring_index_v2,
    read_ed25519_private_key_file_v2,
    read_pinned_approval_v2,
    read_pinned_observation_v2,
    read_pinned_trust_registry_v2,
    read_verified_task_export_v2,
    readback_published_replay_v2,
    seal_replay_closure_receipt_v2,
    verify_published_replay_observation_v2,
)
from vulngym_agent.trusted_inputs import (
    read_attestation_key_file_v1,
    zero_secret_buffer_v1,
)


REPLAY_AUTHORING_RECEIPT_CLI_VERSION: Final[str] = (
    "replay-authoring-receipt-cli-v2"
)
EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_INTERRUPTED: Final[int] = 130

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_ROLES: Final[tuple[str, ...]] = ("author", "critic", "reviewer")
_SPLITS: Final[tuple[str, ...]] = ("test", "train")


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _ = message
        self.exit(EXIT_REJECTED, "error: replay receipt arguments rejected\n")


def _sha256(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _add_key_arguments(
    parser: argparse.ArgumentParser,
    prefix: str,
    *,
    noun: str | None = None,
) -> None:
    label = noun or prefix
    parser.add_argument(f"--{prefix}-key-file", type=Path, required=True)
    parser.add_argument(f"--{prefix}-key-id", required=True)
    parser.add_argument(
        f"--expected-{prefix}-key-fingerprint",
        type=_sha256,
        required=True,
        help=f"externally registered {label} key fingerprint",
    )


def _add_trust_registry_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--trust-registry-file", type=Path, required=True)
    parser.add_argument(
        "--expected-trust-registry-sha256", type=_sha256, required=True
    )
    parser.add_argument(
        "--expected-trust-registry-wire-sha256", type=_sha256, required=True
    )


def _add_private_signing_key_argument(
    parser: argparse.ArgumentParser, prefix: str
) -> None:
    parser.add_argument(f"--{prefix}-private-key-file", type=Path, required=True)


def _add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--task-export-root", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument(
        "--expected-task-export-index-sha256", type=_sha256, required=True
    )
    parser.add_argument(
        "--expected-task-export-index-wire-sha256", type=_sha256, required=True
    )
    parser.add_argument("--sealed-batch-root", type=Path, required=True)
    parser.add_argument("--published-root", type=Path, required=True)
    _add_key_arguments(parser, "snapshot")


def _add_approval_arguments(parser: argparse.ArgumentParser, role: str) -> None:
    parser.add_argument(f"--{role}-approval-file", type=Path, required=True)
    parser.add_argument(
        f"--expected-{role}-approval-sha256", type=_sha256, required=True
    )
    parser.add_argument(
        f"--expected-{role}-approval-wire-sha256", type=_sha256, required=True
    )


def _add_split_index_arguments(
    parser: argparse.ArgumentParser, split: str
) -> None:
    parser.add_argument(f"--{split}-task-export-root", type=Path, required=True)
    parser.add_argument(
        f"--expected-{split}-task-export-index-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        f"--expected-{split}-task-export-index-wire-sha256",
        type=_sha256,
        required=True,
    )
    parser.add_argument(
        f"--expected-{split}-snapshot-key-fingerprint",
        type=_sha256,
        required=True,
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.replay_authoring_receipt_cli",
        description=(
            "Authenticate production replay readback, collect three registered "
            "actor approvals, and build the formal v2 70-task index."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    readback = commands.add_parser(
        "readback",
        help="verify one sealed task export and emit an authenticated observation",
        allow_abbrev=False,
    )
    _add_source_arguments(readback)
    _add_trust_registry_arguments(readback)
    _add_private_signing_key_argument(readback, "readback")

    approve = commands.add_parser(
        "approve",
        help="authenticate one registered actor approval over a pinned observation",
        allow_abbrev=False,
    )
    approve.add_argument("--observation-file", type=Path, required=True)
    approve.add_argument(
        "--expected-observation-sha256", type=_sha256, required=True
    )
    approve.add_argument(
        "--expected-observation-wire-sha256", type=_sha256, required=True
    )
    approve.add_argument("--actor-role", choices=_ROLES, required=True)
    _add_trust_registry_arguments(approve)
    _add_private_signing_key_argument(approve, "actor")

    seal = commands.add_parser(
        "seal-receipt",
        help="rerun readback and seal matching authenticated three-role approvals",
        allow_abbrev=False,
    )
    _add_source_arguments(seal)
    _add_trust_registry_arguments(seal)
    seal.add_argument("--observation-file", type=Path, required=True)
    seal.add_argument(
        "--expected-observation-sha256", type=_sha256, required=True
    )
    seal.add_argument(
        "--expected-observation-wire-sha256", type=_sha256, required=True
    )
    for role in _ROLES:
        _add_approval_arguments(seal, role)

    build_index = commands.add_parser(
        "build-index",
        help="build the formal v2 index from exactly 70 authenticated receipts",
        allow_abbrev=False,
    )
    build_index.add_argument("--benchmark-root", type=Path, required=True)
    build_index.add_argument("--receipt-root", type=Path, required=True)
    _add_trust_registry_arguments(build_index)
    _add_private_signing_key_argument(build_index, "index")
    for split in _SPLITS:
        _add_split_index_arguments(build_index, split)
    return parser


def _write_stdout(value: object) -> None:
    if type(value) not in (
        ReplayClosureObservationV2,
        ReplayActorApprovalV2,
        ReplayAuthoringClosureReceiptV2,
        ReplayAuthoringIndexV2,
    ):
        raise ReplayAuthoringReceiptError(
            "output_invalid", "replay receipt CLI result has an invalid type"
        )
    payload = value.to_bytes()
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload)
        binary.flush()
    else:
        sys.stdout.write(payload.decode("utf-8", errors="strict"))
        sys.stdout.flush()


def _write_error(code: str) -> None:
    try:
        sys.stderr.write(f"error[{code}]: replay receipt operation failed\n")
        sys.stderr.flush()
    except BaseException:
        pass


def _attr_prefix(prefix: str) -> str:
    return prefix.replace("-", "_")


def _load_key(args: argparse.Namespace, prefix: str) -> bytearray:
    return read_attestation_key_file_v1(
        getattr(args, f"{_attr_prefix(prefix)}_key_file")
    )


def _load_trust_registry(args: argparse.Namespace) -> ReplayTrustRegistryV2:
    return read_pinned_trust_registry_v2(
        args.trust_registry_file,
        expected_sha256=args.expected_trust_registry_sha256,
        expected_wire_sha256=args.expected_trust_registry_wire_sha256,
    )


def _load_private_signing_key(
    args: argparse.Namespace, prefix: str
) -> bytearray:
    return read_ed25519_private_key_file_v2(
        getattr(args, f"{_attr_prefix(prefix)}_private_key_file")
    )


def _readback(
    args: argparse.Namespace,
    *,
    snapshot_key: bytes | bytearray,
    readback_private_key: bytes | bytearray,
    trust_registry: ReplayTrustRegistryV2,
) -> ReplayClosureObservationV2:
    return readback_published_replay_v2(
        args.task_export_root,
        args.task_id,
        args.published_root,
        args.sealed_batch_root,
        expected_task_export_index_sha256=(
            args.expected_task_export_index_sha256
        ),
        expected_task_export_index_wire_sha256=(
            args.expected_task_export_index_wire_sha256
        ),
        snapshot_attestation_key=snapshot_key,
        expected_snapshot_key_id=args.snapshot_key_id,
        expected_snapshot_key_fingerprint=args.expected_snapshot_key_fingerprint,
        readback_private_key=readback_private_key,
        trust_registry=trust_registry,
    )


def _run_readback(args: argparse.Namespace) -> ReplayClosureObservationV2:
    snapshot_key: bytearray | None = None
    readback_private_key: bytearray | None = None
    try:
        snapshot_key = _load_key(args, "snapshot")
        readback_private_key = _load_private_signing_key(args, "readback")
        trust_registry = _load_trust_registry(args)
        return _readback(
            args,
            snapshot_key=snapshot_key,
            readback_private_key=readback_private_key,
            trust_registry=trust_registry,
        )
    finally:
        zero_secret_buffer_v1(readback_private_key)
        zero_secret_buffer_v1(snapshot_key)


def _run_approve(args: argparse.Namespace) -> ReplayActorApprovalV2:
    actor_private_key: bytearray | None = None
    try:
        actor_private_key = _load_private_signing_key(args, "actor")
        trust_registry = _load_trust_registry(args)
        observation = read_pinned_observation_v2(
            args.observation_file,
            expected_sha256=args.expected_observation_sha256,
            expected_wire_sha256=args.expected_observation_wire_sha256,
            trust_registry=trust_registry,
        )
        return ReplayActorApprovalV2.from_observation(
            observation,
            actor_role=args.actor_role,
            actor_private_key=actor_private_key,
            trust_registry=trust_registry,
        )
    finally:
        zero_secret_buffer_v1(actor_private_key)


def _run_seal(args: argparse.Namespace) -> ReplayAuthoringClosureReceiptV2:
    snapshot_key: bytearray | None = None
    try:
        snapshot_key = _load_key(args, "snapshot")
        trust_registry = _load_trust_registry(args)
        observation = read_pinned_observation_v2(
            args.observation_file,
            expected_sha256=args.expected_observation_sha256,
            expected_wire_sha256=args.expected_observation_wire_sha256,
            trust_registry=trust_registry,
        )
        verify_published_replay_observation_v2(
            observation,
            args.task_export_root,
            args.published_root,
            args.sealed_batch_root,
            expected_task_export_index_sha256=(
                args.expected_task_export_index_sha256
            ),
            expected_task_export_index_wire_sha256=(
                args.expected_task_export_index_wire_sha256
            ),
            snapshot_attestation_key=snapshot_key,
            expected_snapshot_key_id=args.snapshot_key_id,
            expected_snapshot_key_fingerprint=(
                args.expected_snapshot_key_fingerprint
            ),
            trust_registry=trust_registry,
        )
        approvals = tuple(
            read_pinned_approval_v2(
                getattr(args, f"{role}_approval_file"),
                expected_sha256=getattr(
                    args, f"expected_{role}_approval_sha256"
                ),
                expected_wire_sha256=getattr(
                    args, f"expected_{role}_approval_wire_sha256"
                ),
                trust_registry=trust_registry,
            )
            for role in _ROLES
        )
        return seal_replay_closure_receipt_v2(
            observation,
            approvals,
            trust_registry=trust_registry,
        )
    finally:
        zero_secret_buffer_v1(snapshot_key)


def _run_build_index(args: argparse.Namespace) -> ReplayAuthoringIndexV2:
    index_private_key: bytearray | None = None
    try:
        index_private_key = _load_private_signing_key(args, "index")
        trust_registry = _load_trust_registry(args)
        exports = {
            split: read_verified_task_export_v2(
                getattr(args, f"{split}_task_export_root"),
                expected_index_sha256=getattr(
                    args, f"expected_{split}_task_export_index_sha256"
                ),
                expected_index_wire_sha256=getattr(
                    args, f"expected_{split}_task_export_index_wire_sha256"
                ),
            )
            for split in _SPLITS
        }
        return build_replay_authoring_index_v2(
            args.benchmark_root,
            args.receipt_root,
            task_exports=exports,
            snapshot_key_fingerprints={
                split: getattr(
                    args, f"expected_{split}_snapshot_key_fingerprint"
                )
                for split in _SPLITS
            },
            trust_registry=trust_registry,
            index_private_key=index_private_key,
        )
    finally:
        zero_secret_buffer_v1(index_private_key)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "readback":
            result: object = _run_readback(args)
        elif args.command == "approve":
            result = _run_approve(args)
        elif args.command == "seal-receipt":
            result = _run_seal(args)
        else:
            result = _run_build_index(args)
        _write_stdout(result)
    except KeyboardInterrupt:
        _write_error("interrupted")
        return EXIT_INTERRUPTED
    except ReplayAuthoringReceiptError as error:
        _write_error(error.code)
        return EXIT_REJECTED
    except Exception:
        _write_error("input_rejected")
        return EXIT_REJECTED
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
