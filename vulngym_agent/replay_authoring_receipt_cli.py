"""Path-free CLI for replay closure observations, approvals, and index build."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
from typing import Final, Sequence

from vulngym_agent.replay_authoring_receipt import (
    ReplayActorApprovalV1,
    ReplayAuthoringClosureReceiptV1,
    ReplayAuthoringIndexV1,
    ReplayAuthoringReceiptError,
    ReplayClosureObservationV1,
    build_replay_authoring_index_v1,
    read_pinned_approval_v1,
    read_pinned_observation_v1,
    readback_published_replay_v1,
    seal_replay_closure_receipt_v1,
)
from vulngym_agent.trusted_inputs import (
    read_attestation_key_file_v1,
    zero_secret_buffer_v1,
)


REPLAY_AUTHORING_RECEIPT_CLI_VERSION: Final[str] = (
    "replay-authoring-receipt-cli-v1"
)
EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_INTERRUPTED: Final[int] = 130

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")


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


def _add_readback_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--task-file", type=Path, required=True)
    parser.add_argument(
        "--expected-task-wire-sha256", type=_sha256, required=True
    )
    parser.add_argument("--sealed-bundle-root", type=Path, required=True)
    parser.add_argument("--published-root", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--key-id", required=True)


def _add_approval_arguments(
    parser: argparse.ArgumentParser, role: str
) -> None:
    parser.add_argument(f"--{role}-approval-file", type=Path, required=True)
    parser.add_argument(
        f"--expected-{role}-approval-sha256", type=_sha256, required=True
    )
    parser.add_argument(
        f"--expected-{role}-approval-wire-sha256", type=_sha256, required=True
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.replay_authoring_receipt_cli",
        description=(
            "Independently read replay closure, collect three actor approvals, "
            "and build the external 70-task authoring index."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    readback = commands.add_parser(
        "readback",
        help="rerun one published D2/D3 pair and emit a closure observation",
        allow_abbrev=False,
    )
    _add_readback_arguments(readback)

    approve = commands.add_parser(
        "approve",
        help="bind one actor identity and role to a pinned closure observation",
        allow_abbrev=False,
    )
    approve.add_argument("--observation-file", type=Path, required=True)
    approve.add_argument(
        "--expected-observation-sha256", type=_sha256, required=True
    )
    approve.add_argument(
        "--expected-observation-wire-sha256", type=_sha256, required=True
    )
    approve.add_argument(
        "--actor-role", choices=("author", "critic", "reviewer"), required=True
    )
    approve.add_argument("--actor-id", required=True)

    seal = commands.add_parser(
        "seal-receipt",
        help=(
            "rerun closure and seal matching author, critic, and reviewer approvals"
        ),
        allow_abbrev=False,
    )
    _add_readback_arguments(seal)
    for role in ("author", "critic", "reviewer"):
        _add_approval_arguments(seal, role)

    build_index = commands.add_parser(
        "build-index",
        help=(
            "build the fixed external index from 70 approved receipt files and "
            "public task order"
        ),
        allow_abbrev=False,
    )
    build_index.add_argument("--benchmark-root", type=Path, required=True)
    build_index.add_argument("--receipt-root", type=Path, required=True)
    return parser


def _write_stdout(value: object) -> None:
    if type(value) not in (
        ReplayClosureObservationV1,
        ReplayActorApprovalV1,
        ReplayAuthoringClosureReceiptV1,
        ReplayAuthoringIndexV1,
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


def _readback_with_key(args: argparse.Namespace) -> ReplayClosureObservationV1:
    key: bytearray | None = None
    try:
        key = read_attestation_key_file_v1(args.key_file)
        return readback_published_replay_v1(
            args.task_file,
            args.published_root,
            args.sealed_bundle_root,
            expected_task_wire_sha256=args.expected_task_wire_sha256,
            attestation_key=key,
            expected_key_id=args.key_id,
        )
    finally:
        zero_secret_buffer_v1(key)


def _approval(args: argparse.Namespace, role: str) -> ReplayActorApprovalV1:
    return read_pinned_approval_v1(
        getattr(args, f"{role}_approval_file"),
        expected_sha256=getattr(args, f"expected_{role}_approval_sha256"),
        expected_wire_sha256=getattr(
            args, f"expected_{role}_approval_wire_sha256"
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "readback":
            result: object = _readback_with_key(args)
        elif args.command == "approve":
            observation = read_pinned_observation_v1(
                args.observation_file,
                expected_sha256=args.expected_observation_sha256,
                expected_wire_sha256=args.expected_observation_wire_sha256,
            )
            result = ReplayActorApprovalV1.from_observation(
                observation,
                actor_role=args.actor_role,
                actor_id=args.actor_id,
            )
        elif args.command == "seal-receipt":
            # This is intentionally a new production replay, not a conversion
            # of the observation that the actors saw.
            observation = _readback_with_key(args)
            approvals = tuple(
                _approval(args, role)
                for role in ("author", "critic", "reviewer")
            )
            result = seal_replay_closure_receipt_v1(observation, approvals)
        else:
            result = build_replay_authoring_index_v1(
                args.benchmark_root, args.receipt_root
            )
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
