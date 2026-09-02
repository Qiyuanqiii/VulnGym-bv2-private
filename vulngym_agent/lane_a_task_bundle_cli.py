"""Path-free CLI for building and independently verifying Lane A task bundles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Final, Sequence

from vulngym_agent.lane_a_task_bundle import (
    LaneATaskBundleError,
    verify_lane_a_task_bundle,
    write_lane_a_task_bundle,
)

EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        self.exit(EXIT_REJECTED, "error: lane A bundle arguments rejected\n")


def _digest(value: str) -> str:
    if _SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("invalid digest")
    return value


def _positive_count(value: str) -> int:
    try:
        result = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid count") from None
    if not 1 <= result <= 100_000:
        raise argparse.ArgumentTypeError("invalid count")
    return result


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--public-tasks-file", type=Path, required=True)
    parser.add_argument("--assignments-file", type=Path, required=True)
    parser.add_argument("--expected-public-tasks-sha256", type=_digest, required=True)
    parser.add_argument("--expected-public-tasks-wire-sha256", type=_digest, required=True)
    parser.add_argument("--expected-assignments-sha256", type=_digest, required=True)
    parser.add_argument("--expected-assignments-wire-sha256", type=_digest, required=True)
    parser.add_argument("--expected-task-count", type=_positive_count, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="python -m vulngym_agent.lane_a_task_bundle_cli", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", allow_abbrev=False)
    _common(build)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--protected-path", type=Path, action="append", default=[])
    verify = commands.add_parser("verify", allow_abbrev=False)
    _common(verify)
    verify.add_argument("--bundle-dir", type=Path, required=True)
    verify.add_argument("--expected-bundle-sha256", type=_digest, required=True)
    verify.add_argument("--expected-manifest-wire-sha256", type=_digest, required=True)
    return parser


def _common_values(args: argparse.Namespace) -> dict[str, object]:
    return {
        "expected_public_tasks_sha256": args.expected_public_tasks_sha256,
        "expected_public_tasks_wire_sha256": args.expected_public_tasks_wire_sha256,
        "expected_assignments_sha256": args.expected_assignments_sha256,
        "expected_assignments_wire_sha256": args.expected_assignments_wire_sha256,
        "expected_task_count": args.expected_task_count,
    }


def _write_stdout(value: object) -> None:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    sys.stdout.write(payload + "\n")
    sys.stdout.flush()


def _write_error(code: str, *, committed: bool) -> None:
    summary = {
        "code": code,
        "kind": "vulngym.lane-a-task-bundle-summary.v1",
        "status": "committed_uncertain" if committed else "rejected",
    }
    try:
        payload = json.dumps(summary, sort_keys=True, separators=(",", ":"))
        sys.stderr.write(payload + "\n")
        sys.stderr.flush()
    except BaseException:
        pass


def _run_build(args: argparse.Namespace, mutation_state: list[bool]):
    """Run the writer while retaining its post-publication state for stdout."""

    mutation_state[0] = True
    try:
        return write_lane_a_task_bundle(
            args.output_dir,
            args.public_tasks_file,
            args.assignments_file,
            protected_paths=args.protected_path,
            **_common_values(args),
        )
    except LaneATaskBundleError as error:
        mutation_state[0] = error.committed
        raise
    except BaseException:
        # The core converts every post-commit failure to a committed error.
        mutation_state[0] = False
        raise


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    mutation_state = [False]
    try:
        if args.command == "build":
            manifest = _run_build(args, mutation_state)
            summary = {
                "bundle_sha256": manifest.bundle_sha256,
                "kind": "vulngym.lane-a-task-bundle-summary.v1",
                "manifest_wire_sha256": manifest.wire_sha256,
                "operation": "build",
                "split": manifest.split,
                "status": "ok",
                "task_count": manifest.task_count,
            }
        else:
            bundle = verify_lane_a_task_bundle(
                args.bundle_dir,
                args.public_tasks_file,
                args.assignments_file,
                expected_bundle_sha256=args.expected_bundle_sha256,
                expected_manifest_wire_sha256=args.expected_manifest_wire_sha256,
                **_common_values(args),
            )
            summary = {
                "bundle_sha256": bundle.manifest.bundle_sha256,
                "kind": "vulngym.lane-a-task-bundle-summary.v1",
                "manifest_wire_sha256": bundle.manifest.wire_sha256,
                "operation": "verify",
                "split": bundle.manifest.split,
                "status": "ok",
                "task_count": bundle.manifest.task_count,
            }
        _write_stdout(summary)
        return EXIT_SUCCESS
    except LaneATaskBundleError as error:
        committed = error.committed or mutation_state[0]
        _write_error(
            error.code if error.committed or not mutation_state[0] else "committed_uncertain",
            committed=committed,
        )
        return EXIT_COMMITTED_UNCERTAIN if committed else EXIT_REJECTED
    except BaseException:
        committed = mutation_state[0]
        _write_error(
            "committed_uncertain" if committed else "operation_failed",
            committed=committed,
        )
        return EXIT_COMMITTED_UNCERTAIN if committed else EXIT_REJECTED


if __name__ == "__main__":
    raise SystemExit(main())
