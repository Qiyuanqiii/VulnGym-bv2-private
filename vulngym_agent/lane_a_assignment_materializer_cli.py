"""Path-free CLI for offline Lane A assignment materialization."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Final, Sequence

from vulngym_agent.lane_a_assignment_materializer import (
    LaneAAssignmentMaterializerError,
    verify_lane_a_assignment_materialization,
    write_lane_a_assignment_materialization,
)


EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        self.exit(EXIT_REJECTED, "error: Lane A materializer arguments rejected\n")


def _digest(value: str) -> str:
    if _SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("invalid digest")
    return value


def _count(value: str) -> int:
    try:
        result = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("invalid count") from None
    if not 1 <= result <= 100_000:
        raise argparse.ArgumentTypeError("invalid count")
    return result


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--public-tasks-file", type=Path, required=True)
    parser.add_argument("--reports-file", type=Path, required=True)
    parser.add_argument("--advisory-cache-file", type=Path, required=True)
    parser.add_argument("--repo-map-file", type=Path, required=True)
    parser.add_argument("--expected-public-tasks-sha256", type=_digest, required=True)
    parser.add_argument("--expected-public-tasks-wire-sha256", type=_digest, required=True)
    parser.add_argument("--expected-reports-sha256", type=_digest, required=True)
    parser.add_argument("--expected-reports-wire-sha256", type=_digest, required=True)
    parser.add_argument("--expected-advisory-cache-sha256", type=_digest, required=True)
    parser.add_argument("--expected-advisory-cache-wire-sha256", type=_digest, required=True)
    parser.add_argument("--expected-repo-map-sha256", type=_digest, required=True)
    parser.add_argument("--expected-repo-map-wire-sha256", type=_digest, required=True)
    parser.add_argument("--expected-task-count", type=_count, required=True)
    parser.add_argument("--allow-identifier-subset-fallback", action="store_true")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="python -m vulngym_agent.lane_a_assignment_materializer_cli",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", allow_abbrev=False)
    _common(build)
    build.add_argument("--output-dir", type=Path, required=True)
    build.add_argument("--protected-path", type=Path, action="append", default=[])
    verify = commands.add_parser("verify", allow_abbrev=False)
    _common(verify)
    verify.add_argument("--materialization-dir", type=Path, required=True)
    verify.add_argument("--expected-materialization-sha256", type=_digest, required=True)
    verify.add_argument("--expected-manifest-wire-sha256", type=_digest, required=True)
    return parser


def _pins(args: argparse.Namespace) -> dict[str, object]:
    return {
        "expected_advisory_cache_sha256": args.expected_advisory_cache_sha256,
        "expected_advisory_cache_wire_sha256": args.expected_advisory_cache_wire_sha256,
        "expected_public_tasks_sha256": args.expected_public_tasks_sha256,
        "expected_public_tasks_wire_sha256": args.expected_public_tasks_wire_sha256,
        "expected_reports_sha256": args.expected_reports_sha256,
        "expected_reports_wire_sha256": args.expected_reports_wire_sha256,
        "expected_repo_map_sha256": args.expected_repo_map_sha256,
        "expected_repo_map_wire_sha256": args.expected_repo_map_wire_sha256,
        "expected_task_count": args.expected_task_count,
    }


def _inputs(args: argparse.Namespace) -> tuple[Path, Path, Path, Path]:
    return (
        args.public_tasks_file,
        args.reports_file,
        args.advisory_cache_file,
        args.repo_map_file,
    )


def _write(value: object, *, stream) -> None:
    stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    stream.flush()


def _failure(code: str, *, committed: bool) -> None:
    try:
        _write(
            {
                "code": code,
                "kind": "vulngym.lane-a-assignment-materializer-summary.v1",
                "status": "committed_uncertain" if committed else "rejected",
            },
            stream=sys.stderr,
        )
    except BaseException:
        pass


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    committed = False
    try:
        if args.command == "build":
            try:
                manifest = write_lane_a_assignment_materialization(
                    args.output_dir,
                    *_inputs(args),
                    protected_paths=args.protected_path,
                    allow_identifier_subset_fallback=args.allow_identifier_subset_fallback,
                    **_pins(args),
                )
            except LaneAAssignmentMaterializerError as error:
                committed = error.committed
                raise
            committed = True
            operation = "build"
        else:
            manifest = verify_lane_a_assignment_materialization(
                args.materialization_dir,
                *_inputs(args),
                expected_materialization_sha256=args.expected_materialization_sha256,
                expected_manifest_wire_sha256=args.expected_manifest_wire_sha256,
                allow_identifier_subset_fallback=args.allow_identifier_subset_fallback,
                **_pins(args),
            )
            operation = "verify"
        _write(
            {
                "assignments_sha256": manifest.assignments_sha256,
                "assignments_wire_sha256": manifest.assignments_wire_sha256,
                "coverage_audit_sha256": manifest.coverage_audit_sha256,
                "kind": "vulngym.lane-a-assignment-materializer-summary.v1",
                "manifest_wire_sha256": manifest.manifest_wire_sha256,
                "materialization_sha256": manifest.materialization_sha256,
                "operation": operation,
                "status": "ok",
                "task_count": manifest.task_count,
            },
            stream=sys.stdout,
        )
        return EXIT_SUCCESS
    except LaneAAssignmentMaterializerError as error:
        uncertain = committed or error.committed
        _failure(error.code if not uncertain else "committed_uncertain", committed=uncertain)
        return EXIT_COMMITTED_UNCERTAIN if uncertain else EXIT_REJECTED
    except BaseException:
        _failure("committed_uncertain" if committed else "operation_failed", committed=committed)
        return EXIT_COMMITTED_UNCERTAIN if committed else EXIT_REJECTED


if __name__ == "__main__":
    raise SystemExit(main())
