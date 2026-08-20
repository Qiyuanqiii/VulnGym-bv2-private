"""Command-line boundary for the pinned public benchmark harness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from vulngym_agent.benchmark.harness import (
    BenchmarkHarnessError,
    DEFAULT_TOP_K,
    MAX_TOP_K,
    export_answer_free_tasks,
    project_verified_replay_bundles,
    validate_public_bundle,
)


def _top_k(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("top-k must be an integer") from None
    if not 1 <= parsed <= MAX_TOP_K:
        raise argparse.ArgumentTypeError(
            f"top-k must be between 1 and {MAX_TOP_K}"
        )
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and export the pinned VulnGym 50/20 public profile."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser(
        "validate", help="validate the five-file public profile allowlist"
    )
    validate.add_argument("--benchmark-root", type=Path, required=True)

    export = commands.add_parser(
        "export-tasks", help="transactionally export answer-free snapshot tasks"
    )
    export.add_argument("--benchmark-root", type=Path, required=True)
    export.add_argument("--split", choices=("train", "test"), required=True)
    export.add_argument("--output-dir", type=Path, required=True)

    for name, help_text in (
        ("project-train", "verify replay bundles, project, and run the train oracle"),
        ("project-test", "verify replay bundles and create a blind submission"),
    ):
        project = commands.add_parser(name, help=help_text)
        project.add_argument("--benchmark-root", type=Path, required=True)
        project.add_argument("--artifact-root", type=Path, required=True)
        project.add_argument("--bundle-index", type=Path, required=True)
        project.add_argument("--bundle-index-sha256", required=True)
        project.add_argument("--output-dir", type=Path, required=True)
        project.add_argument("--top-k", type=_top_k, default=DEFAULT_TOP_K)
    return parser


def _print_json(value: object) -> None:
    print(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            summary = validate_public_bundle(args.benchmark_root)
        elif args.command == "export-tasks":
            summary = export_answer_free_tasks(
                args.benchmark_root,
                split=args.split,
                output_dir=args.output_dir,
            )
        else:
            summary = project_verified_replay_bundles(
                args.benchmark_root,
                artifact_root=args.artifact_root,
                bundle_index=args.bundle_index,
                bundle_index_sha256=args.bundle_index_sha256,
                output_dir=args.output_dir,
                split="train" if args.command == "project-train" else "test",
                top_k=args.top_k,
            )
    except BenchmarkHarnessError as error:
        print(f"error[{error.code}]: {error}", file=sys.stderr)
        return 2
    except (ValueError, OSError):
        # Boundary failures stay path-free even when an operating system
        # exception embeds the caller's absolute path.
        print("error: benchmark command rejected its inputs", file=sys.stderr)
        return 2
    _print_json(summary.to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
