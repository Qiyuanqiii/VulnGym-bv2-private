"""Path-sanitized CLI for sealed snapshot batch preparation and verification."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Final, Sequence

from vulngym_agent.benchmark.snapshot_batch import (
    SnapshotBatchError,
    _canonical_existing_path as _batch_canonical_existing_path,
    prepare_snapshot_batch,
    verify_snapshot_batch,
)
from vulngym_agent.trusted_inputs import (
    TrustedInputError as _CliInputError,
    paths_overlap_v1 as _paths_overlap,
    read_attestation_key_file_v1 as _read_key_file,
    zero_secret_buffer_v1,
)


_SHA256_LENGTH: Final[int] = 64


def _sha256(value: str) -> str:
    if len(value) != _SHA256_LENGTH or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or verify an authenticated VulnGym source-snapshot batch."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser(
        "prepare", help="prepare all answer-free tasks and publish once"
    )
    prepare.add_argument("--task-export-dir", type=Path, required=True)
    prepare.add_argument("--expected-tasks-sha256", type=_sha256, required=True)
    prepare.add_argument(
        "--expected-public-manifest-sha256", type=_sha256, required=True
    )
    prepare.add_argument("--source-map", type=Path, required=True)
    prepare.add_argument("--expected-source-map-sha256", type=_sha256, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--key-file", type=Path, required=True)
    prepare.add_argument("--key-id", required=True)

    verify = commands.add_parser(
        "verify-batch", help="authenticate the batch and deeply verify every task"
    )
    verify.add_argument("--sealed-root", type=Path, required=True)
    verify.add_argument("--expected-manifest-sha256", type=_sha256, required=True)
    verify.add_argument("--key-file", type=Path, required=True)
    verify.add_argument("--expected-key-id", required=True)
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
    key: bytearray | None = None
    try:
        if args.command == "prepare":
            if _paths_overlap(args.output_dir, args.key_file, left_exists=False):
                raise _CliInputError("output and key paths conflict")
            key = _read_key_file(args.key_file)
            summary = prepare_snapshot_batch(
                args.task_export_dir,
                expected_tasks_sha256=args.expected_tasks_sha256,
                expected_public_manifest_sha256=args.expected_public_manifest_sha256,
                source_map_path=args.source_map,
                expected_source_map_sha256=args.expected_source_map_sha256,
                output_dir=args.output_dir,
                attestation_key=bytes(key),
                key_id=args.key_id,
            )
        else:
            # A missing or non-canonical artifact root is a verification
            # failure, while key/configuration failures remain usage errors.
            _batch_canonical_existing_path(
                args.sealed_root,
                directory=True,
                status=4,
            )
            if _paths_overlap(args.sealed_root, args.key_file, left_exists=True):
                raise _CliInputError("sealed batch and key paths conflict")
            key = _read_key_file(args.key_file)
            summary = verify_snapshot_batch(
                args.sealed_root,
                expected_manifest_sha256=args.expected_manifest_sha256,
                attestation_key=bytes(key),
                expected_key_id=args.expected_key_id,
            )
    except SnapshotBatchError as error:
        # Codes are useful to orchestration; messages remain deliberately
        # generic so OS exceptions can never disclose local absolute paths.
        print(f"error[{error.code}]: snapshot batch command failed", file=sys.stderr)
        return error.exit_status
    except (_CliInputError, ValueError, TypeError):
        print("error[input_rejected]: snapshot batch command rejected its inputs", file=sys.stderr)
        return 2
    except OSError:
        print("error[io_failed]: snapshot batch command failed", file=sys.stderr)
        return 5
    finally:
        zero_secret_buffer_v1(key)
    _print_json(summary.to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
