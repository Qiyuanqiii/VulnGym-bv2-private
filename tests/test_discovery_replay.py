from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_reviewer_contracts import _finalized, _review_input, _seal
from vulngym_agent.benchmark.discovery_contracts import DiscoveryCandidate
from vulngym_agent.benchmark.producer_contracts import ProducerDeferredV1
from vulngym_agent.benchmark.reviewer_contracts import ReviewerDeferredV1
from vulngym_agent.benchmark.reviewer_projection import project_discovery_run_v1
from vulngym_agent.orchestrator.discovery_pipeline import SourceDiscoveryRunV1
import vulngym_agent.orchestrator.discovery_replay as replay_module
from vulngym_agent.orchestrator.discovery_replay import (
    DEFAULT_DISCOVERY_REPLAY_LIMITS,
    DISCOVERY_REPLAY_FILES,
    DiscoveryReplayError,
    DiscoveryReplayLimits,
    VerifiedDiscoveryRun,
    VerifiedDiscoveryResult,
    read_discovery_run_bundle,
    read_discovery_result_bundle,
    write_discovery_result_bundle,
)


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _finalized_run() -> SourceDiscoveryRunV1:
    reviewer = _finalized(3)
    producer = reviewer.review_input.producer_draft
    return SourceDiscoveryRunV1(
        producer_result=producer,
        reviewer_result=reviewer,
        discovery_result=project_discovery_run_v1(producer, reviewer),
    )


def _d2_deferred_run(*, missing: str = "source evidence is incomplete") -> SourceDiscoveryRunV1:
    task = _review_input(0).producer_draft.task
    producer = ProducerDeferredV1(
        task=task,
        stage="SCOUT",
        reason_code="model_error",
        missing_information=(missing,),
    )
    return SourceDiscoveryRunV1(
        producer_result=producer,
        reviewer_result=None,
        discovery_result=project_discovery_run_v1(producer, None),
    )


def _d3_deferred_run() -> SourceDiscoveryRunV1:
    review_input = _review_input(0)
    producer = review_input.producer_draft
    reviewer = ReviewerDeferredV1(
        review_input=review_input,
        stage="REVIEW",
        reason_code="runtime.model_failed",
        missing_information=("model_response",),
        attempt_seal=_seal(review_input, ()),
    )
    return SourceDiscoveryRunV1(
        producer_result=producer,
        reviewer_result=reviewer,
        discovery_result=project_discovery_run_v1(producer, reviewer),
    )


class DiscoveryReplayTests(unittest.TestCase):
    def _write(self, parent: Path, name: str, run: SourceDiscoveryRunV1):
        output = parent / name
        verified = write_discovery_result_bundle(output, run)
        return output, verified

    def test_finalized_round_trip_is_deterministic_and_exact(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            first, written = self._write(parent, "first", run)
            second, repeated = self._write(parent, "second", run)

            self.assertEqual(set(DISCOVERY_REPLAY_FILES), {item.name for item in first.iterdir()})
            self.assertEqual(written, repeated)
            self.assertEqual(run.discovery_result, written.result)
            self.assertEqual(
                written,
                read_discovery_result_bundle(
                    first,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id=run.task_id,
                ),
            )
            for name in DISCOVERY_REPLAY_FILES:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            self.assertEqual(1, (first / "producer.jsonl").read_bytes().count(b"\n"))
            self.assertEqual(1, (first / "reviewer.jsonl").read_bytes().count(b"\n"))
            self.assertEqual(1, (first / "manifest.jsonl").read_bytes().count(b"\n"))

    def test_richer_reader_returns_the_complete_canonical_run(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            output, written = self._write(Path(temporary), "bundle", run)
            verified = read_discovery_run_bundle(
                output,
                expected_dataset_sha256=written.dataset_sha256,
                expected_task_id=run.task_id,
            )

        self.assertIsInstance(verified, VerifiedDiscoveryRun)
        self.assertEqual(verified.dataset_sha256, written.dataset_sha256)
        self.assertEqual(verified.run, run)
        self.assertIsNot(verified.run, run)
        self.assertEqual(verified.result, run.discovery_result)
        self.assertEqual(verified.run.run_sha256, run.run_sha256)
        self.assertEqual(
            hashlib.sha256(verified.run.to_wire()).hexdigest(),
            hashlib.sha256(run.to_wire()).hexdigest(),
        )
        self.assertEqual(
            hashlib.sha256(
                replay_module._canonical_json(verified.run.discovery_result.to_dict())
            ).hexdigest(),
            hashlib.sha256(
                replay_module._canonical_json(run.discovery_result.to_dict())
            ).hexdigest(),
        )

    def test_legacy_result_wrapper_performs_only_one_bundle_read(self) -> None:
        run = _d2_deferred_run()
        with tempfile.TemporaryDirectory() as temporary:
            output, written = self._write(Path(temporary), "bundle", run)
            real_read = replay_module._read_stable_file
            reads: list[str] = []

            def tracked(path: Path, **kwargs):
                reads.append(path.name)
                return real_read(path, **kwargs)

            with mock.patch.object(
                replay_module, "_read_stable_file", side_effect=tracked
            ):
                verified = read_discovery_result_bundle(
                    output,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id=run.task_id,
                )

        self.assertEqual(reads, list(DISCOVERY_REPLAY_FILES))
        self.assertEqual(verified.result, run.discovery_result)

    def test_d2_and_d3_deferred_branch_shapes_round_trip(self) -> None:
        for name, run, reviewer_lines in (
            ("d2", _d2_deferred_run(), 0),
            ("d3", _d3_deferred_run(), 1),
        ):
            with self.subTest(branch=name), tempfile.TemporaryDirectory() as temporary:
                output, written = self._write(Path(temporary), "bundle", run)
                self.assertEqual(
                    reviewer_lines,
                    (output / "reviewer.jsonl").read_bytes().count(b"\n"),
                )
                readback = read_discovery_result_bundle(
                    output,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id=run.task_id,
                )
                self.assertEqual("deferred", readback.result.status)
                self.assertEqual(run.discovery_result, readback.result)

    def test_expected_digest_and_task_binding_are_required(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            output, written = self._write(Path(temporary), "bundle", run)
            with self.assertRaises(DiscoveryReplayError) as digest_error:
                read_discovery_result_bundle(
                    output,
                    expected_dataset_sha256="f" * 64,
                    expected_task_id=run.task_id,
                )
            self.assertEqual("digest_mismatch", digest_error.exception.code)

            with self.assertRaises(DiscoveryReplayError) as task_error:
                read_discovery_result_bundle(
                    output,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id="VG-TEST-FFFFFFFFFFFFFFFFFFFF",
                )
            self.assertEqual("binding_mismatch", task_error.exception.code)

    def test_reader_normalizes_descriptor_failures_without_path_text(self) -> None:
        run = _finalized_run()
        for operation in ("fstat", "read", "close"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                output, written = self._write(Path(temporary), "bundle", run)
                original = getattr(os, operation)

                def fail(*args, **kwargs):
                    if operation == "close":
                        original(*args, **kwargs)
                    raise OSError(5, "INJECTED_PATH")

                with mock.patch.object(os, operation, side_effect=fail):
                    with self.assertRaises(DiscoveryReplayError) as captured:
                        read_discovery_result_bundle(
                            output,
                            expected_dataset_sha256=written.dataset_sha256,
                            expected_task_id=run.task_id,
                        )
                self.assertEqual("bundle_unavailable", captured.exception.code)
                self.assertNotIn("INJECTED_PATH", str(captured.exception))

    def test_writer_preflights_nested_run_graph_before_serialization(self) -> None:
        for lane in ("d2", "d3", "d0"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as temporary:
                run = _finalized_run()
                original = run.producer_result.candidates[0]
                calls: list[str] = []

                class ExplodingCandidate(DiscoveryCandidate):
                    armed = False

                    def to_dict(self):
                        if type(self).armed:
                            calls.append(lane)
                            raise AssertionError("nested serializer executed")
                        return super().to_dict()

                evil = ExplodingCandidate(
                    task_id=original.task_id,
                    snapshot_id=original.snapshot_id,
                    repo_url=original.repo_url,
                    commit=original.commit,
                    entry_point=original.entry_point,
                    critical_operation=original.critical_operation,
                    trace=original.trace,
                    relationship_evidence_refs=original.relationship_evidence_refs,
                    source_evidence_refs=original.source_evidence_refs,
                    contract_version=original.contract_version,
                )
                ExplodingCandidate.armed = True
                if lane == "d2":
                    object.__setattr__(run.producer_result, "candidates", (evil,))
                elif lane == "d3":
                    object.__setattr__(
                        run.reviewer_result.review_input.producer_draft,
                        "candidates",
                        (evil,),
                    )
                else:
                    object.__setattr__(run.discovery_result, "candidates", (evil,))

                output = Path(temporary) / "bundle"
                with self.assertRaises(DiscoveryReplayError) as captured:
                    write_discovery_result_bundle(output, run)
                self.assertEqual("invalid_result", captured.exception.code)
                self.assertEqual([], calls)
                self.assertFalse(output.exists())

    def test_verified_result_preflights_nested_d0_before_serialization(self) -> None:
        result = _finalized_run().discovery_result
        original = result.candidates[0]
        calls: list[str] = []

        class ExplodingCandidate(DiscoveryCandidate):
            armed = False

            def to_dict(self):
                if type(self).armed:
                    calls.append("d0")
                    raise AssertionError("nested serializer executed")
                return super().to_dict()

        evil = ExplodingCandidate(
            task_id=original.task_id,
            snapshot_id=original.snapshot_id,
            repo_url=original.repo_url,
            commit=original.commit,
            entry_point=original.entry_point,
            critical_operation=original.critical_operation,
            trace=original.trace,
            relationship_evidence_refs=original.relationship_evidence_refs,
            source_evidence_refs=original.source_evidence_refs,
            contract_version=original.contract_version,
        )
        ExplodingCandidate.armed = True
        object.__setattr__(result, "candidates", (evil,))
        with self.assertRaisesRegex(ValueError, "verified discovery result"):
            VerifiedDiscoveryResult("f" * 64, result)
        self.assertEqual([], calls)

    def test_verified_run_preflights_nested_d0_before_serialization(self) -> None:
        run = _finalized_run()
        result = run.discovery_result
        original = result.candidates[0]
        calls: list[str] = []

        class ExplodingCandidate(DiscoveryCandidate):
            armed = False

            def to_dict(self):
                if type(self).armed:
                    calls.append("d0")
                    raise AssertionError("nested serializer executed")
                return super().to_dict()

        evil = ExplodingCandidate(
            task_id=original.task_id,
            snapshot_id=original.snapshot_id,
            repo_url=original.repo_url,
            commit=original.commit,
            entry_point=original.entry_point,
            critical_operation=original.critical_operation,
            trace=original.trace,
            relationship_evidence_refs=original.relationship_evidence_refs,
            source_evidence_refs=original.source_evidence_refs,
            contract_version=original.contract_version,
        )
        ExplodingCandidate.armed = True
        object.__setattr__(result, "candidates", (evil,))
        with self.assertRaisesRegex(ValueError, "verified discovery run"):
            VerifiedDiscoveryRun("f" * 64, run)
        self.assertEqual([], calls)

        mutated_digest = _d2_deferred_run()
        object.__setattr__(mutated_digest, "run_sha256", "f" * 64)
        with self.assertRaisesRegex(ValueError, "verified discovery run"):
            VerifiedDiscoveryRun("f" * 64, mutated_digest)

    def test_writer_rejects_a_mutated_run_digest(self) -> None:
        run = _d2_deferred_run()
        object.__setattr__(run, "run_sha256", "f" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(output, run)
            self.assertEqual("binding_mismatch", captured.exception.code)
            self.assertFalse(output.exists())

        missing = _d2_deferred_run()
        object.__delattr__(missing, "run_sha256")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(output, missing)
            self.assertEqual("invalid_result", captured.exception.code)
            self.assertFalse(output.exists())

    def test_manifest_digest_tamper_and_noncanonical_json_are_rejected(self) -> None:
        run = _d2_deferred_run()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            digest_bundle, written = self._write(parent, "digest", run)
            manifest_path = digest_bundle / "manifest.jsonl"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["dataset_sha256"] = "f" * 64
            manifest_path.write_bytes(_canonical_line(manifest))
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    digest_bundle,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id=run.task_id,
                )
            self.assertEqual("digest_mismatch", captured.exception.code)

            noncanonical, noncanonical_written = self._write(parent, "pretty", run)
            manifest_path = noncanonical / "manifest.jsonl"
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest_path.write_text(
                json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    noncanonical,
                    expected_dataset_sha256=noncanonical_written.dataset_sha256,
                    expected_task_id=run.task_id,
                )
            self.assertEqual("noncanonical_json", captured.exception.code)

    def test_valid_d2_tamper_is_reprojected_and_rejected(self) -> None:
        run = _d2_deferred_run()
        with tempfile.TemporaryDirectory() as temporary:
            output, written = self._write(Path(temporary), "bundle", run)
            producer_path = output / "producer.jsonl"
            producer = json.loads(producer_path.read_text(encoding="utf-8"))
            producer["reason_code"] = "model_blocked"
            producer_path.write_bytes(_canonical_line(producer))
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    output,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id=run.task_id,
                )
            self.assertIn(captured.exception.code, {"binding_mismatch", "digest_mismatch"})

    def test_missing_extra_and_wrong_branch_files_are_rejected(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            extra, extra_written = self._write(parent, "extra", run)
            (extra / "unexpected.jsonl").write_bytes(b"")
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    extra,
                    expected_dataset_sha256=extra_written.dataset_sha256,
                    expected_task_id=run.task_id,
                )
            self.assertEqual("layout_invalid", captured.exception.code)

            missing, missing_written = self._write(parent, "missing", run)
            (missing / "reviewer.jsonl").unlink()
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    missing,
                    expected_dataset_sha256=missing_written.dataset_sha256,
                    expected_task_id=run.task_id,
                )
            self.assertEqual("layout_invalid", captured.exception.code)

            d2_run = _d2_deferred_run()
            wrong, wrong_written = self._write(parent, "wrong", d2_run)
            (wrong / "reviewer.jsonl").write_bytes(
                _finalized().to_wire() + b"\n"
            )
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    wrong,
                    expected_dataset_sha256=wrong_written.dataset_sha256,
                    expected_task_id=d2_run.task_id,
                )
            self.assertEqual("invalid_result", captured.exception.code)

    def test_symlink_member_is_rejected_when_supported(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output, written = self._write(parent, "bundle", run)
            external = parent / "external.jsonl"
            producer = output / "producer.jsonl"
            external.write_bytes(producer.read_bytes())
            producer.unlink()
            try:
                producer.symlink_to(external)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    output,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id=run.task_id,
                )
            self.assertEqual("unsafe_path", captured.exception.code)

    def test_reparse_paths_are_rejected_deterministically(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            output, written = self._write(Path(temporary), "bundle", run)
            with mock.patch.object(replay_module, "_is_reparse", return_value=True):
                with self.assertRaises(DiscoveryReplayError) as captured:
                    read_discovery_result_bundle(
                        output,
                        expected_dataset_sha256=written.dataset_sha256,
                        expected_task_id=run.task_id,
                    )
            self.assertEqual("unsafe_path", captured.exception.code)

    def test_writer_and_reader_enforce_narrowable_limits(self) -> None:
        run = _finalized_run()
        tiny = DiscoveryReplayLimits(max_line_bytes=128, max_total_bytes=1_024)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(parent / "too-small", run, limits=tiny)
            self.assertEqual("limit_exceeded", captured.exception.code)
            self.assertFalse((parent / "too-small").exists())

            output, written = self._write(parent, "bundle", run)
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    output,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id=run.task_id,
                    limits=tiny,
                )
            self.assertEqual("limit_exceeded", captured.exception.code)

            mutated = DiscoveryReplayLimits(
                max_line_bytes=128, max_total_bytes=1_024
            )
            object.__setattr__(mutated, "max_line_bytes", -1)
            with self.assertRaises(DiscoveryReplayError) as captured:
                read_discovery_result_bundle(
                    output,
                    expected_dataset_sha256=written.dataset_sha256,
                    expected_task_id=run.task_id,
                    limits=mutated,
                )
            self.assertEqual("invalid_argument", captured.exception.code)

    def test_mutated_exported_default_limits_do_not_change_runtime_defaults(self) -> None:
        run = _d2_deferred_run()
        original_line = DEFAULT_DISCOVERY_REPLAY_LIMITS.max_line_bytes
        original_total = DEFAULT_DISCOVERY_REPLAY_LIMITS.max_total_bytes
        object.__setattr__(
            DEFAULT_DISCOVERY_REPLAY_LIMITS,
            "max_line_bytes",
            original_line + 1,
        )
        object.__setattr__(
            DEFAULT_DISCOVERY_REPLAY_LIMITS,
            "max_total_bytes",
            original_total + 1,
        )
        try:
            active = replay_module._active_limits(None)
            self.assertIsNot(DEFAULT_DISCOVERY_REPLAY_LIMITS, active)
            self.assertEqual(original_line, active.max_line_bytes)
            self.assertEqual(original_total, active.max_total_bytes)
            with tempfile.TemporaryDirectory() as temporary:
                output, written = self._write(Path(temporary), "bundle", run)
                self.assertEqual(run.discovery_result, written.result)
                self.assertTrue(output.is_dir())
        finally:
            object.__setattr__(
                DEFAULT_DISCOVERY_REPLAY_LIMITS, "max_line_bytes", original_line
            )
            object.__setattr__(
                DEFAULT_DISCOVERY_REPLAY_LIMITS, "max_total_bytes", original_total
            )

    def test_protected_paths_reject_overlap_and_payload_leak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            protected = parent / "protected"
            protected.mkdir()
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(
                    protected / "bundle",
                    _d2_deferred_run(),
                    protected_paths=(protected,),
                )
            self.assertEqual("protected_path", captured.exception.code)

            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(
                    parent / "bad-collection",
                    _d2_deferred_run(),
                    protected_paths=str(protected),  # type: ignore[arg-type]
                )
            self.assertEqual("invalid_argument", captured.exception.code)

            leaked = _d2_deferred_run(missing=f"missing source at {protected}")
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(
                    parent / "leak",
                    leaked,
                    protected_paths=(protected,),
                )
            self.assertEqual("protected_path", captured.exception.code)

    def test_protected_pathlike_is_snapshotted_once_before_use(self) -> None:
        class FlippingPath:
            def __init__(self, first: Path, later: Path) -> None:
                self.first = first
                self.later = later
                self.calls = 0

            def __fspath__(self) -> str:
                self.calls += 1
                return str(self.first if self.calls == 1 else self.later)

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            protected = parent / "protected"
            protected.mkdir()
            flipping = FlippingPath(protected, parent / "unprotected")
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(
                    protected / "bundle",
                    _d2_deferred_run(),
                    protected_paths=(flipping,),
                )
            self.assertEqual("protected_path", captured.exception.code)
            self.assertEqual(1, flipping.calls)

    def test_exceptional_protected_pathlike_is_rejected(self) -> None:
        class BrokenPath:
            def __fspath__(self) -> str:
                raise RuntimeError("path state changed")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(
                    Path(temporary) / "bundle",
                    _d2_deferred_run(),
                    protected_paths=(BrokenPath(),),
                )
            self.assertEqual("invalid_argument", captured.exception.code)

    def test_protected_path_iteration_stops_at_the_fixed_count_limit(self) -> None:
        consumed: list[int] = []

        def paths():
            for index in range(10_000):
                consumed.append(index)
                yield f"protected-{index}"

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(
                    Path(temporary) / "bundle",
                    _d2_deferred_run(),
                    protected_paths=paths(),
                )
        self.assertEqual("invalid_argument", captured.exception.code)
        self.assertEqual(257, len(consumed))

    def test_protected_path_iteration_failure_is_normalized(self) -> None:
        def paths():
            yield "first"
            raise RuntimeError("INJECTED_PATH")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(
                    Path(temporary) / "bundle",
                    _d2_deferred_run(),
                    protected_paths=paths(),
                )
        self.assertEqual("invalid_argument", captured.exception.code)
        self.assertNotIn("INJECTED_PATH", str(captured.exception))

    def test_existing_destination_is_never_overwritten(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            output.mkdir()
            sentinel = output / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(DiscoveryReplayError) as captured:
                write_discovery_result_bundle(output, run)
            self.assertEqual("output_exists", captured.exception.code)
            self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

    def test_staging_directory_is_synced_before_publication(self) -> None:
        run = _finalized_run()
        events: list[str] = []
        real_sync = replay_module._sync_staging_directory
        real_rename = replay_module._rename_directory_noreplace

        def sync(*args, **kwargs):
            events.append("sync")
            return real_sync(*args, **kwargs)

        def rename(*args, **kwargs):
            events.append("rename")
            return real_rename(*args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            replay_module,
            "_sync_staging_directory",
            side_effect=sync,
        ), mock.patch.object(
            replay_module,
            "_rename_directory_noreplace",
            side_effect=rename,
        ):
            self._write(Path(temporary), "bundle", run)
        self.assertEqual(["sync", "rename"], events)

    def test_precommit_publication_failure_retains_private_staging(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output = parent / "bundle"
            with mock.patch.object(
                replay_module,
                "_rename_directory_noreplace",
                side_effect=OSError("injected"),
            ):
                with self.assertRaises(DiscoveryReplayError) as captured:
                    write_discovery_result_bundle(output, run)
            self.assertEqual("publication_failed", captured.exception.code)
            self.assertFalse(captured.exception.committed)
            self.assertFalse(output.exists())
            remaining = list(parent.iterdir())
            self.assertEqual(1, len(remaining))
            self.assertTrue(remaining[0].is_dir())
            self.assertEqual(
                set(DISCOVERY_REPLAY_FILES),
                {item.name for item in remaining[0].iterdir()},
            )

    def test_cleanup_retains_staging_without_unlinking_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            staging = parent / ".bundle.staging"
            staging.mkdir()
            original = staging / "producer.jsonl"
            original.write_bytes(b"original\n")
            with mock.patch.object(
                os,
                "unlink",
                side_effect=AssertionError("staging names must not be unlinked"),
            ):
                replay_module._safe_cleanup_staging(
                    staging,
                    expected_identity=replay_module._directory_identity(
                        os.lstat(staging)
                    ),
                    expected_members={
                        "producer.jsonl": replay_module._identity(os.lstat(original))
                    },
                    parent_chain=replay_module._checked_chain(parent),
                )
            self.assertEqual(b"original\n", original.read_bytes())

    def test_postverification_member_change_is_publication_uncertain(self) -> None:
        run = _d2_deferred_run()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            real_rename = replay_module._rename_directory_noreplace

            def mutate_then_commit(source: Path, destination: Path) -> None:
                (source / "producer.jsonl").write_bytes(b"{}\n")
                real_rename(source, destination)

            with mock.patch.object(
                replay_module,
                "_rename_directory_noreplace",
                side_effect=mutate_then_commit,
            ):
                with self.assertRaises(DiscoveryReplayError) as captured:
                    write_discovery_result_bundle(output, run)
            self.assertEqual("publication_uncertain", captured.exception.code)
            self.assertTrue(captured.exception.committed)
            self.assertEqual(b"{}\n", (output / "producer.jsonl").read_bytes())

    def test_commit_then_error_is_publication_uncertain_and_not_rolled_back(self) -> None:
        run = _finalized_run()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output = parent / "bundle"

            def commit_then_fail(source: Path, destination: Path) -> None:
                os.rename(source, destination)
                raise OSError("injected after commit")

            with mock.patch.object(
                replay_module,
                "_rename_directory_noreplace",
                side_effect=commit_then_fail,
            ):
                with self.assertRaises(DiscoveryReplayError) as captured:
                    write_discovery_result_bundle(output, run)
            self.assertEqual("publication_uncertain", captured.exception.code)
            self.assertTrue(captured.exception.committed)
            self.assertTrue(output.is_dir())
            self.assertEqual(set(DISCOVERY_REPLAY_FILES), {item.name for item in output.iterdir()})


if __name__ == "__main__":
    unittest.main()
