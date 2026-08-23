from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import vulngym_agent.evaluator.batch_configs as batch_configs
from vulngym_agent.evaluator.batch_configs import (
    BATCH_REPLAY_CONFIG_MANIFEST_DIGEST_DOMAIN,
    BatchReplayConfigError,
    BatchReplayConfigManifestV1,
    TaskReplayConfigBindingV1,
    load_batch_replay_configs_v1,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    OciReplayConfigV1,
    REPLAY_CONFIG_DIGEST_DOMAIN,
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class BatchReplayConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "replay-input"
        self.configs_root = self.root / "configs"
        self.configs_root.mkdir(parents=True)
        self.task_ids = tuple(f"VG-TEST-{index:020X}" for index in range(20))
        self.config_pairs = tuple(
            (
                OciReplayConfigV1(
                    task_id=task_id,
                    role="d2",
                    responses=(),
                ),
                OciReplayConfigV1(
                    task_id=task_id,
                    role="d3",
                    responses=(),
                ),
            )
            for task_id in self.task_ids
        )
        self.bindings = tuple(
            TaskReplayConfigBindingV1.from_configs(d2, d3)
            for d2, d3 in self.config_pairs
        )
        for task_id, (d2, d3) in zip(
            self.task_ids, self.config_pairs, strict=True
        ):
            task_root = self.configs_root / task_id
            task_root.mkdir()
            (task_root / "d2.json").write_bytes(d2.to_bytes())
            (task_root / "d3.json").write_bytes(d3.to_bytes())
        self.manifest = BatchReplayConfigManifestV1(
            split="test", tasks=self.bindings
        )
        self._write_manifest(self.manifest)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_manifest(self, manifest: BatchReplayConfigManifestV1) -> None:
        (self.root / "manifest.json").write_bytes(manifest.to_bytes())

    def _load(
        self,
        *,
        manifest: BatchReplayConfigManifestV1 | None = None,
        expected_split: str = "test",
        expected_task_ids: tuple[str, ...] | None = None,
        expected_manifest_sha256: str | None = None,
        expected_manifest_wire_sha256: str | None = None,
    ):
        selected = self.manifest if manifest is None else manifest
        return load_batch_replay_configs_v1(
            self.root,
            expected_manifest_sha256=(
                selected.manifest_sha256
                if expected_manifest_sha256 is None
                else expected_manifest_sha256
            ),
            expected_manifest_wire_sha256=(
                selected.wire_sha256
                if expected_manifest_wire_sha256 is None
                else expected_manifest_wire_sha256
            ),
            expected_split=expected_split,
            expected_task_ids=(
                self.task_ids if expected_task_ids is None else expected_task_ids
            ),
        )

    def _write_raw_manifest(self, value: dict[str, object]) -> tuple[str, str]:
        core = dict(value)
        core.pop("manifest_sha256", None)
        semantic = hashlib.sha256(
            BATCH_REPLAY_CONFIG_MANIFEST_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        value = {**core, "manifest_sha256": semantic}
        payload = _canonical_json(value) + b"\n"
        (self.root / "manifest.json").write_bytes(payload)
        return semantic, hashlib.sha256(payload).hexdigest()

    def _manifest_with_binding(
        self, index: int, replacement: TaskReplayConfigBindingV1
    ) -> BatchReplayConfigManifestV1:
        bindings = list(self.bindings)
        bindings[index] = replacement
        manifest = BatchReplayConfigManifestV1(
            split="test", tasks=tuple(bindings)
        )
        self._write_manifest(manifest)
        return manifest

    def _mutated_config_wire(
        self, original: OciReplayConfigV1, *, field: str, value: object
    ) -> tuple[bytes, str]:
        raw = json.loads(original.to_bytes())
        raw[field] = value
        core = dict(raw)
        core.pop("config_sha256")
        semantic = hashlib.sha256(
            REPLAY_CONFIG_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        raw["config_sha256"] = semantic
        return _canonical_json(raw) + b"\n", semantic

    def test_loads_exact_ordered_frozen_pairs(self) -> None:
        loaded = self._load()
        self.assertIsInstance(loaded, tuple)
        self.assertEqual(len(loaded), 20)
        self.assertEqual(
            tuple(pair[0].task_id for pair in loaded), self.task_ids
        )
        for supplied, frozen in zip(self.config_pairs, loaded, strict=True):
            self.assertIsInstance(frozen, tuple)
            self.assertIsNot(frozen[0], supplied[0])
            self.assertIsNot(frozen[1], supplied[1])
            self.assertEqual(frozen[0].to_bytes(), supplied[0].to_bytes())
            self.assertEqual(frozen[1].to_bytes(), supplied[1].to_bytes())

    def test_requires_both_trusted_manifest_pins(self) -> None:
        with self.assertRaises(BatchReplayConfigError) as wire_captured:
            self._load(expected_manifest_wire_sha256="0" * 64)
        self.assertEqual(wire_captured.exception.code, "manifest_wire_mismatch")

        with self.assertRaises(BatchReplayConfigError) as content_captured:
            self._load(expected_manifest_sha256="0" * 64)
        self.assertEqual(
            content_captured.exception.code, "manifest_digest_mismatch"
        )

        with self.assertRaises(BatchReplayConfigError) as argument_captured:
            load_batch_replay_configs_v1(
                self.root,
                expected_manifest_sha256=self.manifest.manifest_sha256,
                expected_manifest_wire_sha256="not-a-digest",
                expected_split="test",
                expected_task_ids=self.task_ids,
            )
        self.assertEqual(argument_captured.exception.code, "invalid_argument")

    def test_rejects_expected_split_and_task_order_mismatch(self) -> None:
        train_ids = tuple(f"VG-TRAIN-{index:020X}" for index in range(50))
        with self.assertRaises(BatchReplayConfigError) as split_captured:
            self._load(expected_split="train", expected_task_ids=train_ids)
        self.assertEqual(split_captured.exception.code, "binding_mismatch")

        reordered = (self.task_ids[1], self.task_ids[0], *self.task_ids[2:])
        with self.assertRaises(BatchReplayConfigError) as order_captured:
            self._load(expected_task_ids=reordered)
        self.assertEqual(order_captured.exception.code, "binding_mismatch")

    def test_rejects_reordered_manifest_even_with_valid_new_pins(self) -> None:
        manifest = BatchReplayConfigManifestV1(
            split="test",
            tasks=(self.bindings[1], self.bindings[0], *self.bindings[2:]),
        )
        self._write_manifest(manifest)
        with self.assertRaises(BatchReplayConfigError) as captured:
            self._load(manifest=manifest)
        self.assertEqual(captured.exception.code, "binding_mismatch")

    def test_rejects_missing_and_duplicate_manifest_tasks(self) -> None:
        original = self.manifest.to_dict()
        for name, raw_tasks in (
            ("missing", list(original["tasks"])[:-1]),
            (
                "duplicate",
                list(original["tasks"])[:-1] + [list(original["tasks"])[0]],
            ),
        ):
            with self.subTest(name=name):
                value = dict(original)
                value["tasks"] = raw_tasks
                semantic, wire = self._write_raw_manifest(value)
                with self.assertRaises(BatchReplayConfigError) as captured:
                    self._load(
                        expected_manifest_sha256=semantic,
                        expected_manifest_wire_sha256=wire,
                    )
                self.assertEqual(captured.exception.code, "invalid_manifest")
        self._write_manifest(self.manifest)

    def test_rejects_missing_and_extra_layout_members(self) -> None:
        cases = (
            (self.root / "unexpected.json", b"{}\n"),
            (self.configs_root / "VG-TEST-FFFFFFFFFFFFFFFFFFFF", None),
            (self.configs_root / self.task_ids[0] / "extra.json", b"{}\n"),
        )
        for path, payload in cases:
            with self.subTest(path=path.name):
                if payload is None:
                    path.mkdir()
                else:
                    path.write_bytes(payload)
                try:
                    with self.assertRaises(BatchReplayConfigError) as captured:
                        self._load()
                    self.assertEqual(captured.exception.code, "layout_invalid")
                finally:
                    if payload is None:
                        path.rmdir()
                    else:
                        path.unlink()

        missing = self.configs_root / self.task_ids[0] / "d2.json"
        saved = missing.read_bytes()
        missing.unlink()
        try:
            with self.assertRaises(BatchReplayConfigError) as captured:
                self._load()
            self.assertEqual(captured.exception.code, "layout_invalid")
        finally:
            missing.write_bytes(saved)

    def test_rejects_non_regular_config_member(self) -> None:
        target = self.configs_root / self.task_ids[0] / "d2.json"
        saved = target.read_bytes()
        target.unlink()
        target.mkdir()
        try:
            with self.assertRaises(BatchReplayConfigError) as captured:
                self._load()
            self.assertEqual(captured.exception.code, "unsafe_path")
        finally:
            target.rmdir()
            target.write_bytes(saved)

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits are required")
    def test_writable_ancestor_is_allowed_but_writable_input_root_is_not(
        self,
    ) -> None:
        ancestor = Path(self.temporary.name)
        ancestor_mode = stat.S_IMODE(os.lstat(ancestor).st_mode)
        root_mode = stat.S_IMODE(os.lstat(self.root).st_mode)
        try:
            os.chmod(ancestor, 0o777)
            self.assertEqual(len(self._load()), len(self.task_ids))
            os.chmod(self.root, root_mode | stat.S_IWGRP)
            with self.assertRaises(BatchReplayConfigError) as captured:
                self._load()
            self.assertEqual(captured.exception.code, "unsafe_path")
        finally:
            os.chmod(self.root, root_mode)
            os.chmod(ancestor, ancestor_mode)

    def test_rejects_symlink_config_member_when_supported(self) -> None:
        target = self.configs_root / self.task_ids[0] / "d2.json"
        saved = target.read_bytes()
        outside = Path(self.temporary.name) / "outside-replay.json"
        outside.write_bytes(saved)
        target.unlink()
        try:
            try:
                target.symlink_to(outside)
            except OSError as error:
                self.skipTest(f"file symlinks are unavailable: {error}")
            with self.assertRaises(BatchReplayConfigError) as captured:
                self._load()
            self.assertEqual(captured.exception.code, "unsafe_path")
        finally:
            if target.is_symlink():
                target.unlink()
            target.write_bytes(saved)

    def test_rejects_reparse_marked_config_member(self) -> None:
        target = self.configs_root / self.task_ids[0] / "d2.json"
        target_inode = os.lstat(target).st_ino
        real_is_reparse = batch_configs._is_reparse

        def marked(value: os.stat_result) -> bool:
            return value.st_ino == target_inode or real_is_reparse(value)

        with mock.patch.object(batch_configs, "_is_reparse", side_effect=marked):
            with self.assertRaises(BatchReplayConfigError) as captured:
                self._load()
        self.assertEqual(captured.exception.code, "unsafe_path")

    def test_rejects_config_wire_and_canonical_drift(self) -> None:
        task_root = self.configs_root / self.task_ids[0]
        d2_path = task_root / "d2.json"
        original = d2_path.read_bytes()
        drifted = original[:-1] + b" \n"
        d2_path.write_bytes(drifted)
        with self.assertRaises(BatchReplayConfigError) as wire_captured:
            self._load()
        self.assertEqual(wire_captured.exception.code, "config_wire_mismatch")

        original_binding = self.bindings[0]
        replacement = TaskReplayConfigBindingV1(
            task_id=original_binding.task_id,
            d2_replay_sha256=original_binding.d2_replay_sha256,
            d2_replay_wire_sha256=hashlib.sha256(drifted).hexdigest(),
            d3_replay_sha256=original_binding.d3_replay_sha256,
            d3_replay_wire_sha256=original_binding.d3_replay_wire_sha256,
        )
        manifest = self._manifest_with_binding(0, replacement)
        with self.assertRaises(BatchReplayConfigError) as canonical_captured:
            self._load(manifest=manifest)
        self.assertEqual(
            canonical_captured.exception.code, "config_contract_mismatch"
        )

    def test_rejects_role_mismatch_after_manifest_rebinding(self) -> None:
        task_id = self.task_ids[0]
        wrong_role = OciReplayConfigV1(
            task_id=task_id, role="d3", responses=()
        )
        path = self.configs_root / task_id / "d2.json"
        path.write_bytes(wrong_role.to_bytes())
        original = self.bindings[0]
        replacement = TaskReplayConfigBindingV1(
            task_id=task_id,
            d2_replay_sha256=wrong_role.config_sha256,
            d2_replay_wire_sha256=wrong_role.wire_sha256,
            d3_replay_sha256=original.d3_replay_sha256,
            d3_replay_wire_sha256=original.d3_replay_wire_sha256,
        )
        manifest = self._manifest_with_binding(0, replacement)
        with self.assertRaises(BatchReplayConfigError) as captured:
            self._load(manifest=manifest)
        self.assertEqual(captured.exception.code, "config_binding_mismatch")

    def test_rejects_cross_task_config_exchange_after_manifest_rebinding(self) -> None:
        first_path = self.configs_root / self.task_ids[0] / "d2.json"
        second_path = self.configs_root / self.task_ids[1] / "d2.json"
        first_wire = first_path.read_bytes()
        second_wire = second_path.read_bytes()
        first_path.write_bytes(second_wire)
        second_path.write_bytes(first_wire)
        bindings = list(self.bindings)
        first = bindings[0]
        second = bindings[1]
        bindings[0] = TaskReplayConfigBindingV1(
            task_id=first.task_id,
            d2_replay_sha256=second.d2_replay_sha256,
            d2_replay_wire_sha256=second.d2_replay_wire_sha256,
            d3_replay_sha256=first.d3_replay_sha256,
            d3_replay_wire_sha256=first.d3_replay_wire_sha256,
        )
        bindings[1] = TaskReplayConfigBindingV1(
            task_id=second.task_id,
            d2_replay_sha256=first.d2_replay_sha256,
            d2_replay_wire_sha256=first.d2_replay_wire_sha256,
            d3_replay_sha256=second.d3_replay_sha256,
            d3_replay_wire_sha256=second.d3_replay_wire_sha256,
        )
        manifest = BatchReplayConfigManifestV1(
            split="test", tasks=tuple(bindings)
        )
        self._write_manifest(manifest)
        with self.assertRaises(BatchReplayConfigError) as captured:
            self._load(manifest=manifest)
        self.assertEqual(captured.exception.code, "config_binding_mismatch")

    def test_rejects_backend_and_model_contract_drift(self) -> None:
        d2, _d3 = self.config_pairs[0]
        path = self.configs_root / self.task_ids[0] / "d2.json"
        original_binding = self.bindings[0]
        for field, value in (("backend_id", "other"), ("model_id", "other")):
            with self.subTest(field=field):
                wire, semantic = self._mutated_config_wire(
                    d2, field=field, value=value
                )
                path.write_bytes(wire)
                replacement = TaskReplayConfigBindingV1(
                    task_id=original_binding.task_id,
                    d2_replay_sha256=semantic,
                    d2_replay_wire_sha256=hashlib.sha256(wire).hexdigest(),
                    d3_replay_sha256=original_binding.d3_replay_sha256,
                    d3_replay_wire_sha256=original_binding.d3_replay_wire_sha256,
                )
                manifest = self._manifest_with_binding(0, replacement)
                with self.assertRaises(BatchReplayConfigError) as captured:
                    self._load(manifest=manifest)
                self.assertEqual(
                    captured.exception.code, "config_contract_mismatch"
                )

    def test_rejects_aggregate_replay_bytes_over_limit(self) -> None:
        total = sum(
            len(d2.to_bytes()) + len(d3.to_bytes())
            for d2, d3 in self.config_pairs
        )
        with mock.patch.object(
            batch_configs, "MAX_BATCH_REPLAY_WIRE_BYTES", total - 1
        ):
            with self.assertRaises(BatchReplayConfigError) as captured:
                self._load()
        self.assertEqual(captured.exception.code, "limit_exceeded")


if __name__ == "__main__":
    unittest.main()
