from __future__ import annotations

import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest
from unittest import mock

import tests.test_evaluator_supervisor as supervisor_tests
import vulngym_agent.evaluator.publication_reader as reader_module
from vulngym_agent.evaluator.e4_receipt import (
    E4_SUCCESS_RECEIPT_FILENAME,
    E4BatchSuccessReceiptV1,
    E4TaskSuccessClosureV1,
    _issue_e4_success_receipt_authority_v1,
)
from vulngym_agent.evaluator.publication_reader import (
    E4PublicationReaderError,
    read_committed_e4_discovery_execution_v1,
)
from vulngym_agent.evaluator.supervisor import (
    EvaluatorSupervisorError,
    _publish_scheduled_postverified_discovery_execution_v1,
    publish_postverified_discovery_execution_v1,
)


class E4PublicationReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_type = supervisor_tests.EvaluatorSupervisorTests
        fixture_type.setUpClass()
        cls.fixture_type = fixture_type
        cls.fixture = fixture_type(methodName="runTest")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_type.tearDownClass()

    def _scheduled_publication(
        self, name: str
    ) -> tuple[Path, E4BatchSuccessReceiptV1]:
        token = self.fixture._postverified_token()
        closures = tuple(
            E4TaskSuccessClosureV1(
                task_plan_sha256=item.task_plan.plan_sha256,
                task_id=item.task_plan.task_id,
                run_sha256=item.run.run_sha256,
                run_wire_sha256=item.run_wire_sha256,
                discovery_result_sha256=item.discovery_result_sha256,
                runtime_evidence_sha256=item.runtime_evidence_sha256,
            )
            for item in token.pending
        )
        authority = _issue_e4_success_receipt_authority_v1(
            token.plan, closures
        )
        output = self.fixture.root / name
        receipt = _publish_scheduled_postverified_discovery_execution_v1(
            token, authority, output
        )
        return output, receipt

    def test_scheduled_publication_round_trips_from_external_pins(self) -> None:
        token = self.fixture._postverified_token()
        closures = tuple(
            E4TaskSuccessClosureV1(
                task_plan_sha256=item.task_plan.plan_sha256,
                task_id=item.task_plan.task_id,
                run_sha256=item.run.run_sha256,
                run_wire_sha256=item.run_wire_sha256,
                discovery_result_sha256=item.discovery_result_sha256,
                runtime_evidence_sha256=item.runtime_evidence_sha256,
            )
            for item in token.pending
        )
        authority = _issue_e4_success_receipt_authority_v1(
            token.plan, closures
        )
        output = self.fixture.root / "published-e4-reader-valid"
        receipt = _publish_scheduled_postverified_discovery_execution_v1(
            token, authority, output
        )
        parsed = read_committed_e4_discovery_execution_v1(
            output,
            expected_receipt_sha256=receipt.receipt_sha256,
            expected_wire_sha256=receipt.wire_sha256,
        )
        self.assertEqual(parsed, receipt)
        self.assertEqual(len(parsed.success_closures), 20)
        self.assertEqual(
            {item.name for item in output.iterdir()},
            {
                "artifact-index.json",
                "bundles",
                "execution-plan.json",
                "execution-receipt.json",
                E4_SUCCESS_RECEIPT_FILENAME,
            },
        )
        second_output = self.fixture.root / "published-e4-reader-reused"
        with self.assertRaises(EvaluatorSupervisorError) as captured:
            _publish_scheduled_postverified_discovery_execution_v1(
                token, authority, second_output
            )
        self.assertEqual(captured.exception.code, "invalid_state")
        self.assertFalse(second_output.exists())

    def test_direct_e3_publication_is_not_an_official_e4_success(self) -> None:
        token = self.fixture._postverified_token()
        output = self.fixture.root / "published-e3-reader-rejected"
        receipt = publish_postverified_discovery_execution_v1(token, output)
        with self.assertRaises(E4PublicationReaderError) as captured:
            read_committed_e4_discovery_execution_v1(
                output,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=receipt.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "publication_invalid")

    def test_equivalent_resolved_root_spelling_is_checked_by_identity(
        self,
    ) -> None:
        output, _receipt = self._scheduled_publication(
            "published-e4-reader-equivalent-spelling"
        )
        alternate = output.parent / "canonical-equivalent-spelling"
        root_state = os.lstat(output)
        original_lstat = reader_module.os.lstat

        def equivalent_lstat(path):
            if Path(path) == alternate:
                return root_state
            return original_lstat(path)

        with (
            mock.patch.object(
                reader_module.Path, "resolve", return_value=alternate
            ),
            mock.patch.object(
                reader_module.os, "lstat", side_effect=equivalent_lstat
            ),
        ):
            root, _parent_chain, identity = (
                reader_module._checked_publication_root(output)
            )
        self.assertEqual(root, Path(os.path.abspath(output)))
        self.assertEqual(identity, (root_state.st_dev, root_state.st_ino))

    def test_resolved_root_identity_mismatch_is_unsafe(self) -> None:
        output = self.fixture.root / "published-e4-reader-wrong-identity"
        output.mkdir()
        alternate = output.parent / "different-resolved-identity"
        root_state = os.lstat(output)
        different_state = SimpleNamespace(
            st_mode=root_state.st_mode,
            st_dev=root_state.st_dev,
            st_ino=root_state.st_ino + 1,
            st_file_attributes=0,
        )
        original_lstat = reader_module.os.lstat

        def different_lstat(path):
            if Path(path) == alternate:
                return different_state
            return original_lstat(path)

        with (
            mock.patch.object(
                reader_module.Path, "resolve", return_value=alternate
            ),
            mock.patch.object(
                reader_module.os, "lstat", side_effect=different_lstat
            ),
            self.assertRaises(E4PublicationReaderError) as captured,
        ):
            reader_module._checked_publication_root(output)
        self.assertEqual(captured.exception.code, "unsafe_publication")

    def test_reader_rejects_extra_members_and_detached_contract_or_run(
        self,
    ) -> None:
        output, receipt = self._scheduled_publication(
            "published-e4-reader-tamper-source"
        )
        cases = (
            ("extra", "unexpected.bin"),
            ("plan", "execution-plan.json"),
            (
                "run",
                f"bundles/{receipt.execution_receipt.tasks[0].task_id}/producer.jsonl",
            ),
        )
        for label, relative in cases:
            with self.subTest(label=label):
                copied = self.fixture.root / f"published-e4-reader-{label}"
                shutil.copytree(output, copied)
                target = copied / Path(relative)
                if label == "extra":
                    target.write_bytes(b"unexpected\n")
                elif label == "plan":
                    target.write_bytes(b"{}\n")
                else:
                    target.write_bytes(target.read_bytes() + b"{}\n")
                with self.assertRaises(E4PublicationReaderError) as captured:
                    read_committed_e4_discovery_execution_v1(
                        copied,
                        expected_receipt_sha256=receipt.receipt_sha256,
                        expected_wire_sha256=receipt.wire_sha256,
                    )
                self.assertEqual(
                    captured.exception.code, "publication_invalid"
                )


if __name__ == "__main__":
    unittest.main()
