"""Offline routing tests against pinned public review evidence; no model calls."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
from pathlib import Path
import tempfile
import unittest

from scripts import prepare_t2_submission_disposition as target


class SubmissionDispositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = target.load()

    def setUp(self):
        self.data = deepcopy(self.source)

    def test_actual_groups_remain_separate_and_errors_are_excluded(self):
        payloads = target.build(**self.data)
        summary = target.quality.parse(payloads['summary.json'])
        self.assertEqual(summary['candidate_records'], 41)
        old = summary['groups']['historical_lane_a_development']
        self.assertEqual(old['dispositions'], {'excluded_pending_correction': 12,
            'manual_review': 0, 'not_reviewed': 28, 'reviewed_unverified': 0})
        self.assertEqual(old['review_field_counts']['contradicted'], 21)
        self.assertEqual(summary['groups']['known_input_model_development']['dispositions']['manual_review'], 1)
        self.assertIsNone(summary['product_accuracy'])
        self.assertEqual(summary['new_model_calls'], 0)
        self.assertEqual(summary['automatic_corrections_applied'], 0)
        self.assertFalse(summary['human_validation_claimed'])

    def test_current_uncertainty_is_preserved_and_original_data_unchanged(self):
        before = deepcopy(self.data)
        payloads = target.build(**self.data)
        rows = [target.quality.parse(line) for line in payloads['disposition.jsonl'].splitlines()]
        current = rows[-1]
        self.assertEqual(set(current['unresolved_fields']), {'version_basis', 'trace'})
        self.assertEqual(current['machine_verify'], 0)
        self.assertFalse(current['candidate_bytes_changed'])
        self.assertEqual(before, self.data)

    def test_changed_entry_or_report_binding_rejected(self):
        for key in ('original_entry_sha256', 'original_validation_sha256', 'report_id', 'entry_id'):
            value = deepcopy(self.data)
            task = value['cohort']['cases'][0]['task_id']
            next(c for c in value['inventory'] if c['task_id'] == task)[key] = 'f' * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                target.build(**value)

    def test_duplicate_and_missing_inventory_rejected(self):
        self.data['inventory'].append(self.data['inventory'][0])
        with self.assertRaisesRegex(ValueError, 'duplicate_inventory'):
            target.build(**self.data)
        self.data = deepcopy(self.source)
        reviewed = self.data['cohort']['cases'][0]['task_id']
        self.data['inventory'] = [c for c in self.data['inventory'] if c['task_id'] != reviewed]
        with self.assertRaisesRegex(ValueError, 'binding_mismatch'):
            target.build(**self.data)

    def test_all_supported_does_not_mean_human_verified(self):
        fields = {key: {'status': 'supported'} for key in target.quality.RUBRIC}
        self.assertEqual(target.disposition(fields, 'correct'), 'reviewed_unverified')
        self.assertEqual(target.disposition(fields, 'uncertain'), 'manual_review')
        self.assertEqual(target.disposition(fields, 'incorrect'), 'excluded_pending_correction')

    def test_contradiction_takes_precedence_over_uncertainty(self):
        fields = {key: {'status': 'uncertain'} for key in target.quality.RUBRIC}
        fields['entry_role']['status'] = 'contradicted'
        self.assertEqual(target.disposition(fields, 'uncertain'), 'excluded_pending_correction')

    def test_unreviewed_not_silently_scored(self):
        self.assertEqual(target.disposition(None, 'uncertain'), 'not_reviewed')
        fields = {key: {'status': 'not_reviewed'} for key in target.quality.RUBRIC}
        self.assertEqual(target.disposition(fields, 'correct'), 'not_reviewed')
        with self.assertRaises(ValueError):
            target.disposition({}, 'correct')

    def test_ai_review_cannot_claim_independent_human_review(self):
        self.data['current']['reviewer']['independence'] = 'independent_declared'
        with self.assertRaisesRegex(ValueError, 'nonhuman'):
            target.build(**self.data)

    def test_missing_or_unknown_field_rejected(self):
        for status in (None, 'good'):
            value = deepcopy(self.data)
            if status is None:
                del value['current']['fields']['trace']
            else:
                value['current']['fields']['trace']['status'] = status
            with self.assertRaises(ValueError):
                target.build(**value)

    def test_verify_promotion_and_duplicate_candidate_rejected(self):
        for verify in (1, True, False):
            value = deepcopy(self.data)
            value['current']['original_machine_verify'] = verify
            with self.subTest(verify=verify), self.assertRaises(ValueError):
                target.build(**value)
        self.data['current']['entry_sha256'] = self.data['inventory'][0]['original_entry_sha256']
        with self.assertRaises(ValueError):
            target.build(**self.data)

    def test_repeat_generation_byte_equal(self):
        self.assertEqual(target.build(**self.data), target.build(**deepcopy(self.data)))

    def test_cli_readback_and_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'new'
            args = ['--output-dir', str(output)]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(target.main(args), 0)
                before = {p.name: p.read_bytes() for p in output.iterdir()}
                self.assertEqual(target.main(args + ['--check']), 0)
                self.assertEqual(target.main(args), 2)
            self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})


if __name__ == '__main__':
    unittest.main()
