"""Synthetic accounting and abstention separation; no live inputs or API calls."""
from copy import deepcopy
import json
import unittest

from scripts.collect_t2_context_retest_v2 import TASKS, successful_transport_counts, defer_results


class LongwaitReceiptTests(unittest.TestCase):
    def setUp(self):
        self.events, self.calls = [], []
        for n, (task, stage) in enumerate([(TASKS[0], 'plan'), (TASKS[0], 'semantic_judge'),
                (TASKS[1], 'plan'), (TASKS[1], 'semantic_judge'), (TASKS[1], 'reflection')], 1):
            base = dict(attempt=n, task_id=task, stage=stage, request_body_sha256=str(n) * 64, timeout_seconds=300)
            self.events += [dict(base, event='started'), dict(base, event='finished', status='http_200',
                elapsed_seconds=1.0, usage={'prompt_tokens': 10, 'completion_tokens': 2, 'total_tokens': 12,
                                           'prompt_cache_hit_tokens': 4, 'prompt_cache_miss_tokens': 6})]
            self.calls.append(dict(task_id=task, stage=stage, status='success'))
        self.ended = dict(transport_attempts=5, transport_halt_code=None)

    def count(self):
        return successful_transport_counts(self.events, self.calls, self.ended)

    def test_five_requests_is_not_six_or_a_candidate_count(self):
        value = self.count()
        self.assertEqual(value['actual_http_requests'], 5)
        self.assertEqual(value['model_stage_counts'], {'plan': 2, 'reflection': 1, 'semantic_judge': 2})
        self.assertEqual(value['provider_reported_usage']['total_tokens'], 60)
        self.assertNotIn('complete_candidates', value)

    def test_timeout_cannot_use_success_collector(self):
        self.ended['transport_halt_code'] = 'deepseek_timeout'
        with self.assertRaises(AssertionError):
            self.count()

    def test_missing_finish_rejected(self):
        self.events.pop()
        with self.assertRaises(AssertionError):
            self.count()

    def test_invalid_structured_call_not_http_success(self):
        self.calls[1]['status'] = 'invalid'
        with self.assertRaises(AssertionError):
            self.count()

    def test_empty_or_inconsistent_usage_rejected_not_counted_as_zero(self):
        for usage in ({}, {**self.events[1]['usage'], 'total_tokens': 1},
                      {**self.events[1]['usage'], 'prompt_tokens': True}):
            events = deepcopy(self.events)
            events[1]['usage'] = usage
            with self.assertRaises(AssertionError):
                successful_transport_counts(events, self.calls, self.ended)

    def test_reordered_or_duplicate_stage_rejected(self):
        self.calls.reverse()
        with self.assertRaises(AssertionError):
            self.count()

    def test_semantic_and_reflection_defers_remain_distinct(self):
        rows = []
        for task, stage, kind in [(TASKS[0], 'semantic_judge', 'model_semantic_defer_v1'),
                                 (TASKS[1], 'reflection', 'model_reflection_defer_v1')]:
            detail = {'assessment_origin': 'model_self_report_not_independently_verified', 'kind': kind}
            rows.append({'task_id': task, 'payload': {'deferred_sha256': 'a' * 64,
                'deferred': {'reason_code': 'model_deferred', 'stage': stage, 'report_id': 'fixture',
                             'missing_information': ['model_defer_details:' + json.dumps(detail)]}}})
        result = defer_results(rows)
        self.assertEqual([r['stage'] for r in result], ['semantic_judge', 'reflection'])
        self.assertTrue(all(r['complete_candidate'] is False and r['t1_report'] is False for r in result))
        rows[0]['payload']['deferred']['reason_code'] = 'model_blocked'
        with self.assertRaises(AssertionError):
            defer_results(rows)


if __name__ == '__main__':
    unittest.main()
