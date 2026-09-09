"""Synthetic deadline/budget checks. No real key, model, or run directory writes."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_t2_context_retest_v2 as runner
from tests.test_t2_new_input_run import request
from vulngym_agent.agents.model_runtime import ModelBlocked


class LongwaitRetestTests(unittest.TestCase):
    def setUp(self):
        self.calls, self.events = [], []
        def send(body, key, timeout):
            self.calls.append((body, timeout))
            return json.dumps({'model': runner.adapter.MODEL_ID, 'usage': {
                'prompt_tokens': 10, 'completion_tokens': 2, 'total_tokens': 12,
                'raw_field': 'must-not-log'}, 'choices': [{'message': {'content': 'must-not-log'}}]}).encode()
        self.guard = runner.BoundedTransport(send, self.events.append)

    def invoke(self, value=None, *, timeout=300, guard=None):
        return (guard or self.guard)(json.dumps(value or request()).encode(), 'synthetic-key', timeout)

    def test_selected_deadline_does_not_change_default(self):
        self.assertEqual(runner.SETTINGS.timeout_seconds, 300)
        self.assertEqual(runner.adapter.DeepSeekSettings().timeout_seconds, 120)
        self.assertEqual(runner.SETTINGS.max_tokens, 8192)
        self.assertEqual(runner.SETTINGS.reasoning_effort, 'high')

    def test_six_sends_max_and_no_secret_or_content_in_telemetry(self):
        for task in runner.TASKS:
            for number in range(3):
                self.invoke(request(task, f'MODEL-{number}'))
        self.assertEqual(len(self.calls), 6)
        self.assertEqual(len(self.events), 12)
        self.assertNotIn('must-not-log', repr(self.events))
        self.assertNotIn('synthetic-key', repr(self.events))
        self.assertEqual(self.events[-1]['usage']['total_tokens'], 12)
        with self.assertRaisesRegex(ModelBlocked, 'budget_exceeded'):
            self.invoke(request(runner.TASKS[1], 'MODEL-4'))
        self.assertEqual(len(self.calls), 6)

    def test_per_task_cap_does_not_borrow_from_second_task(self):
        for n in range(3):
            self.invoke(request(call=f'MODEL-{n}'))
        with self.assertRaisesRegex(ModelBlocked, 'budget_exceeded'):
            self.invoke(request(call='MODEL-4'))
        self.assertEqual(len(self.calls), 3)

    def test_duplicate_request_never_resent(self):
        self.invoke()
        with self.assertRaisesRegex(ModelBlocked, 'duplicate_request'):
            self.invoke()
        self.assertEqual(len(self.calls), 1)

    def test_only_frozen_300_deadline_is_accepted(self):
        for timeout in (120, 299, 301, True, float('nan'), float('inf')):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ModelBlocked, 'contract_invalid'):
                self.invoke(timeout=timeout)
        self.assertEqual(self.calls, [])

    def test_model_tokens_tasks_and_repair_scope_rejected(self):
        values = [request('other'), request(stage='repair')]
        for key, value in [('model', 'other'), ('max_tokens', 8193), ('max_tokens', True), ('stream', True)]:
            item = deepcopy(request())
            item[key] = value
            values.append(item)
        for item in values:
            with self.subTest(item=item), self.assertRaisesRegex(ModelBlocked, 'contract_invalid'):
                self.invoke(item)
        self.assertEqual(self.calls, [])

    def test_malformed_and_duplicate_json_keys_never_send(self):
        for raw in (b'invalid', b'{"a":1,"a":2}', b'{}'):
            with self.assertRaisesRegex(ModelBlocked, 'contract_invalid'):
                self.guard(raw, 'synthetic-key', 300)
        self.assertEqual(self.calls, [])

    def test_durable_intent_precedes_send(self):
        order = []
        guard = runner.BoundedTransport(lambda *a: order.append('send') or b'{}', lambda row: order.append(row['event']))
        self.invoke(guard=guard)
        self.assertEqual(order, ['started', 'send', 'finished'])

    def test_failed_start_log_sends_nothing_and_latches(self):
        def fail(event):
            raise OSError('synthetic-disk-full')
        guard = runner.BoundedTransport(self.guard.send, fail)
        for _ in range(2):
            with self.assertRaisesRegex(ModelBlocked, 'telemetry_failed'):
                self.invoke(guard=guard)
        self.assertEqual(guard.attempts, 0)
        self.assertEqual(self.calls, [])

    def test_failed_completion_log_stops_later_calls(self):
        def record(event):
            if event['event'] == 'finished':
                raise OSError('synthetic-disk-full')
        guard = runner.BoundedTransport(self.guard.send, record)
        for _ in range(2):
            with self.assertRaisesRegex(ModelBlocked, 'telemetry_failed'):
                self.invoke(guard=guard)
        self.assertEqual(len(self.calls), 1)

    def test_timeout_records_stage_not_response_content_and_stops(self):
        calls = []
        def fail(*args):
            calls.append(1)
            raise runner.adapter._TransportBlocked('deepseek_timeout', {
                'phase': 'wait_headers', 'request_started': True, 'other': 'do-not-log'})
        guard = runner.BoundedTransport(fail, self.events.append)
        for _ in range(2):
            with self.assertRaisesRegex(ModelBlocked, 'deepseek_timeout'):
                self.invoke(guard=guard)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.events[-1]['transport_failure'], {
            'phase': 'wait_headers', 'request_started': True, 'usage_and_billing_known': False})
        self.assertNotIn('do-not-log', repr(self.events))

    def test_auth_balance_permission_rate_limit_failure_stops(self):
        for code in ('deepseek_authentication_failed', 'deepseek_access_denied',
                     'deepseek_balance_insufficient', 'deepseek_rate_limited'):
            calls = []
            def fail(*args):
                calls.append(1)
                raise ModelBlocked(code)
            guard = runner.BoundedTransport(fail, lambda e: None)
            for _ in range(2):
                with self.assertRaisesRegex(ModelBlocked, code):
                    self.invoke(guard=guard)
            self.assertEqual(len(calls), 1)

    def test_unknown_error_text_never_logged(self):
        def fail(*args):
            raise OSError('synthetic-secret')
        guard = runner.BoundedTransport(fail, self.events.append)
        with self.assertRaisesRegex(ModelBlocked, 'transport_failed'):
            self.invoke(guard=guard)
        self.assertNotIn('synthetic-secret', repr(self.events))

    def test_check_does_not_read_key_or_invoke_run(self):
        with patch.object(runner, 'preflight', return_value={'provider_calls': 0}) as check, \
                patch.object(runner.getpass, 'getpass') as key, patch.object(runner, 'run') as run, \
                patch.object(runner, 'emit'):
            self.assertEqual(runner.main(['check']), 0)
        check.assert_called_once_with()
        key.assert_not_called()
        run.assert_not_called()

    def test_run_requires_both_fresh_confirmations_and_digest(self):
        variants = [[], ['--confirm-paid-retest'], ['--confirm-platform-cap'],
                    ['--confirm-paid-retest', '--confirm-platform-cap']]
        with patch.object(runner, 'run') as run, patch.object(runner.getpass, 'getpass') as key, patch.object(runner, 'emit'):
            for flags in variants:
                self.assertEqual(runner.main(['run', *flags]), 2)
        run.assert_not_called()
        key.assert_not_called()

    def test_fully_confirmed_run_routes_exact_digest_and_exit_status(self):
        with patch.object(runner, 'run', return_value=1) as run:
            self.assertEqual(runner.main(['run', '--confirm-paid-retest', '--confirm-platform-cap',
                '--expected-manifest-sha256', 'a' * 64]), 1)
        run.assert_called_once_with('a' * 64)

    def test_run_rejects_manifest_mismatch_before_key(self):
        with patch.object(runner, 'read_bytes', return_value=b'{}'), patch.object(runner.getpass, 'getpass') as key:
            with self.assertRaisesRegex(ValueError, 'digest_mismatch'):
                runner.run('a' * 64)
        key.assert_not_called()

    def test_existing_directory_is_not_reprepared(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(runner, 'RUN', Path(tmp)), \
                patch.object(runner, 'read_bytes') as read:
            with self.assertRaisesRegex(ValueError, 'existing_preparation'):
                runner.prepare()
        read.assert_not_called()

    def test_changed_timeout_or_budget_profile_rejected(self):
        with patch.object(runner, 'read_bytes', return_value=b'{}'), patch.object(runner, 'git') as git:
            with self.assertRaisesRegex(ValueError, 'profile_changed'):
                runner.preflight()
        git.assert_not_called()

    def test_unapproved_input_paths_rejected_before_read(self):
        with patch.object(runner, 'read_bytes') as read:
            for name in ('../secret', '/absolute', 'package/unapproved.json'):
                with self.assertRaisesRegex(ValueError, 'unexpected_input'):
                    runner.checked_input(Path('synthetic'), name, {})
        read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
