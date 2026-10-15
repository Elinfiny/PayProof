"""Six inert cases: existing TEST_ONLY context, fake clock/transport, no native network."""
import json
import unittest
from unittest.mock import Mock, patch
from host_contract_fixture import context
from payproof.core import InvalidData
from payproof.paypal import BASE
from tools.read_pilot_driver import ReadPilotDriver, SyntheticRegistry

ORDER = 'SYNTHETICORDER01'


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def advance(self, value): self.value += value


class ReadPilotDriverTests(unittest.TestCase):
    def setUp(self):
        self.blocks = []
        for name in ('socket.socket', 'socket.create_connection',
                     'payproof.paypal.SandboxPayPal._network'):
            guard = patch(name, side_effect=AssertionError('Native network forbidden'))
            self.blocks.append(guard.start()); self.addCleanup(guard.stop)
        self.context = context({'operations': ['orders:read']})
        self.registry = SyntheticRegistry.for_test(self.context, frozenset({ORDER}))
        self.clock = Clock()

    def tearDown(self):
        for block in self.blocks: block.assert_not_called()

    def driver(self, transport, **kwargs):
        return ReadPilotDriver.for_test(self.context, self.registry, transport,
                                       clock=self.clock, **kwargs)

    def test_01_default_unbound_rejects_flags_and_inactive_verifier(self):
        fake_verifier = Mock(return_value={'admitted': True, 'PID': 123})
        driver = ReadPilotDriver(future_runtime_verifier=fake_verifier, clock=self.clock)
        with self.assertRaises(InvalidData): driver.run(ORDER)
        fake_verifier.assert_not_called()
        self.assertEqual(driver.export()['transport_calls'], 0)
        for bad in (None, True, {'admitted': True}, {'signature': 'local-HMAC'}):
            with self.assertRaises(InvalidData):
                ReadPilotDriver.for_test(bad, self.registry, Mock())
        with self.assertRaises(InvalidData):
            ReadPilotDriver.for_test(self.context, {ORDER: True}, Mock())

    def test_02_exact_oauth_get_two_allowances_metadata_only(self):
        calls = []
        oauth = {'access_token': 'SYNTHETIC-DO-NOT-EXPORT-TOKEN'}
        order = {'id': ORDER, 'payer': {'email': 'synthetic-private@example.invalid'}}
        holder = {}
        def fake(method, path, headers, body):
            d = holder['driver']; calls.append((method, path, d._reserved))
            return oauth if path == '/v1/oauth2/token' else order
        d = self.driver(fake); holder['driver'] = d
        report = d.run(ORDER)
        self.assertEqual(report['status'], 'SYNTHETIC_RETURNED')
        self.assertEqual(calls, [('POST', '/v1/oauth2/token', 1),
                                 ('GET', '/v2/checkout/orders/' + ORDER, 2)])
        self.assertIs(d._originals[0].value, oauth)
        self.assertIs(d._originals[1].value, order)
        exported = json.dumps(report)
        for forbidden in ('SYNTHETIC-DO-NOT-EXPORT-TOKEN', 'fake-secret', 'synthetic-private@example.invalid', ORDER):
            self.assertNotIn(forbidden, exported)

    def test_03_third_duplicate_origin_and_unregistered_refused(self):
        calls = []
        def fake(method, path, headers, body):
            calls.append(path)
            return {'access_token': 'SYNTHETIC'} if method == 'POST' else {'id': ORDER}
        d = self.driver(fake); d.run(ORDER)
        with self.assertRaises(InvalidData): d._boundary.call('POST', '/v1/oauth2/token', {}, b'grant_type=client_credentials')
        self.assertTrue(d.run(ORDER)['repeat_refused'])
        self.assertEqual(len(calls), 2); self.assertEqual(d.export()['allowances_reserved'], 2)
        never = Mock(side_effect=AssertionError('No transport allowed'))
        bad_origin = self.driver(never, origin=BASE + '.invalid')
        self.assertEqual(bad_origin.run(ORDER)['status'], 'REFUSED')
        missing = self.driver(never)
        self.assertEqual(missing.run('UNREGISTEREDORDER')['status'], 'REFUSED')
        for method, path in [('POST', '/v2/checkout/orders'), ('POST', '/v1/notifications/verify-webhook-signature'),
                             ('GET', 'https://api-m.paypal.com/v2/checkout/orders/' + ORDER)]:
            check = self.driver(never); check._order_id = ORDER
            with self.assertRaises(InvalidData): check._boundary.call(method, path, {}, None)
        never.assert_not_called()

    def test_04_expired_preinvoke_and_prerequest_without_transport(self):
        never = Mock(side_effect=AssertionError('Expired transport forbidden'))
        d = self.driver(never); self.clock.advance(300)
        report = d.run(ORDER)
        self.assertEqual(report['status'], 'REFUSED'); self.assertEqual(report['allowances_reserved'], 0)
        self.assertEqual(report['refusal']['phase'], 'PRE_INVOKE')
        sequence = iter([0.0, 0.0, 300.0, 300.0, 300.0])
        alternate = ReadPilotDriver.for_test(self.context, self.registry, never,
                                             clock=lambda: next(sequence))
        report2 = alternate.run(ORDER)
        self.assertEqual(report2['status'], 'REFUSED'); self.assertEqual(report2['transport_calls'], 0)
        self.assertEqual(report2['refusal']['phase'], 'PRE_REQUEST')
        never.assert_not_called()

    def test_05_late_oauth_retains_original_first_unknown_no_get(self):
        calls = []
        original = {'access_token': 'LATE-SYNTHETIC-TOKEN-DO-NOT-EXPORT'}
        def late(method, path, headers, body):
            calls.append(path); self.clock.advance(301); return original
        d = self.driver(late); report = d.run(ORDER)
        self.assertEqual(report['status'], 'UNKNOWN'); self.assertEqual(calls, ['/v1/oauth2/token'])
        self.assertEqual(report['allowances_reserved'], 1); self.assertEqual(report['transport_calls'], 1)
        self.assertEqual(report['first_unknown']['phase'], 'POST_RETURN')
        self.assertEqual(report['first_unknown']['where'], 'transport')
        self.assertIs(d._originals[0].value, original)
        self.assertEqual(d.run(ORDER)['first_unknown'], report['first_unknown'])
        self.assertEqual(len(calls), 1)
        self.assertNotIn(original['access_token'], json.dumps(report))
        self.assertEqual(report['backend_cancellation'], 'NOT_CLAIMED')

    def test_06_cleanup_failure_and_deadline_keep_primary_no_retry(self):
        primary = RuntimeError('SYNTHETIC-PRIMARY-PRIVATE')
        cleanup_error = ValueError('SYNTHETIC-CLEANUP-PRIVATE')
        calls = []
        def fail(method, path, headers, body):
            calls.append(path); raise primary
        def cleanup():
            self.clock.advance(301); raise cleanup_error
        d = self.driver(fail, cleanup=cleanup); report = d.run(ORDER)
        self.assertEqual(report['status'], 'UNKNOWN')
        self.assertEqual(report['first_unknown']['code'], 'TRANSPORT_EXCEPTION')
        self.assertIs(d._originals[0].error, primary)
        self.assertIs(d._originals[1].error, cleanup_error)
        self.assertTrue(any(e.get('code') == 'CLEANUP_FAILURE' for e in report['events']))
        self.assertTrue(any(e.get('where') == 'cleanup' and e.get('code') == 'DEADLINE_EXCEEDED'
                            and e.get('phase') == 'POST_RETURN' for e in report['events']))
        self.assertEqual(report['allowances_reserved'], 1)
        self.assertEqual(d.run(ORDER)['first_unknown'], report['first_unknown'])
        self.assertEqual(len(calls), 1)
        self.assertNotIn(str(primary), json.dumps(report)); self.assertNotIn(str(cleanup_error), json.dumps(report))
