"""Seven synthetic cases; existing test signing key only, never runtime custody."""
import hashlib
import hmac
import json
import socket
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from host_contract_fixture import TEST_KEY, signed_fixture
from payproof import admission, server
from payproof.admission import SandboxContext, _verify_receipt, source_fingerprint
from payproof.core import InvalidData, canonical
from payproof.paypal import SandboxPayPal


V2 = 'PAYPROOF_SANDBOX_READ_ADMISSION_V2'


def materials():
    receipt, raw = signed_fixture({'schema': V2, 'operations': ['orders:read']})
    grant = json.loads(receipt)['grant']
    credentials = json.loads(raw)
    del grant['webhook_id']
    del credentials['webhook_id']
    return grant, credentials


def signed(grant):
    signature = hmac.new(TEST_KEY, canonical(grant).encode(), hashlib.sha256).hexdigest()
    return canonical({'grant': grant, 'signature': signature}).encode()


def verify(grant, credentials):
    return _verify_receipt(signed(grant), TEST_KEY, canonical(credentials).encode(), test_only=True)


class ReadAdmissionV2Tests(unittest.TestCase):
    def setUp(self):
        self.blocks = []
        for target in ('socket.socket', 'socket.create_connection',
                       'payproof.paypal.SandboxPayPal._network'):
            guard = patch(target, side_effect=AssertionError('Native network is forbidden'))
            self.blocks.append(guard.start())
            self.addCleanup(guard.stop)

    def tearDown(self):
        for blocked in self.blocks:
            blocked.assert_not_called()

    def test_01_v2_valid_read_without_webhook(self):
        grant, credentials = materials()
        context = verify(grant, credentials)
        self.assertIs(type(context), SandboxContext)
        self.assertIsNone(context.webhook_id)
        self.assertIs(context.test_only, True)
        self.assertEqual(context.operations, frozenset({'orders:read'}))
        context.require('orders:read')
        self.assertNotIn('fake-secret', repr(context))
        calls = []

        def fake(method, path, headers, body):
            calls.append((method, path))
            if path == '/v1/oauth2/token':
                return {'access_token': 'SYNTHETIC-TOKEN'}
            return {'id': 'SYNTHETICORDER01', 'status': 'COMPLETED'}

        adapter = SandboxPayPal(context, transport=fake)
        self.assertEqual(adapter.get_order('SYNTHETICORDER01')['id'], 'SYNTHETICORDER01')
        self.assertEqual(calls, [('POST', '/v1/oauth2/token'),
                                 ('GET', '/v2/checkout/orders/SYNTHETICORDER01')])

    def test_02_exclusive_read_rejects_create_and_verify_before_transport(self):
        grant, credentials = materials()
        for scope in ([], ['orders:create'], ['webhooks:verify'],
                      ['orders:read', 'orders:create'], ['orders:read', 'orders:read'],
                      'orders:read', True):
            altered = {**grant, 'operations': scope}
            with self.subTest(scope=scope), self.assertRaises(InvalidData):
                verify(altered, credentials)
        transport = Mock(side_effect=AssertionError('Forbidden OAuth/transport'))
        adapter = SandboxPayPal(verify(grant, credentials), transport=transport)
        store = Mock()
        with self.assertRaises(InvalidData):
            adapter.create_order(store, 'SYNTHETIC-REQ', '1.00', 'USD')
        store.reserve_effect.assert_not_called()
        with self.assertRaises(InvalidData):
            adapter.request('POST', '/v2/checkout/orders', {})
        headers = {key: 'SYNTHETIC' for key in ('paypal-auth-algo', 'paypal-cert-url',
                   'paypal-transmission-id', 'paypal-transmission-sig', 'paypal-transmission-time')}
        with self.assertRaises(InvalidData):
            adapter.verify_webhook(headers, b'{"event_type":"SYNTHETIC"}')
        transport.assert_not_called()

    def test_03_exact_missing_extra_and_duplicate_keys(self):
        grant, credentials = materials()
        for key in grant:
            altered = deepcopy(grant)
            del altered[key]
            with self.subTest(missing_grant=key), self.assertRaises(InvalidData):
                verify(altered, credentials)
        for extra in ({'webhook_id': 'fake-hook'}, {'admitted': True}):
            with self.subTest(extra_grant=list(extra)), self.assertRaises(InvalidData):
                verify({**grant, **extra}, credentials)
        for key in credentials:
            altered = deepcopy(credentials)
            del altered[key]
            with self.subTest(missing_credentials=key), self.assertRaises(InvalidData):
                verify(grant, altered)
        for extra in ({'webhook_id': 'fake-hook'}, {'admitted': True}):
            with self.subTest(extra_credentials=list(extra)), self.assertRaises(InvalidData):
                verify(grant, {**credentials, **extra})
        duplicated_grant = signed(grant).decode().replace(
            '"project":"PayProof"', '"project":"PayProof","project":"PayProof"')
        self.assertNotEqual(duplicated_grant.encode(), signed(grant))
        with self.assertRaises(InvalidData):
            _verify_receipt(duplicated_grant.encode(), TEST_KEY,
                            canonical(credentials).encode(), test_only=True)
        raw = canonical(credentials).replace('"client_id":"fake-client"',
                                             '"client_id":"fake-client","client_id":"fake-client"')
        self.assertNotEqual(raw, canonical(credentials))
        with self.assertRaises(InvalidData):
            _verify_receipt(signed(grant), TEST_KEY, raw.encode(), test_only=True)

    def test_04_signature_source_expiry_and_binding_refusals(self):
        grant, credentials = materials()
        bad_signature = {'grant': grant, 'signature': '0' * 64}
        with self.assertRaises(InvalidData):
            _verify_receipt(canonical(bad_signature).encode(), TEST_KEY,
                            canonical(credentials).encode(), test_only=True)
        with self.assertRaises(InvalidData):
            _verify_receipt(signed(grant), TEST_KEY[:10],
                            canonical(credentials).encode(), test_only=True)
        expired = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        naive = (datetime.now() + timedelta(days=1)).isoformat()
        for key, value in (('source_sha256', '0' * 64),
                           ('source_sha256', '17a48ab9345c8d7948961abcc1ae5478222680b12b5434f05bd24420e4cbfd53'),
                           ('expires_at', expired), ('expires_at', naive),
                           ('expires_at', None), ('expires_at', True),
                           ('project', 'Other'), ('environment', 'live'),
                           ('external_budget_usd', '1.00'), ('live_ai', True)):
            with self.subTest(key=key, value=value), self.assertRaises(InvalidData):
                verify({**grant, key: value}, credentials)
        for bad_id in ('other-synthetic-client', '', True):
            with self.subTest(client=bad_id), self.assertRaises(InvalidData):
                verify(grant, {**credentials, 'client_id': bad_id})
        self.assertNotEqual(source_fingerprint(),
                            '17a48ab9345c8d7948961abcc1ae5478222680b12b5434f05bd24420e4cbfd53')

    def test_05_v1_keeps_webhook_requirement_and_binding(self):
        receipt, raw = signed_fixture()
        context = _verify_receipt(receipt, TEST_KEY, raw, test_only=True)
        self.assertEqual(context.webhook_id, 'fake-hook')
        self.assertEqual(context.operations, frozenset({'orders:read', 'orders:create', 'webhooks:verify'}))
        read_receipt, read_raw = signed_fixture({'operations': ['orders:read']})
        read_context = _verify_receipt(read_receipt, TEST_KEY, read_raw, test_only=True)
        self.assertEqual(read_context.webhook_id, 'fake-hook')
        grant = json.loads(read_receipt)['grant']
        credentials = json.loads(read_raw)
        without_webhook = {key: value for key, value in grant.items() if key != 'webhook_id'}
        with self.assertRaises(InvalidData):
            verify(without_webhook, credentials)
        no_credential_hook = {key: value for key, value in credentials.items() if key != 'webhook_id'}
        with self.assertRaises(InvalidData):
            verify(grant, no_credential_hook)
        with self.assertRaises(InvalidData):
            verify(grant, {**credentials, 'webhook_id': 'different-synthetic-hook'})

    def test_06_test_context_cannot_start_production_or_network(self):
        grant, credentials = materials()
        context = verify(grant, credentials)
        with self.assertRaises(InvalidData):
            SandboxPayPal(context)
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'not-created' / 'sandbox.sqlite3'
            with patch('payproof.server.load_host_context', return_value=context):
                with self.assertRaises(InvalidData):
                    server.prepare_application('sandbox-readonly', str(target))
                with self.assertRaises(InvalidData):
                    server.make_server(0, str(target), 'sandbox-readonly')
            self.assertFalse(target.parent.exists())
        with patch('payproof.admission._host_file', side_effect=InvalidData('Synthetic missing host')) as host:
            with self.assertRaises(InvalidData):
                admission.load_host_context()
            host.assert_called_once_with(admission.ADMISSION_PATH, 16384)

    def test_07_json_none_and_boolean_never_supply_sealed_context(self):
        for candidate in (None, True, False, {}, {'admitted': True}, '{"admitted":true}'):
            with self.subTest(candidate=candidate):
                with self.assertRaises(InvalidData):
                    SandboxPayPal(candidate, transport=Mock())
                with self.assertRaises(InvalidData):
                    server._read_scope(candidate)
        for raw in (b'null', b'true', b'false', b'[]', b'{"admitted":true}'):
            with self.subTest(raw=raw), self.assertRaises(InvalidData):
                _verify_receipt(raw, TEST_KEY, b'{}', test_only=True)
        with self.assertRaises(InvalidData):
            SandboxContext('SYNTHETIC', source_fingerprint(),
                           datetime.now(timezone.utc) + timedelta(minutes=1),
                           frozenset({'orders:read'}), 'fake-client', 'fake-secret', None, True, object())
