"""Four focused17 cases; fake connections/clock only, never historical suites."""
import json
import ssl
import unittest
from payproof.github_oidc import FixedJWKSLoader, IdentityRefused, JWKSSnapshot, TransportUnknown


class Clock:
    def __init__(self):
        self.value = 0.0
        self.phase_source = None
        self.fail_phase_once = None
        self.error = RuntimeError('SYNTHETIC_PRIVATE_CLOCK_ERROR')
    def __call__(self):
        if self.fail_phase_once and self.phase_source and self.phase_source() == self.fail_phase_once:
            self.fail_phase_once = None
            raise self.error
        return self.value
    def advance(self, seconds): self.value += seconds


class Socket:
    def __init__(self): self.timeout = None; self.values = []
    def settimeout(self, value):
        if value < 0: raise AssertionError('Negative timeout')
        self.timeout = value; self.values.append(value)
        return None


class Response:
    def __init__(self, owner): self.owner = owner
    @property
    def status(self):
        self.owner.status_calls += 1
        return 200
    def read(self, limit):
        o = self.owner
        o.read_calls += 1
        o.observations['READ'] = (o.conn.timeout, o.conn.sock.timeout)
        o.clock.advance(o.read_delay)
        return o.body[:limit]


class FakeHTTPS:
    """Factory exactly shaped like HTTPSConnection; never authentic TLS evidence."""
    def __init__(self, clock):
        self.clock = clock
        self.constructor_delay = self.request_delay = self.response_delay = self.read_delay = self.close_delay = 0
        self.constructor_calls = self.request_calls = self.response_calls = self.status_calls = self.read_calls = self.close_calls = 0
        self.request_error = self.close_error = None
        self.request_result = object()
        self.close_result = object()
        self.body = b'{"keys":[{"kid":"SYNTHETIC_ONLY"}]}'
        self.response = Response(self)
        self.observations = {}
        self.conn = None
    def __call__(self, host, port, *, timeout, context):
        assert host == 'token.actions.githubusercontent.com' and port == 443
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        self.constructor_calls += 1
        self.observations['CONSTRUCTOR'] = timeout
        o = self
        class Connection:
            def __init__(self): self.timeout = timeout; self.sock = Socket()
            def request(self, method, path, body=None, headers=None):
                assert method == 'GET' and path == '/.well-known/jwks'
                o.request_calls += 1
                o.observations['REQUEST'] = (self.timeout, self.sock.timeout)
                if o.request_error is not None: raise o.request_error
                o.clock.advance(o.request_delay)
                return o.request_result
            def getresponse(self):
                o.response_calls += 1
                o.observations['GETRESPONSE'] = (self.timeout, self.sock.timeout)
                o.clock.advance(o.response_delay)
                return o.response
            def close(self):
                o.close_calls += 1
                o.observations['CLOSE'] = (self.timeout, self.sock.timeout)
                o.clock.advance(o.close_delay)
                if o.close_error is not None: raise o.close_error
                return o.close_result
        self.conn = Connection()
        self.clock.advance(self.constructor_delay)
        return self.conn


class Boundary17Tests(unittest.TestCase):
    def loader(self, clock, factory):
        loader = FixedJWKSLoader.for_test(factory, clock=clock)
        clock.phase_source = lambda: loader._wire._clock_phase
        return loader

    def test_01_late_request_blocks_getresponse_and_late_constructor_is_owned(self):
        for late in ('REQUEST', 'CONSTRUCTOR'):
            clock = Clock(); factory = FakeHTTPS(clock)
            if late == 'REQUEST': factory.request_delay = 301
            else: factory.constructor_delay = 301
            loader = self.loader(clock, factory)
            with self.assertRaises(TransportUnknown): loader.fetch_for_test(observed_at=123, now=123)
            wire = loader._wire
            self.assertEqual(factory.response_calls, 0)
            self.assertEqual(factory.read_calls, 0)
            self.assertEqual(factory.close_calls, 1)
            self.assertEqual(factory.request_calls, 1 if late == 'REQUEST' else 0)
            self.assertTrue(any(x.phase == 'CONSTRUCTOR_RETURN' and x.value is factory.conn
                                for x in wire._per_call_originals))
            if late == 'REQUEST':
                self.assertTrue(any(x.phase == 'REQUEST_RETURN' and x.value is factory.request_result
                                    for x in wire._per_call_originals))
            self.assertEqual(wire.first_unknown['operation'], late)
            first = dict(wire.first_unknown)
            with self.assertRaises(IdentityRefused): loader.fetch_for_test(observed_at=123, now=123)
            self.assertEqual(wire.first_unknown, first)
            self.assertEqual(factory.close_calls, 1)

    def test_02_late_getresponse_or_read_retains_original_and_stops_use(self):
        for late in ('GETRESPONSE', 'READ'):
            clock = Clock(); factory = FakeHTTPS(clock)
            if late == 'GETRESPONSE': factory.response_delay = 301
            else:
                factory.read_delay = 301
                factory.body = b'SYNTHETIC_INVALID_JSON_MUST_NEVER_BE_PARSED'
            loader = self.loader(clock, factory)
            with self.assertRaises(TransportUnknown): loader.fetch_for_test(observed_at=123, now=123)
            wire = loader._wire
            self.assertTrue(any(x.phase == 'GETRESPONSE_RETURN' and x.value is factory.response
                                for x in wire._per_call_originals))
            self.assertEqual(factory.read_calls, 0 if late == 'GETRESPONSE' else 1)
            self.assertEqual(factory.status_calls, 0 if late == 'GETRESPONSE' else 1)
            if late == 'READ':
                self.assertTrue(any(x.phase == 'READ_RETURN' and x.value is factory.body
                                    for x in wire._per_call_originals))
            self.assertEqual(wire.first_unknown['operation'], late)
            self.assertEqual(factory.close_calls, 1)
            with self.assertRaises(IdentityRefused):
                wire.exchange('GET', 'token.actions.githubusercontent.com', '/.well-known/jwks')
            self.assertEqual(factory.constructor_calls, 1)

    def test_03_clock_throw_before_cleanup_keeps_primary_and_close_once(self):
        clock = Clock(); factory = FakeHTTPS(clock)
        primary = RuntimeError('SYNTHETIC_PRIVATE_PRIMARY')
        cleanup = RuntimeError('SYNTHETIC_PRIVATE_CLEANUP')
        factory.request_error = primary
        factory.close_error = cleanup
        factory.close_delay = 301
        loader = self.loader(clock, factory)
        clock.fail_phase_once = 'PRE_REQUEST_CLEANUP'
        with self.assertRaises(TransportUnknown): loader.fetch_for_test(observed_at=123, now=123)
        wire = loader._wire
        self.assertEqual(factory.close_calls, 1)
        self.assertEqual(factory.response_calls, 0)
        self.assertEqual(wire.first_unknown['code'], 'HTTP_EXCEPTION')
        self.assertEqual(wire.first_unknown['operation'], 'REQUEST')
        self.assertTrue(any(x.error is primary for x in wire.originals))
        self.assertTrue(any(x.error is cleanup for x in wire.originals))
        self.assertTrue(any(x.error is clock.error and x.phase == 'CLOCK_EXCEPTION' for x in wire.originals))
        self.assertEqual(wire._clock_errors, [clock.error])
        exported = json.dumps(loader.metadata())
        for secret in (str(primary), str(cleanup), str(clock.error)):
            self.assertNotIn(secret, exported)
        first = dict(wire.first_unknown)
        with self.assertRaises(IdentityRefused): loader.fetch_for_test(observed_at=123, now=123)
        self.assertEqual(wire.first_unknown, first)
        self.assertEqual(factory.close_calls, 1)

    def test_04_remaining_socket_timeout_decreases_and_timely_body_test_only(self):
        clock = Clock(); factory = FakeHTTPS(clock)
        factory.request_delay, factory.response_delay, factory.read_delay = 20, 30, 10
        loader = self.loader(clock, factory)
        snapshot = loader.fetch_for_test(observed_at=123, now=123)
        self.assertIs(type(snapshot), JWKSSnapshot)
        self.assertIs(snapshot._raw, factory.body)
        self.assertEqual(factory.observations['CONSTRUCTOR'], 300)
        self.assertEqual(factory.observations['REQUEST'], (300, 300))
        self.assertEqual(factory.observations['GETRESPONSE'], (280, 280))
        self.assertEqual(factory.observations['READ'], (250, 250))
        self.assertEqual(factory.observations['CLOSE'], (240, 240))
        values = factory.conn.sock.values
        self.assertTrue(all(b <= a for a, b in zip(values, values[1:])))
        self.assertEqual(loader._wire._deadline, 300)
        self.assertEqual(factory.close_calls, 1)
        self.assertFalse(loader.metadata()['authenticated_TLS_provenance'])
        self.assertTrue(any(x.phase == 'REQUEST_RETURN' and x.value is factory.request_result
                            for x in loader._wire._per_call_originals))
        self.assertTrue(any(x.phase == 'CLOSE_RETURN' and x.value is factory.close_result
                            for x in loader._wire._per_call_originals))
        with self.assertRaisesRegex(IdentityRefused, 'UNBOUND'):
            loader.fetch_production(observed_at=123, now=123)
