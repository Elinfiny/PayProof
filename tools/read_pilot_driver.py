"""Inert pilot mechanics. Production verifier injection is deliberately inactive."""
import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from payproof.admission import SandboxContext
from payproof.core import InvalidData, UnknownResult
from payproof.paypal import BASE, SandboxPayPal

_TEST_BINDING = object()
_CONSUMER_BINDING = object()
_TOKEN_PATH = '/v1/oauth2/token'


@dataclass(frozen=True, repr=False)
class SyntheticRegistry:
    """Test provenance only; never an authentic runtime order registry."""
    context: SandboxContext = field(repr=False)
    order_ids: frozenset = field(repr=False)
    _seal: object = field(repr=False)

    @classmethod
    def for_test(cls, context, order_ids):
        if type(context) is not SandboxContext or context.test_only is not True:
            raise InvalidData('Existing TEST_ONLY context required')
        if not isinstance(order_ids, frozenset) or not order_ids:
            raise InvalidData('Preexisting synthetic registry required')
        return cls(context, order_ids, _TEST_BINDING)

    def require_existing(self, context, order_id):
        if self._seal is not _TEST_BINDING or context is not self.context or order_id not in self.order_ids:
            raise InvalidData('Order is not in the bound preexisting registry')


@dataclass(repr=False)
class _Original:
    where: str
    value: object = field(default=None, repr=False)
    error: object = field(default=None, repr=False)


class _Stop(Exception):
    pass


class _Boundary:
    def __init__(self, owner, transport, origin):
        self.owner, self.transport, self.origin = owner, transport, origin
        self.in_flight = False
        self.state = 'NEW'

    def call(self, method, path, headers, body):
        d = self.owner
        if self.origin != BASE or self.in_flight or d._first_unknown is not None:
            raise InvalidData('Origin or request state refused')
        expected = ('POST', _TOKEN_PATH) if d._reserved == 0 else (
            ('GET', '/v2/checkout/orders/' + d._order_id)
            if d._reserved == 1 and self.state == 'OAUTH_RETURNED' else None)
        if expected is None or (method, path) != expected:
            raise InvalidData('Attempt limit, duplicate or endpoint refused')
        if method == 'GET' and body is not None:
            raise InvalidData('Order read body refused')
        if method == 'POST' and body != b'grant_type=client_credentials':
            raise InvalidData('OAuth request body refused')
        d._context.require('orders:read')
        d._deadline_check('PRE_REQUEST', 'transport')
        d._reserved += 1  # Consume allowance before any invocation, never refund.
        self.state = 'OAUTH_RESERVED' if method == 'POST' else 'GET_RESERVED'
        d._events.append({'kind': 'ALLOWANCE_RESERVED', 'ordinal': d._reserved,
                          'operation': 'OAUTH' if method == 'POST' else 'ORDER_READ'})
        d._context.require('orders:read')
        d._deadline_check('PRE_INVOKE', 'transport')
        self.in_flight = True
        d._invoked += 1
        try:
            original = self.transport(method, path, headers, body)
        except Exception as error:
            index = d._retain('transport', error=error)
            d._problem('TRANSPORT_EXCEPTION', 'POST_RETURN', 'transport', index)
            raise _Stop from None
        else:
            # Retain exact original privately BEFORE deadline/conversion/response guards.
            d._retain('transport', value=original)
        finally:
            self.in_flight = False
        d._deadline_check('POST_RETURN', 'transport')
        self.state = 'OAUTH_RETURNED' if method == 'POST' else 'GET_RETURNED'
        return original


class ReadPilotDriver:
    """Default unbound. for_test proves mechanics, never production authorization."""
    def __init__(self, *, future_runtime_verifier=None, clock=time.monotonic, cleanup=None):
        self._future_runtime_verifier = future_runtime_verifier  # Inactive injection point.
        self._clock = clock
        self._cleanup = cleanup or (lambda: None)
        start = self._now()
        self._absolute_deadline = start + 300.0
        self._binding = None
        self._context = self._registry = self._boundary = None
        self._order_id = None
        self._order_hash = None
        self._reserved = self._invoked = 0
        self._consumed = self._returned = False
        self._first_unknown = self._refusal = None
        self._events = []
        self._originals = []  # Private only; never exported, repr'd or logged.

    @classmethod
    def for_test(cls, context, registry, transport, *, clock=time.monotonic, cleanup=None, origin=BASE):
        if type(context) is not SandboxContext or context.test_only is not True:
            raise InvalidData('Only existing sealed TEST_ONLY context allowed')
        if context.operations != frozenset({'orders:read'}):
            raise InvalidData('Exclusive read context required')
        if type(registry) is not SyntheticRegistry or registry._seal is not _TEST_BINDING or registry.context is not context:
            raise InvalidData('Bound synthetic registry required')
        if not callable(transport):
            raise InvalidData('Explicit fake transport required')
        driver = cls(clock=clock, cleanup=cleanup)
        driver._binding, driver._context, driver._registry = _TEST_BINDING, context, registry
        driver._boundary = _Boundary(driver, transport, origin)
        return driver

    def _now(self):
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value):
            raise InvalidData('Finite monotonic clock required')
        return value

    def _retain(self, where, *, value=None, error=None):
        self._originals.append(_Original(where, value, error))
        return len(self._originals) - 1

    def _problem(self, code, phase, where, original_index=None):
        metadata = {'code': code, 'phase': phase, 'where': where,
                    'original_index': original_index, 'allowances_reserved': self._reserved,
                    'transport_calls': self._invoked}
        self._events.append({'kind': 'PROBLEM', **metadata})
        if self._invoked:
            if self._first_unknown is None:
                self._first_unknown = metadata.copy()
        elif self._refusal is None:
            self._refusal = metadata.copy()

    def _deadline_check(self, phase, where, *, stop=True):
        if self._now() >= self._absolute_deadline:
            self._problem('DEADLINE_EXCEEDED', phase, where,
                          len(self._originals) - 1 if self._originals else None)
            if stop:
                raise _Stop
            return False
        return True

    def run(self, order_id):
        # No callable, JSON, flag, PID or locally signed HMAC can activate production.
        if self._binding not in (_TEST_BINDING,_CONSUMER_BINDING):
            raise InvalidData('Production verifier, grant and custody are unbound')
        if self._consumed:
            return self.export(repeat_refused=True)
        self._consumed = True
        try:
            if not isinstance(order_id, str) or not re.fullmatch(r'[A-Z0-9]{1,36}', order_id):
                raise InvalidData('Fixed sandbox order identifier required')
            if self._binding is _TEST_BINDING:
                self._registry.require_existing(self._context, order_id)
            self._order_id = order_id
            self._order_hash = hashlib.sha256(order_id.encode()).hexdigest()
            self._context.require('orders:read')
            self._deadline_check('PRE_INVOKE', 'driver')
            adapter = SandboxPayPal(self._context, transport=self._boundary.call)
            adapter.get_order(order_id)
            self._deadline_check('POST_RETURN', 'adapter')
            self._returned = True
        except _Stop:
            pass
        except Exception as error:
            index = self._retain('adapter_or_policy', error=error)
            self._problem('ADAPTER_OR_POLICY_REFUSAL', 'POST_RETURN', 'adapter_or_policy', index)
        finally:
            # Cleanup is best-effort even after the deadline, but lateness is never success.
            self._deadline_check('PRE_INVOKE', 'cleanup', stop=False)
            try:
                original = self._cleanup()
            except Exception as error:
                index = self._retain('cleanup', error=error)
                self._problem('CLEANUP_FAILURE', 'POST_RETURN', 'cleanup', index)
            else:
                self._retain('cleanup', value=original)
            self._deadline_check('POST_RETURN', 'cleanup', stop=False)
        return self.export()

    def export(self, *, repeat_refused=False):
        status = 'UNKNOWN' if self._first_unknown is not None else (
            'REFUSED' if self._refusal is not None else
            'SYNTHETIC_RETURNED' if self._returned else 'UNBOUND')
        return {'scope': 'SYNTHETIC_MECHANICS_ONLY' if self._context is None or self._context.test_only else 'HOST_CONSUMER_READ', 'status': status,
                'production_verifier_active': False, 'real_runtime_admitted': False,
                'allowances_reserved': self._reserved, 'transport_calls': self._invoked,
                'attempt_limit': 2, 'OAuth_limit': 1, 'GET_limit': 1, 'retries': 0,
                'deadline_seconds': 300, 'order_id_sha256': self._order_hash,
                'repeat_refused': repeat_refused,
                'first_unknown': dict(self._first_unknown) if self._first_unknown else None,
                'refusal': dict(self._refusal) if self._refusal else None,
                'events': [dict(event) for event in self._events],
                'backend_cancellation': 'NOT_CLAIMED'}


def _from_consumer(cls, context, registry, provider):
    from payproof.admission import ConsumerContext
    from payproof.bootstrap_bridge import ConsumerRegistry, ConsumerProvider, _REGISTRY
    if (type(context) is not ConsumerContext or type(registry) is not ConsumerRegistry
            or registry._seal is not _REGISTRY or type(provider) is not ConsumerProvider
            or registry.provider is not provider or provider.context is not context):
        raise InvalidData('AUTHENTIC_CONSUMER_CHAIN_REQUIRED')
    context.require(production=not context.test_only)
    driver=cls(clock=provider._clock);driver._binding=_CONSUMER_BINDING
    driver._context=context.context;driver._registry=registry
    driver._boundary=_Boundary(driver,provider.paypal,BASE)
    return driver

ReadPilotDriver.from_consumer=classmethod(_from_consumer)
