"""Private RS256 identity verifier candidate; no production trust adapter is enabled.

No token-specified key/URL is followed. TEST_ONLY evidence is never a host grant.
"""
import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ISSUER = 'https://token.actions.githubusercontent.com'
JWKS_URL = ISSUER + '/.well-known/jwks'
REPOSITORY = 'Elinfiny/PayProof'
REPOSITORY_ID = '1419908202'
OWNER_ID = '273768139'
_TEST = object()
_PROVIDER = object()
_EVIDENCE = object()


class IdentityRefused(ValueError):
    """Stable rejection code only, never raw token or crypto error details."""


def _reject(code):
    raise IdentityRefused(code) from None


def _object(raw, limit):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= limit:
        _reject('OBJECT_SIZE')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _reject('DUPLICATE_KEY')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: _reject('NONFINITE_JSON'))
    except (ValueError, UnicodeError):
        _reject('INVALID_JSON')
    if type(value) is not dict:
        _reject('OBJECT_REQUIRED')
    return value


def _b64(text, limit):
    if type(text) is not str or not 0 < len(text) <= limit or not re.fullmatch(r'[A-Za-z0-9_-]+', text):
        _reject('BASE64URL')
    try:
        raw = base64.b64decode(text + '=' * (-len(text) % 4), altchars=b'-_', validate=True)
    except (ValueError, base64.binascii.Error):
        _reject('BASE64URL')
    if base64.urlsafe_b64encode(raw).rstrip(b'=').decode() != text:
        _reject('NONCANONICAL_BASE64URL')
    return raw


@dataclass(frozen=True, repr=False)
class IdentityPolicy:
    """Expected values supplied by a future source grant, never inferred from JWT."""
    audience: str
    workflow_ref: str
    ref: str
    sha: str
    workflow_sha: str
    event_name: str
    subject: str
    run_id: str
    run_attempt: str
    not_before: int
    expires_at: int

    def __post_init__(self):
        if (type(self.audience) is not str or not self.audience or len(self.audience) > 256
                or self.workflow_ref != REPOSITORY + '/.github/workflows/payproof-read-pilot.yml@refs/heads/main'
                or self.ref != 'refs/heads/main' or self.event_name != 'workflow_dispatch'
                or self.subject != 'repo:Elinfiny@273768139/PayProof@1419908202:ref:refs/heads/main'
                or any(type(x) is not str or not re.fullmatch(r'[0-9a-f]{40}', x) for x in (self.sha, self.workflow_sha))
                or self.sha != self.workflow_sha
                or type(self.run_id) is not str or not re.fullmatch(r'[1-9][0-9]{0,19}', self.run_id)
                or self.run_attempt != '1'
                or type(self.not_before) is not int or type(self.expires_at) is not int
                or not 0 < self.expires_at - self.not_before <= 300):
            _reject('POLICY_UNBOUND')


@dataclass(frozen=True, repr=False)
class JWKSSnapshot:
    """Only synthetic snapshots can be minted in this candidate.

    A fixed-URL authenticated provider loader needs separate review/authority;
    raw JWKS + a URL string is not authenticated provenance.
    """
    _raw: bytes = field(repr=False)
    observed_at: int
    _seal: object = field(repr=False)
    origin: str = ISSUER
    url: str = JWKS_URL

    @classmethod
    def synthetic_for_test(cls, raw, *, observed_at):
        _object(raw, 65536)
        if type(observed_at) is not int:
            _reject('SNAPSHOT_TIME')
        return cls(raw, observed_at, _TEST)


@dataclass(frozen=True, repr=False)
class VerifiedIdentity:
    _claims: object = field(repr=False)
    _seal: object = field(repr=False)
    policy: IdentityPolicy = field(repr=False)
    test_only: bool = True

    def metadata(self):
        if self._seal is not _EVIDENCE or self.test_only is not True:
            _reject('EVIDENCE_SCOPE')
        return {'scope': 'TEST_ONLY_SIGNATURE_AND_CLAIMS', 'repository_id': REPOSITORY_ID,
                'repository_owner_id': OWNER_ID, 'source_sha': self.policy.sha,
                'workflow_ref': self.policy.workflow_ref, 'event_name': self.policy.event_name,
                'production_grant': False, 'raw_token_exported': False}


class GitHubOIDCVerifier:
    def __init__(self, binding=None, key_source=None):
        self._binding, self._key_source = binding, key_source

    def verify_production(self, token, *, now):
        from .admission import ConsumerContext
        if type(self._binding) is not ConsumerContext:
            _reject('AUTHENTIC_RUNTIME_BINDING_UNBOUND')
        g=self._binding.require(production=True)
        if type(self._key_source) is not FixedJWKSLoader or self._key_source._binding is not self._binding:
            _reject('AUTHENTIC_JWKS_PROVIDER_REQUIRED')
        snapshot=self._key_source.fetch_production(observed_at=now,now=now)
        identity=self._verify(token,policy=consumer_policy(g),snapshot=snapshot,now=now,test_only=False)
        if identity._claims.get('actor')!='Elinfiny' or identity._claims.get('actor_id')!=OWNER_ID:
            _reject('OWNER_ACTOR_REQUIRED')
        return identity

    def verify_for_test(self, token, *, policy, snapshot, now):
        return self._verify(token,policy=policy,snapshot=snapshot,now=now,test_only=True)

    def _verify(self, token, *, policy, snapshot, now, test_only):
        if type(policy) is not IdentityPolicy or type(snapshot) is not JWKSSnapshot or snapshot._seal is not (_TEST if test_only else _PROVIDER):
            _reject('TYPED_TEST_INPUT_REQUIRED')
        if snapshot.origin != ISSUER or snapshot.url != JWKS_URL:
            _reject('JWKS_ORIGIN')
        if type(now) is not int or not policy.not_before <= now < policy.expires_at:
            _reject('ABSOLUTE_WINDOW')
        if not 0 <= now - snapshot.observed_at <= 300:
            _reject('JWKS_STALE')
        if type(token) is not str or len(token) > 32768 or token.count('.') != 2:
            _reject('COMPACT_JWS')
        head, payload, signature = token.split('.')
        header = _object(_b64(head, 4096), 3072)
        if (header.get('alg') != 'RS256' or header.get('typ') != 'JWT'
                or not {'alg', 'typ', 'kid'} <= set(header)
                or not set(header) <= {'alg', 'typ', 'kid', 'x5t', 'x5t#S256'}
                or type(header['kid']) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', header['kid'])):
            _reject('HEADER_ALGORITHM_OR_KEY_REFERENCE')
        jwks = _object(snapshot._raw, 65536)
        keys = jwks.get('keys')
        if set(jwks) != {'keys'} or type(keys) is not list or not 1 <= len(keys) <= 32:
            _reject('JWKS_SHAPE')
        if any(type(k) is not dict or type(k.get('kid')) is not str for k in keys):
            _reject('JWKS_KEYS')
        if len({k['kid'] for k in keys}) != len(keys):
            _reject('DUPLICATE_KID')
        selected = [k for k in keys if k['kid'] == header['kid']]
        if len(selected) != 1:
            _reject('KID_NOT_FOUND')
        key = selected[0]
        if (key.get('kty') != 'RSA' or key.get('use') != 'sig' or key.get('alg') != 'RS256'
                or not {'kid', 'kty', 'use', 'alg', 'n', 'e'} <= set(key)
                or not set(key) <= {'kid', 'kty', 'use', 'alg', 'n', 'e', 'x5c', 'x5t', 'x5t#S256'}):
            _reject('RSA_SIGNING_KEY_REQUIRED')
        nraw, eraw = _b64(key['n'], 1400), _b64(key['e'], 8)
        if nraw[0] == 0 or eraw[0] == 0:
            _reject('NONCANONICAL_RSA_INTEGER')
        n, e = int.from_bytes(nraw, 'big'), int.from_bytes(eraw, 'big')
        if not 2048 <= n.bit_length() <= 8192 or e != 65537:
            _reject('RSA_KEY_POLICY')
        try:
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            public_key.verify(_b64(signature, 1400), (head + '.' + payload).encode('ascii'),
                              padding.PKCS1v15(), hashes.SHA256())
        except (InvalidSignature, ValueError, TypeError):
            _reject('SIGNATURE_INVALID')
        # No identity is used until cryptographic signature verification completes.
        claims = _object(_b64(payload, 24576), 18432)
        expected = {'iss': ISSUER, 'aud': policy.audience, 'repository': REPOSITORY,
                    'repository_id': REPOSITORY_ID, 'repository_owner_id': OWNER_ID,
                    'repository_owner': 'Elinfiny', 'repository_visibility': 'private',
                    'workflow_ref': policy.workflow_ref, 'workflow_sha': policy.workflow_sha,
                    'ref': policy.ref, 'sha': policy.sha, 'event_name': policy.event_name,
                    'sub': policy.subject, 'run_id': policy.run_id, 'run_attempt': policy.run_attempt,
                    'runner_environment': 'github-hosted', 'ref_type': 'branch'}
        if any(type(claims.get(k)) is not str or claims[k] != v for k, v in expected.items()):
            _reject('IDENTITY_OR_ISSUER_AUDIENCE')
        if any(type(claims.get(k)) is not int for k in ('iat', 'nbf', 'exp')):
            _reject('NUMERIC_DATE_REQUIRED')
        iat, nbf, exp = (claims[k] for k in ('iat', 'nbf', 'exp'))
        if not (policy.not_before <= iat <= now < exp <= policy.expires_at
                and policy.not_before <= nbf <= now
                and 0 < exp - iat <= 300):
            _reject('TOKEN_TIME_WINDOW')
        if type(claims.get('jti')) is not str or not 1 <= len(claims['jti']) <= 256:
            _reject('JTI_REQUIRED')
        # job_workflow_ref is optional/reusable-workflow-specific; no invented job claim.
        return VerifiedIdentity(MappingProxyType(claims), _EVIDENCE, policy, test_only)


def require_test_evidence(identity):
    if (type(identity) is not VerifiedIdentity or identity._seal is not _EVIDENCE
            or identity.test_only is not True):
        _reject('VERIFIED_TEST_EVIDENCE_REQUIRED')
    return identity


# Private transport candidate16. Production calls stay unbound; factories used
# by the six inert cases are explicit TEST_ONLY providers, never TLS provenance.
import http.client
import ssl
import time


class TransportUnknown(IdentityRefused):
    pass


@dataclass(repr=False)
class _PrivateOriginal:
    phase: str
    value: object = field(default=None, repr=False)
    error: object = field(default=None, repr=False)


class _FixedHTTPS:
    """Per-call bounded HTTPS, with a separately claimed best-effort close.

    Every blocking return/exception is privately owned before its post guard.
    No fake factory grants authentic TLS/caller provenance or production access.
    """
    def __init__(self, *, factory=None, clock=time.monotonic, seconds=300, limit_calls=1, scope=None):
        if (type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 300
                or type(limit_calls) is not int or not 1 <= limit_calls <= 64):
            _reject('BOUNDED_TRANSPORT_BUDGET_REQUIRED')
        self._factory = factory if factory is not None else http.client.HTTPSConnection
        self._clock, self._scope = clock, scope
        self._limit_calls, self.calls = limit_calls, 0
        self.originals = []  # Legacy HTTP outcomes, still private.
        self._per_call_originals = []  # Constructor/request/status/read/close, private.
        self._clock_errors = []  # Original clock failures, separate from primary.
        self.first_unknown = None
        self._clock_phase = 'INITIAL_CLOCK'
        self._deadline = self._now('INITIAL_CLOCK', 'INITIALIZE') + seconds

    def _retain(self, phase, value=None, error=None):
        original = _PrivateOriginal(phase, value, error)
        self.originals.append(original)
        self._per_call_originals.append(original)

    def _own_call(self, operation, *, value=None, error=None):
        original = _PrivateOriginal(operation, value, error)
        self._per_call_originals.append(original)
        return original

    def _unknown(self, code, phase, operation=None):
        if self.first_unknown is None:
            self.first_unknown = {'code': code, 'phase': phase, 'operation': operation,
                'call': self.calls, 'original_index': len(self.originals) - 1,
                'call_original_index': len(self._per_call_originals) - 1}

    def _now(self, phase, operation):
        self._clock_phase = phase
        try:
            value = self._clock()
        except Exception as error:
            self._clock_errors.append(error)
            self._retain('CLOCK_EXCEPTION', error=error)
            self._unknown('CLOCK_EXCEPTION', phase, operation)
            raise TransportUnknown('TRANSPORT_UNKNOWN') from None
        try:
            valid = type(value) in (int, float) and math.isfinite(value)
        except Exception as error:
            self._own_call('INVALID_CLOCK_RETURN', value=value)
            self._clock_errors.append(error)
            self._retain('CLOCK_EXCEPTION', error=error)
            self._unknown('CLOCK_EXCEPTION', phase, operation)
            raise TransportUnknown('TRANSPORT_UNKNOWN') from None
        if not valid:
            self._own_call('INVALID_CLOCK_RETURN', value=value)
            error = IdentityRefused('FINITE_MONOTONIC_CLOCK_REQUIRED')
            self._clock_errors.append(error)
            self._retain('CLOCK_EXCEPTION', error=error)
            self._unknown('CLOCK_EXCEPTION', phase, operation)
            raise TransportUnknown('TRANSPORT_UNKNOWN') from None
        return value

    def _guard(self, phase, operation=None, *, cleanup=False):
        try:
            now = self._now(phase, operation)
        except TransportUnknown:
            if cleanup:
                return None  # Clock failure cannot skip the already claimed close.
            raise
        remaining = self._deadline - now
        if remaining <= 0:
            self._unknown('ABSOLUTE_DEADLINE', phase, operation)
        if self.first_unknown is not None and not cleanup:
            raise TransportUnknown('TRANSPORT_UNKNOWN') from None
        return max(0.0, remaining)

    def _refresh_timeout(self, conn, remaining, *, cleanup=False):
        if remaining is None:
            return  # No invented fresh timeout when clock evidence is absent.
        try:
            conn.timeout = remaining
            sock = getattr(conn, 'sock', None)
            if sock is not None:
                self._guard('PRE_REQUEST', 'SOCKET_SETTIMEOUT', cleanup=cleanup)
                latest = self._guard('PRE_INVOKE', 'SOCKET_SETTIMEOUT', cleanup=cleanup)
                if latest is not None:
                    remaining = latest
                    conn.timeout = remaining
                outcome = sock.settimeout(remaining)
                self._own_call('SOCKET_SETTIMEOUT_RETURN', value=outcome)
                self._guard('POST_RETURN', 'SOCKET_SETTIMEOUT', cleanup=cleanup)
        except Exception as error:
            self._retain('SOCKET_TIMEOUT_EXCEPTION', error=error)
            self._unknown('SOCKET_TIMEOUT_EXCEPTION', 'POST_RETURN', 'SOCKET_SETTIMEOUT')
            if not cleanup:
                raise TransportUnknown('TRANSPORT_UNKNOWN') from None

    def _invoke(self, operation, function, *, conn=None, on_owned=None, legacy=None):
        self._guard('PRE_REQUEST', operation)
        remaining = self._guard('PRE_INVOKE', operation)
        if conn is not None:
            self._refresh_timeout(conn, remaining)
        # Recheck after timeout configuration; all calls share the initial deadline.
        remaining = self._guard('PRE_INVOKE', operation)
        if conn is not None:
            conn.timeout = remaining
        try:
            value = function(remaining)
        except Exception as error:
            self._retain(operation + '_EXCEPTION', error=error)
            self._unknown('HTTP_EXCEPTION', 'POST_RETURN', operation)
            # Original primary is already owned before any fallible clock guard.
            self._guard('POST_RETURN', operation)
            raise TransportUnknown('TRANSPORT_UNKNOWN') from None
        self._own_call(operation + '_RETURN', value=value)
        if legacy is not None:
            self._retain(legacy, value=value)
        if on_owned is not None:
            on_owned(value)  # Internal ownership transfer, before post-return guard.
        self._guard('POST_RETURN', operation)
        return value

    def _close_once(self, holder):
        conn = holder['conn']
        if conn is None or holder['close_claimed']:
            return
        holder['close_claimed'] = True  # Claim before any clock/helper may fail.
        try:
            self._guard('PRE_REQUEST_CLEANUP', 'CLOSE', cleanup=True)
            remaining = self._guard('PRE_INVOKE_CLEANUP', 'CLOSE', cleanup=True)
            self._refresh_timeout(conn, remaining, cleanup=True)
        except Exception as error:
            self._retain('CLEANUP_PREPARATION_EXCEPTION', error=error)
            self._unknown('CLEANUP_PREPARATION_EXCEPTION', 'PRE_INVOKE_CLEANUP', 'CLOSE')
        # Clock/expiry/timeout configuration cannot bypass the close attempt.
        try:
            outcome = conn.close()
        except Exception as error:
            self._retain('CLEANUP_EXCEPTION', error=error)
            self._unknown('CLEANUP_EXCEPTION', 'POST_RETURN_CLEANUP', 'CLOSE')
        else:
            self._own_call('CLOSE_RETURN', value=outcome)
            self._retain('CLEANUP_RETURN', value=outcome)
        self._guard('POST_RETURN_CLEANUP', 'CLOSE', cleanup=True)

    def exchange(self, method, host, path, *, body=None, headers=None, limit=65536):
        if self._scope not in (_TEST, _PROVIDER) or not callable(self._factory) or (self._scope is _PROVIDER and self._factory is not http.client.HTTPSConnection):
            _reject('AUTHENTIC_RUNTIME_BINDING_UNBOUND')
        if self.first_unknown is not None or self.calls >= self._limit_calls:
            _reject('NO_RETRY_OR_FALLBACK')
        if (host not in {'token.actions.githubusercontent.com', 'api.github.com', 'api-m.sandbox.paypal.com'}
                or type(path) is not str or not path.startswith('/')
                or any(c in path for c in ('\r', '\n', '?', '#', '://'))
                or method not in {'GET', 'POST'} or limit != 65536):
            _reject('FIXED_TRANSPORT_ROUTE')
        self._guard('PRE_REQUEST', 'EXCHANGE')
        self.calls += 1
        self._guard('PRE_INVOKE', 'EXCHANGE')
        holder = {'conn': None, 'close_claimed': False}
        pending = None
        status = raw = None
        try:
            context = self._invoke('TLS_CONTEXT', lambda remaining: ssl.create_default_context())
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                _reject('TLS_VERIFICATION_REQUIRED')
            self._invoke('ALPN', lambda remaining: context.set_alpn_protocols(['http/1.1']))
            conn = self._invoke('CONSTRUCTOR', lambda remaining: self._factory(
                host, 443, timeout=remaining, context=context),
                on_owned=lambda value: holder.__setitem__('conn', value))
            self._invoke('REQUEST', lambda remaining: conn.request(method, path, body=body,
                         headers=headers or {}), conn=conn)
            response = self._invoke('GETRESPONSE', lambda remaining: conn.getresponse(),
                                    conn=conn, legacy='HTTP_RESPONSE')
            status = self._invoke('STATUS', lambda remaining: response.status, conn=conn)
            raw = self._invoke('READ', lambda remaining: response.read(limit + 1),
                               conn=conn, legacy='HTTP_BODY')
            if type(status) is not int or type(raw) is not bytes or len(raw) > limit:
                _reject('HTTP_RESPONSE_BOUNDS')
        except Exception as error:
            self._retain('HTTP_EXCEPTION', error=error)
            pending = error
            if not isinstance(error, IdentityRefused):
                self._unknown('HTTP_EXCEPTION', 'POST_RETURN', 'EXCHANGE')
        finally:
            self._close_once(holder)
        if self.first_unknown is not None:
            raise TransportUnknown('TRANSPORT_UNKNOWN') from None
        if pending is not None:
            raise pending
        return status, raw

    def metadata(self):
        return {'scope': 'TEST_ONLY_TRANSPORT_MECHANICS', 'requests': self.calls,
                'first_unknown': dict(self.first_unknown) if self.first_unknown else None,
                'raw_values_exported': False, 'authenticated_TLS_provenance': False,
                'backend_cancellation': 'NOT_CLAIMED'}


class FixedJWKSLoader:
    def __init__(self, runtime_binding=None):
        self._binding = None
        self._wire = None
        self._consumed = False

    @classmethod
    def for_test(cls, https_connection_factory, *, clock=time.monotonic, seconds=300):
        loader = cls()
        loader._wire = _FixedHTTPS(factory=https_connection_factory, clock=clock,
                                  seconds=seconds, limit_calls=1, scope=_TEST)
        return loader

    @classmethod
    def from_host(cls, context):
        from .admission import ConsumerContext
        if type(context) is not ConsumerContext: _reject('V3_REQUIRED')
        g=context.require(production=True)
        loader=cls();loader._binding=context
        loader._wire=_FixedHTTPS(seconds=min(300,context.context.expires_at.timestamp()-time.time()),scope=_PROVIDER)
        return loader

    def fetch_production(self, *, observed_at, now):
        if self._binding is None or self._consumed: _reject('AUTHENTIC_RUNTIME_BINDING_UNBOUND')
        self._binding.require(production=True)
        if type(now) is not int or observed_at!=now: _reject('JWKS_FRESHNESS')
        self._consumed=True
        status,raw=self._wire.exchange('GET','token.actions.githubusercontent.com','/.well-known/jwks',headers={'Accept':'application/json'})
        if status!=200: _reject('JWKS_STATUS_NO_REDIRECT')
        _object(raw,65536)
        return JWKSSnapshot(raw,observed_at,_PROVIDER)

    def fetch_for_test(self, *, observed_at, now):
        if self._wire is None or self._consumed:
            _reject('JWKS_UNBOUND_OR_ALREADY_CONSUMED')
        if (type(observed_at) is not int or type(now) is not int
                or not 0 <= now - observed_at <= 300):
            _reject('JWKS_FRESHNESS')
        self._consumed = True
        status, raw = self._wire.exchange('GET', 'token.actions.githubusercontent.com',
                                         '/.well-known/jwks', headers={'Accept': 'application/json'})
        if status != 200:
            _reject('JWKS_STATUS_NO_REDIRECT')
        data = _object(raw, 65536)
        if set(data) != {'keys'} or type(data['keys']) is not list or not 1 <= len(data['keys']) <= 32:
            _reject('JWKS_SHAPE')
        # Even when an injected fake claims TLS, its snapshot remains TEST_ONLY.
        return JWKSSnapshot.synthetic_for_test(raw, observed_at=observed_at)

    def metadata(self):
        return self._wire.metadata() if self._wire else {'scope': 'UNBOUND', 'requests': 0}


def consumer_policy(grant):
    from datetime import datetime
    c=grant['caller']
    return IdentityPolicy(c['audience'],REPOSITORY+'/'+c['workflow_path']+'@refs/heads/main',
        c['ref'],c['source_commit'],c['source_commit'],c['event'],
        'repo:Elinfiny@273768139/PayProof@1419908202:ref:refs/heads/main',
        c['run_id'],'1',c['not_before'],int(datetime.fromisoformat(grant['expires_at'].replace('Z','+00:00')).timestamp()))


# Private inactive job-native extension36; legacy prefix unchanged.
@dataclass(frozen=True, repr=False)
class NativeIdentityPolicy:
    """Expected values supplied by a future source grant, never inferred from JWT."""
    audience: str
    workflow_ref: str
    ref: str
    sha: str
    workflow_sha: str
    event_name: str
    subject: str
    run_id: str
    run_attempt: str
    not_before: int
    expires_at: int

    def __post_init__(self):
        if (self.audience != 'urn:payproof:orders-read:consumer-v3'
                or self.workflow_ref != REPOSITORY + '/.github/workflows/payproof-read-pilot.yml@refs/heads/main'
                or self.ref != 'refs/heads/main' or self.event_name != 'workflow_dispatch'
                or self.subject != 'repo:Elinfiny@273768139/PayProof@1419908202:environment:payproof-sandbox-readonly'
                or any(type(x) is not str or not re.fullmatch(r'[0-9a-f]{40}', x) for x in (self.sha, self.workflow_sha))
                or self.sha != self.workflow_sha
                or type(self.run_id) is not str or not re.fullmatch(r'[1-9][0-9]{0,19}', self.run_id)
                or self.run_attempt != '1'
                or type(self.not_before) is not int or type(self.expires_at) is not int
                or not 0 < self.expires_at - self.not_before <= 300):
            _reject('POLICY_UNBOUND')

class JobLifetime:
    """One born-before-effects holder. Originals never enter exported metadata."""
    def __init__(self, *, clock=time.monotonic, seconds=300, cleanup=None):
        if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<seconds<=300:
            _reject('JOB_WINDOW')
        self.clock=clock; self.originals=[]; self.clock_originals=[]; self.cleanup_errors=[]; self.first_unknown=None
        self._cleanup=cleanup; self._cleanup_claimed=False; self._last=None
        self.deadline=self._now()+seconds
    def _now(self):
        try:
            value=self.clock()
            self.clock_originals.append(value)  # Own the exact object before any validation.
        except BaseException as error:
            self.originals.append(('CLOCK',None,error)); self.mark('CLOCK_FAILURE'); raise TransportUnknown('JOB_UNKNOWN') from None
        if type(value) not in (int,float) or not math.isfinite(value) or (self._last is not None and value<self._last):
            self.mark('CLOCK_INVALID'); raise TransportUnknown('JOB_UNKNOWN') from None
        self._last=value; return value
    def mark(self,code):
        if self.first_unknown is None:self.first_unknown={'code':code,'original_index':len(self.originals)-1}
    def guard(self,phase,*,cleanup=False):
        try:
            remaining=self.deadline-self._now()
            if remaining<=0:self.mark('ABSOLUTE_DEADLINE')
        except TransportUnknown:
            if cleanup:return 0.0
            raise
        if self.first_unknown is not None and not cleanup:raise TransportUnknown('JOB_UNKNOWN') from None
        return max(0.0,remaining)
    def invoke(self,label,function):
        self.guard('PRE_REQUEST');self.guard('PRE_INVOKE')
        try:value=function()
        except BaseException as error:
            self.originals.append((label,None,error));self.mark('PRIMARY_EXCEPTION');self.guard('POST_RETURN');raise
        self.originals.append((label,value,None));self.guard('POST_RETURN');return value
    def cleanup_once(self):
        if self._cleanup_claimed:return
        self._cleanup_claimed=True
        self.guard('PRE_REQUEST_CLEANUP',cleanup=True)
        self.guard('PRE_INVOKE_CLEANUP',cleanup=True)
        if self._cleanup is not None:
            try:value=self._cleanup()
            except BaseException as error:
                self.originals.append(('CLEANUP',None,error));self.cleanup_errors.append(error);self.mark('CLEANUP_EXCEPTION')
            else:self.originals.append(('CLEANUP',value,None))
        self.guard('POST_RETURN_CLEANUP',cleanup=True)

class SharedJobHTTPS(_FixedHTTPS):
    def __init__(self,lifetime,*,factory=None,scope=None,limit_calls=64):
        if type(lifetime) is not JobLifetime:_reject('SAME_JOB_LIFETIME_REQUIRED')
        self.lifetime=lifetime
        super().__init__(factory=factory,clock=lifetime.clock,seconds=lifetime.guard('INIT'),limit_calls=limit_calls,scope=scope)
        self._deadline=lifetime.deadline
    def _guard(self,phase,operation=None,*,cleanup=False):
        return self.lifetime.guard(phase,cleanup=cleanup)
    def _unknown(self,code,phase,operation=None):
        super()._unknown(code,phase,operation);self.lifetime.mark(code)

class NativeOIDCVerifier:
    """Separate Environment policy; no ConsumerContext/HMAC bootstrapping cycle."""
    def verify_test(self,token,*,policy,raw_jwks,now,lifetime):
        lifetime.guard('PRE_VERIFY')
        result=self._verify_environment(token,policy=policy,snapshot=JWKSSnapshot.synthetic_for_test(raw_jwks,observed_at=now),now=now,test_only=True)
        lifetime.guard('POST_VERIFY');return result
    def verify_native(self,token,*,authority=None,wire=None,now=None):
        from .admission import JobPolicyEvidence
        if type(authority) is not JobPolicyEvidence:_reject('AUTHENTIC_JOB_POLICY_UNBOUND')
        authority.require(production=True)
        if type(wire) is not SharedJobHTTPS or wire._scope is not _PROVIDER:_reject('AUTHENTIC_JWKS_REQUIRED')
        if getattr(self,'_used',False):_reject('OIDC_ONCE')
        self._used=True
        status,raw=wire.exchange('GET','token.actions.githubusercontent.com','/.well-known/jwks',headers={'Accept':'application/json'})
        if status!=200:_reject('JWKS_STATUS')
        result=self._verify_environment(token,policy=authority.policy,snapshot=JWKSSnapshot(raw,now,_PROVIDER),now=now,test_only=False)
        wire.lifetime.guard('POST_VERIFY');return result
    def _verify_environment(self, token, *, policy, snapshot, now, test_only):
        if type(policy) is not NativeIdentityPolicy or type(snapshot) is not JWKSSnapshot or snapshot._seal is not (_TEST if test_only else _PROVIDER):
            _reject('TYPED_TEST_INPUT_REQUIRED')
        if snapshot.origin != ISSUER or snapshot.url != JWKS_URL:
            _reject('JWKS_ORIGIN')
        if type(now) is not int or not policy.not_before <= now < policy.expires_at:
            _reject('ABSOLUTE_WINDOW')
        if not 0 <= now - snapshot.observed_at <= 300:
            _reject('JWKS_STALE')
        if type(token) is not str or len(token) > 32768 or token.count('.') != 2:
            _reject('COMPACT_JWS')
        head, payload, signature = token.split('.')
        header = _object(_b64(head, 4096), 3072)
        if (header.get('alg') != 'RS256' or header.get('typ') != 'JWT'
                or not {'alg', 'typ', 'kid'} <= set(header)
                or not set(header) <= {'alg', 'typ', 'kid', 'x5t', 'x5t#S256'}
                or type(header['kid']) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', header['kid'])):
            _reject('HEADER_ALGORITHM_OR_KEY_REFERENCE')
        jwks = _object(snapshot._raw, 65536)
        keys = jwks.get('keys')
        if set(jwks) != {'keys'} or type(keys) is not list or not 1 <= len(keys) <= 32:
            _reject('JWKS_SHAPE')
        if any(type(k) is not dict or type(k.get('kid')) is not str for k in keys):
            _reject('JWKS_KEYS')
        if len({k['kid'] for k in keys}) != len(keys):
            _reject('DUPLICATE_KID')
        selected = [k for k in keys if k['kid'] == header['kid']]
        if len(selected) != 1:
            _reject('KID_NOT_FOUND')
        key = selected[0]
        if (key.get('kty') != 'RSA' or key.get('use') != 'sig' or key.get('alg') != 'RS256'
                or not {'kid', 'kty', 'use', 'alg', 'n', 'e'} <= set(key)
                or not set(key) <= {'kid', 'kty', 'use', 'alg', 'n', 'e', 'x5c', 'x5t', 'x5t#S256'}):
            _reject('RSA_SIGNING_KEY_REQUIRED')
        nraw, eraw = _b64(key['n'], 1400), _b64(key['e'], 8)
        if nraw[0] == 0 or eraw[0] == 0:
            _reject('NONCANONICAL_RSA_INTEGER')
        n, e = int.from_bytes(nraw, 'big'), int.from_bytes(eraw, 'big')
        if not 2048 <= n.bit_length() <= 8192 or e != 65537:
            _reject('RSA_KEY_POLICY')
        try:
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            public_key.verify(_b64(signature, 1400), (head + '.' + payload).encode('ascii'),
                              padding.PKCS1v15(), hashes.SHA256())
        except (InvalidSignature, ValueError, TypeError):
            _reject('SIGNATURE_INVALID')
        # No identity is used until cryptographic signature verification completes.
        claims = _object(_b64(payload, 24576), 18432)
        expected = {'iss': ISSUER, 'aud': policy.audience, 'repository': REPOSITORY,
                    'repository_id': REPOSITORY_ID, 'repository_owner_id': OWNER_ID,
                    'repository_owner': 'Elinfiny', 'repository_visibility': 'private',
                    'workflow_ref': policy.workflow_ref, 'workflow_sha': policy.workflow_sha,
                    'ref': policy.ref, 'sha': policy.sha, 'event_name': policy.event_name,
                    'sub': policy.subject, 'run_id': policy.run_id, 'run_attempt': policy.run_attempt,
                    'runner_environment': 'github-hosted', 'ref_type': 'branch', 'environment': 'payproof-sandbox-readonly'}
        if any(type(claims.get(k)) is not str or claims[k] != v for k, v in expected.items()):
            _reject('IDENTITY_OR_ISSUER_AUDIENCE')
        if any(type(claims.get(k)) is not int for k in ('iat', 'nbf', 'exp')):
            _reject('NUMERIC_DATE_REQUIRED')
        iat, nbf, exp = (claims[k] for k in ('iat', 'nbf', 'exp'))
        if not (policy.not_before <= iat <= now < exp <= policy.expires_at
                and policy.not_before <= nbf <= now
                and 0 < exp - iat <= 300):
            _reject('TOKEN_TIME_WINDOW')
        if type(claims.get('jti')) is not str or not 1 <= len(claims['jti']) <= 256:
            _reject('JTI_REQUIRED')
        # job_workflow_ref is optional/reusable-workflow-specific; no invented job claim.
        return VerifiedIdentity(MappingProxyType(claims), _EVIDENCE, policy, test_only)
