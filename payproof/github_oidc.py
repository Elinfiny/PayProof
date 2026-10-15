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
        # No JSON/callback/HMAC can fill the absent reviewed provider adapter.
        _reject('AUTHENTIC_RUNTIME_BINDING_UNBOUND')

    def verify_for_test(self, token, *, policy, snapshot, now):
        if type(policy) is not IdentityPolicy or type(snapshot) is not JWKSSnapshot or snapshot._seal is not _TEST:
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
        return VerifiedIdentity(MappingProxyType(claims), _EVIDENCE, policy)


def require_test_evidence(identity):
    if (type(identity) is not VerifiedIdentity or identity._seal is not _EVIDENCE
            or identity.test_only is not True):
        _reject('VERIFIED_TEST_EVIDENCE_REQUIRED')
    return identity
