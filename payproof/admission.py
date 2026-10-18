"""Host-only sandbox admission. No issuer, signing key, grant or credentials are shipped."""
import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from .core import InvalidData, canonical

_SEAL = object()
ADMISSION_PATH = Path('/run/payproof/sandbox-admission.json')
TRUST_KEY_PATH = Path('/run/secrets/payproof_admission_key')
CREDENTIAL_PATH = Path('/run/secrets/payproof_paypal_sandbox.json')
OPERATIONS = frozenset({'orders:read', 'orders:create', 'webhooks:verify'})


def source_fingerprint():
    root = Path(__file__).parent
    names = ('admission.py', 'core.py', 'paypal.py', 'service.py', 'server.py')
    rows = [(name, hashlib.sha256((root/name).read_bytes()).hexdigest()) for name in names]
    return hashlib.sha256(canonical(rows).encode()).hexdigest()


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidData('Duplicate contract key')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(InvalidData('Nonfinite JSON')))
    except (ValueError, UnicodeError):
        raise InvalidData('Invalid host contract') from None
    if not isinstance(value, dict):
        raise InvalidData('Host contract object required')
    return value


@dataclass(frozen=True, repr=False)
class SandboxContext:
    admission_id: str
    source_sha256: str
    expires_at: datetime
    operations: frozenset
    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)
    webhook_id: str | None = field(repr=False)
    test_only: bool = field(repr=False)
    _seal: object = field(repr=False)

    def __post_init__(self):
        if self._seal is not _SEAL:
            raise InvalidData('Only a verified host admission can supply context')

    def require(self, operation):
        if type(self) is not SandboxContext or self._seal is not _SEAL:
            raise InvalidData('Invalid host context')
        if operation not in self.operations or datetime.now(timezone.utc) >= self.expires_at:
            raise InvalidData('Host scope expired or operation not admitted')
        if self.source_sha256 != source_fingerprint():
            raise InvalidData('Admitted source differs from the running source')


def _verify_read_grant_v2(grant, credentials_raw, *, test_only):
    """Read-only profile, reached only after the common host HMAC verification."""
    required = {'schema','admission_id','project','environment','source_sha256','expires_at','operations',
                'client_id_sha256','external_budget_usd','live_ai'}
    if set(grant) != required or grant['schema'] != 'PAYPROOF_SANDBOX_READ_ADMISSION_V2' or grant['project'] != 'PayProof' or grant['environment'] != 'sandbox':
        raise InvalidData('Wrong read-only host scope')
    if grant['external_budget_usd'] != '0.00' or grant['live_ai'] is not False:
        raise InvalidData('This sandbox context does not authorize spending or live AI')
    if type(grant['operations']) is not list or grant['operations'] != ['orders:read']:
        raise InvalidData('Exclusive orders:read scope required')
    try:
        expires = datetime.fromisoformat(grant['expires_at'].replace('Z','+00:00'))
    except (ValueError, AttributeError):
        raise InvalidData('Host expiry missing') from None
    if expires.tzinfo is None or datetime.now(timezone.utc) >= expires:
        raise InvalidData('Host admission expired')
    if grant['source_sha256'] != source_fingerprint():
        raise InvalidData('Host source binding mismatch')
    credentials = _json(credentials_raw)
    if set(credentials) != {'client_id','client_secret'} or any(not isinstance(v,str) or not v or len(v)>4096 for v in credentials.values()):
        raise InvalidData('Read-only sandbox custody incomplete')
    if hashlib.sha256(credentials['client_id'].encode()).hexdigest() != grant['client_id_sha256']:
        raise InvalidData('Sandbox application/custody binding mismatch')
    if not isinstance(grant['admission_id'], str) or not grant['admission_id'] or len(grant['admission_id'])>128:
        raise InvalidData('Host admission identity missing')
    return SandboxContext(grant['admission_id'],grant['source_sha256'],expires,frozenset({'orders:read'}),
                          credentials['client_id'],credentials['client_secret'],None,test_only,_SEAL)


def _verify_receipt(receipt_raw, trust_key, credentials_raw, *, test_only=False):
    """Internal verifier. Production key comes only from the fixed host file loader."""
    envelope = _json(receipt_raw)
    if set(envelope) != {'grant', 'signature'} or not isinstance(envelope['grant'], dict):
        raise InvalidData('Signed host envelope required')
    grant = envelope['grant']
    signature = envelope['signature']
    if not isinstance(trust_key, bytes) or len(trust_key) < 32 or not isinstance(signature, str):
        raise InvalidData('Host trust material missing')
    expected = hmac.new(trust_key, canonical(grant).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise InvalidData('Host admission signature mismatch')
    if grant.get('schema') == 'PAYPROOF_SANDBOX_READ_CONSUMER_ADMISSION_V3':
        return _verify_consumer_v3(grant, credentials_raw, test_only=test_only)
    if grant.get('schema') == 'PAYPROOF_SANDBOX_READ_ADMISSION_V2':
        return _verify_read_grant_v2(grant, credentials_raw, test_only=test_only)
    required = {'schema','admission_id','project','environment','source_sha256','expires_at','operations',
                'client_id_sha256','webhook_id','external_budget_usd','live_ai'}
    if set(grant) != required or grant['schema'] != 'PAYPROOF_SANDBOX_ADMISSION_V1' or grant['project'] != 'PayProof' or grant['environment'] != 'sandbox':
        raise InvalidData('Wrong host scope')
    if grant['external_budget_usd'] != '0.00' or grant['live_ai'] is not False:
        raise InvalidData('This sandbox context does not authorize spending or live AI')
    if not isinstance(grant['operations'], list) or not grant['operations'] or any(not isinstance(v,str) for v in grant['operations']):
        raise InvalidData('Explicit operations required')
    operations = frozenset(grant['operations'])
    if not operations <= OPERATIONS or len(operations) != len(grant['operations']):
        raise InvalidData('Operation scope invalid')
    try:
        expires = datetime.fromisoformat(grant['expires_at'].replace('Z','+00:00'))
    except (ValueError, AttributeError):
        raise InvalidData('Host expiry missing') from None
    if expires.tzinfo is None or datetime.now(timezone.utc) >= expires:
        raise InvalidData('Host admission expired')
    if grant['source_sha256'] != source_fingerprint():
        raise InvalidData('Host source binding mismatch')
    credentials = _json(credentials_raw)
    if set(credentials) != {'client_id','client_secret','webhook_id'} or any(not isinstance(v,str) or not v or len(v)>4096 for v in credentials.values()):
        raise InvalidData('Sandbox custody incomplete')
    if hashlib.sha256(credentials['client_id'].encode()).hexdigest() != grant['client_id_sha256'] or credentials['webhook_id'] != grant['webhook_id']:
        raise InvalidData('Sandbox application/custody binding mismatch')
    if not isinstance(grant['admission_id'], str) or not grant['admission_id'] or len(grant['admission_id'])>128:
        raise InvalidData('Host admission identity missing')
    return SandboxContext(grant['admission_id'],grant['source_sha256'],expires,operations,
                          credentials['client_id'],credentials['client_secret'],credentials['webhook_id'],test_only,_SEAL)


def _host_file(path, limit):
    flags = os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_NONBLOCK',0)
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 0 < info.st_size <= limit:
                raise InvalidData('Host file ownership/type/permissions rejected')
            raw = os.read(fd,limit+1)
            if len(raw) != info.st_size or len(raw)>limit:
                raise InvalidData('Host file changed while reading')
            return raw
        finally:
            os.close(fd)
    except OSError:
        raise InvalidData('Host admission or custody not available') from None


def load_host_context():
    """No path, JSON or boolean argument is accepted from the browser."""
    receipt = _host_file(ADMISSION_PATH,16384)
    key = _host_file(TRUST_KEY_PATH,256)
    credentials = _host_file(CREDENTIAL_PATH,16384)
    return _verify_receipt(receipt,key,credentials)


# V3 extends the SAME authenticated fixed-host boundary. No issuer/key is shipped.
_V3_SEAL = object()
V3_SCHEMA = 'PAYPROOF_SANDBOX_READ_CONSUMER_ADMISSION_V3'
V3_PATHS = ('payproof/admission.py', 'payproof/core.py', 'payproof/paypal.py',
            'payproof/service.py', 'payproof/server.py', 'payproof/github_oidc.py',
            'payproof/bootstrap_bridge.py', 'tools/read_pilot_driver.py')
V3_AUDIENCE = 'urn:payproof:orders-read:consumer-v3'

def runtime_manifest():
    root = Path(__file__).parent.parent
    rows=[]
    for path in V3_PATHS:
        raw=(root/path).read_bytes()
        rows.append({'path':path,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    return rows

def _digest(value, length=64):
    import re
    if type(value) is not str or re.fullmatch('[a-f0-9]{'+str(length)+'}',value) is None:
        raise InvalidData('V3_DIGEST')
    return value

def canonical_effect_key(client_id_sha256, order_id_sha256):
    return hashlib.sha256(canonical(['PayProof','sandbox','1419908202',
        _digest(client_id_sha256),_digest(order_id_sha256),'orders:read']).encode()).hexdigest()

@dataclass(frozen=True, repr=False)
class ConsumerContext:
    context: SandboxContext = field(repr=False)
    _grant_raw: bytes = field(repr=False)
    _seal: object = field(repr=False)
    test_only: bool

    @property
    def grant(self):
        if self._seal is not _V3_SEAL: raise InvalidData('V3_SEAL')
        return _json(self._grant_raw)  # Detached copy, callers cannot mutate authority.

    def require(self, production=False):
        if (type(self) is not ConsumerContext or self._seal is not _V3_SEAL
                or type(self.context) is not SandboxContext
                or self.context.test_only is not self.test_only
                or (production and self.test_only)):
            raise InvalidData('V3_AUTHENTIC_CONTEXT_REQUIRED')
        self.context.require('orders:read')
        g=self.grant
        if self.context.operations != frozenset({'orders:read'}) or runtime_manifest()!=g['bundle_manifest']:
            raise InvalidData('V3_RUNTIME_SOURCE_CHANGED')
        return g

def _verify_consumer_v3(g, credentials_raw, *, test_only):
    # Called only AFTER the shared HMAC verification; test flag never grants production.
    import re
    base={'schema','admission_id','project','environment','source_sha256','expires_at',
          'operations','client_id_sha256','external_budget_usd','live_ai'}
    if set(g)!=base|{'bundle_manifest','bundle_sha256','caller','registry',
                    'canonical_effect_key_sha256','legacy_grant_ids'}:
        raise InvalidData('V3_EXACT_KEYS')
    if g['schema']!=V3_SCHEMA: raise InvalidData('V3_SCHEMA')
    manifest=runtime_manifest()
    if (type(g['bundle_manifest']) is not list or g['bundle_manifest']!=manifest
            or _digest(g['bundle_sha256'])!=hashlib.sha256(canonical(manifest).encode()).hexdigest()):
        raise InvalidData('V3_MANIFEST')
    # Retain V2 checks unchanged: authenticate current five-file hash and exact credentials.
    narrow={k:g[k] for k in base};narrow['schema']='PAYPROOF_SANDBOX_READ_ADMISSION_V2'
    ctx=_verify_read_grant_v2(narrow,credentials_raw,test_only=test_only)
    c=g['caller'];fields={'repository_id','owner_id','actor','actor_id','fork','visibility',
        'source_commit','source_tree','workflow_path','workflow_sha256','run_id','job_id',
        'job_name','attempt','ref','event','issuer','audience','not_before'}
    if type(c) is not dict or set(c)!=fields: raise InvalidData('V3_CALLER_KEYS')
    fixed={'repository_id':'1419908202','owner_id':'273768139','actor':'Elinfiny',
        'actor_id':'273768139','fork':False,'visibility':'private',
        'workflow_path':'.github/workflows/payproof-read-pilot.yml','job_name':'read_only',
        'attempt':'1','ref':'refs/heads/main','event':'workflow_dispatch',
        'issuer':'https://token.actions.githubusercontent.com','audience':V3_AUDIENCE}
    if any(type(c[k]) is not type(v) or c[k]!=v for k,v in fixed.items()):
        raise InvalidData('V3_CALLER_SCOPE')
    for k in ('source_commit','source_tree'): _digest(c[k],40)
    _digest(c['workflow_sha256'])
    if any(type(c[k]) is not str or re.fullmatch('[1-9][0-9]{0,19}',c[k]) is None for k in ('run_id','job_id')):
        raise InvalidData('V3_RUN_JOB')
    expiry=int(ctx.expires_at.timestamp())
    if type(c['not_before']) is not int or not c['not_before']<=datetime.now(timezone.utc).timestamp()<expiry or not 0<expiry-c['not_before']<=300:
        raise InvalidData('V3_ABSOLUTE_WINDOW')
    r=g['registry']
    if type(r) is not dict or set(r)!={'provider','revision','path','sha256','order_id_sha256','legacy_refs_sha256'} or r['provider']!='github' or r['path']!='payproof-orders-registry.json':
        raise InvalidData('V3_REGISTRY_SCOPE')
    _digest(r['revision'],40)
    for k in ('sha256','order_id_sha256','legacy_refs_sha256'): _digest(r[k])
    ids=g['legacy_grant_ids']
    if (type(ids) is not list or len(ids)>32 or any(type(x) is not str or re.fullmatch('[A-Za-z0-9_-]{1,128}',x) is None for x in ids) or ids!=sorted(set(ids))):
        raise InvalidData('V3_LEGACY_LINEAGE')
    if g['canonical_effect_key_sha256']!=canonical_effect_key(g['client_id_sha256'],r['order_id_sha256']):
        raise InvalidData('V3_CANONICAL_EFFECT')
    return ConsumerContext(ctx,canonical(g).encode(),_V3_SEAL,test_only)

def verify_consumer_for_test(receipt_raw, public_fixture_key, credentials_raw):
    result=_verify_receipt(receipt_raw,public_fixture_key,credentials_raw,test_only=True)
    if type(result) is not ConsumerContext: raise InvalidData('V3_REQUIRED')
    result.require()
    return result

def load_consumer_context():
    # Same three fixed paths and real HMAC loader; never a browser path or callback.
    result=load_host_context()
    if type(result) is not ConsumerContext: raise InvalidData('V3_REQUIRED')
    result.require(production=True)
    return result


# Private inactive job-native extension36; legacy prefix unchanged.

# Neither native policy provenance nor credential custody has a producer in36.
_JOB_NATIVE_SEAL=object()
_JOB_SYNTHETIC_SEAL=object()
JOB_NATIVE_SCHEMA='PAYPROOF_JOB_NATIVE_CONTEXT_V1'

@dataclass(frozen=True,repr=False)
class JobPolicyEvidence:
    policy: object=field(repr=False)
    _grant_raw: bytes=field(repr=False)
    protected_manifest: object=field(repr=False)
    _seal: object=field(repr=False)
    @property
    def test_only(self):return self._seal is _JOB_SYNTHETIC_SEAL
    @property
    def grant(self):return self.require()
    def require(self,production=False):
        from .github_oidc import NativeIdentityPolicy,IdentityRefused
        if (type(self) is not JobPolicyEvidence or self._seal not in (_JOB_NATIVE_SEAL,_JOB_SYNTHETIC_SEAL)
                or (production and self._seal is not _JOB_NATIVE_SEAL)
                or type(self.policy) is not NativeIdentityPolicy or self.protected_manifest is None):
            raise IdentityRefused('AUTHENTIC_JOB_POLICY_UNBOUND')
        g=_json(self._grant_raw)
        if g.get('schema')!=JOB_NATIVE_SCHEMA or g.get('bundle_manifest')!=runtime_manifest():
            raise IdentityRefused('JOB_SOURCE_MANIFEST')
        if (g.get('bundle_sha256')!=hashlib.sha256(canonical(runtime_manifest()).encode()).hexdigest()
                or g.get('source_sha256')!=source_fingerprint()
                or g.get('operations')!=['orders:read'] or g.get('project')!='PayProof'
                or g.get('environment')!='sandbox' or g.get('external_budget_usd')!='0.00'
                or g.get('live_ai') is not False):
            raise IdentityRefused('JOB_EXACT_READ_SCOPE')
        c=g.get('caller',{})
        if (c.get('source_commit')!=self.policy.sha or c.get('run_id')!=self.policy.run_id
                or c.get('workflow_path')!='.github/workflows/payproof-read-pilot.yml'
                or c.get('ref')!='refs/heads/main' or c.get('job_name')!='read_only'
                or c.get('attempt')!='1' or c.get('environment')!='payproof-sandbox-readonly'):
            raise IdentityRefused('JOB_CALLER_POLICY')
        fixed={'repository_id':'1419908202','owner_id':'273768139','actor':'Elinfiny',
               'actor_id':'273768139','fork':False,'visibility':'private','event':'workflow_dispatch',
               'issuer':'https://token.actions.githubusercontent.com','audience':V3_AUDIENCE}
        if any(type(c.get(k)) is not type(v) or c[k]!=v for k,v in fixed.items()):
            raise IdentityRefused('JOB_FIXED_CALLER')
        _digest(c.get('source_tree'),40);_digest(c.get('workflow_sha256'))
        r=g.get('registry')
        if (type(r) is not dict or r.get('provider')!='github'
                or r.get('path')!='payproof-orders-registry.json'):
            raise IdentityRefused('JOB_REGISTRY_UNBOUND')
        _digest(r.get('revision'),40)
        for key in ('sha256','order_id_sha256','legacy_refs_sha256'):_digest(r.get(key))
        if (g.get('canonical_effect_key_sha256')!=canonical_effect_key(g['client_id_sha256'],r['order_id_sha256'])
                or not isinstance(g.get('legacy_grant_ids'),list)
                or datetime.fromisoformat(g['expires_at']).timestamp()>self.policy.expires_at):
            raise IdentityRefused('JOB_EFFECT_OR_EXPIRY')
        return g
    @classmethod
    def synthetic(cls,policy,grant):
        # A public fixture cannot become a native policy or signed host V3.
        value=cls(policy,canonical(grant).encode(), 'SYNTHETIC_TEST_MANIFEST',_JOB_SYNTHETIC_SEAL)
        value.require();return value

@dataclass(frozen=True,repr=False)
class JobCredentials:
    _raw: bytes=field(repr=False)
    _seal: object=field(repr=False)
    @classmethod
    def synthetic(cls,client_id,client_secret):
        return cls(canonical({'client_id':client_id,'client_secret':client_secret}).encode(),_JOB_SYNTHETIC_SEAL)
    def require(self,*,production=False):
        if self._seal not in (_JOB_NATIVE_SEAL,_JOB_SYNTHETIC_SEAL) or (production and self._seal is not _JOB_NATIVE_SEAL):
            raise InvalidData('JOB_CREDENTIAL_CUSTODY_UNBOUND')
        c=_json(self._raw)
        if set(c)!={'client_id','client_secret'} or any(type(v) is not str or not 0<len(v)<=4096 for v in c.values()):
            raise InvalidData('JOB_CREDENTIAL_BOUNDS')
        return c

def intake_step_scoped_credentials(payload,*,custody=None):
    # No ENV read, generic factory or supplied bytes can prove actual custody.
    # A genuine provider-bound custody producer needs separate qualification.
    raise InvalidData('AUTHENTIC_STEP_CUSTODY_UNBOUND')

@dataclass(frozen=True,repr=False)
class JobNativeContext:
    context: SandboxContext=field(repr=False)
    evidence: JobPolicyEvidence=field(repr=False)
    identity: object=field(repr=False)
    provider: object=field(repr=False)
    _seal: object=field(repr=False)
    @property
    def test_only(self):return self._seal is _JOB_SYNTHETIC_SEAL
    @property
    def grant(self):return self.require()
    def require(self,production=False):
        from .github_oidc import IdentityRefused,_EVIDENCE
        if (type(self) is not JobNativeContext or self._seal not in (_JOB_NATIVE_SEAL,_JOB_SYNTHETIC_SEAL)
                or (production and self.test_only) or self.identity._seal is not _EVIDENCE
                or self.identity.test_only is not self.test_only
                or self.provider._source_identity is not self.identity):
            raise IdentityRefused('JOB_TYPED_CONTEXT_REQUIRED')
        g=self.evidence.require(production=production);self.context.require('orders:read')
        self.provider.lifetime.guard('CONTEXT_REQUIRE');return g

def _context_from_verified_job(evidence,identity,provider,credentials):
    from .github_oidc import VerifiedIdentity,_EVIDENCE,IdentityRefused
    from .bootstrap_bridge import JobNativeProvider
    if (type(evidence) is not JobPolicyEvidence or type(identity) is not VerifiedIdentity
            or identity._seal is not _EVIDENCE or type(provider) is not JobNativeProvider
            or provider._source_identity is not identity or provider.context is not evidence
            or identity.policy is not evidence.policy or type(credentials) is not JobCredentials):
        raise IdentityRefused('JOB_VERIFIED_CHAIN_REQUIRED')
    g=evidence.require(production=not evidence.test_only)
    if identity.test_only is not evidence.test_only or credentials._seal is not evidence._seal:raise IdentityRefused('JOB_SCOPE_MIX')
    c=credentials.require(production=not evidence.test_only)
    if hashlib.sha256(c['client_id'].encode()).hexdigest()!=g['client_id_sha256']:raise IdentityRefused('JOB_APPLICATION_MISMATCH')
    ctx=SandboxContext(g['admission_id'],source_fingerprint(),datetime.fromisoformat(g['expires_at']),frozenset({'orders:read'}),c['client_id'],c['client_secret'],None,evidence.test_only,_SEAL)
    result=JobNativeContext(ctx,evidence,identity,provider,_JOB_SYNTHETIC_SEAL if evidence.test_only else _JOB_NATIVE_SEAL)
    result.require(production=not evidence.test_only);return result

# Private producer67. Legacy signed-host prefix and synthetic APIs unchanged.
def intake_step_scoped_credentials(payload=None, *, custody=None):
    from .job_policy_source42 import ProducedSource67, CREDENTIAL_NAMES67, _object
    if payload is not None or type(custody) is not ProducedSource67:
        raise InvalidData('EXACT_VERIFIED_STEP_CUSTODY67')
    g = custody.require(production=True)  # TEST_ONLY and arbitrary payload refuse BEFORE ENV.
    if g['bundle_manifest'] != runtime_manifest():
        raise InvalidData('LOCAL_FINAL_MANIFEST67')
    # Only after signature, whole source, environment, sole job, exact step map,
    # registry lineage and local manifest verification may these two be read.
    values = tuple(os.environ.get(n) for n in CREDENTIAL_NAMES67)
    if any(type(v) is not str or not 0 < len(v) <= 4096 for v in values):
        raise InvalidData('STEP_CREDENTIAL_BOUNDS67')
    if hashlib.sha256(values[0].encode()).hexdigest() != g['client_id_sha256']:
        raise InvalidData('STEP_APPLICATION_FINGERPRINT67')
    result = JobCredentials(canonical(dict(zip(('client_id','client_secret'),values))).encode(),_JOB_NATIVE_SEAL)
    result.require(production=True); return result

# Private68: consume ONLY a runtime projection carrying original static source.
_intake_before68 = intake_step_scoped_credentials
def intake_step_scoped_credentials(payload=None, *, custody=None):
    from .job_policy_source42 import ProducedSource67
    if type(custody) is ProducedSource67:
        g=custody.require(production=True)
        if g.get('external_static_authorization68_sha256') is not None:
            _digest(g['external_static_authorization68_sha256'])
    return _intake_before68(payload,custody=custody)


# Direction107: distinct operator trust, never a legacy signed-host context.
# The operator owns the private process. This is NOT a vendor attestation.
from enum import Enum
import re as _operator_re107

class OperatorProfile107(Enum):
    OWNER_MANAGED_SANDBOX = 'OWNER_MANAGED_SANDBOX'
    GITHUB_OWNER_MANAGED_SANDBOX = 'GITHUB_OWNER_MANAGED_SANDBOX'
    GITHUB_OWNER_WORKFLOW109 = 'GITHUB_OWNER_WORKFLOW109'
    SYNTHETIC_FIXTURE = 'SYNTHETIC_FIXTURE'

_OPERATOR_SEAL107 = object()
_OPERATOR_TEST_SEAL107 = object()

@dataclass(frozen=True, repr=False)
class OperatorConfiguration107:
    profile: OperatorProfile107
    source_sha256: str
    source_commit: str
    source_tree: str
    operator_allocation: str
    credential_provenance: str
    client_id_sha256: str
    order_id: str
    amount: str
    currency: str
    order_lineage_sha256: str
    once_id: str
    not_before: datetime
    expires_at: datetime
    included_allowance_usd: str = '0.00'

    def validate(self, actual_source, now):
        from .core import identifier, money, currency
        if type(self) is not OperatorConfiguration107 or type(self.profile) is not OperatorProfile107:
            raise InvalidData('OPERATOR_TYPED_CONFIGURATION107')
        for value in (self.source_sha256, self.client_id_sha256, self.order_lineage_sha256):
            if type(value) is not str or not _operator_re107.fullmatch('[a-f0-9]{64}', value):
                raise InvalidData('OPERATOR_DIGEST107')
        for value in (self.source_commit, self.source_tree):
            if type(value) is not str or not _operator_re107.fullmatch('[a-f0-9]{40}', value):
                raise InvalidData('OPERATOR_SOURCE_REF107')
        if self.source_sha256 != actual_source:
            raise InvalidData('OPERATOR_SOURCE_MISMATCH107')
        for value in (self.operator_allocation, self.credential_provenance, self.once_id):
            if type(value) is not str or not _operator_re107.fullmatch('[A-Za-z0-9_-]{1,128}', value):
                raise InvalidData('OPERATOR_MISSING_LINEAGE107')
        identifier(self.order_id); money(self.amount); currency(self.currency)
        if not _operator_re107.fullmatch('[A-Z0-9]{1,36}', self.order_id):
            raise InvalidData('OPERATOR_ORDER107')
        if (type(self.not_before) is not datetime or type(self.expires_at) is not datetime
                or self.not_before.tzinfo is None or self.expires_at.tzinfo is None
                or not self.not_before <= now < self.expires_at
                or not 0 < (self.expires_at-self.not_before).total_seconds() <= 120
                or self.included_allowance_usd != '0.00'):
            raise InvalidData('OPERATOR_WINDOW_OR_ALLOWANCE107')
        return self

@dataclass(repr=False)
class OperatorSession107:
    """Process-private, nonserializable; does not satisfy SandboxContext type."""
    _configuration: OperatorConfiguration107 = field(repr=False)
    _client_id: str = field(repr=False)
    _client_secret: str = field(repr=False)
    _seal: object = field(repr=False)
    _clock: object = field(repr=False)
    _source: object = field(repr=False)
    _monotonic: object = field(repr=False, default=None)
    _monotonic_deadline: float = field(repr=False, default=0.0)
    _closed: bool = field(default=False, repr=False)

    def __post_init__(self):
        if self._seal not in (_OPERATOR_SEAL107, _OPERATOR_TEST_SEAL107):
            raise InvalidData('OPERATOR_FACTORY_REQUIRED107')
        synthetic = self._configuration.profile is OperatorProfile107.SYNTHETIC_FIXTURE
        if synthetic != (self._seal is _OPERATOR_TEST_SEAL107):
            raise InvalidData('OPERATOR_PROFILE_MIX107')

    def __reduce_ex__(self, protocol):
        raise TypeError('Operator sessions cannot be serialized')

    @property
    def test_only(self):
        return self._seal is _OPERATOR_TEST_SEAL107

    @property
    def operations(self):
        return frozenset({'orders:read'})

    def require(self, operation, *, profile=None):
        if self._closed or operation != 'orders:read':
            raise InvalidData('OPERATOR_READ_ONLY_OR_CLOSED107')
        if profile is not None and profile is not self._configuration.profile:
            raise InvalidData('OPERATOR_PROFILE_MIX107')
        self.__post_init__()
        if not callable(self._monotonic) or self._monotonic() >= self._monotonic_deadline:
            raise InvalidData('OPERATOR_MONOTONIC_EXPIRED108')
        self._configuration.validate(self._source(), self._clock())

    def close(self):
        # Drop references; Python cannot promise cryptographic RAM zeroization.
        self._client_id = self._client_secret = ''
        self._closed = True

def _open_operator_session107(configuration, *, actual_source, credential_reader,
                              reserve_once, clock, profile, monotonic=None):
    """Called by the explicit private entry, never by an HTTP request.

    The credential callback and durable journal are operator-controlled inputs,
    not platform custody proof. Legacy host seals/loaders are never called.
    """
    if (type(configuration) is not OperatorConfiguration107
            or configuration.profile is not profile or type(profile) is not OperatorProfile107):
        raise InvalidData('OPERATOR_PROFILE_MIX107')
    import time
    monotonic = monotonic or time.monotonic
    started_wall = clock()
    configuration.validate(actual_source(), started_wall)  # Before credentials or network.
    deadline = monotonic() + min(120.0,(configuration.expires_at-started_wall).total_seconds())
    if not callable(credential_reader) or not callable(reserve_once):
        raise InvalidData('OPERATOR_PRIVATE_BOUNDARY_REQUIRED107')
    # Stable logical effect key: a different public once_id cannot rearm this order.
    key = hashlib.sha256(canonical(['PayProof','sandbox','orders:read',
        configuration.client_id_sha256, configuration.order_id]).encode()).hexdigest()
    metadata = {'order_lineage_sha256':configuration.order_lineage_sha256,
        'once_id':configuration.once_id,'source_sha256':configuration.source_sha256,
        'source_commit':configuration.source_commit,'source_tree':configuration.source_tree,
        'not_before':configuration.not_before.isoformat(),'expires_at':configuration.expires_at.isoformat()}
    reserve_once(key,metadata)  # Labels attach to the same identity; never rearm it.
    values = credential_reader()
    if (type(values) is not tuple or len(values) != 2
            or any(type(v) is not str or not 0 < len(v) <= 4096 or '\n' in v or '\r' in v for v in values)):
        raise InvalidData('OPERATOR_CREDENTIAL_INPUT107')
    if hashlib.sha256(values[0].encode()).hexdigest() != configuration.client_id_sha256:
        raise InvalidData('OPERATOR_APPLICATION_MISMATCH107')
    configuration.validate(actual_source(), clock())
    if monotonic() >= deadline:
        raise InvalidData('OPERATOR_MONOTONIC_EXPIRED108')
    return OperatorSession107(configuration, values[0], values[1],
        _OPERATOR_TEST_SEAL107 if profile is OperatorProfile107.SYNTHETIC_FIXTURE else _OPERATOR_SEAL107,
        clock, actual_source, monotonic, deadline)


# External dispatcher projections identify an admitted run; they do not grant it.
# Native creation must be supplied by the separately qualified conditional-own
# journal producer bound to the actual first GitHub run/job. No public loader,
# signing key, runtime Library reader or environment boolean is an authority.
_DISPATCH_NATIVE108 = object()
_DISPATCH_SYNTHETIC108 = object()

@dataclass(frozen=True, repr=False)
class OwnedDispatch108:
    _record: bytes = field(repr=False)
    _seal: object = field(repr=False)
    _provider_run_id: str = field(repr=False)
    _provider_job_id: str = field(repr=False)

    def __post_init__(self):
        if self._seal not in (_DISPATCH_NATIVE108,_DISPATCH_SYNTHETIC108):
            raise InvalidData('EXTERNAL_DISPATCH_PROVIDER_BINDING_REQUIRED108')

    @property
    def test_only(self):return self._seal is _DISPATCH_SYNTHETIC108

    def require(self, *, synthetic=False):
        self.__post_init__()
        if self.test_only is not synthetic:
            raise InvalidData('EXTERNAL_DISPATCH_PROFILE_MIX108')
        record = _json(self._record)
        required={'schema','producer','stable_effect_key','admission_id','intent_version',
            'consumed_version','intent_sha256','consumed_sha256','previous_sha256',
            'source_commit','source_tree','source_sha256','workflow_sha256',
            'workflow_path','repository_id','owner_id','actor_id','run_id','job_id',
            'job_name','attempt','ref','event','registered_lineage_sha256'}
        required |= {'client_id_sha256','order_id_sha256','expected_amount','expected_currency',
                     'operator_allocation','credential_provenance'}
        if set(record)!=required or record['schema']!='PAYPROOF_OWN_CONDITIONAL_DISPATCH108':
            raise InvalidData('EXTERNAL_DISPATCH_RECORD108')
        if (record['producer']!='PayPal V1 conditional own journal'
                or type(record['intent_version']) is not int
                or record['consumed_version']!=record['intent_version']+1
                or record['previous_sha256']!=record['intent_sha256']):
            raise InvalidData('EXTERNAL_DISPATCH_CHAIN108')
        for key in ('stable_effect_key','intent_sha256','consumed_sha256','previous_sha256',
                    'source_sha256','workflow_sha256','registered_lineage_sha256',
                    'client_id_sha256','order_id_sha256'):_digest(record[key])
        for key in ('source_commit','source_tree'):_digest(record[key],40)
        for key in ('run_id','job_id'):
            if type(record[key]) is not str or not _operator_re107.fullmatch('[1-9][0-9]{0,19}',record[key]):
                raise InvalidData('EXTERNAL_DISPATCH_RUN_JOB108')
        if (record['run_id']!=self._provider_run_id or record['job_id']!=self._provider_job_id):
            raise InvalidData('EXTERNAL_DISPATCH_ACTUAL_FIRST_RUN108')
        fixed={'repository_id':'1419908202','owner_id':'273768139','actor_id':'273768139',
            'attempt':'1','ref':'refs/heads/main','event':'workflow_dispatch',
            'job_name':'sandbox_read','workflow_path':'.github/workflows/payproof-sandbox-delivery108.yml'}
        if any(type(record[k]) is not type(v) or record[k]!=v for k,v in fixed.items()):
            raise InvalidData('EXTERNAL_DISPATCH_CALLER108')
        if type(record['admission_id']) is not str or not _operator_re107.fullmatch('[A-Za-z0-9_-]{1,128}',record['admission_id']):
            raise InvalidData('EXTERNAL_DISPATCH_ADMISSION108')
        return record

    def __reduce_ex__(self,protocol):raise TypeError('Dispatch bindings are process-private')

def load_owned_dispatch108():
    # This is the exact remaining provider adapter fact, not a fabricated seal:
    # authentic own CAS INTENT->CONSUMED readback, single actual dispatch and its
    # first actual run/job binding, delivered to the same admitted runtime.
    # The current surface exposes no such runtime bridge. Public data cannot
    # substitute for it. Implementing/qualifying that bridge requires review.
    raise InvalidData('MISSING_OWN_CAS_FIRST_RUN_JOB_ADAPTER108')


# Prospective109 operator-controlled, provider-processed workflow boundary.
# These tokens are local implementation types, never cross-process attestations.
_WORKFLOW_OWNER109=object()
_WORKFLOW_SYNTHETIC109=object()

@dataclass(frozen=True,repr=False)
class WorkflowLaunch109:
    _configuration: OperatorConfiguration107=field(repr=False)
    _admission: bytes=field(repr=False)
    _actual: bytes=field(repr=False)
    _seal: object=field(repr=False)

    def __post_init__(self):
        if self._seal not in (_WORKFLOW_OWNER109,_WORKFLOW_SYNTHETIC109):
            raise InvalidData('WORKFLOW_PRIVATE_LAUNCH_REQUIRED109')
        expected=(OperatorProfile107.SYNTHETIC_FIXTURE if self.test_only
                  else OperatorProfile107.GITHUB_OWNER_WORKFLOW109)
        if type(self._configuration) is not OperatorConfiguration107 or self._configuration.profile is not expected:
            raise InvalidData('WORKFLOW_PROFILE_MIX109')

    @property
    def test_only(self):return self._seal is _WORKFLOW_SYNTHETIC109

    @property
    def trust_origin(self):
        return 'SYNTHETIC_WORKFLOW109' if self.test_only else 'GITHUB_OWNER_WORKFLOW109'

    def require(self,configuration):
        self.__post_init__()
        if self._configuration is not configuration:raise InvalidData('WORKFLOW_CONFIGURATION_MIX109')
        return _json(self._admission),_json(self._actual)

    def __reduce_ex__(self,protocol):raise TypeError('Workflow launch is process-private')


# Explicit prospective Owner-controlled profile111; no native67 seal fabrication.
_FIXTURE_OWNER111=object()
_FIXTURE_SYNTHETIC111=object()

@dataclass(frozen=True,repr=False)
class FixtureLaunch111:
    _record: bytes=field(repr=False)
    _actual: bytes=field(repr=False)
    _seal: object=field(repr=False)

    def __post_init__(self):
        if self._seal not in (_FIXTURE_OWNER111,_FIXTURE_SYNTHETIC111):
            raise InvalidData('FIXTURE_PRIVATE_LAUNCH111')

    @property
    def test_only(self):return self._seal is _FIXTURE_SYNTHETIC111

    def require(self):
        self.__post_init__()
        return _json(self._record),_json(self._actual)

    def __reduce_ex__(self,protocol):raise TypeError('Fixture launch is process-private')

@dataclass(repr=False)
class FixtureSession111:
    launch: FixtureLaunch111=field(repr=False)
    client_id: str=field(repr=False)
    client_secret: str=field(repr=False)
    _guard: object=field(repr=False)
    _closed: bool=field(default=False,repr=False)

    @property
    def test_only(self):return self.launch.test_only

    @property
    def operations(self):return frozenset({'orders:create','orders:read'})

    def require(self,operation):
        if self._closed or operation not in self.operations or type(self.launch) is not FixtureLaunch111:
            raise InvalidData('FIXTURE_SCOPE_OR_CLOSED111')
        self.launch.require();self._guard()

    def close(self):
        self.client_id=self.client_secret='';self._closed=True

    def __reduce_ex__(self,protocol):raise TypeError('Fixture session is process-private')
