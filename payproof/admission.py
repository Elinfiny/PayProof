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
