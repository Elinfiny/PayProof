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
    webhook_id: str = field(repr=False)
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
