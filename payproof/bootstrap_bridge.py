"""Inactive bootstrap consumer: verify and bind a finite TEST_ONLY plan, no issuer.

No credentials/host key/receipt/context are created. Production remains unbound.
"""
import hashlib
import re
from dataclasses import dataclass, field

from .github_oidc import GitHubOIDCVerifier, IdentityRefused, require_test_evidence


@dataclass(frozen=True, repr=False)
class SourceBinding:
    grant_id: str
    reviewed_bundle_sha256: str
    admission_source_sha256: str
    client_id_sha256: str
    order_id_sha256: str
    registry_receipt_sha256: str

    def __post_init__(self):
        if type(self.grant_id) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', self.grant_id):
            raise IdentityRefused('SOURCE_GRANT_ID')
        for name in ('reviewed_bundle_sha256', 'admission_source_sha256', 'client_id_sha256',
                     'order_id_sha256', 'registry_receipt_sha256'):
            if type(getattr(self, name)) is not str or not re.fullmatch(r'[a-f0-9]{64}', getattr(self, name)):
                raise IdentityRefused('SOURCE_BINDING_INCOMPLETE')


@dataclass(frozen=True, repr=False)
class ReservationPlan:
    """Required durable CAS contract, not an implementation or persistence receipt."""
    scope_key_sha256: str
    storage: str = 'UNIMPLEMENTED_DURABLE_PROVIDER_CAS'
    initial_state: str = 'ABSENT'
    consume_state: str = 'CONSUMED_BEFORE_OAUTH'
    maximum_attempts: int = 2
    oauth: int = 1
    get: int = 1
    restart: str = 'REFUSE_IF_ANY_RECORD_EXISTS'
    persist_success_required: bool = True

    def require(self, expected_key):
        if (self.scope_key_sha256 != expected_key or self.storage != 'UNIMPLEMENTED_DURABLE_PROVIDER_CAS'
                or self.initial_state != 'ABSENT' or self.consume_state != 'CONSUMED_BEFORE_OAUTH'
                or type(self.maximum_attempts) is not int or self.maximum_attempts != 2
                or type(self.oauth) is not int or self.oauth != 1 or type(self.get) is not int or self.get != 1
                or self.restart != 'REFUSE_IF_ANY_RECORD_EXISTS' or self.persist_success_required is not True):
            raise IdentityRefused('DURABLE_RESERVATION_CONTRACT')


class BootstrapBridge:
    def __init__(self, runtime_binding=None):
        self._runtime_binding = None  # A JSON/callable/admitted flag cannot activate this candidate.

    def activate(self, *args, **kwargs):
        raise IdentityRefused('AUTHENTIC_RUNTIME_BINDING_UNBOUND')

    def inspect_for_test(self, token, *, policy, snapshot, now, source_binding,
                         actual_bundle_sha256, admission_source_sha256, credentials,
                         registry_entry, reservation):
        identity = GitHubOIDCVerifier().verify_for_test(token, policy=policy, snapshot=snapshot, now=now)
        require_test_evidence(identity)
        if type(source_binding) is not SourceBinding:
            raise IdentityRefused('SOURCE_BINDING_REQUIRED')
        if (source_binding.reviewed_bundle_sha256 != actual_bundle_sha256
                or source_binding.admission_source_sha256 != admission_source_sha256):
            raise IdentityRefused('FINAL_SOURCE_PIN_MISMATCH')
        # TEST_ONLY in-memory custody fixture; no loader, secret path or value export.
        if (type(credentials) is not dict or set(credentials) != {'client_id', 'client_secret'}
                or any(type(v) is not str or not 0 < len(v) <= 4096 for v in credentials.values())
                or hashlib.sha256(credentials['client_id'].encode()).hexdigest() != source_binding.client_id_sha256):
            raise IdentityRefused('READ_CUSTODY_EXACT_TWO_FIELDS')
        if (type(registry_entry) is not dict
                or set(registry_entry) != {'order_id_sha256', 'registry_receipt_sha256', 'preexisting'}
                or registry_entry['preexisting'] is not True
                or registry_entry['order_id_sha256'] != source_binding.order_id_sha256
                or registry_entry['registry_receipt_sha256'] != source_binding.registry_receipt_sha256):
            raise IdentityRefused('EXISTING_REGISTRY_BINDING')
        # One stable key spans all restarts/runs/tokens; a new JWT cannot reset it.
        key = hashlib.sha256((source_binding.grant_id + ':' + source_binding.order_id_sha256).encode()).hexdigest()
        if type(reservation) is not ReservationPlan:
            raise IdentityRefused('DURABLE_RESERVATION_REQUIRED')
        reservation.require(key)
        return {'scope': 'TEST_ONLY_INACTIVE_BOOTSTRAP_PLAN', 'identity': identity.metadata(),
                'source_bundle_sha256': actual_bundle_sha256, 'admission_source_sha256': admission_source_sha256,
                'reservation_scope_key_sha256': key, 'reservation_durability': 'NOT_IMPLEMENTED_OR_CLAIMED',
                'reservation_state_required_before_OAuth': 'CONSUMED_BEFORE_OAUTH',
                'restart': 'REFUSE_IF_ANY_RECORD_EXISTS', 'operations': ['orders:read'],
                'credentials_exported': False, 'issuer_generated': False, 'host_receipt_generated': False,
                'production_context': False, 'missing_binding': 'AUTHENTIC_REVIEWED_RUNTIME_BOOTSTRAP_BINDING'}
