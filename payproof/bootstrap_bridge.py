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

    def reserve_for_test(self, token, *, https_connection_factory, source_commit, source_tree,
                         caller_run_id, caller_run_attempt, clock, wall_clock, **inputs):
        # Complete source/custody/registry checks BEFORE any provider-shaped call.
        self.inspect_for_test(token, **inputs)
        identity = GitHubOIDCVerifier().verify_for_test(token, policy=inputs['policy'],
            snapshot=inputs['snapshot'], now=inputs['now'])
        reservation = GitRefReservation.for_test(https_connection_factory, identity=identity,
            source_binding=inputs['source_binding'], source_commit=source_commit,
            source_tree=source_tree, clock=clock, wall_clock=wall_clock)
        return reservation.reserve_for_test(caller_run_id=caller_run_id,
            caller_run_attempt=caller_run_attempt, grant_id=inputs['source_binding'].grant_id)


import base64
import json
import time
from .github_oidc import _FixedHTTPS, _TEST, _object, TransportUnknown

_REPO = '/repos/Elinfiny/PayProof'
_RESERVATION_TEST_SEAL = object()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def _sha1_object(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def _hex40(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{40}', value) is not None


@dataclass(frozen=True, repr=False)
class _ReservationBinding:
    source: SourceBinding = field(repr=False)
    identity: object = field(repr=False)
    source_commit: str
    source_tree: str
    _seal: object = field(repr=False)


class GitRefReservation:
    """Real Git REST create-only protocol, exercised only by explicit fake HTTPS.

    A ref is mutable by sufficiently privileged other actors. Namespace write/delete
    protection remains separately unqualified; no global append-only claim.
    """
    def __init__(self, runtime_binding=None):
        self._binding = None
        self._wire = None
        self._wall_clock = time.time
        self._consumed = False
        self.state = 'UNBOUND'
        self._writes_started = 0
        self._private_outcome = None
        self._effect_key = self._commit = None
        self._job_token = None

    @classmethod
    def for_test(cls, https_connection_factory, *, identity, source_binding,
                 source_commit, source_tree, clock=time.monotonic, wall_clock=time.time):
        require_test_evidence(identity)
        if (type(source_binding) is not SourceBinding or not _hex40(source_commit)
                or not _hex40(source_tree) or source_commit != identity.policy.sha):
            raise IdentityRefused('AUTHENTIC_SOURCE_BINDING_REQUIRED')
        now = wall_clock()
        if type(now) not in (int, float) or not identity.policy.not_before <= now < identity.policy.expires_at:
            raise IdentityRefused('SOURCE_ABSOLUTE_DEADLINE')
        result = cls()
        result._binding = _ReservationBinding(source_binding, identity, source_commit, source_tree,
                                              _RESERVATION_TEST_SEAL)
        result._wall_clock = wall_clock
        result._wire = _FixedHTTPS(factory=https_connection_factory, clock=clock,
            seconds=identity.policy.expires_at - now, limit_calls=10, scope=_TEST)
        result.state = 'TEST_ONLY_READY'
        result._job_token = 'TEST_ONLY_NOT_A_PROVIDER_CREDENTIAL'
        return result

    def reserve_production(self, *args, **kwargs):
        raise IdentityRefused('AUTHENTIC_RUNTIME_BINDING_UNBOUND')

    def _api(self, method, suffix, payload=None):
        if self._wall_clock() >= self._binding.identity.policy.expires_at:
            raise TransportUnknown('SOURCE_ABSOLUTE_DEADLINE')
        if method == 'POST':
            self._writes_started += 1
        status, raw = self._wire.exchange(method, 'api.github.com', _REPO + suffix,
            body=_canonical(payload) if payload is not None else None,
            headers={'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                     'X-GitHub-Api-Version': '2026-03-10',
                     'Authorization': 'Bearer ' + self._job_token})
        if self._wall_clock() >= self._binding.identity.policy.expires_at:
            raise TransportUnknown('SOURCE_ABSOLUTE_DEADLINE')
        return status, raw

    def reserve_for_test(self, *, caller_run_id, caller_run_attempt, grant_id, restart=False):
        binding = self._binding
        if binding is None or binding._seal is not _RESERVATION_TEST_SEAL or self._wire is None:
            raise IdentityRefused('AUTHENTIC_RUNTIME_BINDING_UNBOUND')
        policy = binding.identity.policy
        if (self._consumed or restart is not False or caller_run_attempt != '1'
                or type(caller_run_attempt) is not str or caller_run_id != policy.run_id
                or type(caller_run_id) is not str or grant_id != binding.source.grant_id):
            raise IdentityRefused('RESTART_ATTEMPT_OR_RUN_BINDING_REFUSED')
        self._consumed = True  # Never reset after failure, UNKNOWN or a new token.
        self.state = 'ATTEMPTING_TEST_ONLY'
        source = binding.source
        key = hashlib.sha256((source.grant_id + ':' + source.order_id_sha256).encode()).hexdigest()
        self._effect_key = key
        ref = 'refs/tags/payproof-reservations/v1/' + key
        suffix = '/git/ref/tags/payproof-reservations/v1/' + key
        record = {'schema': 'PAYPROOF_CONSUMED_RESERVATION_V1', 'state': 'CONSUMED_BEFORE_OAUTH',
            'repository_id': '1419908202', 'repository_owner_id': '273768139',
            'grant_id': source.grant_id, 'effect_key_sha256': key,
            'order_id_sha256': source.order_id_sha256,
            'registry_receipt_sha256': source.registry_receipt_sha256,
            'reviewed_bundle_sha256': source.reviewed_bundle_sha256,
            'admission_source_sha256': source.admission_source_sha256,
            'source_commit': binding.source_commit, 'source_tree': binding.source_tree,
            'run_id': policy.run_id, 'run_attempt': '1', 'absolute_deadline_epoch': policy.expires_at,
            'OAuth_allowances_consumed': 1, 'GET_allowances_consumed': 1,
            'restart': 'REFUSE_ALL_EXISTING_RECORDS', 'scope': 'TEST_ONLY_TRANSPORT_MECHANICS'}
        expected_raw = _canonical(record)
        blob_sha = _sha1_object('blob', expected_raw)
        tree_body = b'100644 reservation.json\0' + bytes.fromhex(blob_sha)
        expected_tree = _sha1_object('tree', tree_body)
        message = 'Consume PayProof read allowance ' + key
        try:
            status, raw = self._api('GET', '')
            repo = _object(raw, 65536)
            if (status != 200 or repo.get('id') != 1419908202 or repo.get('private') is not True
                    or repo.get('full_name') != 'Elinfiny/PayProof'
                    or type(repo.get('owner')) is not dict or repo['owner'].get('id') != 273768139):
                raise IdentityRefused('SAME_PRIVATE_REPOSITORY_REQUIRED')
            status, raw = self._api('GET', suffix)
            if status == 200:
                self.state = 'EXISTING_RECORD_REFUSED'
                raise IdentityRefused('EXISTING_RECORD_NEVER_ADOPTED')
            if status != 404:
                raise IdentityRefused('REFERENCE_ABSENCE_UNPROVED')
            status, raw = self._api('POST', '/git/trees', {'tree': [
                {'path': 'reservation.json', 'mode': '100644', 'type': 'blob', 'content': expected_raw.decode()}]})
            created_tree = _object(raw, 65536)
            if status != 201 or created_tree.get('sha') != expected_tree:
                raise TransportUnknown('TREE_CREATE_UNKNOWN')
            status, created_commit_raw = self._api('POST', '/git/commits',
                {'message': message, 'tree': expected_tree, 'parents': [binding.source_commit]})
            created_commit = _object(created_commit_raw, 65536)
            commit = created_commit.get('sha')
            if status != 201 or not _hex40(commit):
                raise TransportUnknown('COMMIT_CREATE_UNKNOWN')
            self._commit = commit
            status, created_ref_raw = self._api('POST', '/git/refs', {'ref': ref, 'sha': commit})
            if status in (409, 422):
                # 422 alone is validation/spam, NOT proof of an existing record.
                collision_status, collision_raw = self._api('GET', suffix)
                self._private_outcome = (status, collision_status, collision_raw)
                if collision_status == 200:
                    self.state = 'COLLISION_RECORD_REFUSED'
                    raise IdentityRefused('COLLISION_CONFIRMED_NEVER_ADOPTED')
                raise IdentityRefused('REF_CREATE_REJECTED_EXISTENCE_UNPROVED')
            if status != 201:
                raise TransportUnknown('ATOMIC_REF_CREATE_UNKNOWN')
            created_ref = _object(created_ref_raw, 65536)
            if (created_ref.get('ref') != ref or created_ref.get('object', {}).get('sha') != commit
                    or created_ref.get('object', {}).get('type') != 'commit'):
                raise TransportUnknown('REF_CREATE_BINDING_UNKNOWN')
            status, first_ref_raw = self._api('GET', suffix)
            if status != 200 or first_ref_raw != created_ref_raw:
                raise TransportUnknown('REF_READBACK_UNKNOWN')
            status, commit_raw = self._api('GET', '/git/commits/' + commit)
            commit_read = _object(commit_raw, 65536)
            if (status != 200 or commit_raw != created_commit_raw
                    or commit_read.get('sha') != commit or commit_read.get('tree', {}).get('sha') != expected_tree
                    or [x.get('sha') for x in commit_read.get('parents', [])] != [binding.source_commit]
                    or commit_read.get('message') != message):
                raise TransportUnknown('COMMIT_WHOLEBYTE_READBACK_UNKNOWN')
            status, tree_raw = self._api('GET', '/git/trees/' + expected_tree)
            tree = _object(tree_raw, 65536)
            entries = tree.get('tree')
            if (status != 200 or tree.get('sha') != expected_tree or tree.get('truncated') is not False
                    or type(entries) is not list or len(entries) != 1
                    or entries[0].get('path') != 'reservation.json' or entries[0].get('type') != 'blob'
                    or entries[0].get('mode') != '100644' or entries[0].get('sha') != blob_sha
                    or entries[0].get('size') != len(expected_raw)):
                raise TransportUnknown('TREE_WHOLE_READBACK_UNKNOWN')
            status, blob_raw = self._api('GET', '/git/blobs/' + blob_sha)
            blob = _object(blob_raw, 65536)
            if (status != 200 or blob.get('encoding') != 'base64' or blob.get('sha') != blob_sha
                    or blob.get('size') != len(expected_raw) or type(blob.get('content')) is not str):
                raise TransportUnknown('BLOB_READBACK_UNKNOWN')
            try:
                actual_raw = base64.b64decode(blob['content'].replace('\n', ''), validate=True)
            except (ValueError, base64.binascii.Error):
                raise TransportUnknown('BLOB_ENCODING_UNKNOWN') from None
            if actual_raw != expected_raw or _sha1_object('blob', actual_raw) != blob_sha:
                raise TransportUnknown('RECORD_WHOLEBYTE_READBACK_UNKNOWN')
            status, last_ref_raw = self._api('GET', suffix)
            if status != 200 or last_ref_raw != first_ref_raw:
                raise TransportUnknown('FINAL_REF_STABILITY_UNKNOWN')
            self._private_outcome = record
            self.state = 'SYNTHETIC_CREATE201_AND_DURABLE_READBACK_VERIFIED'
            return self.metadata()
        except TransportUnknown as error:
            self._wire._retain('RESERVATION_UNKNOWN', error=error)
            self._wire._unknown('RESERVATION_UNKNOWN', 'POST_RETURN')
            self.state = 'UNKNOWN_NO_OAUTH_NO_RETRY'
            raise
        except IdentityRefused as error:
            if (self._writes_started and self.state == 'ATTEMPTING_TEST_ONLY'
                    and str(error) != 'REF_CREATE_REJECTED_EXISTENCE_UNPROVED'):
                self._wire._retain('PROVIDER_PARSE_OR_BINDING_UNKNOWN', error=error)
                self._wire._unknown('PROVIDER_PARSE_OR_BINDING_UNKNOWN', 'POST_RETURN')
                self.state = 'UNKNOWN_NO_OAUTH_NO_RETRY'
                raise TransportUnknown('RESERVATION_UNKNOWN') from None
            if self.state == 'ATTEMPTING_TEST_ONLY':
                self.state = 'REFUSED_NO_OAUTH'
            raise
        except Exception as error:
            self._wire._retain('RESERVATION_PROTOCOL_EXCEPTION', error=error)
            self._wire._unknown('PROTOCOL_EXCEPTION', 'POST_RETURN')
            self.state = 'UNKNOWN_NO_OAUTH_NO_RETRY'
            raise TransportUnknown('RESERVATION_UNKNOWN') from None

    def metadata(self):
        return {'scope': 'TEST_ONLY_GIT_RESERVATION_PROTOCOL', 'state': self.state,
            'effect_key_sha256': self._effect_key, 'commit': self._commit,
            'wire': self._wire.metadata() if self._wire else {'requests': 0},
            'OAuth_calls': 0, 'GET_order_calls': 0, 'production_context': False,
            'real_provider_durability_qualified': False, 'append_only_global': False,
            'namespace_delete_update_protection': 'UNQUALIFIED'}


if __name__ == '__main__':
    raise IdentityRefused('AUTHENTIC_RUNTIME_BINDING_UNBOUND')
