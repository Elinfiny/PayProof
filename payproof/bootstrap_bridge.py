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

    def activate(self, token, job_token=None, order_id=None):
        if type(self._runtime_binding) is not ConsumerProvider:
            raise IdentityRefused('AUTHENTIC_RUNTIME_BINDING_UNBOUND')
        self._runtime_binding.context.require(production=True)
        return self._runtime_binding.consume(token,order_id)

    @classmethod
    def from_host(cls, job_token):
        from .admission import load_consumer_context
        context=load_consumer_context()
        result=cls();result._runtime_binding=ConsumerProvider.from_host(context,job_token)
        return result

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
_RESERVATION_HOST_SEAL = object()


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

    def reserve_production(self, **kwargs):
        if not hasattr(self,'_consumer_context') or self._consumer_context.test_only:
            raise IdentityRefused('AUTHENTIC_RUNTIME_BINDING_UNBOUND')
        self._consumer_context.require(production=True)
        return self._reserve(**kwargs)

    def _api(self, method, suffix, payload=None):
        if hasattr(self,'_consumer_context'): self._consumer_context.require(production=not self._consumer_context.test_only)
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

    def reserve_for_test(self, **kwargs):
        if hasattr(self,'_consumer_context') and not self._consumer_context.test_only:
            raise IdentityRefused('TEST_ONLY_ENTRY_REFUSED')
        return self._reserve(**kwargs)

    def _reserve(self, *, caller_run_id, caller_run_attempt, grant_id, restart=False):
        binding = self._binding
        expected_seal = _RESERVATION_HOST_SEAL if hasattr(self,'_consumer_context') and not self._consumer_context.test_only else _RESERVATION_TEST_SEAL
        if binding is None or binding._seal is not expected_seal or self._wire is None:
            raise IdentityRefused('AUTHENTIC_RUNTIME_BINDING_UNBOUND')
        policy = binding.identity.policy
        if (self._consumed or restart is not False or caller_run_attempt != '1'
                or type(caller_run_attempt) is not str or caller_run_id != policy.run_id
                or type(caller_run_id) is not str or grant_id != binding.source.grant_id):
            raise IdentityRefused('RESTART_ATTEMPT_OR_RUN_BINDING_REFUSED')
        self._consumed = True  # Never reset after failure, UNKNOWN or a new token.
        self.state = 'ATTEMPTING_TEST_ONLY'
        source = binding.source
        key = getattr(self,'_canonical_consumer_key',None) or hashlib.sha256((source.grant_id + ':' + source.order_id_sha256).encode()).hexdigest()
        namespace = 'v2/' if hasattr(self,'_canonical_consumer_key') else 'v1/'
        self._effect_key = key
        ref = 'refs/tags/payproof-reservations/' + namespace + key
        suffix = '/git/ref/tags/payproof-reservations/' + namespace + key
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
            'restart': 'REFUSE_ALL_EXISTING_RECORDS', 'scope': 'SYNTHETIC_CONSUMER' if getattr(self,'_consumer_context',None) is not None and self._consumer_context.test_only else 'HOST_CONSUMER' if hasattr(self,'_consumer_context') else 'TEST_ONLY_TRANSPORT_MECHANICS'}
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
            self._winning_ref_raw = last_ref_raw  # Exact accepted current winner, private.
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


# Concrete V3 consumer. Production factories are fixed; fakes stay TEST_ONLY.
from .admission import ConsumerContext, canonical_effect_key
from .github_oidc import _PROVIDER, _EVIDENCE, VerifiedIdentity, consumer_policy, FixedJWKSLoader
import http.client
_REGISTRY = object()

class ConsumerRegistry:
    def __init__(self, provider, seal):
        if seal is not _REGISTRY: raise IdentityRefused('REGISTRY_PROVIDER_REQUIRED')
        self.provider=provider;self.context=provider.context.context;self._seal=seal
    def require_existing(self, context, order_id):
        if self._seal is not _REGISTRY or context is not self.context:
            raise IdentityRefused('REGISTRY_CONTEXT')
        self.provider.reverify(order_id,consumed=True)

class ConsumerProvider:
    def __init__(self):
        self.context=None;self._wire=None;self._jwks=None;self._job_token=None
        self._used=False;self._reservation=None;self._driver=None;self._originals=[]
        self._first_unknown=None;self._clock=time.monotonic;self._wall=time.time
        self._immutable_registry_cache=None
    @classmethod
    def from_host(cls, context, job_token):
        if type(context) is not ConsumerContext: raise IdentityRefused('V3_REQUIRED')
        context.require(production=True)
        if type(job_token) is not str or not 1<=len(job_token)<=4096: raise IdentityRefused('JOB_TOKEN_REQUIRED')
        p=cls();p.context=context;p._job_token=job_token
        seconds=min(300,context.context.expires_at.timestamp()-time.time())
        p._wire=_FixedHTTPS(seconds=seconds,limit_calls=64,scope=_PROVIDER)
        p._jwks=FixedJWKSLoader.from_host(context)
        return p
    @classmethod
    def for_test(cls, context, factory, *, clock=time.monotonic):
        if type(context) is not ConsumerContext or context.test_only is not True:
            raise IdentityRefused('EXPLICIT_SYNTHETIC_V3_REQUIRED')
        context.require();p=cls();p.context=context;p._clock=clock
        seconds=min(300,context.context.expires_at.timestamp()-time.time())
        p._wire=_FixedHTTPS(factory=factory,clock=clock,seconds=seconds,limit_calls=64,scope=_TEST)
        p._jwks=FixedJWKSLoader.for_test(factory,clock=clock,seconds=seconds)
        p._job_token='PUBLIC_SYNTHETIC_JOBTOKEN';return p
    def _json_api(self,path):
        self.context.require(production=not self.context.test_only)
        status,raw=self._wire.exchange('GET','api.github.com',_REPO+path,
            headers={'Accept':'application/vnd.github+json','Authorization':'Bearer '+self._job_token})
        if status!=200: raise IdentityRefused('CURRENT_PROVIDER_READBACK_REQUIRED')
        return _object(raw,65536)
    def _blob_at(self,revision,path,digest):
        commit=self._json_api('/git/commits/'+revision)
        if commit.get('sha')!=revision: raise IdentityRefused('IMMUTABLE_REVISION')
        tree=commit.get('tree',{}).get('sha')
        for index,part in enumerate(path.split('/')):
            body=self._json_api('/git/trees/'+tree)
            if body.get('sha')!=tree or body.get('truncated') is not False or type(body.get('tree')) is not list:
                raise IdentityRefused('COMPLETE_TREE_REQUIRED')
            entries=[x for x in body['tree'] if x.get('path')==part]
            if len(entries)!=1: raise IdentityRefused('PATH_MEMBERSHIP')
            entry=entries[0]
            if index<len(path.split('/'))-1:
                if entry.get('type')!='tree': raise IdentityRefused('TREE_PATH')
                tree=entry['sha']
            elif entry.get('type')!='blob' or entry.get('mode')!='100644':
                raise IdentityRefused('REGULAR_SOURCE_FILE_REQUIRED')
        blob=self._json_api('/git/blobs/'+entry['sha'])
        if blob.get('sha')!=entry['sha'] or blob.get('encoding')!='base64': raise IdentityRefused('BLOB_PROVENANCE')
        try: raw=base64.b64decode(blob['content'].replace('\n',''),validate=True)
        except Exception: raise IdentityRefused('BLOB_ENCODING') from None
        if len(raw)!=blob.get('size') or len(raw)!=entry.get('size') or _sha1_object('blob',raw)!=entry['sha'] or hashlib.sha256(raw).hexdigest()!=digest:
            raise IdentityRefused('WHOLE_IMMUTABLE_SOURCE_DIGEST')
        return raw
    def reverify(self,order_id,consumed=False):
        g=self.context.require(production=not self.context.test_only);r=g['registry']
        if type(order_id) is not str or re.fullmatch('[A-Z0-9]{1,36}',order_id) is None or hashlib.sha256(order_id.encode()).hexdigest()!=r['order_id_sha256']:
            raise IdentityRefused('EXACT_EXISTING_ORDER')
        # Cache only immutable observed registry bytes, bound to this exact sealed invocation.
        cache_key=(self.context,g['bundle_sha256'],g['caller']['source_commit'],
                   r['order_id_sha256'],r['revision'],r['path'],r['sha256'])
        cache=self._immutable_registry_cache
        if cache is not None:
            if cache[0][0] is not self.context or cache[0][1:]!=cache_key[1:]:
                raise IdentityRefused('IMMUTABLE_CACHE_BINDING')
            registry_raw=cache[1]
        else:
            registry_raw=self._blob_at(r['revision'],r['path'],r['sha256'])
        actual=_object(registry_raw,65536)
        expected={'schema':'PAYPROOF_PREEXISTING_REGISTRY_V3','client_id_sha256':g['client_id_sha256'],
            'order_id_sha256':r['order_id_sha256'],'canonical_effect_key_sha256':g['canonical_effect_key_sha256'],
            'legacy_refs_sha256':r['legacy_refs_sha256'],'legacy_grant_ids':g['legacy_grant_ids']}
        if set(actual)!=set(expected)|{'provenance'} or any(actual[k]!=v for k,v in expected.items()):
            raise IdentityRefused('AUTHENTIC_REGISTRY_APP_OR_LINEAGE')
        provenance=actual['provenance']
        if (type(provenance) is not dict or set(provenance)!={'provider','environment','receipt_sha256'}
                or provenance['provider']!='paypal' or provenance['environment']!='sandbox'
                or re.fullmatch('[a-f0-9]{64}',str(provenance['receipt_sha256'])) is None):
            raise IdentityRefused('PREEXISTING_PROVIDER_PROVENANCE')
        if self._immutable_registry_cache is None:
            self._immutable_registry_cache=(cache_key,registry_raw)
        # NEVER cache dynamic lineage or winner. Query again before EVERY PayPal request.
        # Read OLD namespace in full; an empty NEW namespace is never sufficient.
        status,raw=self._wire.exchange('GET','api.github.com',_REPO+'/git/matching-refs/tags/payproof-reservations/v1/',
            headers={'Authorization':'Bearer '+self._job_token})
        self._originals.append(raw)
        try: old=json.loads(raw)
        except Exception: raise IdentityRefused('LEGACY_NAMESPACE_UNKNOWN') from None
        if status!=200 or type(old) is not list or hashlib.sha256(_canonical(old)).hexdigest()!=r['legacy_refs_sha256'] or old:
            # Conservative: any old record, including unrelated/unparsed state, stops.
            raise IdentityRefused('LEGACY_RECORD_OR_UNKNOWN_REFUSED')
        for legacy in g['legacy_grant_ids']:
            key=hashlib.sha256((legacy+':'+r['order_id_sha256']).encode()).hexdigest()
            status,raw=self._wire.exchange('GET','api.github.com',_REPO+'/git/ref/tags/payproof-reservations/v1/'+key,
                headers={'Authorization':'Bearer '+self._job_token})
            if status!=404: raise IdentityRefused('KNOWN_OLD_EFFECT_REFUSED')
        if consumed:
            if self._reservation is None or self._reservation.state!='SYNTHETIC_CREATE201_AND_DURABLE_READBACK_VERIFIED':
                raise IdentityRefused('CONSUMED_RESERVATION_REQUIRED')
            status,raw=self._wire.exchange('GET','api.github.com',
                _REPO+'/git/ref/tags/payproof-reservations/v2/'+g['canonical_effect_key_sha256'],
                headers={'Authorization':'Bearer '+self._job_token})
            if status!=200 or raw!=self._reservation._winning_ref_raw:
                raise IdentityRefused('CONSUMED_WINNER_READBACK_CHANGED_OR_UNKNOWN')
            ref=_object(raw,65536)
            if (ref.get('ref')!='refs/tags/payproof-reservations/v2/'+g['canonical_effect_key_sha256']
                    or ref.get('object',{}).get('sha')!=self._reservation._commit
                    or ref.get('object',{}).get('type')!='commit'):
                raise IdentityRefused('CONSUMED_RECORD_CHANGED')
    def _caller(self,identity):
        g=self.context.grant;c=g['caller']
        if (identity._seal is not _EVIDENCE or identity.test_only is not self.context.test_only
                or identity._claims.get('actor')!='Elinfiny' or identity._claims.get('actor_id')!='273768139'):
            raise IdentityRefused('AUTHENTIC_OWNER_CALLER')
        repo=self._json_api('')
        if repo.get('id')!=1419908202 or repo.get('private') is not True or repo.get('fork') is not False or repo.get('owner',{}).get('id')!=273768139:
            raise IdentityRefused('SAME_NONFORK_PRIVATE_REPO')
        source=self._json_api('/git/commits/'+c['source_commit'])
        if source.get('sha')!=c['source_commit'] or source.get('tree',{}).get('sha')!=c['source_tree']:
            raise IdentityRefused('IMMUTABLE_SOURCE_COMMIT_TREE')
        main=self._json_api('/branches/main')
        if main.get('commit',{}).get('sha')!=c['source_commit']: raise IdentityRefused('CURRENT_MAIN_DRIFT')
        self._blob_at(c['source_commit'],c['workflow_path'],c['workflow_sha256'])
        for row in g['bundle_manifest']:
            self._blob_at(c['source_commit'],row['path'],row['sha256'])
        run=self._json_api('/actions/runs/'+c['run_id'])
        if (str(run.get('id'))!=c['run_id'] or str(run.get('run_attempt'))!='1'
                or run.get('head_sha')!=c['source_commit'] or run.get('event')!='workflow_dispatch'
                or run.get('actor',{}).get('id')!=273768139 or run.get('head_repository',{}).get('fork') is not False):
            raise IdentityRefused('CURRENT_RUN_ACTOR_SOURCE')
        jobs=self._json_api('/actions/runs/'+c['run_id']+'/attempts/1/jobs')
        rows=jobs.get('jobs')
        if (jobs.get('total_count')!=1 or type(rows) is not list or len(rows)!=1
                or str(rows[0].get('id'))!=c['job_id'] or rows[0].get('name')!=c['job_name']
                or str(rows[0].get('run_id'))!=c['run_id'] or rows[0].get('head_sha')!=c['source_commit']):
            raise IdentityRefused('SOLE_PINNED_JOB_REQUIRED')
        # No invented job_id JWT claim. Single-job workflow source+signed run+native job readback.
    def consume(self,token,order_id,restart=False):
        if self.context is None: raise IdentityRefused('UNBOUND')
        if self._used or restart is not False: raise IdentityRefused('RESTART_REFUSED')
        self._used=True
        try:
            g=self.context.require(production=not self.context.test_only);now=int(time.time())
            if self.context.test_only:
                snapshot=self._jwks.fetch_for_test(observed_at=now,now=now)
                identity=GitHubOIDCVerifier().verify_for_test(token,policy=consumer_policy(g),snapshot=snapshot,now=now)
            else:
                identity=GitHubOIDCVerifier(self.context,self._jwks).verify_production(token,now=now)
            self._caller(identity);self.reverify(order_id)
            source=SourceBinding(g['admission_id'],g['bundle_sha256'],g['source_sha256'],
                g['client_id_sha256'],g['registry']['order_id_sha256'],g['registry']['sha256'])
            r=GitRefReservation();r._binding=_ReservationBinding(source,identity,g['caller']['source_commit'],g['caller']['source_tree'],_RESERVATION_TEST_SEAL if self.context.test_only else _RESERVATION_HOST_SEAL)
            r._consumer_context=self.context;r._canonical_consumer_key=g['canonical_effect_key_sha256'];r._wall_clock=time.time
            r._job_token=self._job_token;r._wire=_FixedHTTPS(factory=self._wire._factory,clock=self._clock,
                seconds=min(300,self.context.context.expires_at.timestamp()-time.time()),limit_calls=10,
                scope=_TEST if self.context.test_only else _PROVIDER)
            self._reservation=r
            args={'caller_run_id':g['caller']['run_id'],'caller_run_attempt':'1','grant_id':g['admission_id']}
            if self.context.test_only: r.reserve_for_test(**args)
            else: r.reserve_production(**args)
            from tools.read_pilot_driver import ReadPilotDriver
            self._driver=ReadPilotDriver.from_consumer(self.context,ConsumerRegistry(self,_REGISTRY),self)
            return self._driver.run(order_id)
        except Exception as error:
            self._originals.append(error)
            if self._first_unknown is None:
                for wire in (self._jwks._wire,self._wire,getattr(self._reservation,'_wire',None)):
                    if wire is not None and wire.first_unknown is not None:
                        self._first_unknown=dict(wire.first_unknown);break
            raise IdentityRefused('CONSUMER_UNKNOWN' if self._first_unknown else 'CONSUMER_REFUSED') from None
    def paypal(self,method,path,headers,body):
        # Called by the bound driver's in-flight endpoint/allowance boundary only.
        d=self._driver
        if (d is None or d._context is not self.context.context or d._registry.provider is not self
                or d._boundary.in_flight is not True or d._first_unknown is not None):
            raise IdentityRefused('BOUND_IN_FLIGHT_CONSUMER_REQUIRED')
        expected=('POST','/v1/oauth2/token') if d._reserved==1 else (
            ('GET','/v2/checkout/orders/'+d._order_id) if d._reserved==2 else None)
        if (method,path)!=expected: raise IdentityRefused('FIXED_PAYPAL_ALLOWANCE_ROUTE')
        self.reverify(d._order_id,consumed=True)
        self.context.require(production=not self.context.test_only)
        status,raw=self._wire.exchange(method,'api-m.sandbox.paypal.com',path,headers=headers,body=body)
        if status!=200: raise TransportUnknown('PAYPAL_STATUS_UNKNOWN')
        return _object(raw,65536)
