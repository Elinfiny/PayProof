"""Exactly6 new inert cases for16; explicit fake TLS/Git and ephemeral JWT fixture."""
import base64
import hashlib
import json
import os
import ssl
import unittest
from dataclasses import replace
from unittest.mock import Mock
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from payproof.github_oidc import (ISSUER, FixedJWKSLoader, GitHubOIDCVerifier, IdentityPolicy,
    JWKSSnapshot, IdentityRefused, TransportUnknown)
from payproof.bootstrap_bridge import (SourceBinding, ReservationPlan, BootstrapBridge,
    GitRefReservation, _canonical, _sha1_object)

NOW = 1800000100
REPO = '/repos/Elinfiny/PayProof'


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def advance(self, seconds): self.value += seconds


class FakeResponse:
    def __init__(self, status, raw): self.status, self.raw = status, raw
    def read(self, limit): return self.raw[:limit]


class FakeHTTPS:
    """Explicit fixture provider, never actual TLS/caller/durability proof."""
    def __init__(self, backend): self.backend = backend
    def __call__(self, host, port, *, timeout, context):
        assert port == 443 and 0 < timeout <= 300
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        self.backend.hosts.append(host)
        backend = self.backend
        class Connection:
            def request(self, method, path, body=None, headers=None):
                self.method, self.path, self.body = method, path, body
                backend.request_headers = dict(headers or {})
                backend.calls.append((host, method, path))  # Never retain Authorization.
            def getresponse(self):
                result = backend.handle(self.method, self.path, self.body)
                backend.responses.append(result)
                return result
            def close(self):
                if backend.close_failure and self.path == backend.close_failure_path:
                    backend.clock.advance(301)
                    raise backend.cleanup_error
                return None
        return Connection()


class FakeBackend:
    def __init__(self, clock):
        self.clock = clock
        self.calls, self.hosts, self.responses = [], [], []
        self.refs = {}
        self.trees, self.commits, self.blobs = {}, {}, {}
        self.jwks_raw = b'{"keys":[{"kid":"SYNTHETIC"}]}'
        self.jwks_status = 200
        self.jwks_late = False
        self.race_at_ref_create = False
        self.ref_validation_failure = False
        self.raise_commit = False
        self.raise_ref_after_create = False
        self.close_failure = False
        self.close_failure_path = REPO + '/git/commits'
        self.primary_error = RuntimeError('SYNTHETIC_PRIVATE_PRIMARY')
        self.cleanup_error = RuntimeError('SYNTHETIC_PRIVATE_CLEANUP')

    def reply(self, status, value): return FakeResponse(status, _canonical(value))

    def ref_reply(self, ref):
        return self.reply(200, {'ref': ref, 'object': {'sha': self.refs[ref], 'type': 'commit'}})

    def handle(self, method, path, raw):
        if path == '/.well-known/jwks':
            if self.jwks_late: self.clock.advance(301)
            return FakeResponse(self.jwks_status, self.jwks_raw)
        if method == 'GET' and path == REPO:
            return self.reply(200, {'id':1419908202, 'full_name':'Elinfiny/PayProof', 'private':True,
                                    'owner':{'id':273768139}})
        if method == 'GET' and path.startswith(REPO + '/git/ref/'):
            ref = 'refs/' + path.split('/git/ref/', 1)[1]
            return self.ref_reply(ref) if ref in self.refs else self.reply(404, {'message':'Not Found'})
        data = json.loads(raw) if raw is not None else None
        if method == 'POST' and path == REPO + '/git/trees':
            entry = data['tree'][0]
            content = entry['content'].encode()
            blob = _sha1_object('blob', content)
            tree = _sha1_object('tree', b'100644 reservation.json\0' + bytes.fromhex(blob))
            self.blobs[blob] = content
            result = {'sha':tree, 'truncated':False, 'tree':[{'path':'reservation.json', 'mode':'100644',
                'type':'blob', 'sha':blob, 'size':len(content)}]}
            self.trees[tree] = result
            return self.reply(201, result)
        if method == 'POST' and path == REPO + '/git/commits':
            if self.raise_commit: raise self.primary_error
            # Arbitrary fixture commit identity; never presented as an actual Git commit.
            sha = hashlib.sha1(b'SYNTHETIC_NATIVE_SHAPED_COMMIT:' + raw).hexdigest()
            result = {'sha':sha, 'tree':{'sha':data['tree']},
                      'parents':[{'sha':p} for p in data['parents']], 'message':data['message']}
            self.commits[sha] = result
            return self.reply(201, result)
        if method == 'POST' and path == REPO + '/git/refs':
            ref = data['ref']
            if self.ref_validation_failure: return self.reply(422, {'message':'Validation Failed'})
            if self.race_at_ref_create: self.refs[ref] = 'f' * 40
            if ref in self.refs: return self.reply(422, {'message':'Reference already exists'})
            self.refs[ref] = data['sha']
            if self.raise_ref_after_create: raise self.primary_error
            response = self.ref_reply(ref)
            return FakeResponse(201, response.raw)
        for kind, values in [('commits',self.commits), ('trees',self.trees)]:
            prefix = REPO + '/git/' + kind + '/'
            if method == 'GET' and path.startswith(prefix): return self.reply(200, values[path.removeprefix(prefix)])
        prefix = REPO + '/git/blobs/'
        if method == 'GET' and path.startswith(prefix):
            sha = path.removeprefix(prefix); content = self.blobs[sha]
            if getattr(self, 'request_headers', {}).get('Accept') == 'application/vnd.github.raw+json':
                return FakeResponse(200, content)
            return self.reply(200, {'sha':sha, 'encoding':'base64', 'size':len(content),
                                   'content':base64.b64encode(content).decode()})
        raise AssertionError('Unplanned fake endpoint')


class BootstrapTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        n = cls.key.public_key().public_numbers()
        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        integer = lambda x: enc(x.to_bytes((x.bit_length()+7)//8,'big'))
        cls.jwk = {'kty':'RSA','alg':'RS256','use':'sig','kid':'SYNTHETIC',
                   'n':integer(n.n),'e':integer(n.e)}
    @classmethod
    def tearDownClass(cls): cls.key = None

    def setUp(self):
        self.clock = Clock(); self.backend = FakeBackend(self.clock)
        self.backend.jwks_raw = _canonical({'keys':[self.jwk]})
        self.policy = IdentityPolicy('urn:payproof:read-bootstrap:test-only',
            'Elinfiny/PayProof/.github/workflows/payproof-read-pilot.yml@refs/heads/main',
            'refs/heads/main','a'*40,'a'*40,'workflow_dispatch',
            'repo:Elinfiny@273768139/PayProof@1419908202:ref:refs/heads/main',
            '123456','1',NOW-100,NOW+200)
        claims = {'iss':ISSUER,'aud':self.policy.audience,'repository':'Elinfiny/PayProof',
            'repository_id':'1419908202','repository_owner_id':'273768139','repository_owner':'Elinfiny',
            'repository_visibility':'private','workflow_ref':self.policy.workflow_ref,'workflow_sha':'a'*40,
            'ref':self.policy.ref,'sha':'a'*40,'event_name':'workflow_dispatch','sub':self.policy.subject,
            'run_id':'123456','run_attempt':'1','runner_environment':'github-hosted','ref_type':'branch',
            'iat':NOW-10,'nbf':NOW-10,'exp':NOW+120,'jti':'SYNTHETIC_ONLY'}
        enc = lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        head = enc(_canonical({'typ':'JWT','alg':'RS256','kid':'SYNTHETIC'})); payload = enc(_canonical(claims))
        self.token = head+'.'+payload+'.'+enc(self.key.sign((head+'.'+payload).encode(),padding.PKCS1v15(),hashes.SHA256()))
        self.snapshot = JWKSSnapshot.synthetic_for_test(self.backend.jwks_raw, observed_at=NOW)
        self.identity = GitHubOIDCVerifier().verify_for_test(self.token,policy=self.policy,snapshot=self.snapshot,now=NOW)
        digest=lambda s:hashlib.sha256(s.encode()).hexdigest()
        self.source = SourceBinding('SYNTHETIC_CANONICAL_GRANT',os.environ['PAYPROOF_BOOTSTRAP_TEST_SOURCE_SHA256'],
            os.environ['PAYPROOF_ADMISSION_TEST_SOURCE_SHA256'],digest('SYNTHETIC_ID'),digest('SYNTHETIC_ORDER'),digest('SYNTHETIC_REGISTRY'))

    def reservation(self, backend=None):
        return GitRefReservation.for_test(FakeHTTPS(backend or self.backend), identity=self.identity,
            source_binding=self.source,source_commit='a'*40,source_tree='b'*40,
            clock=self.clock,wall_clock=lambda:NOW)

    def reserve(self, reservation, **changes):
        args={'caller_run_id':'123456','caller_run_attempt':'1','grant_id':self.source.grant_id}|changes
        return reservation.reserve_for_test(**args)

    def test_01_fixed_jwks_tls_get_and_signature_snapshot_remain_test_only(self):
        loader=FixedJWKSLoader.for_test(FakeHTTPS(self.backend),clock=self.clock)
        snapshot=loader.fetch_for_test(observed_at=NOW,now=NOW)
        self.assertEqual(self.backend.calls,[('token.actions.githubusercontent.com','GET','/.well-known/jwks')])
        identity=GitHubOIDCVerifier().verify_for_test(self.token,policy=self.policy,snapshot=snapshot,now=NOW)
        self.assertTrue(identity.test_only)
        self.assertFalse(loader.metadata()['authenticated_TLS_provenance'])
        with self.assertRaises(IdentityRefused): loader.fetch_for_test(observed_at=NOW,now=NOW)
        self.assertEqual(len(self.backend.calls),1)

    def test_02_redirect_oversize_and_late_preserve_original_no_second_get(self):
        for mode in ('redirect','oversize','late'):
            clock=Clock(); backend=FakeBackend(clock)
            if mode=='redirect': backend.jwks_status=302
            if mode=='oversize': backend.jwks_raw=b'x'*65537
            if mode=='late': backend.jwks_late=True
            loader=FixedJWKSLoader.for_test(FakeHTTPS(backend),clock=clock)
            with self.assertRaises(IdentityRefused): loader.fetch_for_test(observed_at=NOW,now=NOW)
            self.assertIs(loader._wire.originals[0].value,backend.responses[0])
            with self.assertRaises(IdentityRefused): loader.fetch_for_test(observed_at=NOW,now=NOW)
            self.assertEqual(len(backend.calls),1)
            if mode=='late': self.assertEqual(loader.metadata()['first_unknown']['phase'],'POST_RETURN')

    def test_03_atomic201_full_readback_then_existing_and_race_loser_refused(self):
        first=self.reservation(); report=self.reserve(first)
        self.assertEqual(report['state'],'SYNTHETIC_CREATE201_AND_DURABLE_READBACK_VERIFIED')
        self.assertEqual(len(self.backend.calls),10)
        self.assertEqual(sum(m=='POST' for _,m,_ in self.backend.calls),3)
        self.assertFalse(report['real_provider_durability_qualified'])
        self.assertFalse(report['append_only_global'])
        record=first._private_outcome
        self.assertEqual(record['OAuth_allowances_consumed'],1)
        self.assertEqual(record['GET_allowances_consumed'],1)
        self.assertEqual(record['run_id'],'123456')
        with self.assertRaisesRegex(IdentityRefused,'EXISTING_RECORD'): self.reserve(self.reservation())
        self.assertEqual(len(self.backend.calls),12)
        race=FakeBackend(self.clock);race.race_at_ref_create=True
        loser=self.reservation(race)
        with self.assertRaisesRegex(IdentityRefused,'COLLISION_CONFIRMED'): self.reserve(loser)
        self.assertEqual(loser.state,'COLLISION_RECORD_REFUSED')
        self.assertEqual(len(race.calls),6)
        invalid=FakeBackend(self.clock);invalid.ref_validation_failure=True
        with self.assertRaisesRegex(IdentityRefused,'EXISTENCE_UNPROVED'): self.reserve(self.reservation(invalid))
        self.assertFalse(invalid.refs)

    def test_04_ambiguous_commit_and_late_cleanup_keep_first_unknown_no_transport(self):
        self.backend.raise_commit=True;self.backend.close_failure=True
        r=self.reservation()
        with self.assertRaises(TransportUnknown): self.reserve(r)
        first=dict(r._wire.first_unknown)
        self.assertEqual(first['code'],'HTTP_EXCEPTION')
        self.assertTrue(any(x.error is self.backend.primary_error for x in r._wire.originals))
        self.assertTrue(any(x.error is self.backend.cleanup_error for x in r._wire.originals))
        self.assertEqual(r.metadata()['OAuth_calls'],0)
        before=len(self.backend.calls)
        with self.assertRaises(IdentityRefused): self.reserve(r)
        self.assertEqual(len(self.backend.calls),before)
        self.assertEqual(r._wire.first_unknown,first)
        freshclock=Clock();backend=FakeBackend(freshclock);backend.raise_ref_after_create=True
        r2=GitRefReservation.for_test(FakeHTTPS(backend),identity=self.identity,source_binding=self.source,
            source_commit='a'*40,source_tree='b'*40,clock=freshclock,wall_clock=lambda:NOW)
        with self.assertRaises(TransportUnknown): self.reserve(r2)
        self.assertTrue(backend.refs)
        self.assertEqual(len(backend.calls),5)
        self.assertEqual(r2.state,'UNKNOWN_NO_OAUTH_NO_RETRY')

    def test_05_attempt2_restart_run_and_grant_reset_refuse_before_provider(self):
        for change in ({'caller_run_attempt':'2'},{'restart':True},{'caller_run_id':'wrong'},
                       {'grant_id':'NEW_RESET_GRANT'},{'caller_run_attempt':True}):
            r=self.reservation()
            with self.assertRaises(IdentityRefused): self.reserve(r,**change)
        self.assertEqual(self.backend.calls,[])
        with self.assertRaises(IdentityRefused):
            GitRefReservation.for_test(FakeHTTPS(self.backend),identity=self.identity,source_binding=self.source,
                source_commit='c'*40,source_tree='b'*40,clock=self.clock,wall_clock=lambda:NOW)

    def test_06_default_and_missing_auth_source_custody_registry_before_provider(self):
        callback=Mock(side_effect=AssertionError('No provider'))
        for alleged in (None,True,{'admitted':True,'PID':123},{'HMAC':'local'},callback):
            with self.assertRaisesRegex(IdentityRefused,'UNBOUND'): FixedJWKSLoader(alleged).fetch_production(observed_at=NOW, now=NOW)
            with self.assertRaisesRegex(IdentityRefused,'UNBOUND'): GitRefReservation(alleged).reserve_production()
            with self.assertRaisesRegex(IdentityRefused,'UNBOUND'): BootstrapBridge(alleged).activate(self.token)
        callback.assert_not_called()
        key=hashlib.sha256((self.source.grant_id+':'+self.source.order_id_sha256).encode()).hexdigest()
        inputs={'policy':self.policy,'snapshot':self.snapshot,'now':NOW,'source_binding':self.source,
            'actual_bundle_sha256':self.source.reviewed_bundle_sha256,'admission_source_sha256':self.source.admission_source_sha256,
            'credentials':{'client_id':'SYNTHETIC_ID','client_secret':'SYNTHETIC_MEMORY_ONLY'},
            'registry_entry':{'order_id_sha256':self.source.order_id_sha256,
                'registry_receipt_sha256':self.source.registry_receipt_sha256,'preexisting':True},
            'reservation':ReservationPlan(key)}
        for missing in ({'source_binding':None},{'credentials':{}},{'registry_entry':{}},
                        {'snapshot':{'admitted':True}},{'actual_bundle_sha256':'0'*64}):
            with self.assertRaises(IdentityRefused):
                BootstrapBridge().reserve_for_test(self.token,https_connection_factory=FakeHTTPS(self.backend),
                    source_commit='a'*40,source_tree='b'*40,caller_run_id='123456',caller_run_attempt='1',
                    clock=self.clock,wall_clock=lambda:NOW,**(inputs|missing))
        self.assertEqual(self.backend.calls,[])
