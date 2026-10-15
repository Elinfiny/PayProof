"""Exactly six NEW inert V3 cases. All keys/data are public SYNTHETIC fixtures.
No native host loader, credentials, network, subprocess, CI or production activation.
"""
import base64,hashlib,hmac,json,pathlib,ssl,sys,time,unittest
from copy import deepcopy
from unittest.mock import patch,Mock
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
from payproof import admission
from payproof.core import InvalidData,canonical
from payproof.github_oidc import ISSUER,IdentityRefused,TransportUnknown
from payproof.bootstrap_bridge import ConsumerProvider,BootstrapBridge,_canonical,_sha1_object
from tools.read_pilot_driver import ReadPilotDriver
REPO='/repos/Elinfiny/PayProof'
ORDER='SYNTHETICEXISTINGORDER'
PUBLIC_KEY=b'PUBLIC_TEST_ONLY_HMAC_FIXTURE_29_000000000000'
SENTINEL='PUBLIC_SYNTHETIC_SECRET_DO_NOT_EXPORT'
COUNTS=[]
def deny(event,args):
    if event.startswith(('socket.','subprocess.')) or event in ('os.system','os.posix_spawn'):
        raise AssertionError('INERT_HARNESS_DENIES_NATIVE_IO')
    if event=='open' and args and isinstance(args[0],(str,bytes)):
        path=str(args[0])
        if path.startswith('/run/') or '/.env' in path or 'payproof_admission_key' in path:
            raise AssertionError('INERT_HARNESS_DENIES_HOST_FILE')
sys.addaudithook(deny)
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
            return self.reply(200, {'sha':sha, 'encoding':'base64', 'size':len(content),
                                   'content':base64.b64encode(content).decode()})
        raise AssertionError('Unplanned fake endpoint')



class Backend(FakeBackend):
    def __init__(self,clock):
        super().__init__(clock);self.closes=0;self.late=None;self.badparse=False
        self.source='a'*40;self.revision='c'*40;self.workflow=b'PUBLIC_SYNTHETIC_ONE_JOB_WORKFLOW'
        self.old=[];self.badjob=False;self.badregistry=False
        self.after_oauth=None;self.oauth_done=False;self.trace=[];self.ref_mutation=False;self.late_dynamic=False;self.unknown_dynamic=False
    def add_blob(self,raw):
        sha=_sha1_object('blob',raw);self.blobs[sha]=raw;return sha
    def tree(self,entries):
        sha=hashlib.sha1(b'SYNTHETIC_TREE'+_canonical(entries)).hexdigest()
        self.trees[sha]={'sha':sha,'tree':entries,'truncated':False};return sha
    def fixtures(self,registry):
        wf=self.add_blob(self.workflow)
        inn=self.tree([{'path':'payproof-read-pilot.yml','mode':'100644','type':'blob','sha':wf,'size':len(self.workflow)}])
        mid=self.tree([{'path':'workflows','mode':'040000','type':'tree','sha':inn}])
        source_dirs={}
        for row in admission.runtime_manifest():
            directory,filename=row['path'].split('/')
            content=(pathlib.Path(admission.__file__).parent.parent/row['path']).read_bytes()
            source_dirs.setdefault(directory,[]).append({'path':filename,'mode':'100644','type':'blob','sha':self.add_blob(content),'size':len(content)})
        root=self.tree([{'path':'.github','mode':'040000','type':'tree','sha':mid}]+[{'path':d,'mode':'040000','type':'tree','sha':self.tree(entries)} for d,entries in source_dirs.items()])
        self.commits[self.source]={'sha':self.source,'tree':{'sha':root}}
        rb=self.add_blob(_canonical(registry));rr=self.tree([{'path':'payproof-orders-registry.json','mode':'100644','type':'blob','sha':rb,'size':len(_canonical(registry))}])
        self.commits[self.revision]={'sha':self.revision,'tree':{'sha':rr}}
        return root
    def handle(self,method,path,raw):
        self.trace.append((method,path))
        if self.oauth_done and '/git/ref/tags/payproof-reservations/v2/' in path:
            if self.late_dynamic:self.clock.advance(301)
            if self.unknown_dynamic:return self.reply(503,{'message':'SYNTHETIC_UNKNOWN'})
            if self.ref_mutation:
                ref='refs/'+path.split('/git/ref/',1)[1]
                return self.reply(200,{'ref':ref,'object':{'sha':self.refs.get(ref),'type':'tag'}})
        if self.late=='reservation' and path==REPO+'/git/commits' and method=='POST': self.clock.advance(301)
        if path==REPO and method=='GET':
            return self.reply(200,{'id':1419908202,'private':True,'fork':False,'full_name':'Elinfiny/PayProof','owner':{'id':273768139}})
        if path==REPO+'/branches/main':return self.reply(200,{'commit':{'sha':self.source}})
        if path==REPO+'/actions/runs/123':return self.reply(200,{'id':123,'run_attempt':1,'head_sha':self.source,'event':'workflow_dispatch','actor':{'id':273768139},'head_repository':{'fork':False}})
        if path==REPO+'/actions/runs/123/attempts/1/jobs':return self.reply(200,{'total_count':1,'jobs':[{'id':999 if self.badjob else 456,'name':'read_only','run_id':123,'head_sha':self.source}]})
        if path==REPO+'/git/matching-refs/tags/payproof-reservations/v1/':return self.reply(200,self.old)
        if path.startswith('/v1/oauth2/') or path.startswith('/v2/checkout/'):
            if method=='POST':
                self.oauth_done=True
                if self.after_oauth:self.after_oauth()
            if self.late=='paypal':self.clock.advance(301)
            if self.badparse:return FakeResponse(200,b'not-json:'+SENTINEL.encode())
            return self.reply(200,{'access_token':'PUBLIC_SYNTHETIC_BEARER'} if method=='POST' else {'id':ORDER,'payer':{'private':SENTINEL}})
        result=super().handle(method,path,raw)
        if self.badregistry and path.startswith(REPO+'/git/blobs/') and SENTINEL not in str(path):
            return FakeResponse(200,b'{}')
        return result

class Factory(FakeHTTPS):
    def __call__(self,*a,**kw):
        c=super().__call__(*a,**kw);close=c.close
        def once():
            self.backend.closes+=1;return close()
        c.close=once;return c

class Consumer29Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ephemeral public-purpose fixture only; never passed to a production verifier.
        cls.rsa=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        num=lambda n:enc(n.to_bytes((n.bit_length()+7)//8,'big'))
        n=cls.rsa.public_key().public_numbers()
        cls.jwk={'kid':'SYNTHETIC','kty':'RSA','use':'sig','alg':'RS256','n':num(n.n),'e':num(n.e)}
    def setUp(self):
        self.clock=Clock();self.b=Backend(self.clock);self.b.jwks_raw=_canonical({'keys':[self.jwk]})
        self.now=int(time.time());sha=lambda v:hashlib.sha256(v).hexdigest()
        self.credentials={'client_id':'PUBLIC_SYNTHETIC_APP','client_secret':SENTINEL}
        app=sha(self.credentials['client_id'].encode());order=sha(ORDER.encode());key=admission.canonical_effect_key(app,order)
        oldsha=sha(_canonical([]))
        self.registry={'schema':'PAYPROOF_PREEXISTING_REGISTRY_V3','client_id_sha256':app,'order_id_sha256':order,
            'canonical_effect_key_sha256':key,'legacy_refs_sha256':oldsha,'legacy_grant_ids':[],
            'provenance':{'provider':'paypal','environment':'sandbox','receipt_sha256':'d'*64}}
        tree=self.b.fixtures(self.registry)
        manifest=admission.runtime_manifest()
        from datetime import datetime,timezone
        self.g={'schema':admission.V3_SCHEMA,'admission_id':'PUBLIC_SYNTHETIC_GRANT_29','project':'PayProof','environment':'sandbox',
            'source_sha256':admission.source_fingerprint(),'expires_at':datetime.fromtimestamp(self.now+240,timezone.utc).isoformat(),
            'operations':['orders:read'],'client_id_sha256':app,'external_budget_usd':'0.00','live_ai':False,
            'bundle_manifest':manifest,'bundle_sha256':sha(canonical(manifest).encode()),
            'caller':{'repository_id':'1419908202','owner_id':'273768139','actor':'Elinfiny','actor_id':'273768139','fork':False,'visibility':'private',
                'source_commit':'a'*40,'source_tree':tree,'workflow_path':'.github/workflows/payproof-read-pilot.yml',
                'workflow_sha256':sha(self.b.workflow),'run_id':'123','job_id':'456','job_name':'read_only','attempt':'1',
                'ref':'refs/heads/main','event':'workflow_dispatch','issuer':ISSUER,'audience':admission.V3_AUDIENCE,'not_before':self.now-10},
            'registry':{'provider':'github','revision':'c'*40,'path':'payproof-orders-registry.json','sha256':sha(_canonical(self.registry)),
                'order_id_sha256':order,'legacy_refs_sha256':oldsha},'canonical_effect_key_sha256':key,'legacy_grant_ids':[]}
        self.claims={'iss':ISSUER,'aud':admission.V3_AUDIENCE,'repository':'Elinfiny/PayProof','repository_id':'1419908202',
            'repository_owner_id':'273768139','repository_owner':'Elinfiny','repository_visibility':'private',
            'workflow_ref':'Elinfiny/PayProof/.github/workflows/payproof-read-pilot.yml@refs/heads/main',
            'workflow_sha':'a'*40,'ref':'refs/heads/main','sha':'a'*40,'event_name':'workflow_dispatch',
            'sub':'repo:Elinfiny@273768139/PayProof@1419908202:ref:refs/heads/main','run_id':'123','run_attempt':'1',
            'runner_environment':'github-hosted','ref_type':'branch','iat':self.now-5,'nbf':self.now-5,'exp':self.now+200,
            'jti':'PUBLIC_SYNTHETIC_JTI','actor':'Elinfiny','actor_id':'273768139'}
        self.native=patch('payproof.admission.load_host_context',side_effect=AssertionError('PRODUCTION_LOADER_DENIED'));self.native_mock=self.native.start();self.addCleanup(self.native.stop)
    def token(self,changes=None,corrupt=False):
        enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        a=enc(_canonical({'typ':'JWT','alg':'RS256','kid':'SYNTHETIC'}));b=enc(_canonical(self.claims|(changes or {})))
        signature=self.rsa.sign((a+'.'+b).encode(),padding.PKCS1v15(),hashes.SHA256())
        if corrupt:signature=bytes([signature[0]^1])+signature[1:]
        return a+'.'+b+'.'+enc(signature)
    def context(self,g=None,forge=False):
        g=g or self.g;sig=hmac.new(PUBLIC_KEY,canonical(g).encode(),hashlib.sha256).hexdigest()
        return admission.verify_consumer_for_test(_canonical({'grant':g,'signature':'0'*64 if forge else sig}),PUBLIC_KEY,_canonical(self.credentials))
    def provider(self,g=None):return ConsumerProvider.for_test(self.context(g),Factory(self.b),clock=self.clock)
    def no_paypal(self):self.assertFalse(any(h=='api-m.sandbox.paypal.com' for h,m,p in self.b.calls))
    def report(self,name):
        counts={'case':name,'GitHub':sum(h=='api.github.com' for h,m,p in self.b.calls),
            'JWKS':sum(h=='token.actions.githubusercontent.com' for h,m,p in self.b.calls),
            'OAuth':sum(h=='api-m.sandbox.paypal.com' and m=='POST' for h,m,p in self.b.calls),
            'orderGET':sum(h=='api-m.sandbox.paypal.com' and m=='GET' for h,m,p in self.b.calls),'closes':self.b.closes}
        COUNTS.append(counts);print('SYNTHETIC_CASE_COUNTS '+json.dumps(counts,sort_keys=True))
    def test_01_valid_shared_V3_chain_exact_fake_OAuth_GET(self):
        p=self.provider();out=p.consume(self.token(),ORDER)
        self.assertEqual(out['status'],'SYNTHETIC_RETURNED');self.assertEqual(out['transport_calls'],2)
        self.assertEqual(sum(h=='api-m.sandbox.paypal.com' and m=='POST' for h,m,r in self.b.calls),1)
        self.assertEqual(sum(h=='api-m.sandbox.paypal.com' and m=='GET' for h,m,r in self.b.calls),1)
        for private in (SENTINEL,ORDER,'PUBLIC_SYNTHETIC_BEARER',self.token()):self.assertNotIn(private,json.dumps(out))
        self.assertTrue(p.context.test_only);self.assertFalse(out['real_runtime_admitted'])
        trace=self.b.trace
        for route in ('/v1/oauth2/token','/v2/checkout/orders/'+ORDER):
            index=next(i for i,(_,path) in enumerate(trace) if path==route)
            self.assertIn('/git/ref/tags/payproof-reservations/v2/',trace[index-1][1])
            self.assertIn('/git/matching-refs/tags/payproof-reservations/v1/',trace[index-2][1])
        registry_revision='/git/commits/'+self.b.revision
        self.assertEqual(sum(path.endswith(registry_revision) for _,path in trace),1)
        self.assertLessEqual(p._wire.calls,64);self.assertLessEqual(p._reservation._wire.calls,10);self.assertEqual(p._jwks._wire.calls,1)
        self.report('01-valid-fresh-guards-before-BOTH-immutable-read-once')
    def test_02_wrong_signed_caller_and_signature_before_effect(self):
        for change in ({'repository_id':'1'},{'actor':'other'},{'aud':'other'},{'event_name':'push'},{'run_attempt':'2'},{'sha':'f'*40},{'exp':self.now-1},{'iss':'https://wrong.invalid'}):
            with self.subTest(change=change):
                with self.assertRaises(IdentityRefused):self.provider().consume(self.token(change),ORDER)
        with self.assertRaises(IdentityRefused):self.provider().consume(self.token(corrupt=True),ORDER)
        self.b.badjob=True
        with self.assertRaises(IdentityRefused):self.provider().consume(self.token(),ORDER)
        self.no_paypal();self.report('02-repo-actor-audience-event-attempt-source-expiry-issuer-signature-job')
    def test_03_forged_V2_missing_registry_app_digest_stale_manifest(self):
        for change in ({'schema':'PAYPROOF_SANDBOX_READ_ADMISSION_V2'},{'bundle_sha256':'f'*64},{'client_id_sha256':'f'*64},{'operations':['orders:create']},{'extra':True}):
            with self.subTest(change=change):
                with self.assertRaises((InvalidData,IdentityRefused)):self.context(self.g|change)
        with self.assertRaises(InvalidData):self.context(forge=True)
        for field in ('registry','caller','bundle_manifest'):
            bad=deepcopy(self.g);del bad[field]
            with self.assertRaises(InvalidData):self.context(bad)
        bad=deepcopy(self.g);bad['registry']['sha256']='f'*64
        with self.assertRaises(IdentityRefused):self.provider(bad).consume(self.token(),ORDER)
        self.b.badregistry=True
        with self.assertRaises(IdentityRefused):self.provider().consume(self.token(),ORDER)
        self.no_paypal();self.report('03-V2-forgery-missing-app-digest-manifest-registry')
    def test_04_canonical_spent_lineage_restart_and_race_loser(self):
        p=self.provider();p.consume(self.token(),ORDER);before=sum(h=='api-m.sandbox.paypal.com' for h,m,r in self.b.calls)
        g=self.g|{'admission_id':'PUBLIC_SYNTHETIC_NEW_GRANT'}
        self.assertEqual(self.context(g).grant['canonical_effect_key_sha256'],self.context().grant['canonical_effect_key_sha256'])
        with self.assertRaises(IdentityRefused):self.provider(g).consume(self.token(),ORDER)
        with self.assertRaises(IdentityRefused):p.consume(self.token(),ORDER)
        with self.assertRaises(IdentityRefused):self.provider().consume(self.token(),ORDER,restart=True)
        self.assertEqual(sum(h=='api-m.sandbox.paypal.com' for h,m,r in self.b.calls),before)
        for state in ('ATTEMPTING','UNKNOWN','CONSUMED'):
            self.b.old=[{'ref':'refs/tags/payproof-reservations/v1/'+('e'*64),'state':state}]
            with self.assertRaises(IdentityRefused):self.provider().consume(self.token(),ORDER)
        self.b.old=[];self.b.refs={};self.b.race_at_ref_create=True
        with self.assertRaises(IdentityRefused):self.provider().consume(self.token(),ORDER)
        self.assertEqual(sum(h=='api-m.sandbox.paypal.com' for h,m,r in self.b.calls),before);self.report('04-spent-newgrant-restart-legacy-UNKNOWN-ATTEMPTING-CONSUMED-race')
    def test_05_late_JWKS_reservation_PayPal_parse_and_cleanup_no_retry(self):
        modes=('jwks','reservation','paypal','parse','cleanup')
        for mode in modes:
            with self.subTest(mode=mode):
                self.setUp();p=self.provider()
                if mode=='jwks':self.b.jwks_late=True
                if mode in ('reservation','paypal'):self.b.late=mode
                if mode=='parse':self.b.badparse=True
                if mode=='cleanup':self.b.raise_commit=True;self.b.close_failure=True
                if mode in ('jwks','reservation','cleanup'):
                    with self.assertRaises(IdentityRefused):p.consume(self.token(),ORDER)
                    self.assertIsNotNone(p._first_unknown);self.no_paypal()
                else:
                    out=p.consume(self.token(),ORDER);self.assertEqual(out['status'],'UNKNOWN')
                    self.assertIsNotNone(out['first_unknown']);self.assertEqual(out['transport_calls'],1)
                wires=[p._jwks._wire,p._wire]+([p._reservation._wire] if p._reservation else [])
                self.assertTrue(any(w.originals for w in wires))
                if mode=='jwks':self.assertIs(p._jwks._wire.originals[0].value,self.b.responses[0])
                if mode=='cleanup':
                    self.assertTrue(any(x.error is self.b.primary_error for x in p._reservation._wire.originals))
                    self.assertTrue(any(x.error is self.b.cleanup_error for x in p._reservation._wire.originals))
                    self.assertEqual(p._first_unknown['code'],'HTTP_EXCEPTION')
                count=len(self.b.calls)
                with self.assertRaises(IdentityRefused):p.consume(self.token(),ORDER)
                self.assertEqual(len(self.b.calls),count);self.assertEqual(self.b.closes,len(self.b.calls));self.report('05-'+mode)
    def test_06_closed_default_TEST_ONLY_promotion_secret_diagnostic(self):
        fake=Mock(side_effect=AssertionError(SENTINEL))
        for alleged in (None,True,{'admitted':True,'uid':0},fake,self.context()):
            with self.assertRaises(IdentityRefused):BootstrapBridge(alleged).activate(self.token(),order_id=ORDER)
        with self.assertRaises(InvalidData):ConsumerProvider.from_host(self.context(),'PUBLIC_SYNTHETIC')
        with self.assertRaises(InvalidData):self.context().require(production=True)
        with self.assertRaises(InvalidData):ReadPilotDriver(future_runtime_verifier=fake).run(ORDER)
        fake.assert_not_called();self.native_mock.assert_not_called();self.no_paypal()
        self.assertNotIn(SENTINEL,repr(self.context()));self.report('06-unbound-test-only-JSON-flag-callback-UID-secret')


    def test_07_mutate_delete_replace_winner_after_OAuth_blocks_GET(self):
        for mode in ('mutate','delete','replace'):
            with self.subTest(mode=mode):
                self.setUp();p=self.provider()
                def change():
                    ref='refs/tags/payproof-reservations/v2/'+self.g['canonical_effect_key_sha256']
                    if mode=='delete':del self.b.refs[ref]
                    elif mode=='replace':self.b.refs[ref]='f'*40
                    else:self.b.ref_mutation=True
                self.b.after_oauth=change
                out=p.consume(self.token(),ORDER)
                self.assertEqual(out['status'],'UNKNOWN');self.assertIsNotNone(out['first_unknown'])
                self.assertTrue(p._reservation._consumed);self.assertTrue(p._driver._consumed)
                self.assertEqual(p._driver._reserved,2)
                self.assertTrue(any(x.value is not None and isinstance(x.value,dict) and x.value.get('access_token')=='PUBLIC_SYNTHETIC_BEARER' for x in p._driver._originals))
                self.assertEqual(sum(h=='api-m.sandbox.paypal.com' and m=='POST' for h,m,r in self.b.calls),1)
                self.assertEqual(sum(h=='api-m.sandbox.paypal.com' and m=='GET' for h,m,r in self.b.calls),0)
                self.assertEqual(sum(m=='POST' and path==REPO+'/git/refs' for h,m,path in self.b.calls),1)
                count=len(self.b.calls)
                with self.assertRaises(IdentityRefused):p.consume(self.token(),ORDER)
                self.assertEqual(len(self.b.calls),count);self.assertEqual(self.b.closes,len(self.b.calls))
                self.assertNotIn(SENTINEL,json.dumps(out));self.report('07-afterOAuth-'+mode)

    def test_08_fresh_legacy_unknown_late_after_OAuth_no_following_GET(self):
        for mode in ('legacy','unknown','late'):
            with self.subTest(mode=mode):
                self.setUp();p=self.provider()
                def change():
                    if mode=='legacy':self.b.old=[{'ref':'refs/tags/payproof-reservations/v1/'+('e'*64),'state':'UNKNOWN'}]
                    elif mode=='unknown':self.b.unknown_dynamic=True
                    else:self.b.late_dynamic=True
                self.b.after_oauth=change;out=p.consume(self.token(),ORDER)
                self.assertEqual(out['status'],'UNKNOWN');self.assertIsNotNone(out['first_unknown'])
                first=dict(out['first_unknown']);count=len(self.b.calls)
                self.assertTrue(p._reservation._consumed);self.assertEqual(p._driver._reserved,2)
                self.assertEqual(sum(h=='api-m.sandbox.paypal.com' and m=='POST' for h,m,r in self.b.calls),1)
                self.assertEqual(sum(h=='api-m.sandbox.paypal.com' and m=='GET' for h,m,r in self.b.calls),0)
                self.assertTrue(any(x.value is not None and isinstance(x.value,dict) and 'access_token' in x.value for x in p._driver._originals))
                if mode=='late':self.assertIsNotNone(p._wire.first_unknown)
                self.assertEqual(self.b.closes,len(self.b.calls));self.assertNotIn(SENTINEL,json.dumps(out))
                with self.assertRaises(IdentityRefused):p.consume(self.token(),ORDER)
                self.assertEqual(len(self.b.calls),count);self.assertEqual(p._driver.export()['first_unknown'],first)
                self.report('08-afterOAuth-'+mode)

if __name__=='__main__':unittest.main(verbosity=2)
