"""Changed integration paths only. No sockets/provider credentials/native grants.

All provider replies and signing keys below are newly generated synthetic data.
Native entrypoint calls are isolated with doubles; no listener is opened.
"""
import base64,contextlib,copy,io,json,os,pathlib,socket,subprocess,tempfile,time,unittest,zlib
from datetime import datetime,timedelta,timezone
from unittest.mock import patch,Mock
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from payment186 import common as c, state as st, client,worker,chain,native_ports,server,oidc
from payment186.signature import SyntheticSignature152

PKG=pathlib.Path(c.__file__).parent
def enc(b):return base64.b64encode(b).decode()
def grant():
    now=int(time.time());source=c.source_binding()
    return dict(schema='OWNER_PAYMENT186_ONCE',owner_request='00000000-0000-4000-8000-000000000186',source_sha256=source,workflow_sha='a'*40,run_id='123186',start_at=now-1,expires_at=now+599,limits=copy.deepcopy(c.LIMITS),buyer_pairing='PUBLIC_SHA_NATIVE_BIND_ONCE',master_receipt={'version':187,'raw_sha256':'c'*64,'self_sha256':'d'*64},proposal_sha256=c.sha(c.canonical(c.proposal(source))))
def body(op,raw,status=200):return {'operation':op,'status':status,'raw_base64':enc(raw)}
def slot(g,op,path='/synthetic'):
    return {'key':c.once_prefix(g)+':'+op,'metadata':{'profile':chain.PROFILE,'app_sha256':st.APP,'source_sha256':c.engine_source(g),'caller':c.caller(g),'target_sha256':c.sha(path.encode()),'operation':op,'fake_usd':'1.00','real_usd':'0.00','expires_at':g['expires_at']}}
def recipient(s):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    der=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    s.bind_recipient({'public_key_der':enc(der)},'b'*64);c.write_once(s.root/'BROWSER_ADMITTED.json',c.canonical({'pairing_sha256':s.pairing,'grant_sha256':c.sha(c.canonical(s.g))}));return key
def webhook():return {'id':'SYNTHETIC-HOOK186','url':'https://'+c.HOST+'/webhooks/payproof186','event_types':[{'name':'PAYMENT.CAPTURE.COMPLETED'}]}
def order(completed=False,approved=False):
    amount={'value':'1.00','currency_code':'USD'};unit={'amount':amount}
    if completed:unit['payments']={'captures':[{'id':'SYNTHETIC-CAPTURE186','status':'COMPLETED','amount':amount}]}
    return {'id':'SYNTHETIC-ORDER186','status':'COMPLETED' if completed else 'APPROVED' if approved else 'CREATED','purchase_units':[unit],'update_time':datetime.now(timezone.utc).isoformat(),'links':[{'rel':'approve','href':'https://www.sandbox.paypal.com/checkoutnow?token=SYNTHETIC-ORDER186'}]}
def signature_fixture():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=datetime.now(timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SYNTHETIC ONLY')])
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(186).not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(hours=1)).sign(key,hashes.SHA256())
    url='https://api.sandbox.paypal.com/v1/notifications/certs/SYNTHETIC186'
    raw=c.canonical({'id':'SYNTHETIC-EVENT186','event_type':'PAYMENT.CAPTURE.COMPLETED','resource':{'id':'SYNTHETIC-CAPTURE186','status':'COMPLETED','amount':{'value':'1.00','currency_code':'USD'},'supplementary_data':{'related_ids':{'order_id':'SYNTHETIC-ORDER186'}}}})
    stamp=now.isoformat();tid='SYNTHETIC-TX186';message=(tid+'|'+stamp+'|SYNTHETIC-HOOK186|'+str(zlib.crc32(raw)&0xffffffff)).encode()
    headers={'paypal-auth-algo':'SHA256withRSA','paypal-cert-url':url,'paypal-transmission-id':tid,'paypal-transmission-time':stamp,'paypal-transmission-sig':enc(key.sign(message,padding.PKCS1v15(),hashes.SHA256()))}
    return SyntheticSignature152('SYNTHETIC-HOOK186',{url:cert}),headers,raw

class Base(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.root.chmod(0o700)
        self.addCleanup(patch.stopall)
        patch.object(socket.socket,'connect',side_effect=AssertionError('NETWORK_FORBIDDEN')).start()
        self.g=grant();self.s=st.State(self.root,self.g)
    def store_original(self,op,raw):
        self.s.reserve(slot(self.g,op));return self.s.retain_result(body(op,c.canonical(raw)))
    def ready_order(self):
        key=recipient(self.s);self.store_original('subscription_create',webhook());self.s.bind_webhook({'webhook_id':webhook()['id']})
        self.store_original('order_create',order());self.s.bind_order({'order_id':order()['id'],'approval_url':order()['links'][0]['href']});return key
class OfflineCase(Base):
    def test_exact_proposal_and_budget_reject_drift(self):
        c.validate_grant(self.g,time.time(),c.source_binding())
        for field,value in [('proposal_sha256','0'*64),('source_sha256','1'*64),('run_id','0'),('expires_at',self.g['expires_at']+1),('limits',{})]:
            with self.subTest(field=field),self.assertRaises(Exception):c.validate_grant(dict(self.g,**{field:value}),time.time(),c.source_binding())
    def test_once_before_io_and_result_ack_after_readback(self):
        recipient(self.s);r=self.s.reserve(slot(self.g,'oauth'));self.assertEqual(r['state'],'CONSUMED');self.assertTrue((self.root/'SLOT_oauth.json').is_file())
        with self.assertRaises(Exception):self.s.reserve(slot(self.g,'oauth'))
        self.s.retain_result(body('oauth',b''));self.assertEqual((self.root/'HTTP_oauth.bin').read_bytes(),b'')
    def test_fsync_failure_consumes_no_ack_no_repeat(self):
        recipient(self.s)
        with patch('os.fsync',side_effect=OSError('synthetic disk error')),self.assertRaises(OSError):self.s.reserve(slot(self.g,'oauth'))
        with self.assertRaises(Exception):self.s.reserve(slot(self.g,'oauth'))
        self.assertTrue((self.root/'SLOT_oauth.json').exists())
    def test_secret_and_unbound_ids_refused(self):
        with self.assertRaises(Exception):self.s.bind_webhook({'webhook_id':'UNKNOWN-HOOK'})
        self.s.reserve(slot(self.g,'order_create'))
        with self.assertRaises(Exception):self.s.retain_result(body('order_create',b'{"access_token":"SYNTHETIC"}'))
        self.assertFalse((self.root/'HTTP_order_create.bin').exists())
    def test_browser_capability_and_expiry(self):
        recipient(self.s)
        self.s.browser_auth('b'*64)
        with self.assertRaises(Exception):self.s.browser_auth('c'*64)
        self.s.clock=lambda:self.g['expires_at']
        with self.assertRaises(Exception):self.s.browser_auth('b'*64)
    def test_unpaired_browser_cannot_release_payment_authority(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048);der=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.s.bind_recipient({'public_key_der':enc(der)},'b'*64);self.assertFalse(self.s.browser_ready())
        with self.assertRaises(Exception):self.s.reserve(slot(self.g,'oauth'))
        c.write_once(self.root/'ADMISSION.json',c.canonical(self.g))
        with patch.object(server,'ROOT',self.root),patch.object(server,'host'):
            with self.assertRaises(Exception):server.pair('e'*64)
            server.pair(self.s.pairing)
            with self.assertRaises(FileExistsError):server.pair(self.s.pairing)
        self.assertTrue(self.s.browser_ready());self.s.reserve(slot(self.g,'oauth'))
    def test_python_encrypt_node_webcrypto_decrypt_and_negative_bindings(self):
        key=self.ready_order();binding=self.s.recipient[1]
        private=key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        payload={'raw':enc(self.s.wire),'binding':binding,'sha256':c.sha(self.s.wire),'private':enc(private)}
        result=subprocess.run(['node',str(PKG.parent/'tests/browser_crypto186.cjs'),str(PKG/'buyer.js')],input=json.dumps(payload),text=True,capture_output=True,check=True,timeout=20)
        self.assertEqual(json.loads(result.stdout),{'valid':True,'negative_cases':6,'browser_public_export':True,'private_export_refused':True})
        self.assertEqual((self.root/'buyer-envelope.bin').read_bytes(),self.s.wire)
    def test_local_signature_original_before_ack_and_duplicate(self):
        self.ready_order();self.s.signature,headers,raw=signature_fixture()
        reply=self.s.webhook_event(headers,raw);self.assertEqual(reply['state'],'DURABLE_BEFORE_ACK');self.assertEqual((self.root/'WEBHOOK.bin').read_bytes(),raw)
        self.assertEqual(self.s.webhook_event(headers,raw)['state'],'DUPLICATE_RETAINED')
        with self.assertRaises(Exception):self.s.webhook_event(headers,raw.replace(b'SYNTHETIC-ORDER186',b'SYNTHETIC-ORDER187'))
    def test_close_even_when_custody_disk_fails(self):
        recipient(self.s)
        with patch.object(self.s,'save',side_effect=OSError()),self.assertRaises(OSError):self.s.close('SYNTHETIC')
        self.assertTrue(self.s.closed);self.assertTrue(self.s.stop.is_set());self.assertIsNone(self.s.recipient)
        with self.assertRaises(Exception):self.s.browser_auth('b'*64)
    def test_completed_report_without_evidence_refused(self):
        with self.assertRaises(Exception):self.s.terminal_report(dict(state='COMPLETED',provider_slots={},bridge_unknown=False,cleanup='PRESERVED_EXISTING',order_sha256=None,capture_sha256=None))
    def test_unknown_api_allows_only_dedicated_terminal(self):
        api=client.API('SYNTHETIC',time.time()+30)
        with patch.object(client,'https',side_effect=TimeoutError()),self.assertRaises(c.UnknownResult):api.call('order',{})
        with self.assertRaises(Exception):api.call('order',{})
        report={'state':'UNKNOWN'};raw=c.canonical(report)
        with patch.object(client,'https',return_value=(200,raw,c.sha(raw))) as transport:self.assertEqual(api.call('terminal',report,terminal=True),report);self.assertEqual(transport.call_count,1)
        with self.assertRaises(Exception):api.call('terminal',report,terminal=True)
    def test_native_initialization_failure_closes_without_socket(self):
        c.write_once(self.root/'ADMISSION.json',c.canonical(self.g))
        with patch.object(server,'ROOT',self.root),patch.object(server,'host'),patch.object(server,'https',side_effect=TimeoutError()),patch.object(server,'Server') as listener,contextlib.redirect_stdout(io.StringIO()):result=server.native()
        self.assertEqual(result,1);listener.assert_not_called();self.assertEqual(c.obj((self.root/'NATIVE_RESULT.json').read_bytes())['closed'],True)
        self.assertEqual(c.obj((self.root/'CLOSED.json').read_bytes())['state'],'ACCESS_CLOSED')
    def test_listener_close_survives_shutdown_and_custody_errors(self):
        listener=Mock();thread=Mock();thread.is_alive.side_effect=[True,False];listener.socket.fileno.return_value=-1;listener.shutdown.side_effect=RuntimeError('synthetic')
        self.assertTrue(server.close_access(listener,thread));listener.server_close.assert_called_once();thread.join.assert_called_once_with(6)
        listener=Mock();listener.socket.fileno.return_value=-1
        self.assertTrue(server.close_access(listener,None));listener.server_close.assert_called_once()
    def test_python_syntax_workflow_guard_and_product_pins(self):
        import ast,yaml
        for path in PKG.glob('*.py'):ast.parse(path.read_text())
        workflow=yaml.safe_load((PKG.parent/'workflow_candidates/payproof-payment186.yml.disabled').read_text())
        job=workflow['jobs']['payment186'];self.assertIs(job['if'],False);self.assertEqual(job['timeout-minutes'],10);self.assertEqual(job['environment'],'payproof-sandbox-readonly')
        self.assertNotIn('env',job);self.assertNotIn('PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET',str(job['steps'][-2]));self.assertEqual(workflow['concurrency']['cancel-in-progress'],False)
        import payproof
        base=pathlib.Path(payproof.__file__).parent.parent
        for name,digest in c.obj((PKG/'manifest.json').read_bytes())['accepted_payproof_files'].items():self.assertEqual(c.sha((base/name).read_bytes()),digest)
        raw=(PKG.parent/'workflow_candidates/payproof-payment186.yml.disabled').read_bytes();manifest=c.obj((PKG/'manifest.json').read_bytes())
        self.assertEqual(raw.count(b'    if: false\n'),1);self.assertEqual(c.sha(raw.replace(b'    if: false\n',b'    if: true\n')),manifest['workflow_active_sha256'])
    def test_browser_flow_dom_contract(self):
        result=subprocess.run(['node',str(PKG.parent/'tests/browser_flow186.cjs'),str(PKG/'buyer.js')],text=True,capture_output=True,check=True,timeout=20)
        self.assertEqual(json.loads(result.stdout),dict(cases=4,capability_removed=True,automatic_transfer=True,no_retries=True,closure=True))

class EndToEnd(Base):
    def run_flow(self,fail=None,existing=False,approved=True):
        native=self.root/'native';native.mkdir(mode=0o700);runtime=self.root/'payment186';runtime.mkdir(mode=0o700)
        g=self.g;s=st.State(native,g);key=recipient(s);s.signature,headers,eventraw=signature_fixture();c.write_once(runtime/'PREFLIGHT.json',c.canonical(g))
        provider_calls=[];bridge_calls=[];completed=False;final_order=None
        fake_client='SYNTHETIC-CLIENT186';app=c.sha(fake_client.encode())
        def provider(_self,method,path,headers_,body_,timeout):
            nonlocal completed,final_order
            provider_calls.append((method,path))
            if fail=='provider_capture' and path.endswith('/capture'):raise TimeoutError('synthetic response lost')
            if path=='/v1/oauth2/token':row={'access_token':'SYNTHETIC-TOKEN186','expires_in':500}
            elif path=='/v1/notifications/webhooks' and method=='GET':row={'webhooks':[webhook()] if existing else []}
            elif path=='/v1/notifications/webhooks' and method=='POST':row=webhook()
            elif method=='DELETE':
                if fail=='cleanup':raise TimeoutError('synthetic delete response lost')
                return 204,b''
            elif path=='/v2/checkout/orders' and method=='POST':row=order()
            elif path.endswith('/capture'):
                completed=True;final_order=order(completed=True);row=final_order;s.webhook_event(headers,eventraw)
            elif path=='/v1/notifications/verify-webhook-signature':row={'verification_status':'SUCCESS'}
            elif path.endswith('/SYNTHETIC-ORDER186'):row=final_order if completed else order(approved=approved)
            else:raise AssertionError('UNEXPECTED_ROUTE')
            return 200,c.canonical(row)
        def bridge(host,path,method='GET',body=b'',headers_=None,**kwargs):
            # API passes headers positionally. No credentials are persisted here.
            name=path.rsplit('/',1)[-1];bridge_calls.append(name);row=c.obj(body) if body else None;s.require()
            if name=='grant':out=g
            elif name=='ready':out={'recipient_ready':True,'grant_sha256':c.sha(c.canonical(g)),'transport_ok':True}
            elif name=='buyer':out={'acknowledged':s.buyer_ack}
            elif name=='event':out=s.event
            else:
                fn={'reserve':s.reserve,'result':s.retain_result,'webhook':s.bind_webhook,'order':s.bind_order,'ai':s.ai,'terminal':s.terminal_report}[name]
                out=fn(row)
                if name=='order':
                    from payment186.envelope import unpack
                    cipher=unpack(s.wire,s.recipient[1],c.sha(s.wire),time.time());url=key.decrypt(cipher,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)).decode();self.assertEqual(url,order()['links'][0]['href'])
                    s.acknowledge_buyer({'order_id':order()['id'],'file_sha256':c.sha(s.wire)})
                if fail=='result_ack_lost' and name=='result' and row['operation']=='order_create':raise TimeoutError('synthetic saved ACK lost')
            raw=c.canonical(out);return 200,raw,c.sha(raw)
        env={'RUNNER_TEMP':str(self.root),'PAYMENT186_OWNER_REQUEST':g['owner_request'],'PAYMENT186_START_EPOCH':str(g['start_at']),'PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID':fake_client,'PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET':'SYNTHETIC-SECRET186'}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,env));stack.enter_context(patch.object(worker,'token',return_value='SYNTHETIC-OIDC'))
            for module in (native_ports,chain,st,worker):stack.enter_context(patch.object(module,'APP',app))
            for module in (native_ports,client):stack.enter_context(patch.object(module,'actual',return_value=(g['workflow_sha'],g['run_id'])))
            stack.enter_context(patch.object(client,'https',side_effect=bridge));stack.enter_context(patch.object(chain.FixedSandboxNetwork151,'request',autospec=True,side_effect=provider))
            out=stack.enter_context(contextlib.redirect_stdout(io.StringIO()));status=worker.execute()
        s.close('SYNTHETIC_TEST_END');report=c.obj((runtime/'RESULT.json').read_bytes())
        self.assertNotIn('SYNTHETIC-SECRET186',out.getvalue());self.assertNotIn('SYNTHETIC-TOKEN186',out.getvalue());self.assertTrue(s.closed)
        return status,report,provider_calls,bridge_calls,native
    def test_complete_one_order_capture_signature_local_ai_cleanup(self):
        code,r,calls,bridges,native=self.run_flow();self.assertEqual((code,r['state'],r['cleanup']),(0,'COMPLETED','DELETED_NEW'));self.assertEqual(len(calls),10)
        self.assertTrue(c.obj((native/'AI.json').read_bytes())['order']['local_assistance']['model_ready']);self.assertTrue((native/'BOUND_CAPTURE.json').is_file());self.assertEqual(bridges.count('terminal'),1)
    def test_existing_subscription_never_deleted(self):
        code,r,calls,_,_=self.run_flow(existing=True);self.assertEqual(code,0);self.assertEqual(r['cleanup'],'PRESERVED_EXISTING');self.assertFalse(any(m=='DELETE' for m,p in calls));self.assertEqual(len(calls),8)
    def test_missing_real_approval_never_capture(self):
        code,r,calls,_,_=self.run_flow(approved=False);self.assertEqual(code,1);self.assertFalse(any(p.endswith('/capture') for m,p in calls));self.assertEqual(r['cleanup'],'DELETED_NEW')
    def test_saved_response_ack_lost_preserved_no_replay(self):
        code,r,calls,bridges,native=self.run_flow(fail='result_ack_lost');self.assertEqual(code,1);self.assertEqual(r['state'],'UNKNOWN');self.assertTrue((native/'HTTP_order_create.bin').is_file());self.assertEqual(calls.count(('POST','/v2/checkout/orders')),1);self.assertNotIn('order',bridges);self.assertEqual(bridges.count('terminal'),1);self.assertEqual(r['cleanup'],'DELETED_NEW')
    def test_capture_unknown_no_retry_but_cleanup_once(self):
        code,r,calls,_,_=self.run_flow(fail='provider_capture');self.assertEqual(code,1);self.assertEqual(sum(p.endswith('/capture') for m,p in calls),1);self.assertEqual(sum(m=='DELETE' for m,p in calls),1)
    def test_cleanup_unknown_never_repeat(self):
        code,r,calls,_,_=self.run_flow(fail='cleanup');self.assertEqual(code,1);self.assertEqual(r['cleanup'],'UNKNOWN_NO_RETRY');self.assertEqual(sum(m=='DELETE' for m,p in calls),1)

class OIDC(Base):
    def test_exact_signed_identity_and_negative_claims(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048);pub=key.public_key().public_numbers();now=int(time.time())
        b64=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        jwks=c.canonical({'keys':[{'kid':'SYNTHETIC186','kty':'RSA','alg':'RS256','use':'sig','n':b64(pub.n.to_bytes(256,'big')),'e':b64(pub.e.to_bytes(3,'big'))}]})
        claims=dict(iss=c.ISSUER,aud=c.AUDIENCE,repository=c.REPO,repository_id=c.REPO_ID,repository_owner='Elinfiny',repository_owner_id=c.OWNER_ID,repository_visibility='public',actor='Elinfiny',actor_id=c.OWNER_ID,workflow_ref=c.WORKFLOW,workflow_sha=self.g['workflow_sha'],sha=self.g['workflow_sha'],ref='refs/heads/main',ref_type='branch',event_name='workflow_dispatch',run_id=self.g['run_id'],run_attempt='1',runner_environment='github-hosted',sub='repo:'+c.REPO+':environment:payproof-sandbox-readonly',iat=now,nbf=now,exp=now+300,jti='SYNTHETIC186')
        def token(row):
            message=b64(c.canonical({'typ':'JWT','alg':'RS256','kid':'SYNTHETIC186'}))+'.'+b64(c.canonical(row));return message+'.'+b64(key.sign(message.encode(),padding.PKCS1v15(),hashes.SHA256()))
        self.assertEqual(len(oidc.verify_oidc(token(claims),jwks,self.g,now)),64)
        for field,value in [('run_id','999'),('run_attempt','2'),('workflow_sha','f'*40),('aud','other'),('sub','repo:'+c.REPO+':ref:refs/heads/main'),('repository_id','9'),('exp',now),('actor_id','9')]:
            with self.subTest(field=field),self.assertRaises(Exception):oidc.verify_oidc(token(dict(claims,**{field:value})),jwks,self.g,now)

if __name__=='__main__':unittest.main()
