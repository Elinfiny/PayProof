"""Only new153 interfaces; real loopback TLS fixtures, zero external network."""
import base64,copy,hashlib,io,json,os,pathlib,ssl,tempfile,threading,time,unittest
from datetime import datetime,timedelta,timezone
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from cryptography.x509.oid import NameOID
from payproof.core import Store
from tools.sandbox_chain151 import APP,InvalidData,UnknownResult
from tools.sandbox_native152 import SyntheticProviderEvidence152
from tools.sandbox_bridge153 import Scope153,Capability153,Receiver153,EventInbox151,PRIVATE,WEBHOOK,ManagedIngress153
from tools.sandbox_bridge_client153 import BridgeClient153,SyntheticBridgeTransport153,FixedBridgeHTTPS153
from tools.sandbox_receiver153 import Server153,serve153
from tools.sandbox_worker153 import run_chain153,await_witness153,WitnessAbsent153,PollWitness153
from tools.sandbox_ingress152 import SyntheticSignature152
from test_sandbox_chain151 import SandboxChain151Tests

TEST_TOKEN='SYNTHETIC-ONLY-153-NOT-A-REAL-TOKEN-AAAAAAAAAAA'
class Bridge153Tests(unittest.TestCase):
 def setUp(self):
  self.f=SandboxChain151Tests('test02_native_default_and_synthetic_network_refused');self.f.setUp();self.addCleanup(self.f.doCleanups);self.now=[time.time()];self.scope=Scope153('a'*40,'P153-SYNTHETIC',self.f.grant.app_sha256,'https://payproof153-synthetic.onrender.com','srv-synthetic153000',self.now[0]-1,self.now[0]+500,True)
  import dataclasses
  self.f.url=self.scope.origin+WEBHOOK;self.f.grant=dataclasses.replace(self.f.grant,listener_url=self.f.url)
  self.cap=Capability153(self.scope,TEST_TOKEN,clock=lambda:self.now[0]);self.inbox=EventInbox151(self.f.root/'bridge153.sqlite');self.receiver=Receiver153(self.cap,self.inbox);self.transport=SyntheticBridgeTransport153(self.receiver);self.client=BridgeClient153(self.scope,TEST_TOKEN,'41099999999',self.transport,clock=lambda:self.now[0],sleeper=lambda n:None)
 def headers(self,body=b'',token=TEST_TOKEN):return {'host':self.scope.origin[8:],'authorization':'Bearer '+token,'x-payproof-source':self.scope.source,'x-payproof-session':self.scope.session,'x-payproof-service':self.scope.service_id,'x-payproof-run':'41099999999','content-length':str(len(body))}
 def call(self,path,body=b'',method='POST',headers=None):return self.receiver.handle(method,PRIVATE+'/'+path,list((headers or self.headers(body)).items()),body)
 def bootstrap(self):self.client.readiness();self.client.bootstrap()
 def prepare_engine(self):
  c=self.f.start();c.oauth();c.subscription();c.bind_evidence(SyntheticProviderEvidence152(c));return c
 def signed(self,raw=None):
  import zlib
  raw=raw or self.f.event();now=datetime.now(timezone.utc);key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SYNTHETIC153')]);cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(2).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(minutes=10)).sign(key,hashes.SHA256());h=self.f.headers();h['paypal-transmission-time']=now.isoformat();h['paypal-cert-url']='https://api.sandbox.paypal.com/v1/notifications/certs/SYNTHETIC153';m=(h['paypal-transmission-id']+'|'+h['paypal-transmission-time']+'|FAKE-HOOK|'+str(zlib.crc32(raw)&0xffffffff)).encode();h['paypal-transmission-sig']=base64.b64encode(key.sign(m,padding.PKCS1v15(),hashes.SHA256())).decode();self.receiver.signature=SyntheticSignature152('FAKE-HOOK',{h['paypal-cert-url']:cert});return raw,h
 def public_event(self,raw,h):return self.receiver.handle('POST',WEBHOOK,list(dict(h,host=self.scope.origin[8:],**{'content-type':'application/json','content-length':str(len(raw))}).items()),raw)
 def ready_order(self):self.bootstrap();raw,h=self.signed();self.client.webhook('FAKE-HOOK');self.client.order('ORDER151','https://www.sandbox.paypal.com/checkoutnow?token=ORDER151');return raw,h
 def test01_wrong_token_before_raw_access(self):
  with self.assertRaisesRegex(InvalidData,'PRIVATE_AUTH'):self.call('event',b'',method='GET',headers=self.headers(token='X'*43))
  self.assertEqual(self.receiver.raw_reads,0)
 def test02_expired_capability_before_any_store_or_request(self):
  self.now[0]=self.scope.expires_at
  with self.assertRaisesRegex(InvalidData,'EXPIRED'):self.client.readiness()
  self.assertEqual(self.transport.calls,[])
 def test03_source_session_service_and_run_mismatch(self):
  self.bootstrap()
  for k,v in [('x-payproof-source','b'*40),('x-payproof-session','P153-OTHER'),('x-payproof-service','srv-other153000'),('x-payproof-run','41099999998')]:
   h=self.headers();h[k]=v
   with self.subTest(key=k),self.assertRaises(InvalidData):self.call('event',method='GET',headers=h)
  self.assertEqual(self.receiver.raw_reads,0)
 def test04_bootstrap_once_and_bound_identity(self):
  self.bootstrap();self.assertEqual(self.receiver.run_id,self.client.run_id)
  with self.assertRaises(InvalidData):self.call('bootstrap',json.dumps({'bad':'payload'}).encode())
  self.assertEqual(self.receiver.counts['bootstrap'],1)
 def test05_bootstrap_before_webhook_order_and_poll(self):
  with self.assertRaises(InvalidData):self.call('webhook',b'{"webhook_id":"FAKE-HOOK"}')
  self.assertIsNone(self.receiver.webhook_id)
 def test06_order_bind_once_before_buyer(self):
  self.ready_order()
  with self.assertRaises(InvalidData):self.call('order',json.dumps({'order_id':'ORDER152','approval_url':'https://www.sandbox.paypal.com/checkoutnow?token=ORDER152'}).encode())
  self.assertEqual(self.receiver.order_id,'ORDER151')
 def test07_real_consumer_or_unrelated_approval_link_refused(self):
  self.bootstrap();self.client.webhook('FAKE-HOOK')
  for u in ['https://www.paypal.com/checkoutnow?token=ORDER151','https://www.sandbox.paypal.com/checkoutnow?token=OTHER','https://www.sandbox.paypal.com.evil.invalid/checkoutnow?token=ORDER151']:
   raw=json.dumps({'order_id':'ORDER151','approval_url':u}).encode()
   with self.assertRaises(InvalidData):self.call('order',raw)
  self.assertIsNone(self.receiver.order_id)
 def test08_unrelated_order_does_not_consume_legitimate_inbox(self):
  raw,h=self.ready_order();bad=raw.replace(b'ORDER151',b'OTHER151')
  with self.assertRaisesRegex(InvalidData,'WRONG_ORDER'):self.public_event(bad,h)
  self.assertFalse(self.receiver._has_event());self.assertEqual(self.public_event(raw,h)[0],202)
 def test09_invalid_signature_does_not_consume_legitimate_slot(self):
  raw,h=self.ready_order();bad=dict(h,**{'paypal-transmission-sig':base64.b64encode(b'X'*256).decode()})
  self.assertEqual(self.public_event(raw,bad)[0],400);self.assertFalse(self.receiver._has_event());self.assertEqual(self.public_event(raw,h)[0],202)
 def test10_exact_original_bytes_and_signature_headers_transfer(self):
  raw,h=self.ready_order();self.assertEqual(self.public_event(raw,h)[0],202);got_h,got_raw=self.client.event();self.assertEqual(got_raw,raw);self.assertEqual(got_h,h)
 def test11_duplicate_ack_only_after_retention_and_no_second_row(self):
  raw,h=self.ready_order();self.assertEqual(self.public_event(raw,h)[0],202);r=self.public_event(raw,h);self.assertEqual(json.loads(r[1])['state'],'DUPLICATE_RETAINED')
  import sqlite3
  with sqlite3.connect(self.inbox.path) as db:self.assertEqual(db.execute('SELECT count(*) FROM inbox').fetchone()[0],1)
 def test12_event_before_capture_return_complete_private_end_to_end(self):
  c=self.prepare_engine();raw,h=self.signed();store=Store(self.f.root/'private-e2e153.sqlite');original=c.transport.request;received=[]
  def request(method,path,headers,body,timeout):
   if path=='/v2/checkout/orders/ORDER151/capture':received.append(self.public_event(raw,h)[0]);self.assertIsNone(c.capture_id)
   return original(method,path,headers,body,timeout)
  def buyer(b):b._call('buyer-ack','POST',{})
  with patch.object(c.transport,'request',side_effect=request):result=run_chain153(c,self.client,store,approval_handoff=buyer)
  self.assertEqual(received,[202]);self.assertTrue(c.verified_complete);self.assertTrue(c.closed);self.assertTrue(self.client.closed);self.assertEqual(store.order('ORDER151')['state'],'COMPLETED');self.assertEqual(self.receiver.report['state'],'COMPLETED');self.assertEqual(c.used['verify'],1);self.assertEqual(c.used['event_read'],1);self.assertEqual(c.used['capture'],1);self.assertEqual(c.used['oauth'],1);self.assertEqual(c.used['subscription_delete'],1)
 def test13_missing_event_finite_readonly_poll_not_success(self):
  self.ready_order()
  with self.assertRaisesRegex(InvalidData,'NO_EVENT'):self.client.poll_event()
  self.assertEqual(self.client.counts['event'],24);self.assertEqual(self.receiver.raw_reads,24);self.assertIsNone(self.receiver.report)
 def test14_buyer_ack_not_provider_proof_and_poll_bound(self):
  self.ready_order()
  with self.assertRaisesRegex(InvalidData,'BUYER_NOT_ACKNOWLEDGED'):self.client.await_buyer()
  self.assertEqual(self.client.counts['buyer-status'],60);self.assertIsNone(self.receiver.report)
 def test15_unknown_config_response_consumed_no_replay(self):
  with patch.object(self.transport,'request',side_effect=TimeoutError('private transport diagnostic')):
   with self.assertRaises(UnknownResult):self.client.bootstrap()
  self.assertEqual(self.client.counts['bootstrap'],1)
  with self.assertRaises(UnknownResult):self.client.bootstrap()
  self.assertEqual(self.client.counts['bootstrap'],1)
 def test16_busy503_no_event_consumption(self):
  self.receiver.lock.acquire()
  try:self.assertEqual(self.receiver.handle('POST',WEBHOOK,[],b'')[0],503)
  finally:self.receiver.lock.release()
  self.assertFalse(self.receiver._has_event())
 def test17_native_and_fake_network_boundaries(self):
  with self.assertRaisesRegex(InvalidData,'FAKE_NEVER_HTTPS'):FixedBridgeHTTPS153(self.scope)
  with self.assertRaisesRegex(InvalidData,'INACTIVE'):ManagedIngress153.native({}, {})
  with self.assertRaisesRegex(InvalidData,'INACTIVE'):await_witness153('.')
 def test18_no_unauthenticated_raw_or_public_payment_routes(self):
  for path in ['/raw','/capture','/orders',WEBHOOK+'?token=bad',PRIVATE+'/event?token=bad']:
   with self.assertRaises(InvalidData):self.receiver.handle('GET',path,[('host',self.scope.origin[8:])],b'')
  self.assertEqual(self.receiver.raw_reads,0)
 def test19_wrong_host_duplicate_headers_xfp_not_authority(self):
  raw,h=self.ready_order()
  with self.assertRaises(InvalidData):self.receiver.handle('POST',WEBHOOK,[('host','evil.invalid'),('x-forwarded-proto','https')],raw)
  with self.assertRaises(InvalidData):self.receiver.handle('GET',PRIVATE+'/event',list(self.headers().items())+[('authorization','Bearer '+TEST_TOKEN)],b'')
 def test20_report_no_arbitrary_secret_fields_or_values(self):
  self.bootstrap()
  bad={'state':'COMPLETED','token':TEST_TOKEN}
  with self.assertRaisesRegex(InvalidData,'SANITIZED'):self.call('report',json.dumps(bad).encode())
  self.assertNotIn(TEST_TOKEN,json.dumps(self.receiver.export()));self.assertNotIn(TEST_TOKEN,repr(self.cap))
 def test21_close_purges_private_bytes_and_token_no_reset(self):
  raw,h=self.ready_order();self.public_event(raw,h);self.assertTrue(pathlib.Path(self.inbox.path).exists());self.client.close_remote();self.assertFalse(pathlib.Path(self.inbox.path).exists());self.assertTrue(self.receiver.closed);self.assertEqual(self.cap._token,b'')
  with self.assertRaises(InvalidData):self.receiver.handle('GET',PRIVATE+'/event',list(self.headers().items()),b'')
 def test22_expiry_during_private_return_freezes_dependencies(self):
  old=self.transport.request
  def late(*a):r=old(*a);self.now[0]=self.scope.expires_at;return r
  with patch.object(self.transport,'request',side_effect=late):
   with self.assertRaises(UnknownResult):self.client.readiness()
  self.assertEqual(self.client.first_unknown,'BRIDGE_UNKNOWN153')
 def test23_capability_source_and_absolute_lifetime_schema(self):
  import dataclasses
  for fields in [{'source':'wrong'},{'app_sha256':'wrong'},{'origin':'http://evil.invalid'},{'expires_at':self.now[0]+1000}]:
   with self.assertRaises(InvalidData):Capability153(dataclasses.replace(self.scope,**fields),TEST_TOKEN,clock=lambda:self.now[0])
 def test24_witness404_is_known_absence_not_dispatch_or_paypal(self):
  class Reply:
   status=404
   def read(self,n):return b'{}'
  class Conn:
   def __init__(self,*a,**k):pass
   def request(self,*a,**k):pass
   def getresponse(self):return Reply()
   def close(self):pass
  with patch('http.client.HTTPSConnection',Conn),patch.dict(os.environ,{'GITHUB_TOKEN':''}):
   with self.assertRaises(WitnessAbsent153):PollWitness153()._get('/repos/Elinfiny/PayProof/git/ref/heads/payproof-sandbox152-once')
 def tls_fixture(self):
  now=datetime.now(timezone.utc);key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(153).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(minutes=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).sign(key,hashes.SHA256());pem=self.f.root/'fixture-cert.pem';keyfile=self.f.root/'fixture-key.pem';pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM));keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));os.chmod(keyfile,0o600);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(pem,keyfile);return ctx,ssl.create_default_context(cafile=str(pem))
 def test25_real_loopback_tls_start_private_auth_and_complete_stop(self):
  import http.client
  ctx,clientctx=self.tls_fixture();server=Server153(('127.0.0.1',0),self.receiver,tls_context=ctx);t=threading.Thread(target=serve153,args=(server,));t.start()
  try:
   c=http.client.HTTPSConnection('localhost',server.server_address[1],timeout=3,context=clientctx);c.request('GET',PRIVATE+'/ready',headers=self.headers());r=c.getresponse();self.assertEqual(r.status,200);self.assertEqual(json.loads(r.read())['source'],self.scope.source);c.close()
   c=http.client.HTTPSConnection('localhost',server.server_address[1],timeout=3,context=clientctx);c.request('GET',PRIVATE+'/event',headers={'Host':self.scope.origin[8:]});r=c.getresponse();self.assertEqual(r.status,400);self.assertNotIn(b'raw_base64',r.read());c.close()
   self.now[0]=self.scope.expires_at;t.join(4);self.assertFalse(t.is_alive());self.assertTrue(self.receiver.closed);self.assertFalse(pathlib.Path(self.inbox.path).exists())
  finally:
   if t.is_alive():server.shutdown();t.join(4)
 def test26_native_listener_without_oauth_or_full_engine(self):
  self.ready_order();self.assertFalse(hasattr(self.receiver,'engine'));self.assertFalse(hasattr(self.receiver,'token'));self.assertFalse(hasattr(self.receiver,'client_secret'));self.assertFalse(hasattr(self.receiver,'client_id'))
 def test27_engine_listener_mismatch_refused_before_new_order(self):
  import dataclasses
  c=self.prepare_engine();c.grant=dataclasses.replace(c.grant,listener_url='https://other.invalid/webhooks/payproof151')
  with self.assertRaisesRegex(InvalidData,'EXACT_ENGINE_BRIDGE'):run_chain153(c,self.client,self.f.store)
  self.assertNotIn('order_create',c.used)
 def test28_master_bootstrap_no_runid_circularity_and_actual_consumed_readback(self):
  from tools.master_bootstrap153 import prepare_checkpoint153,witness_from_readback153
  from tools.sandbox_chain151 import canonical
  v={'revision':600,'guard':{'epoch_checkpoint_counter':600,'material_checkpoints':600},'created_at_utc':datetime.now(timezone.utc).isoformat(),'operation':{'effect_replay_boundary':canonical({'consumed113':'UNKNOWN_NO_RETRY','PayProof153':{'native153':{}}})},'integrity':{'canonical_json_sha256':None}};v['integrity']['canonical_json_sha256']=hashlib.sha256(canonical(v).encode()).hexdigest();raw=json.dumps(v).encode();kwargs={'session':self.scope.session,'source_head':'a'*40,'source_tree':'b'*40,'source_admission_sha256':'c'*64}
  # No actual run exists or is required for the job intent/consumption.
  for stage in ('JOB_INTENT','JOB_CONSUMED'):raw=prepare_checkpoint153(raw,stage=stage,**kwargs)['checkpoint_bytes']
  import dataclasses
  native_scope=dataclasses.replace(self.scope,test_only=False,app_sha256=APP);run={'repository_id':1419908202,'actor_id':273768139,'run_attempt':1,'event':'workflow_dispatch','head_sha':'a'*40,'head_branch':'main','workflow_path':'.github/workflows/payproof-sandbox-chain151.yml','id':41099999999,'tree':'b'*40,'status':'in_progress'};kwargs.update(actual_run=run,scope=native_scope,buyer_receipt={'state':'OWNER_SANDBOX_BUYER_AND_ADMITTED_BROWSER_ROUTE_READY','evidence':'SYNTHETIC_ONLY_NOT_REAL_NATIVE_READBACK'})
  raw=prepare_checkpoint153(raw,stage='BATCH_INTENT',**kwargs)['checkpoint_bytes']
  with self.assertRaisesRegex(InvalidData,'ACTUAL_BATCH_CONSUMED'):witness_from_readback153(raw,603)
  raw=prepare_checkpoint153(raw,stage='BATCH_CONSUMED',**kwargs)['checkpoint_bytes'];w=witness_from_readback153(raw,604);self.assertEqual(w['identity']['run_id'],'41099999999');self.assertEqual(w['listener_url'],self.scope.origin+WEBHOOK);self.assertEqual(w['bridge153']['service_id'],self.scope.service_id);self.assertEqual(w['master_checkpoint']['raw_sha256'],hashlib.sha256(raw).hexdigest());self.assertIn('consumed113',json.loads(json.loads(raw)['operation']['effect_replay_boundary']))
  with self.assertRaisesRegex(InvalidData,'ONCE_STAGE'):prepare_checkpoint153(raw,stage='BATCH_CONSUMED',**kwargs)
 def test29_batch_refuses_small_remaining_window_or_wrong_actual_run(self):
  from tools.master_bootstrap153 import actual_run153
  with self.assertRaisesRegex(InvalidData,'ACTUAL_PROVIDER_RUN'):actual_run153({'id':41099999999,'run_attempt':2},'a'*40)
 def test30_portal_does_not_leak_approval_and_native_cookie_is_secure(self):
  import http.client,urllib.parse
  raw,h=self.ready_order();ctx,clientctx=self.tls_fixture();server=Server153(('127.0.0.1',0),self.receiver,tls_context=ctx);t=threading.Thread(target=serve153,args=(server,));t.start()
  def request(method,path,headers,body=None):
   c=http.client.HTTPSConnection('localhost',server.server_address[1],timeout=3,context=clientctx);c.request(method,path,headers=headers,body=body);r=c.getresponse();out=(r.status,dict(r.getheaders()),r.read());c.close();return out
  try:
   host={'Host':self.scope.origin[8:]};status,_,page=request('GET',PRIVATE+'/portal',host);self.assertEqual(status,200);self.assertNotIn(b'checkoutnow',page);self.assertNotIn(TEST_TOKEN.encode(),page)
   body=urllib.parse.urlencode({'token':TEST_TOKEN});status,headers,_=request('POST',PRIVATE+'/login',dict(host,Origin=self.scope.origin,**{'Content-Type':'application/x-www-form-urlencoded'}),body);self.assertEqual(status,303);cookie=headers['Set-Cookie'];self.assertIn('Secure; HttpOnly; SameSite=Strict',cookie)
   status,_,page=request('GET',PRIVATE+'/portal',dict(host,Cookie=cookie.split(';')[0]));self.assertEqual(status,200);self.assertIn(b'https://www.sandbox.paypal.com/checkoutnow?token=ORDER151',page);self.assertNotIn(TEST_TOKEN.encode(),page)
   status,_,health=request('GET','/healthz',{'Host':'localhost'});self.assertEqual(status,200);self.assertNotIn(b'ORDER151',health)
  finally:self.now[0]=self.scope.expires_at;t.join(4)
  self.assertFalse(t.is_alive())
 def test31_full_private_chain_over_real_loopback_tls_and_original_custody(self):
  import http.client
  c=self.prepare_engine();raw,h=self.signed();ctx,clientctx=self.tls_fixture();server=Server153(('127.0.0.1',0),self.receiver,tls_context=ctx);thread=threading.Thread(target=serve153,args=(server,));thread.start();store=Store(self.f.root/'tls-engine153.sqlite')
  def transport(method,path,headers,body,timeout):
   conn=http.client.HTTPSConnection('localhost',server.server_address[1],timeout=3,context=clientctx)
   try:conn.request(method,path,headers=headers,body=body);r=conn.getresponse();return r.status,r.read(1500000)
   finally:conn.close()
  original=c.transport.request
  def provider(method,path,headers,body,timeout):
   if path.endswith('/capture'):
    status,_=transport('POST',WEBHOOK,dict(h,Host=self.scope.origin[8:],**{'Content-Type':'application/json','Content-Length':str(len(raw))}),raw,3);self.assertEqual(status,202);self.assertIsNone(c.capture_id)
   return original(method,path,headers,body,timeout)
  try:
   with patch.object(self.transport,'request',side_effect=transport),patch.object(c.transport,'request',side_effect=provider):run_chain153(c,self.client,store,approval_handoff=lambda b:b._call('buyer-ack','POST',{}))
   self.assertEqual(self.receiver.report['state'],'COMPLETED')
   import sqlite3
   with sqlite3.connect(self.inbox.path) as db:
    rows=db.execute('SELECT operation,status,raw,sha256 FROM originals153').fetchall();self.assertEqual(len(rows),5)
    for op,status,body,d in rows:self.assertEqual(hashlib.sha256(body).hexdigest(),d);self.assertNotIn(c.secret.encode() if c.secret else b'IMPOSSIBLE',body);self.assertNotEqual(op,'oauth')
   self.assertEqual(store.order('ORDER151')['state'],'COMPLETED');self.assertEqual(c.used['capture'],1);self.assertEqual(c.used['verify'],1)
  finally:self.now[0]=self.scope.expires_at;thread.join(4)
  self.assertFalse(thread.is_alive());self.assertFalse(pathlib.Path(self.inbox.path).exists())
 def test32_private_original_rejects_oauth_token_and_raw_without_auth(self):
  self.bootstrap()
  for raw in [b'{"access_token":"NEVER_EXPORT"}',TEST_TOKEN.encode()]:
   body=json.dumps({'status':200,'raw_base64':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}).encode()
   with self.assertRaisesRegex(InvalidData,'SECRET_IN_PRIVATE_ORIGINAL'):self.call('evidence-order_create',body)
  self.assertNotIn('evidence-order_create',self.receiver.counts)
  with self.assertRaises(InvalidData):self.receiver.handle('GET',PRIVATE+'/evidence-order_create',[('host',self.scope.origin[8:])],b'')
 def test33_original_archive_failure_cannot_report_success(self):
  c=self.prepare_engine();raw,h=self.signed();store=Store(self.f.root/'archive-refusal153.sqlite');old=c.transport.request
  def provider(method,path,headers,body,timeout):
   if path.endswith('/capture'):self.public_event(raw,h)
   return old(method,path,headers,body,timeout)
  with patch.object(c.transport,'request',side_effect=provider),patch.object(self.client,'original',side_effect=UnknownResult('PRIVATE_ARCHIVE_UNKNOWN153')):
   with self.assertRaises(UnknownResult):run_chain153(c,self.client,store,approval_handoff=lambda b:b._call('buyer-ack','POST',{}))
  self.assertIsNone(self.receiver.report);self.assertTrue(c.closed);self.assertTrue(self.client.closed)
 def test34_private_original_read_budget_and_native_application_identity(self):
  import dataclasses
  with self.assertRaisesRegex(InvalidData,'SCOPE153'):Capability153(dataclasses.replace(self.scope,test_only=False,app_sha256='b'*64),TEST_TOKEN)
  self.bootstrap();raw=b'{"original":"SYNTHETIC"}';payload=json.dumps({'status':201,'raw_base64':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}).encode();self.call('evidence-order_create',payload)
  for _ in range(2):self.assertEqual(self.call('evidence-order_create',method='GET')[0],200)
  with self.assertRaisesRegex(InvalidData,'ORIGINAL_READ_BOUND'):self.call('evidence-order_create',method='GET')
 def test35_prewarm_finite_start_stop_without_any_capability(self):
  from tools.sandbox_receiver153 import prewarm153
  result=prewarm153(0,test_only=True);self.assertEqual(result,{'closed':True,'watcher_joined':True,'test_only':True})
 def test36_listener_refuses_provider_credentials_even_in_prewarm(self):
  from tools import sandbox_bridge153,sandbox_receiver153
  with patch.object(sandbox_bridge153,'LIVE153',True),patch.dict(os.environ,{'PAYPROOF_PREWARM_ONLY':'1','PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET':'SYNTHETIC_NOT_REAL'}):
   with self.assertRaisesRegex(InvalidData,'PROVIDER_SECRETS_FORBIDDEN'):sandbox_receiver153.main()
 def test37_control_checkpoint_utf8_canonical_matches_actual_convention(self):
  from tools.master_bootstrap153 import _cp,prepare_checkpoint153,control_canonical153
  v={'revision':600,'guard':{'epoch_checkpoint_counter':600,'material_checkpoints':600},'owner_note':'Păstrează dovezile și stările incerte — fără reluări','operation':{'effect_replay_boundary':'{}'},'integrity':{'canonical_json_sha256':None}};v['integrity']['canonical_json_sha256']=hashlib.sha256(control_canonical153(v).encode()).hexdigest();raw=json.dumps(v,ensure_ascii=False).encode();self.assertEqual(_cp(raw)['revision'],600)
  prepared=prepare_checkpoint153(raw,stage='JOB_INTENT',session=self.scope.session,source_head='a'*40,source_tree='b'*40,source_admission_sha256='c'*64);self.assertEqual(_cp(prepared['checkpoint_bytes'])['owner_note'],v['owner_note'])
