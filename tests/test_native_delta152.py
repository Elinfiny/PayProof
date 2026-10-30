"""Only new152 contract/security deltas. No old27-method suite replay."""
import base64,copy,io,json,os,pathlib,sqlite3,tempfile,time,unittest,zlib
from datetime import datetime,timedelta,timezone
from unittest.mock import patch
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from tools.sandbox_chain151 import InvalidData,UnknownResult,CAPS,APP,digest
from tools.sandbox_native152 import (validate_identity152,validate_batch152,NativePorts152,
 ProviderEvidence152,SyntheticProviderEvidence152)
from tools.sandbox_ingress152 import SyntheticSignature152,LocalSignature152,certificate_url152
from tools.sandbox_http152 import DeadlineRaw152,BoundedHTTP152,Handler152
from tools.sandbox_listener151 import Receiver151,EventInbox151
from test_sandbox_chain151 import SandboxChain151Tests

class NativeDelta152Tests(unittest.TestCase):
 def setUp(self):
  # Reuse data builders, not their accepted test methods.
  self.f=SandboxChain151Tests('test02_native_default_and_synthetic_network_refused');self.f.setUp();self.addCleanup(self.f.doCleanups)
 def identity(self):
  e={'GITHUB_REPOSITORY':'Elinfiny/PayProof','GITHUB_REPOSITORY_ID':'1419908202','GITHUB_REPOSITORY_OWNER':'Elinfiny','GITHUB_REPOSITORY_OWNER_ID':'273768139','GITHUB_ACTOR':'Elinfiny','GITHUB_ACTOR_ID':'273768139','GITHUB_RUN_ATTEMPT':'1','GITHUB_RUN_ID':'41099999999','GITHUB_SHA':'a'*40,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_JOB':'sandbox-chain','GITHUB_WORKFLOW_REF':'Elinfiny/PayProof/.github/workflows/payproof-sandbox-chain151.yml@refs/heads/main'}
  return e,validate_identity152(e,'a'*40,'b'*40)
 def batch(self):
  _,identity=self.identity();now=time.time()
  return {'schema':'PAYPROOF_MASTER_EXTERNAL_BATCH152','once_prefix':'P151-SYNTHETIC-152','listener_url':'https://example.invalid/webhooks/payproof151','state':'CONSUMED','identity':identity,'app_sha256':APP,'operations':CAPS,'fake_usd':'1.00','real_usd':'0.00','not_before':now-1,'expires_at':now+120,'dynamic_targets':'ONLY_IDS_RETURNED_BY_THIS_CHAIN_CREATE_AND_SUBSCRIPTION','master_checkpoint':{'stable_id':'libfile_382af1e4da2481918fc68e272db49927','version':511,'raw_sha256':'c'*64,'self_sha256':'d'*64},'independent_admission':'EXACT_NATIVE152_ADMISSION_REQUIRED','cost_gate':'TOTAL_INCREMENTAL_ZERO_PROVEN'}
 def test01_provider_identity_refusals(self):
  env,i=self.identity();self.assertEqual(i['run_id'],env['GITHUB_RUN_ID'])
  for k in ('GITHUB_ACTOR_ID','GITHUB_REPOSITORY_ID','GITHUB_RUN_ATTEMPT','GITHUB_WORKFLOW_REF','GITHUB_SHA','GITHUB_REF'):
   with self.subTest(k=k):
    with self.assertRaises(InvalidData):validate_identity152(dict(env,**{k:'wrong'}),'a'*40,'b'*40)
 def test02_batch_is_exact_preconsumed_scope_not_cas_per_call(self):
  w=self.batch();_,i=self.identity();self.assertIs(validate_batch152(w,i,time.time()),w)
  for key,value in [('state','INTENT'),('operations',{'capture':2}),('real_usd','1.00'),('dynamic_targets','ANY'),('expires_at',time.time()-1),('cost_gate','Free'),('app_sha256','f'*64),('independent_admission','public input')]:
   with self.subTest(key=key):
    with self.assertRaises(InvalidData):validate_batch152(dict(w,**{key:value}),i,time.time())
 def test03_native_default_before_secret_release_or_network(self):
  with self.assertRaisesRegex(InvalidData,'NOT_ADMITTED'):NativePorts152('/does/not/exist','/never-created')
 def test04_separate_provider_adapter_complete_fake_chain(self):
  c=self.f.start();c.oauth();c.subscription();c.bind_evidence(SyntheticProviderEvidence152(c));c.create_order();c.capture_approved();c.read_final()
  r=c.webhook(self.f.store,self.f.headers(),self.f.event());self.assertTrue(c.verified_complete);self.assertFalse(r['authentic_runtime']);self.assertEqual(r['service_result']['view']['mode'],'SANDBOX_CONTRACT_TEST');self.assertEqual(self.f.store.order('ORDER151')['state'],'COMPLETED')
  calls=list(c.transport.calls);c.webhook(self.f.store,self.f.headers(),self.f.event());self.assertEqual(c.transport.calls,calls)
 def test05_legacy_fixture_never_grants_native_provider_evidence(self):
  c=self.f.start();c.oauth();c.subscription()
  with self.assertRaisesRegex(InvalidData,'PROVIDER_EVIDENCE_SCOPE'):c.bind_evidence(ProviderEvidence152(c))
  self.assertIsNone(c.evidence_context)
 def test06_provider_context_wrong_chain_rejected(self):
  c=self.f.start();c.oauth();c.subscription()
  with self.assertRaisesRegex(InvalidData,'CHAIN_IDENTITY'):c.bind_evidence(SyntheticProviderEvidence152(object()))
 def test07_new_profile_official_failure_no_event_or_read(self):
  c=self.f.start(self.f.replies(verified=False));c.oauth();c.subscription();c.bind_evidence(SyntheticProviderEvidence152(c));c.create_order();c.capture_approved();c.read_final()
  with self.assertRaisesRegex(InvalidData,'AUTHENTICITY_NOT_VERIFIED'):c.webhook(self.f.store,self.f.headers(),self.f.event())
  self.assertNotIn('event_read',c.used);self.assertFalse(c.verified_complete)
 def test08_local_slot_persisted_and_receipt_distinguishes_external_batch(self):
  _,identity=self.identity();w=self.batch();w['once_prefix']='P151-SYNTHETIC-152'
  ports=object.__new__(NativePorts152);ports.witness=w;ports.batch_digest='e'*64;ports.witness_commit='f'*40;ports.path=self.f.root/'local152.sqlite'
  with sqlite3.connect(ports.path) as db:db.execute('CREATE TABLE slots (key TEXT PRIMARY KEY, metadata TEXT NOT NULL)')
  m={'operation':'capture','source_sha256':'a'*64,'caller':'fake-caller','app_sha256':APP,'expires_at':w['expires_at'],'fake_usd':'1.00','real_usd':'0.00','target_sha256':'b'*64}
  with patch.object(NativePorts152,'current_source',return_value='a'*64),patch.object(NativePorts152,'current_caller',return_value='fake-caller'):
   r=ports.reserve_and_readback(w['once_prefix']+':capture',m);self.assertTrue(ports.matches_receipt(r,w['once_prefix']+':capture',m));self.assertNotIn('metadata',r);self.assertEqual(r['local_metadata'],m)
   with self.assertRaisesRegex(InvalidData,'LOCAL_SLOT_CONSUMED'):ports.reserve_and_readback(w['once_prefix']+':capture',m)
 def test09_absolute_deadline_before_parse_and_slow_drip(self):
  class Sock:
   def __init__(self):self.timeouts=[]
   def settimeout(self,n):self.timeouts.append(n)
  sock=Sock();raw=DeadlineRaw152(io.BytesIO(b'GET / HTTP/1.0\r\n'),sock,20)
  with patch('tools.sandbox_http152.time.monotonic',side_effect=[16,19,20.1]):
   self.assertEqual(raw.readinto(bytearray(1)),1);self.assertEqual(raw.readinto(bytearray(1)),1)
   with self.assertRaisesRegex(TimeoutError,'ABSOLUTE'):raw.readinto(bytearray(1))
  self.assertEqual(sock.timeouts,[4,1]);raw.close()
 def test10_header_byte_bound_before_parser(self):
  class Sock:
   def settimeout(self,n):pass
  raw=DeadlineRaw152(io.BytesIO(b'A'*17000),Sock(),time.monotonic()+5);self.assertEqual(raw.readinto(bytearray(20000)),16384)
  with self.assertRaisesRegex(ValueError,'BYTE_BOUND'):raw.readinto(bytearray(1))
  raw.close()
 def test11_eighth_connection_bound_rejects_ninth(self):
  import threading
  server=object.__new__(BoundedHTTP152);server.slots=threading.BoundedSemaphore(8)
  for _ in range(8):self.assertTrue(server.slots.acquire(False))
  with patch.object(server,'shutdown_request') as close:server.process_request(object(),('127.0.0.1',1));close.assert_called_once()
 def test12_accepted_connection_timeout_set_before_handler(self):
  class Sock:
   def __init__(self):self.timeout=None
   def settimeout(self,n):self.timeout=n
  sock=Sock();server=object.__new__(BoundedHTTP152)
  with patch('http.server.HTTPServer.get_request',return_value=(sock,('127.0.0.1',1))):self.assertIs(server.get_request()[0],sock)
  self.assertEqual(sock.timeout,5)
 def key_and_headers(self):
  # Test-only signing key: not a host issuer or new native trust key.
  key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=datetime.now(timezone.utc)
  name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SYNTHETIC ONLY')]);cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(minutes=10)).sign(key,hashes.SHA256())
  h=self.f.headers();h['paypal-cert-url']='https://api.sandbox.paypal.com/v1/notifications/certs/SYNTHETIC-ONLY';h['paypal-transmission-time']=now.isoformat();raw=self.f.event();msg=(h['paypal-transmission-id']+'|'+h['paypal-transmission-time']+'|FAKE-HOOK|'+str(zlib.crc32(raw)&0xffffffff)).encode();h['paypal-transmission-sig']=base64.b64encode(key.sign(msg,padding.PKCS1v15(),hashes.SHA256())).decode();return cert,h
 def test13_signature_exact_original_bytes_and_origin(self):
  cert,h=self.key_and_headers();v=SyntheticSignature152('FAKE-HOOK',{h['paypal-cert-url']:cert});self.assertTrue(v.verify(h,self.f.event()));self.assertFalse(v.verify(h,self.f.event()+b' '));self.assertFalse(v.verify(dict(h,**{'paypal-auth-algo':'SHA1withRSA'}),self.f.event()))
  for u in ('http://api.sandbox.paypal.com/v1/notifications/certs/X','https://evil.invalid/v1/notifications/certs/X','https://api.sandbox.paypal.com@evil.invalid/v1/notifications/certs/X','https://api.sandbox.paypal.com:443/v1/notifications/certs/X','https://api.sandbox.paypal.com/v1/notifications/certs/X?url=evil'):
   with self.assertRaises(InvalidData):certificate_url152(u)
 def test14_forged_first_event_cannot_consume_legitimate_inbox_or_api(self):
  c=self.f.ready();cert,h=self.key_and_headers();v=SyntheticSignature152('FAKE-HOOK',{h['paypal-cert-url']:cert});inbox=EventInbox151(self.f.root/'prefilter-inbox.sqlite');r=Receiver151(c,self.f.store,inbox,signature_prefilter=v);raw=self.f.event()
  def pairs(headers):return list(dict(headers,host='example.invalid',**{'content-type':'application/json','content-length':str(len(raw))}).items())
  before=list(c.transport.calls);bad=dict(h,**{'paypal-transmission-sig':base64.b64encode(b'X'*256).decode()});out=r.receive('POST','/webhooks/payproof151',pairs(bad),raw,tls_verified=True);self.assertEqual(out['status'],400);self.assertEqual(c.transport.calls,before)
  with sqlite3.connect(inbox.path) as db:self.assertEqual(db.execute('SELECT count(*) FROM inbox').fetchone()[0],0)
  out=r.receive('POST','/webhooks/payproof151',pairs(h),raw,tls_verified=True);self.assertEqual(out['state'],'VERIFIED_COMPLETE');self.assertEqual(c.used['verify'],1);self.assertEqual(c.used['event_read'],1)
 def test15_prefilter_cannot_supply_native_authority(self):
  c=self.f.start();c.oauth();c.subscription();cert,h=self.key_and_headers();v=SyntheticSignature152('FAKE-HOOK',{h['paypal-cert-url']:cert})
  import dataclasses
  c.grant=dataclasses.replace(c.grant,test_only=False)
  with self.assertRaisesRegex(InvalidData,'NATIVE_SIGNATURE_PREFILTER_REQUIRED'):Receiver151(c,self.f.store,EventInbox151(self.f.root/'native-refusal.sqlite'),signature_prefilter=v)
 def test16_local_header_and_event_serialization_race_no_slot_consumed(self):
  c=self.f.ready();r=Receiver151(c,self.f.store,EventInbox151(self.f.root/'busy.sqlite'));self.assertTrue(r._receive_lock.acquire(False))
  try:self.assertEqual(r.receive('POST','/webhooks/payproof151',[],b'')['state'],'BUSY_NO_SLOT_CONSUMED152')
  finally:r._receive_lock.release()
  self.assertNotIn('verify',c.used)

 def test17_bad_certificate_fetch_does_not_permanently_burn_legitimate_key(self):
  cert,h=self.key_and_headers()
  from cryptography.hazmat.primitives.serialization import Encoding
  pem=cert.public_bytes(Encoding.PEM)
  class Response:
   def __init__(self,status,raw):self.status=status;self.raw=raw
   def read(self,n):return self.raw[:n]
  class Conn:
   rows=[Response(404,b'no'),Response(200,pem)]
   def __init__(self,*a,**k):pass
   def request(self,*a,**k):pass
   def getresponse(self):return self.rows.pop(0)
   def close(self):pass
  v=LocalSignature152('FAKE-HOOK')
  with patch('tools.sandbox_ingress152.http.client.HTTPSConnection',Conn):
   with self.assertRaisesRegex(InvalidData,'NO_SLOT'):v._certificate('https://api.sandbox.paypal.com/v1/notifications/certs/BAD')
   self.assertEqual(v.cache,{})
   self.assertTrue(v.verify(h,self.f.event()))
  self.assertEqual(v.fetches,2)
 def test18_new_order_registered_before_buyer_capture(self):
  from tools.sandbox_entry151 import acquire152
  from payproof.core import Store
  c=self.f.start();c.oauth();c.subscription();c.bind_evidence(SyntheticProviderEvidence152(c));store=Store(self.f.root/'new-provider-store.sqlite')
  url=acquire152(c,store);self.assertTrue(url.startswith('https://www.sandbox.paypal.com/checkoutnow?'));self.assertEqual(store.order('ORDER151')['state'],'UNKNOWN');self.assertNotIn('capture',c.used)
  c.capture_approved();c.read_final();c.webhook(store,self.f.headers(),self.f.event());self.assertEqual(store.order('ORDER151')['state'],'COMPLETED')
 def test19_external_batch_receipt_keeps_postreservation_expiry_guard(self):
  ports=object.__new__(NativePorts152);ports.batch_digest='e'*64;ports.witness_commit='f'*40
  c=self.f.start();c.ledger=ports
  def late(key,metadata):
   self.f.clock[0]+=1000
   return {'kind':'EXTERNAL_BATCH_CONSUMED_LOCAL_SLOT152','external_batch_sha256':ports.batch_digest,'witness_commit':ports.witness_commit,'key':key,'state':'CONSUMED','local_metadata':metadata}
  with patch.object(NativePorts152,'reserve_and_readback',side_effect=late):
   with self.assertRaises(UnknownResult):c.oauth()
  self.assertEqual(c.used,{'oauth':1});self.assertEqual(c.transport.calls,[]);self.assertEqual(c.first_unknown,'RESERVATION_LATE_OR_BINDING_DRIFT152')
 def test20_concrete_github_witness_checks_parent_blob_and_current_ref(self):
  from tools.sandbox_native152 import GitHubWitness152,PATH,REF
  import hashlib
  _,identity=self.identity();raw=json.dumps(self.batch()).encode();blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest();head='e'*40
  ref={'ref':'refs/'+REF,'object':{'sha':head,'type':'commit'}}
  rows=[ref,{'sha':head,'parents':[{'sha':identity['head']}],'tree':{'sha':'f'*40}}, {'tree':[{'path':PATH,'type':'blob','mode':'100644','sha':blob}]}, {'content':base64.b64encode(raw).decode()},ref]
  class Response:
   status=200
   def __init__(self,row):self.row=row
   def read(self,n):return json.dumps(self.row).encode()[:n]
  class Conn:
   calls=[]
   def __init__(self,*a,**k):pass
   def request(self,method,path,headers):self.calls.append((method,path))
   def getresponse(self):return Response(rows.pop(0))
   def close(self):pass
  with patch.dict(os.environ,{'GITHUB_TOKEN':''}),patch('tools.sandbox_native152.http.client.HTTPSConnection',Conn):
   w,h,commit=GitHubWitness152().read(identity)
  self.assertEqual(w['identity'],identity);self.assertEqual(h,digest(raw));self.assertEqual(commit,head);self.assertEqual(len(Conn.calls),5);self.assertTrue(all(m=='GET' and p.startswith('/repos/Elinfiny/PayProof/git/') for m,p in Conn.calls))
