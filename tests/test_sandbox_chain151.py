"""New bounded synthetic chain tests. No prior provider effects are replayed."""
import copy,dataclasses,hashlib,hmac,json,os,pathlib,sqlite3,tempfile,time,unittest
from datetime import datetime,timedelta,timezone
from unittest.mock import patch
from payproof.core import Store,InvalidData,UnknownResult
from host_contract_fixture import context as legacy_context,signed_fixture,TEST_KEY
from payproof.admission import _verify_receipt
from payproof.core import canonical
from tools.sandbox_chain151 import Chain151,SyntheticTransport151,FixedSandboxNetwork151,NativePorts151,load_native151,synthetic_grant151,CAPS,EVENT
from tools.sandbox_listener151 import EventInbox151,Receiver151,server151

def context(overrides=None):
 raw,credentials=signed_fixture();envelope=json.loads(raw);credentials=json.loads(credentials)
 credentials['webhook_id']='FAKE-HOOK';envelope['grant']['webhook_id']='FAKE-HOOK';envelope['grant'].update(overrides or {})
 envelope['signature']=hmac.new(TEST_KEY,canonical(envelope['grant']).encode(),hashlib.sha256).hexdigest()
 return _verify_receipt(canonical(envelope).encode(),TEST_KEY,canonical(credentials).encode(),test_only=True)

class SyntheticExternalLedger:
 """Durable test-only CAS model; NEVER a real external Master receipt."""
 def __init__(self,path):
  self.path=path
  with sqlite3.connect(path) as db:db.execute('create table if not exists once151 (key text primary key, metadata text not null)')
 def reserve_and_readback(self,key,metadata):
  with sqlite3.connect(self.path) as db:
   db.execute('begin immediate')
   try:db.execute('insert into once151 values (?,?)',(key,json.dumps(metadata,sort_keys=True)))
   except sqlite3.IntegrityError:raise InvalidData('EXTERNAL_TEST_ONCE_CONSUMED151') from None
   saved=json.loads(db.execute('select metadata from once151 where key=?',(key,)).fetchone()[0]);return {'key':key,'state':'CONSUMED','metadata':saved}

class SandboxChain151Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);os.chmod(self.root,0o700)
  self.clock=[time.time()];self.source='a'*64;self.caller='SYNTHETIC-CALLER151';self.url='https://example.invalid/webhooks/payproof151';self.client='fake-client';self.secret='fake-secret'
  self.grant=synthetic_grant151(source=self.source,caller=self.caller,now=self.clock[0],app_sha256=hashlib.sha256(self.client.encode()).hexdigest(),listener_url=self.url)
  self.ledger=SyntheticExternalLedger(self.root/'external-test.sqlite');self.store=Store(self.root/'evidence.sqlite');self.store.register('ORDER151','1.00','USD');self.chain=None
 def order(self,status='COMPLETED'):
  return {'id':'ORDER151','status':status,'update_time':(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat(),'purchase_units':[{'amount':{'value':'1.00','currency_code':'USD'},'payments':{'captures':[] if status=='APPROVED' else [{'id':'CAPTURE151','status':'COMPLETED','amount':{'value':'1.00','currency_code':'USD'}}]}}]}
 def replies(self,verified=True):
  wh={'id':'FAKE-HOOK','url':self.url,'event_types':[{'name':EVENT}]}
  return [(('POST','/v1/oauth2/token'),200,{'access_token':'SYNTHETIC-TOKEN151','expires_in':600}),(('GET','/v1/notifications/webhooks'),200,{'webhooks':[]}),(('POST','/v1/notifications/webhooks'),201,wh),(('POST','/v2/checkout/orders'),201,{'id':'ORDER151','status':'CREATED','links':[{'rel':'approve','href':'https://www.sandbox.paypal.com/checkoutnow?token=ORDER151'}]}),(('GET','/v2/checkout/orders/ORDER151'),200,self.order('APPROVED')),(('POST','/v2/checkout/orders/ORDER151/capture'),201,self.order()),(('GET','/v2/checkout/orders/ORDER151'),200,self.order()),(('POST','/v1/notifications/verify-webhook-signature'),200,{'verification_status':'SUCCESS' if verified else 'FAILURE'}),(('GET','/v2/checkout/orders/ORDER151'),200,self.order()),(('DELETE','/v1/notifications/webhooks/FAKE-HOOK'),204,b'')]
 def start(self,replies=None):
  transport=SyntheticTransport151(self.replies() if replies is None else replies);c=Chain151(self.grant,transport,self.ledger,source_sha256=self.source,caller=self.caller,clock=lambda:self.clock[0]);c.credentials(self.client,self.secret);self.chain=c;self.addCleanup(c.close);return c
 def ready(self,replies=None):
  c=self.start(replies);c.oauth();c.subscription();c.bind_evidence(context({'webhook_id':'FAKE-HOOK'}));c.create_order();c.capture_approved();c.read_final();return c
 def event(self):
  return json.dumps({'id':'EVENT151','event_type':EVENT,'resource':{'id':'CAPTURE151','status':'COMPLETED','amount':{'value':'1.00','currency_code':'USD'},'supplementary_data':{'related_ids':{'order_id':'ORDER151'}}}},separators=(',',':')).encode()
 def headers(self):return {'paypal-auth-algo':'SHA256withRSA','paypal-cert-url':'https://api.sandbox.paypal.com/v1/notifications/certs/TEST','paypal-transmission-id':'TX151','paypal-transmission-sig':'SYNTHETIC-SIG151','paypal-transmission-time':'2026-10-30T00:00:00Z'}
 def test01_complete_acquisition_real_service_contract_and_cleanup(self):
  c=self.ready();r=c.webhook(self.store,self.headers(),self.event());self.assertTrue(c.verified_complete);self.assertEqual(self.store.order('ORDER151')['state'],'COMPLETED');self.assertTrue(r['service_result']['view']['payment_mutation_actions']==[]);self.assertFalse(r['authentic_runtime']);c.cleanup_subscription();self.assertEqual(len(c.transport.calls),10);c.close();s=json.dumps(c.export());self.assertNotIn(self.secret,s);self.assertNotIn('SYNTHETIC-TOKEN151',s);self.assertEqual(c.private_returns,[])
 def test02_native_default_and_synthetic_network_refused(self):
  with self.assertRaisesRegex(InvalidData,'UNBOUND151'):load_native151(NativePorts151())
  with self.assertRaisesRegex(InvalidData,'SYNTHETIC_NEVER_NETWORK'):FixedSandboxNetwork151(self.grant)
  with self.assertRaises(InvalidData):Chain151({},SyntheticTransport151([]),self.ledger,source_sha256=self.source,caller=self.caller)
 def test03_source_caller_expiry_profile_and_scope_refused_before_io(self):
  mutations=[{'source_sha256':'b'*64},{'caller':'WRONG'},{'expires_at':self.clock[0]-1},{'not_before':self.clock[0]+1},{'profile':'orders:read'},{'listener_url':'http://example.invalid/webhooks/payproof151'},{'listener_url':'https://example.invalid:8443/webhooks/payproof151'}]
  for m in mutations:
   with self.subTest(m=m):
    t=SyntheticTransport151([])
    with self.assertRaises(InvalidData):Chain151(dataclasses.replace(self.grant,**m),t,self.ledger,source_sha256=self.source,caller=self.caller,clock=lambda:self.clock[0])
    self.assertEqual(t.calls,[])
 def test04_wrong_credential_application_no_call(self):
  c=self.start();c.client=c.secret=''
  with self.assertRaisesRegex(InvalidData,'APP_SCOPE'):c.credentials('wrong-client','wrong-secret')
  self.assertEqual(c.transport.calls,[])
 def test05_external_once_survives_restart_and_race_loser(self):
  c=self.start();c.oauth();c.close();t=SyntheticTransport151(self.replies());new=Chain151(self.grant,t,SyntheticExternalLedger(self.ledger.path),source_sha256=self.source,caller=self.caller,clock=lambda:self.clock[0]);new.credentials(self.client,self.secret)
  with self.assertRaisesRegex(InvalidData,'CONSUMED'):new.oauth()
  self.assertEqual(t.calls,[]);new.close()
 def test06_capture_timeout_consumed_no_followup_no_cleanup(self):
  rs=self.replies();rs[5]=(rs[5][0],200,TimeoutError('SYNTHETIC-SECRET-ERROR'));c=self.start(rs);c.oauth();c.subscription();c.bind_evidence(context({'webhook_id':'FAKE-HOOK'}));c.create_order()
  with self.assertRaises(UnknownResult):c.capture_approved()
  before=len(c.transport.calls)
  for fn in [c.read_final,c.capture_approved,c.cleanup_subscription]:
   with self.assertRaises(UnknownResult):fn()
  self.assertEqual(len(c.transport.calls),before);self.assertNotIn('SYNTHETIC-SECRET-ERROR',json.dumps(c.export()))
 def test07_late_provider_return_retained_before_guard_no_next_effect(self):
  c=self.start();original=SyntheticTransport151.request
  def late(t,*args):
   result=original(t,*args);self.clock[0]+=500;return result
  with patch.object(SyntheticTransport151,'request',late):
   with self.assertRaises(UnknownResult):c.oauth()
  self.assertEqual(len(c.private_returns),1);self.assertEqual(len(c.transport.calls),1)
  with self.assertRaises(UnknownResult):c.subscription()
 def test08_pre_capture_amount_currency_identity_and_unapproved_refused(self):
  for field in ['id','amount','currency','status']:
   with self.subTest(field=field):
    # Independent synthetic journal per distinct negative fixture, no provider effect.
    self.ledger=SyntheticExternalLedger(self.root/(field+'.sqlite'));rs=self.replies();r=rs[4][2]
    if field=='id':r['id']='OTHER'
    elif field=='status':r['status']='CREATED'
    else:r['purchase_units'][0]['amount']['value' if field=='amount' else 'currency_code']='2.00' if field=='amount' else 'EUR'
    c=self.start(rs);c.oauth();c.subscription();c.bind_evidence(context({'webhook_id':'FAKE-HOOK'}));c.create_order()
    with self.assertRaises(InvalidData):c.capture_approved()
    self.assertNotIn('capture',c.used);c.close()
 def test09_capture_or_final_read_mismatch_freezes_no_promotion(self):
  for index in [5,6]:
   with self.subTest(index=index):
    self.ledger=SyntheticExternalLedger(self.root/('mismatch'+str(index)+'.sqlite'));rs=self.replies();rs[index][2]['purchase_units'][0]['payments']['captures'][0]['amount']['value']='0.50';c=self.start(rs);c.oauth();c.subscription();c.bind_evidence(context({'webhook_id':'FAKE-HOOK'}));c.create_order()
    with self.assertRaises(UnknownResult):c.capture_approved() if index==5 else (c.capture_approved(),c.read_final())
    self.assertFalse(c.verified_complete);self.assertNotEqual(self.store.order('ORDER151')['state'],'COMPLETED');c.close()
 def test10_evidence_context_scope_app_webhook_before_create(self):
  c=self.start();c.oauth();c.subscription()
  for ctx in [None,legacy_context(),context({'webhook_id':'FAKE-HOOK','operations':['orders:read']})]:
   with self.subTest(ctx=type(ctx).__name__):
    with self.assertRaises(InvalidData):c.bind_evidence(ctx)
  with self.assertRaises(InvalidData):c.create_order()
  self.assertNotIn('order_create',c.used)
 def test11_signed_raw_event_and_duplicate_no_second_verification(self):
  c=self.ready();raw=self.event();c.webhook(self.store,self.headers(),raw);before=len(c.transport.calls);r=c.webhook(self.store,self.headers(),raw);self.assertEqual(r['disposition'],'DUPLICATE_RETAINED');self.assertEqual(len(c.transport.calls),before)
  changed=json.loads(raw);changed['extra']='drift'
  with self.assertRaisesRegex(InvalidData,'BODY_DRIFT'):c.webhook(self.store,self.headers(),json.dumps(changed).encode())
 def test12_invalid_signature_no_paid_promotion_no_authoritative_get(self):
  c=self.ready(self.replies(False))
  with self.assertRaisesRegex(InvalidData,'authenticity not verified'):c.webhook(self.store,self.headers(),self.event())
  self.assertFalse(c.verified_complete);self.assertNotIn('event_read',c.used);self.assertNotEqual(self.store.order('ORDER151')['state'],'COMPLETED')
 def test13_verification_timeout_unknown_no_get_no_retry(self):
  rs=self.replies();rs[7]=(rs[7][0],200,TimeoutError());c=self.ready(rs)
  with self.assertRaises(UnknownResult):c.webhook(self.store,self.headers(),self.event())
  self.assertNotIn('event_read',c.used);self.assertFalse(c.verified_complete)
 def test14_wrong_event_identity_amount_currency_and_duplicate_json_before_provider(self):
  c=self.ready();before=len(c.transport.calls)
  for mutate in [lambda x:x.update(id='bad lowercase'),lambda x:x['resource'].update(id='OTHER'),lambda x:x['resource']['amount'].update(value='2.00'),lambda x:x['resource']['amount'].update(currency_code='EUR'),lambda x:x['resource']['supplementary_data']['related_ids'].update(order_id='OTHER')]:
   event=json.loads(self.event());mutate(event)
   with self.assertRaises(InvalidData):c.webhook(self.store,self.headers(),json.dumps(event).encode())
  with self.assertRaises(InvalidData):c.webhook(self.store,self.headers(),b'{"id":"A","id":"B"}')
  self.assertEqual(len(c.transport.calls),before)
 def test15_listener_original_bytes_persistence_and_duplicate(self):
  c=self.ready();inbox=EventInbox151(self.root/'inbox.sqlite');receiver=Receiver151(c,self.store,inbox);raw=self.event();headers=[('Host','example.invalid'),('Content-Type','application/json'),('Content-Length',str(len(raw))),*self.headers().items()];r=receiver.receive('POST','/webhooks/payproof151',headers,raw,tls_verified=True);self.assertEqual(r['state'],'VERIFIED_COMPLETE');before=len(c.transport.calls);self.assertEqual(receiver.receive('POST','/webhooks/payproof151',headers,raw,tls_verified=True)['state'],'RETAINED_DUPLICATE_NO_PROVIDER_CALL');self.assertEqual(len(c.transport.calls),before)
  with sqlite3.connect(inbox.path) as db:self.assertEqual(db.execute('select raw from inbox').fetchone()[0],raw)
  self.assertEqual(os.stat(inbox.path).st_mode&0o777,0o600)
 def test16_listener_bounds_host_path_signature_headers_and_proxy_spoof(self):
  c=self.ready();receiver=Receiver151(c,self.store,EventInbox151(self.root/'inbox.sqlite'));raw=self.event();base=[('Host','example.invalid'),('Content-Type','application/json'),('Content-Length',str(len(raw))),*self.headers().items()];before=len(c.transport.calls)
  for method,path,headers,tls,body in [('GET','/webhooks/payproof151',base,True,raw),('POST','/wrong',base,True,raw),('POST','/webhooks/payproof151',base+[('Host','wrong')],True,raw),('POST','/webhooks/payproof151',[('Host','wrong')]+base[1:],True,raw),('POST','/webhooks/payproof151',base+[('X-Forwarded-Proto','https')],False,raw),('POST','/webhooks/payproof151',base[:-1],True,raw),('POST','/webhooks/payproof151',base,True,b'x'*65537)]:
   with self.subTest(method=method,path=path,tls=tls):
    with self.assertRaises(InvalidData):receiver.receive(method,path,headers,body,tls_verified=tls)
  self.assertEqual(len(c.transport.calls),before)
  with self.assertRaises(InvalidData):server151(receiver,host='127.0.0.1',port=0)
 def test17_existing_subscription_never_deleted_or_recreated(self):
  rs=self.replies();wh=rs[2][2];rs[1]=(rs[1][0],200,{'webhooks':[wh]});rs.pop(2);c=self.ready(rs);self.assertFalse(c.created_subscription);c.webhook(self.store,self.headers(),self.event())
  with self.assertRaises(InvalidData):c.cleanup_subscription()
  self.assertNotIn('subscription_create',c.used);self.assertNotIn('subscription_delete',c.used)
 def test18_no_product_capture_route_or_legacy_scope_expansion(self):
  from payproof.paypal import SandboxPayPal
  adapter=SandboxPayPal(context(),transport=lambda *a:(_ for _ in ()).throw(AssertionError('NO_TRANSPORT')))
  with self.assertRaises(InvalidData):adapter.request('POST','/v2/checkout/orders/ORDER151/capture')
  from tools.sandbox_chain151 import ORIGIN
  self.assertEqual(ORIGIN,'https://api-m.sandbox.paypal.com');self.assertEqual(max(CAPS.values()),1)
 def test19_malformed_subscription_result_freezes_before_order(self):
  rs=self.replies();rs[1]=(rs[1][0],200,{'webhooks':[{'event_types':None}]});c=self.start(rs);c.oauth()
  with self.assertRaises(UnknownResult):c.subscription()
  self.assertNotIn('order_create',c.used)
 def test20_inbox_bound_and_forged_proxy_refused(self):
  c=self.ready();inbox=EventInbox151(self.root/'inbox.sqlite')
  with self.assertRaises(InvalidData):Receiver151(c,self.store,inbox,proxy_provenance=object())
  inbox.retain(b'FIRST',{})
  with self.assertRaisesRegex(InvalidData,'ONE_EVENT'):inbox.retain(b'SECOND',{})
 def test21_operation_alias_payload_and_preapproval_cannot_expand_effect_scope(self):
  c=self.start();c.oauth();before=len(c.transport.calls)
  for op,method,path,payload in [('final_read','POST','/v2/checkout/orders',{}),('capture','POST','/v2/checkout/orders/OTHER/capture',{}),('order_create','POST','/v2/checkout/orders',{'intent':'CAPTURE','purchase_units':[{'amount':{'value':'9.00','currency_code':'USD'}}]}),('verify','POST','/v1/notifications/verify-webhook-signature',b'{}'),('subscription_create','POST','/v1/notifications/webhooks',{'url':self.url,'event_types':[{'name':EVENT}]})]:
   with self.subTest(op=op):
    with self.assertRaises(InvalidData):c.effect(op,method,path,payload)
  self.assertEqual(len(c.transport.calls),before)
 def test22_ambiguous_external_cas_or_readback_freezes_before_network(self):
  for outcome in ['ambiguous','wrong_readback']:
   with self.subTest(outcome=outcome):
    c=self.start()
    def ambiguous(*a):raise UnknownResult('PRIVATE_ERROR_NOT_EXPORTED')
    with patch.object(self.ledger,'reserve_and_readback',ambiguous if outcome=='ambiguous' else lambda *a:None):
     with self.assertRaises(UnknownResult):c.oauth()
    with self.assertRaises(UnknownResult):c.subscription()
    self.assertEqual(c.transport.calls,[]);self.assertNotIn('PRIVATE_ERROR',json.dumps(c.export()));c.close()
 def test23_native_entry_refuses_before_custody_and_transport(self):
  from tools.sandbox_entry151 import begin151
  with self.assertRaisesRegex(InvalidData,'NATIVE_CUSTODY_ADMISSION_UNBOUND'):begin151(NativePorts151())
 def test24_entry_composition_complete_and_credentials_closed(self):
  from tools.sandbox_entry151 import acquire151,after_buyer_approval151,finish151
  c=self.start();c.oauth();c.subscription();link=acquire151(c,context({'webhook_id':'FAKE-HOOK'}));self.assertIn('www.sandbox.paypal.com',link);after_buyer_approval151(c);r=finish151(c,self.store,self.headers(),self.event());self.assertTrue(c.closed);self.assertTrue(c.verified_complete);self.assertEqual(len(c.transport.calls),10);self.assertEqual(r['service_result']['view']['order']['state'],'COMPLETED')
 def test25_entry_unknown_cleanup_keeps_primary_and_no_subscription_delete(self):
  from tools.sandbox_entry151 import finish151
  rs=self.replies();rs[7]=(rs[7][0],200,TimeoutError());c=self.ready(rs)
  with self.assertRaises(UnknownResult):finish151(c,self.store,self.headers(),self.event())
  self.assertTrue(c.closed);self.assertTrue(c.first_unknown);self.assertNotIn('subscription_delete',c.used);self.assertNotIn('event_read',c.used)

 def test26_expiry_during_external_reservation_blocks_transport_keeps_consumed(self):
  c=self.start();reserve=self.ledger.reserve_and_readback
  def late(key,metadata):
   receipt=reserve(key,metadata);self.clock[0]=c.grant.expires_at+1;return receipt
  with patch.object(self.ledger,'reserve_and_readback',late):
   with self.assertRaises(UnknownResult):c.oauth()
  self.assertEqual(c.transport.calls,[]);self.assertEqual(c.used,{'oauth':1});self.assertEqual(c.first_unknown,'RESERVATION_LATE_OR_BINDING_DRIFT152')
  with self.assertRaises(UnknownResult):c.subscription()
 def test27_token_expiry_during_reservation_blocks_next_transport(self):
  c=self.start();c.oauth();before=len(c.transport.calls);reserve=self.ledger.reserve_and_readback;c.token_until=self.clock[0]+1
  def late(key,metadata):
   receipt=reserve(key,metadata);self.clock[0]+=2;return receipt
  with patch.object(self.ledger,'reserve_and_readback',late):
   with self.assertRaises(UnknownResult):c.subscription()
  self.assertEqual(len(c.transport.calls),before);self.assertEqual(c.used.get('subscription_read'),1);self.assertTrue(c.first_unknown)

if __name__=='__main__':unittest.main(verbosity=2)
