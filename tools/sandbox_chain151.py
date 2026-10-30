"""Private Sandbox test-data acquisition, not a product payment endpoint.

Native admission/custody/external-ledger ports deliberately have no default
issuer. The synthetic harness cannot select the network transport. No CLI,
environment variable or public JSON turns this module on.
"""
import base64,copy,hashlib,http.client,json,re,ssl,time
from dataclasses import dataclass
from urllib.parse import urlsplit,parse_qs
from payproof.admission import SandboxContext,_json
from payproof.core import InvalidData,UnknownResult,canonical,project_order
from payproof.paypal import SandboxPayPal
from payproof.service import PaymentEvidenceService

ORIGIN='https://api-m.sandbox.paypal.com'
APP='b954b4c7eff1b9aac313ca9867e2d8fa31fb1782453b0ce583cb2dd1bb436e74'
PROFILE='PAYPROOF151_SEPARATE_SANDBOX_TEST_DATA'
_TEST=object();_NATIVE=object()
CAPS={k:1 for k in ('oauth','subscription_read','subscription_create','order_create','approval_read','capture','final_read','verify','event_read','subscription_delete')}
EVENT='PAYMENT.CAPTURE.COMPLETED';LIMIT=65536
def digest(b):return hashlib.sha256(b).hexdigest()
def ident(s):
 if not isinstance(s,str) or not re.fullmatch('[A-Z0-9-]{1,64}',s):raise InvalidData('IDENTITY151')
 return s
def require_url(url):
 p=urlsplit(url)
 if p.scheme!='https' or not p.hostname or p.username or p.password or p.port not in (None,443) or p.query or p.fragment or p.path!='/webhooks/payproof151':raise InvalidData('LISTENER_HTTPS443_BINDING151')
 return url

@dataclass(frozen=True,repr=False)
class Grant151:
 profile:str;app_sha256:str;source_sha256:str;caller:str;not_before:float;expires_at:float;once_prefix:str;listener_url:str;test_only:bool;seal:object
 def validate(self,source,caller,now):
  if self.seal is not (_TEST if self.test_only else _NATIVE):raise InvalidData('TYPED_AUTHORITY151')
  if self.profile!=PROFILE or self.source_sha256!=source or self.caller!=caller:raise InvalidData('SOURCE_CALLER_SCOPE151')
  if not self.test_only and self.app_sha256!=APP:raise InvalidData('EXISTING_APPLICATION151')
  if not self.not_before<=now<self.expires_at or self.expires_at-self.not_before>600:raise InvalidData('EXPIRED_OR_UNBOUNDED151')
  if not re.fullmatch('[a-f0-9]{64}',source) or not re.fullmatch('P151-[A-Z0-9-]{1,24}',self.once_prefix):raise InvalidData('SOURCE_ONCE_BINDING151')
  require_url(self.listener_url)

class NativePorts151:
 """Bridge to the EXISTING independently qualified provider-owned109 route.

 A future exact reviewed host binding must implement release(), current_source,
 current_caller and reserve_and_readback using real provider and external Master
 CAS evidence. This base is not a vault, issuer, scheduler or working grant.
 """
 def release(self):raise InvalidData('NATIVE_CUSTODY_ADMISSION_UNBOUND151')
 def reserve_and_readback(self,key,metadata):raise InvalidData('EXTERNAL_MASTER_CAS_UNBOUND151')
 def current_source(self):raise InvalidData('NATIVE_SOURCE_UNBOUND151')
 def current_caller(self):raise InvalidData('NATIVE_CALLER_UNBOUND151')

def load_native151(ports):
 if type(ports) is not NativePorts151:raise InvalidData('NATIVE_PORT_REQUIRED151')
 # Deliberate refusal before credential/environment/network access.
 return ports.release()

class SyntheticTransport151:
 def __init__(self,replies):self.replies=list(replies);self.calls=[]
 def request(self,method,path,headers,body,timeout):
  self.calls.append((method,path));expected,status,raw=self.replies.pop(0)
  if (method,path)!=expected:raise AssertionError('UNEXPECTED_FAKE_ROUTE151')
  if isinstance(raw,Exception):raise raw
  return status,raw if isinstance(raw,bytes) else canonical(raw).encode()

class FixedSandboxNetwork151:
 def __init__(self,grant):
  if type(grant) is not Grant151 or grant.test_only or grant.seal is not _NATIVE:raise InvalidData('SYNTHETIC_NEVER_NETWORK151')
 def request(self,method,path,headers,body,timeout):
  allowed=(method=='POST' and path in ('/v1/oauth2/token','/v2/checkout/orders','/v1/notifications/webhooks','/v1/notifications/verify-webhook-signature')) or (method=='GET' and (path=='/v1/notifications/webhooks' or re.fullmatch('/v2/checkout/orders/[A-Z0-9-]{1,64}',path))) or (method=='POST' and re.fullmatch('/v2/checkout/orders/[A-Z0-9-]{1,64}/capture',path)) or (method=='DELETE' and re.fullmatch('/v1/notifications/webhooks/[A-Z0-9-]{1,64}',path))
  if not allowed:raise InvalidData('FIXED_SANDBOX_ROUTE151')
  c=http.client.HTTPSConnection('api-m.sandbox.paypal.com',timeout=min(timeout,10),context=ssl.create_default_context())
  try:
   c.request(method,path,body=body,headers=headers);r=c.getresponse();raw=r.read(1048577)
   if len(raw)>1048576 or r.status in (301,302,303,307,308):raise UnknownResult('BOUNDED_NO_REDIRECT151')
   return r.status,raw
  finally:c.close()

class Chain151:
 def __init__(self,grant,transport,ledger,*,source_sha256,caller,clock=time.time):
  if type(grant) is not Grant151:raise InvalidData('TYPED_AUTHORITY151')
  grant.validate(source_sha256,caller,clock())
  if grant.test_only and type(transport) is not SyntheticTransport151:raise InvalidData('FAKE_ONLY151')
  if not grant.test_only:
   from .sandbox_native152 import NativePorts152
   if type(transport) is not FixedSandboxNetwork151 or type(ledger) not in (NativePorts151,NativePorts152):raise InvalidData('NATIVE_PORTS151')
  self.grant=grant;self.transport=transport;self.ledger=ledger;self.source=source_sha256;self.caller=caller;self.clock=clock
  self.used={};self.first_unknown=None;self.client='';self.secret='';self.token='';self.token_until=0;self.private_returns=[]
  self.order=None;self.capture_id=None;self.webhook_id=None;self.created_subscription=False;self.evidence_context=None;self.seen={};self.verified_complete=False;self.closed=False
  self._approved=False;self._active_raw=None;self._signature_verified=False;self._may_subscribe=False
 def require(self):
  if self.closed:raise InvalidData('CLOSED151')
  if self.first_unknown:raise UnknownResult(self.first_unknown)
  self.grant.validate(self.source,self.caller,self.clock())
  if not self.grant.test_only:
   if self.ledger.current_source()!=self.source or self.ledger.current_caller()!=self.caller:raise InvalidData('CURRENT_NATIVE_BINDINGS151')
 def freeze(self):
  self.first_unknown=self.first_unknown or 'PROVIDER_OUTCOME_UNKNOWN151'
  raise UnknownResult(self.first_unknown) from None
 def credentials(self,client,secret):
  self.require()
  if self.client or not isinstance(client,str) or not isinstance(secret,str) or not client or not secret or len(client)>512 or len(secret)>512 or digest(client.encode())!=self.grant.app_sha256:raise InvalidData('CREDENTIAL_APP_SCOPE151')
  self.client,self.secret=client,secret
 def effect(self,operation,method,path,payload=None):
  self.require()
  if operation not in CAPS or self.used.get(operation,0)>=CAPS[operation]:raise InvalidData('ONCE_CONSUMED151')
  order_path='/v2/checkout/orders/'+self.order if self.order else None
  routes={'oauth':('POST','/v1/oauth2/token'),'subscription_read':('GET','/v1/notifications/webhooks'),'subscription_create':('POST','/v1/notifications/webhooks'),'order_create':('POST','/v2/checkout/orders'),'approval_read':('GET',order_path),'capture':('POST',order_path+'/capture' if order_path else None),'final_read':('GET',order_path),'verify':('POST','/v1/notifications/verify-webhook-signature'),'event_read':('GET',order_path),'subscription_delete':('DELETE','/v1/notifications/webhooks/'+self.webhook_id if self.webhook_id else None)}
  if (method,path)!=routes[operation] or routes[operation][1] is None:raise InvalidData('OPERATION_ROUTE_BINDING151')
  create_payload={'intent':'CAPTURE','purchase_units':[{'amount':{'value':'1.00','currency_code':'USD'}}]}
  if operation=='order_create' and (payload!=create_payload or self.order or not self.evidence_context):raise InvalidData('EXACT_CREATE_SCOPE151')
  if operation=='capture' and (not self._approved or payload!={}):raise InvalidData('CAPTURE_APPROVAL_SCOPE151')
  if operation=='subscription_create' and (not self._may_subscribe or payload!={'url':self.grant.listener_url,'event_types':[{'name':EVENT}]}):raise InvalidData('SUBSCRIPTION_SCOPE151')
  if operation=='subscription_delete' and (not self.created_subscription or not self.verified_complete):raise InvalidData('SUBSCRIPTION_CLEANUP_SCOPE151')
  if operation=='final_read' and not self.capture_id:raise InvalidData('FINAL_READ_CAPTURE_SCOPE151')
  if operation=='event_read' and not self._signature_verified:raise InvalidData('EVENT_READ_SIGNATURE_SCOPE151')
  if operation=='verify' and (not self._active_raw or not isinstance(payload,bytes) or not payload.endswith(b', "webhook_event": '+self._active_raw+b'}') or _json(payload).get('webhook_id')!=self.webhook_id):raise InvalidData('EXACT_RAW_VERIFY_SCOPE151')
  if operation!='oauth' and (not self.token or self.clock()>=self.token_until):raise InvalidData('OAUTH_NOT_CURRENT151')
  metadata={'profile':PROFILE,'app_sha256':self.grant.app_sha256,'source_sha256':self.source,'caller':self.caller,'target_sha256':digest(path.encode()),'operation':operation,'fake_usd':'1.00','real_usd':'0.00','expires_at':self.grant.expires_at}
  key=self.grant.once_prefix+':'+operation
  # Real port must CAS the existing external owned ledger and read back BEFORE I/O.
  try:receipt=self.ledger.reserve_and_readback(key,metadata)
  except UnknownResult:
   self.first_unknown='EXTERNAL_RESERVATION_UNKNOWN151';self.freeze()
  from .sandbox_native152 import NativePorts152
  matches=self.ledger.matches_receipt(receipt,key,metadata) if type(self.ledger) is NativePorts152 else receipt=={'key':key,'state':'CONSUMED','metadata':metadata}
  if not matches:
   self.first_unknown='EXTERNAL_RESERVATION_READBACK_UNKNOWN151';self.freeze()
  self.used[operation]=1
  # A durable reservation can return after expiry or a native binding change.
  # The consumed slot is retained even when no provider request may begin.
  try:
   self.require()
   if operation!='oauth' and self.clock()>=self.token_until:raise InvalidData('OAUTH_EXPIRED_AFTER_RESERVATION152')
  except Exception:
   self.first_unknown='RESERVATION_LATE_OR_BINDING_DRIFT152';self.freeze()
  headers={'Content-Type':'application/json'}
  if operation=='oauth':headers.update(Authorization='Basic '+base64.b64encode((self.client+':'+self.secret).encode()).decode());body=b'grant_type=client_credentials';headers['Content-Type']='application/x-www-form-urlencoded'
  else:
   headers['Authorization']='Bearer '+self.token;body=payload if isinstance(payload,bytes) else canonical(payload).encode() if payload is not None else None
   if operation in ('order_create','capture'):headers['PayPal-Request-Id']='P151-'+digest(key.encode())[:32]
  try:
   self.require()
   remaining=self.grant.expires_at-self.clock()
   if operation!='oauth':remaining=min(remaining,self.token_until-self.clock())
   if remaining<=0:raise UnknownResult('NO_POSITIVE_REQUEST_WINDOW152')
   status,raw=self.transport.request(method,path,headers,body,min(10,remaining))
   if not isinstance(raw,bytes) or len(raw)>1048576:raise UnknownResult()
   self.private_returns.append((operation,status,raw))
   self.require()
   if not 200<=status<300:raise UnknownResult()
   result=_json(raw) if raw else None
  except Exception:self.freeze()
  if operation=='verify':self._signature_verified=isinstance(result,dict) and result.get('verification_status')=='SUCCESS'
  return result
 def oauth(self):
  if not self.client or not self.secret:raise InvalidData('CUSTODY_REQUIRED151')
  r=self.effect('oauth','POST','/v1/oauth2/token')
  if not isinstance(r,dict) or not isinstance(r.get('access_token'),str) or not 0<len(r['access_token'])<=8192 or type(r.get('expires_in')) is not int or r['expires_in']<=0:self.freeze()
  self.token=r['access_token'];self.token_until=min(self.grant.expires_at,self.clock()+r['expires_in'])
 def subscription(self):
  rows=self.effect('subscription_read','GET','/v1/notifications/webhooks')
  if not isinstance(rows,dict) or not isinstance(rows.get('webhooks'),list):self.freeze()
  if any(not isinstance(w,dict) or not isinstance(w.get('event_types'),list) for w in rows['webhooks']):self.freeze()
  matches=[w for w in rows['webhooks'] if w.get('url')==self.grant.listener_url and any(isinstance(e,dict) and e.get('name')==EVENT for e in w['event_types'])]
  if len(matches)>1:raise InvalidData('AMBIGUOUS_SUBSCRIPTION151')
  if matches:r=matches[0]
  else:
   self._may_subscribe=True
   r=self.effect('subscription_create','POST','/v1/notifications/webhooks',{'url':self.grant.listener_url,'event_types':[{'name':EVENT}]});self.created_subscription=True
  if not isinstance(r,dict) or r.get('url')!=self.grant.listener_url or not isinstance(r.get('event_types'),list) or not any(isinstance(e,dict) and e.get('name')==EVENT for e in r['event_types']):self.freeze()
  try:self.webhook_id=ident(r['id'])
  except Exception:self.freeze()
  return {'webhook_id_sha256':digest(self.webhook_id.encode()),'created':self.created_subscription}
 def bind_evidence(self,context):
  self.require()
  from .sandbox_native152 import ProviderEvidence152,SyntheticProviderEvidence152
  if type(context) in (ProviderEvidence152,SyntheticProviderEvidence152):
   if context.engine is not self:raise InvalidData('EVIDENCE_CHAIN_IDENTITY152')
   context.require();self.evidence_context=context;return
  if not self.webhook_id or type(context) is not SandboxContext or context.test_only!=self.grant.test_only or context.webhook_id!=self.webhook_id or digest(context.client_id.encode())!=self.grant.app_sha256:raise InvalidData('EVIDENCE_HOST_APP_WEBHOOK151')
  context.require('orders:read');context.require('webhooks:verify');self.evidence_context=context
 def create_order(self):
  self.require()
  if self.order or not self.evidence_context:raise InvalidData('READY_EVIDENCE_BEFORE_CREATE151')
  r=self.effect('order_create','POST','/v2/checkout/orders',{'intent':'CAPTURE','purchase_units':[{'amount':{'value':'1.00','currency_code':'USD'}}]})
  try:
   order=ident(r['id']);assert r['status'] in ('CREATED','PAYER_ACTION_REQUIRED')
   links=[x['href'] for x in r.get('links',[]) if x.get('rel') in ('approve','payer-action')];assert len(links)==1
   p=urlsplit(links[0]);assert p.scheme=='https' and p.hostname=='www.sandbox.paypal.com' and p.port in (None,443) and not p.username and not p.password and p.path=='/checkoutnow' and parse_qs(p.query)=={'token':[order]} and not p.fragment
  except Exception:self.freeze()
  self.order=order;return links[0] # Private controlled Sandbox buyer step, never consumer Developer login.
 def capture_approved(self):
  self.require()
  if not self.order:raise InvalidData('REGISTERED_ORDER151')
  r=self.effect('approval_read','GET','/v2/checkout/orders/'+self.order)
  try:
   p=project_order(r,{'id':self.order,'amount':'1.00','currency':'USD'});assert r['status']=='APPROVED' and not p['captures']
  except Exception:raise InvalidData('APPROVED_MATCHING_ORDER151') from None
  self._approved=True
  r=self.effect('capture','POST','/v2/checkout/orders/'+self.order+'/capture',{})
  try:
   p=project_order(r,{'id':self.order,'amount':'1.00','currency':'USD'});assert r['status']=='COMPLETED' and len(p['captures'])==1 and p['captures'][0]['status']=='COMPLETED' and p['captures'][0]['amount']=='1.00'
   self.capture_id=p['captures'][0]['id']
  except Exception:self.freeze()
 def read_final(self):
  self.require()
  if not self.capture_id:raise InvalidData('CAPTURE_POSTCONDITION151')
  r=self.effect('final_read','GET','/v2/checkout/orders/'+self.order)
  try:
   p=project_order(r,{'id':self.order,'amount':'1.00','currency':'USD'});assert r['status']=='COMPLETED' and len(p['captures'])==1 and p['captures'][0]['id']==self.capture_id and p['captures'][0]['status']=='COMPLETED' and p['captures'][0]['amount']=='1.00'
  except Exception:self.freeze()
  return p
 def _evidence_transport(self,method,path,headers,body):
  self.require()
  if (method,path)==('POST','/v1/oauth2/token'):
   if not self.token or self.clock()>=self.token_until:raise InvalidData('CURRENT_OAUTH151')
   return {'access_token':self.token} # Same RAM token; no second OAuth dispatch.
  if (method,path)==('POST','/v1/notifications/verify-webhook-signature'):return self.effect('verify',method,path,body)
  if self.order and (method,path)==('GET','/v2/checkout/orders/'+self.order):return self.effect('event_read',method,path)
  raise InvalidData('EVIDENCE_ROUTE151')
 def inspect_event(self,raw):
  self.require()
  if not self.capture_id or not self.used.get('final_read') or not self.evidence_context:raise InvalidData('CAPTURE_READBACK_BEFORE_EVENT151')
  if not isinstance(raw,bytes) or not 0<len(raw)<=LIMIT:raise InvalidData('ORIGINAL_EVENT_BOUNDS151')
  event=_json(raw)
  try:
   resource=event['resource'];eventid=ident(event['id']);assert event['event_type']==EVENT and resource['id']==self.capture_id and resource['status']=='COMPLETED' and resource['amount']=={'value':'1.00','currency_code':'USD'} and resource['supplementary_data']['related_ids']['order_id']==self.order
  except Exception:raise InvalidData('CORRELATED_EVENT151') from None
  return eventid
 def webhook(self,store,headers,raw):
  eventid=self.inspect_event(raw)
  h=digest(raw)
  if eventid in self.seen:
   if self.seen[eventid]['raw_sha256']!=h:raise InvalidData('EVENT_BODY_DRIFT151')
   return {'disposition':'DUPLICATE_RETAINED','raw_sha256':h,'provider_calls':0}
  from .sandbox_native152 import ProviderEvidence152,SyntheticProviderEvidence152,provider_webhook152
  if type(self.evidence_context) in (ProviderEvidence152,SyntheticProviderEvidence152):
   report=provider_webhook152(self,store,headers,raw)
  else:
   adapter=SandboxPayPal(self.evidence_context,transport=self._evidence_transport)
   self._active_raw=raw
   try:report=PaymentEvidenceService(store,adapter).webhook(headers,raw)
   finally:adapter.client_id=adapter.client_secret='';self._active_raw=None
  self.seen[eventid]={'raw_sha256':h,'disposition':report['disposition']}
  if report['disposition']=='VERIFICATION_UNKNOWN':self.freeze()
  if report.get('view',{}).get('order',{}).get('state')=='COMPLETED':self.verified_complete=True
  return {'service_result':report,'raw_sha256':h,'parsed_order_hash_is_not_original_bytes':True,'authentic_runtime':not self.grant.test_only}
 def cleanup_subscription(self):
  self.require()
  if not self.created_subscription or not self.webhook_id or not self.verified_complete:raise InvalidData('NEW_VERIFIED_SUBSCRIPTION_CLEANUP_ONLY151')
  self.effect('subscription_delete','DELETE','/v1/notifications/webhooks/'+self.webhook_id)
 def close(self):
  self.client=self.secret=self.token='';self.token_until=0;self.private_returns.clear();self.evidence_context=None;self._active_raw=None;self.closed=True
 def export(self):
  return {'schema':'PAYPROOF151_CHAIN_RECEIPT','synthetic':self.grant.test_only,'native_admission':not self.grant.test_only,'completed_evidence':self.verified_complete,'first_unknown':self.first_unknown,'used_operations':dict(self.used),'app_sha256':self.grant.app_sha256,'source_sha256':self.source,'order_id_sha256':digest(self.order.encode()) if self.order else None,'capture_id_sha256':digest(self.capture_id.encode()) if self.capture_id else None,'payment_actions_in_product':[],'credentials_exported':False,'cleanup_credentials_dropped':self.closed,'raw_HTTP_exported':False}

def synthetic_grant151(*,source,caller,now,app_sha256,listener_url):
 """Explicit TEST_ONLY capability; never usable with FixedSandboxNetwork151."""
 return Grant151(PROFILE,app_sha256,source,caller,now-1,now+300,'P151-SYNTHETIC-TEST',listener_url,True,_TEST)
