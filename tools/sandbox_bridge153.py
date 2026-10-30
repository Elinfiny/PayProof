"""Private, bounded receiver independent of PayPal OAuth/engine; dormant source.

Ephemeral token is a temporary application password, never issuer/provider key.
No real token is generated here. Native loads it only from protected environment.
"""
import base64,hashlib,hmac,json,os,pathlib,re,sqlite3,threading,time
from dataclasses import dataclass
from urllib.parse import urlsplit
from payproof.admission import _json
from .sandbox_chain151 import APP,EVENT,LIMIT,InvalidData,UnknownResult,canonical,ident
from .sandbox_ingress152 import LocalSignature152,SyntheticSignature152
from .sandbox_listener151 import EventInbox151

PRIVATE='/private/payproof153'
WEBHOOK='/webhooks/payproof151'
LIVE153=True

def source153(s):
 if not isinstance(s,str) or not re.fullmatch('[a-f0-9]{40}',s):raise InvalidData('SOURCE153')
 return s

def origin153(s):
 try:p=urlsplit(s)
 except (ValueError,TypeError):raise InvalidData('MANAGED_ORIGIN153') from None
 if p.scheme!='https' or not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}\.onrender\.com',p.netloc) or p.path or p.query or p.fragment:raise InvalidData('MANAGED_ORIGIN153')
 return s

@dataclass(frozen=True,repr=False)
class Scope153:
 source:str;session:str;app_sha256:str;origin:str;service_id:str;issued_at:float;expires_at:float;test_only:bool
 def require(self,now):
  source153(self.source);origin153(self.origin)
  if (not self.test_only and self.app_sha256!=APP) or not re.fullmatch('[a-f0-9]{64}',self.app_sha256) or not re.fullmatch('P153-[A-Z0-9-]{1,32}',self.session) or not re.fullmatch('srv-[a-z0-9]{10,40}',self.service_id):raise InvalidData('SCOPE153')
  if type(self.issued_at) not in (int,float) or type(self.expires_at) not in (int,float) or not self.issued_at<=now<self.expires_at or not 0<self.expires_at-self.issued_at<=600:raise InvalidData('CAPABILITY_EXPIRED153')
 def public(self):return {'source':self.source,'session':self.session,'app_sha256':self.app_sha256,'origin':self.origin,'service_id':self.service_id,'expires_at':self.expires_at}

class Capability153:
 def __init__(self,scope,token,clock=time.time):
  if type(scope) is not Scope153:raise InvalidData('TYPED_SCOPE153')
  scope.require(clock())
  if not isinstance(token,str) or not re.fullmatch('[A-Za-z0-9_-]{43,128}',token):raise InvalidData('TOKEN_ENTROPY_ENCODING153')
  self.scope=scope;self._token=token.encode();self.clock=clock;self.closed=False
 def authenticate(self,headers):
  if self.closed:raise InvalidData('CAPABILITY_CLOSED153')
  self.scope.require(self.clock());candidate=headers.get('authorization','')
  if not isinstance(candidate,str) or len(candidate)>160 or not hmac.compare_digest(candidate.encode(),b'Bearer '+self._token):raise InvalidData('PRIVATE_AUTH153')
  if headers.get('x-payproof-session')!=self.scope.session or headers.get('x-payproof-source')!=self.scope.source or headers.get('x-payproof-service')!=self.scope.service_id:raise InvalidData('PRIVATE_SCOPE153')
 def close(self):self.closed=True;self._token=b''
 def __repr__(self):return '<Capability153 REDACTED>'

@dataclass(frozen=True,repr=False)
class ManagedIngress153:
 """Provider-owned deployment metadata + actual Master service readback, no XFP."""
 scope:Scope153;port:int
 @classmethod
 def native(cls,config,env):
  if not LIVE153:raise InvalidData('NATIVE153_INACTIVE')
  origin=origin153(env.get('RENDER_EXTERNAL_URL','').rstrip('/'));source=source153(env.get('RENDER_GIT_COMMIT',''))
  service=env.get('RENDER_SERVICE_ID','');port=int(env.get('PORT','0'))
  if env.get('RENDER')!='true' or not 1024<=port<=65535 or config.get('source')!=source or config.get('origin') not in (None,origin) or config.get('service_id') not in (None,service):raise InvalidData('NATIVE_RENDER_BINDING153')
  scope=Scope153(source,config['session'],APP,origin,service,config['issued_at'],config['expires_at'],False);scope.require(time.time());return cls(scope,port)
 def require(self,host):
  self.scope.require(time.time())
  if host!=urlsplit(self.scope.origin).hostname:raise InvalidData('EXACT_HOST153')
  # Backend $PORT is platform-private. Master must verify the created service's
  # managed HTTPS redirect/URL/source/Free settings before any native witness.

class Receiver153:
 def __init__(self,capability,inbox,*,signature=None):
  if type(capability) is not Capability153 or type(inbox) is not EventInbox151:raise InvalidData('PRIVATE_RECEIVER_PORTS153')
  if signature is not None and (not capability.scope.test_only or type(signature) is not SyntheticSignature152):raise InvalidData('FAKE_SIGNATURE_NEVER_NATIVE153')
  self.cap=capability;self.scope=capability.scope;self.inbox=inbox;self.signature=signature;self.run_id=None;self.webhook_id=None;self.order_id=None;self.approval=None;self.report=None;self.closed=False;self.buyer_ack=False;self.first_unknown=None;self.lock=threading.Lock();self.counts={};self.raw_reads=0
 def _require(self):
  if self.closed:raise InvalidData('RECEIVER_CLOSED153')
  self.scope.require(self.cap.clock())
  if self.first_unknown:raise UnknownResult(self.first_unknown)
 def _run(self,h):
  r=h.get('x-payproof-run','')
  if not re.fullmatch('[1-9][0-9]{0,19}',r) or self.run_id not in (None,r):raise InvalidData('PRIVATE_RUN153')
  return r
 def _once(self,name):
  if self.counts.get(name):raise InvalidData('BRIDGE_ONCE_CONSUMED153')
  self.counts[name]=1
 def _json(self,value):return canonical(value).encode()
 def _private(self,method,path,h,body):
  self.cap.authenticate(h);self._require()
  # Authenticated metadata is available before a job exists; it never binds a run.
  if method=='GET' and path==PRIVATE+'/ready':
   if 'x-payproof-run' in h:self._run(h)
   return 200,self._json(dict(self.scope.public(),issued_at=self.scope.issued_at,bound=self.run_id is not None,webhook_ready=self.webhook_id is not None,order_ready=self.order_id is not None,run_id=self.run_id)),{}
  run=self._run(h)
  if method=='POST' and path==PRIVATE+'/bootstrap':
   p=_json(body)
   if p!={'app_sha256':self.scope.app_sha256,'source':self.scope.source,'run_id':run,'session':self.scope.session,'service_id':self.scope.service_id,'expires_at':self.scope.expires_at}:raise InvalidData('BOOTSTRAP_BINDING153')
   self._once('bootstrap');self.run_id=run;return 201,b'{"state":"BOOTSTRAPPED"}',{}
  if self.run_id!=run:raise InvalidData('BOOTSTRAP_BEFORE_DEPENDENCIES153')
  if method=='POST' and path==PRIVATE+'/webhook':
   p=_json(body)
   if set(p)!={'webhook_id'}:raise InvalidData('WEBHOOK_CONFIG153')
   hook=ident(p['webhook_id']);self._once('webhook');self.webhook_id=hook
   if self.signature is None:self.signature=LocalSignature152(hook)
   elif self.signature.webhook_id!=hook:raise InvalidData('FAKE_WEBHOOK_BINDING153')
   return 201,b'{"state":"WEBHOOK_BOUND"}',{}
  if method=='POST' and path==PRIVATE+'/order':
   if not self.webhook_id:raise InvalidData('WEBHOOK_BEFORE_ORDER153')
   p=_json(body)
   if set(p)!={'order_id','approval_url'}:raise InvalidData('ORDER_CONFIG153')
   order=ident(p['order_id']);u=urlsplit(p['approval_url'])
   if u.scheme!='https' or u.netloc!='www.sandbox.paypal.com' or u.path!='/checkoutnow' or u.query!='token='+order or u.fragment:raise InvalidData('AUTHENTIC_SANDBOX_APPROVAL153')
   self._once('order');self.order_id=order;self.approval=p['approval_url'];return 201,b'{"state":"ORDER_BOUND_BEFORE_BUYER"}',{}
  if method=='GET' and path==PRIVATE+'/event':
   if not self.order_id:raise InvalidData('ORDER_BEFORE_POLL153')
   self.raw_reads+=1
   if self.raw_reads>24:raise InvalidData('READONLY_POLL_BOUND153')
   with sqlite3.connect(self.inbox.path) as db:row=db.execute('SELECT raw,headers,digest FROM inbox LIMIT 1').fetchone()
   if row is None:return 204,b'',{}
   raw,headers,d=row
   return 200,self._json({'raw_base64':base64.b64encode(raw).decode(),'headers':json.loads(headers),'sha256':d}),{}
  if method=='POST' and path==PRIVATE+'/buyer-ack':
   if not self.approval or body!=b'{}':raise InvalidData('BUYER_ACK153')
   self._once('buyer_ack');self.buyer_ack=True;return 201,b'{"state":"BUYER_GESTURE_REPORTED_NOT_PROVIDER_PROOF"}',{}
  if method=='GET' and path==PRIVATE+'/buyer-status':return 200,self._json({'acknowledged':self.buyer_ack,'is_payment_proof':False}),{}
  if path.startswith(PRIVATE+'/evidence-'):
   op=path[len(PRIVATE+'/evidence-'):]
   if op not in ('order_create','capture','final_read','verify','event_read'):raise InvalidData('EVIDENCE_OPERATION153')
   with sqlite3.connect(self.inbox.path) as db:
    db.execute('CREATE TABLE IF NOT EXISTS originals153 (operation TEXT PRIMARY KEY, status INTEGER, raw BLOB, sha256 TEXT)')
    if method=='POST':
     p=_json(body)
     if set(p)!={'status','raw_base64','sha256'} or type(p['status']) is not int or not 100<=p['status']<=599:raise InvalidData('PRIVATE_ORIGINAL153')
     raw=base64.b64decode(p['raw_base64'],validate=True)
     if self.cap._token in raw or any(label in raw.lower() for label in (b'"access_token"',b'"client_secret"')):raise InvalidData('SECRET_IN_PRIVATE_ORIGINAL153')
     if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=p['sha256']:raise InvalidData('ORIGINAL_HASH153')
     self._once('evidence-'+op)
     db.execute('INSERT INTO originals153 VALUES (?,?,?,?)',(op,p['status'],raw,p['sha256']));return 201,b'{"state":"PRIVATE_ORIGINAL_RETAINED"}',{}
    if method=='GET':
     key='read-original-'+op;self.counts[key]=self.counts.get(key,0)+1
     if self.counts[key]>2:raise InvalidData('ORIGINAL_READ_BOUND153')
     r=db.execute('SELECT status,raw,sha256 FROM originals153 WHERE operation=?',(op,)).fetchone()
     if r is None:return 204,b'',{}
     return 200,self._json({'operation':op,'status':r[0],'raw_base64':base64.b64encode(r[1]).decode(),'sha256':r[2]}),{}
   raise InvalidData('ORIGINAL_METHOD153')
  if method=='GET' and path==PRIVATE+'/buyer':
   if not self.approval:raise InvalidData('BUYER_NOT_READY153')
   return 200,self._json({'approval_url':self.approval,'order_sha256':hashlib.sha256(self.order_id.encode()).hexdigest()}),{}
  if method=='POST' and path==PRIVATE+'/report':
   p=_json(body)
   if set(p)!={'state','event_sha256','order_sha256','capture_sha256','first_unknown','cleanup'} or p['state'] not in ('COMPLETED','UNKNOWN','REFUSED'):raise InvalidData('SANITIZED_REPORT153')
   for k in ('event_sha256','order_sha256','capture_sha256'):
    if p[k] is not None and not re.fullmatch('[a-f0-9]{64}',p[k]):raise InvalidData('SANITIZED_HASH153')
   if p['first_unknown'] not in (None,'NATIVE_CHAIN_UNKNOWN153','BRIDGE_UNKNOWN153'):raise InvalidData('SANITIZED_CAUSE153')
   if p['cleanup'] not in ('NEW_SUBSCRIPTION_DELETED','PRESERVED_EXISTING','UNKNOWN_NO_PROVIDER_CLEANUP','NOT_COMPLETED'):raise InvalidData('SANITIZED_CLEANUP153')
   self._once('report');self.report=p;return 201,b'{"state":"REPORT_RETAINED"}',{}
  if method=='GET' and path==PRIVATE+'/report':return 200,self._json({'report':self.report,'event_retained':self._has_event(),'counts':self.counts,'closed':self.closed}),{}
  if method=='POST' and path==PRIVATE+'/close':
   if body!=b'{}':raise InvalidData('CLOSE153')
   self._once('close');self.close();return 200,b'{"state":"CLOSED_DATA_AND_TOKEN_DROPPED"}',{}
  raise InvalidData('PRIVATE_ROUTE153')
 def _has_event(self):
  with sqlite3.connect(self.inbox.path) as db:return db.execute('SELECT count(*) FROM inbox').fetchone()[0]==1
 def _event(self,h,body):
  if not self.order_id or not self.webhook_id:raise InvalidData('BOOTSTRAP_ORDER_REQUIRED153')
  if h.get('content-type','').split(';')[0].strip()!='application/json' or h.get('content-length')!=str(len(body)) or not 0<len(body)<=LIMIT:raise InvalidData('RAW_ENVELOPE153')
  event=_json(body)
  try:
   resource=event['resource'];ident(event['id']);ident(resource['id'])
   if event['event_type']!=EVENT or resource['status']!='COMPLETED' or resource['amount']!={'value':'1.00','currency_code':'USD'} or resource['supplementary_data']['related_ids']['order_id']!=self.order_id:raise ValueError()
  except (KeyError,ValueError,TypeError):raise InvalidData('WRONG_ORDER_EVENT153') from None
  names=('paypal-auth-algo','paypal-cert-url','paypal-transmission-id','paypal-transmission-sig','paypal-transmission-time')
  safe={k:h[k] for k in names if k in h}
  if len(safe)!=5 or not self.signature.verify(safe,body):return 400,b'{"state":"INVALID_SIGNATURE_NO_SLOT"}',{}
  # Retain BEFORE ACK, independent of CAPTURE-return timing in the worker.
  key,new=self.inbox.retain(body,safe);return 202,self._json({'state':'RETAINED' if new else 'DUPLICATE_RETAINED','sha256':key}),{}
 def handle(self,method,path,header_pairs,body):
  if not self.lock.acquire(False):return 503,b'{"state":"BUSY_NO_SLOT"}',{}
  try:
   self._require();h={}
   if len(header_pairs)>32 or sum(len(k)+len(v) for k,v in header_pairs)>16384:raise InvalidData('HEADER_LIMIT153')
   for k,v in header_pairs:
    k=k.lower()
    if k in h or not isinstance(v,str) or len(v)>4096:raise InvalidData('DUPLICATE_HEADER153')
    h[k]=v
   if h.get('host')!=urlsplit(self.scope.origin).hostname or 'transfer-encoding' in h or '?' in path or '#' in path:raise InvalidData('EXACT_ENDPOINT153')
   if not isinstance(body,bytes) or len(body)>(1400000 if path.startswith(PRIVATE+'/evidence-') else 98304):raise InvalidData('BODY_BOUND153')
   if method=='POST' and h.get('content-length')!=str(len(body)):raise InvalidData('LENGTH153')
   if path.startswith(PRIVATE+'/'):return self._private(method,path,h,body)
   if method=='POST' and path==WEBHOOK:return self._event(h,body)
   raise InvalidData('NO_PUBLIC_PAYMENT_OR_RAW_ROUTE153')
  finally:self.lock.release()
 def close(self):
  self.closed=True;self.approval=None;self.order_id=None;self.webhook_id=None;self.signature=None;self.cap.close()
  # Ephemeral owner-private inbox only, no provider deletion or consumed reset.
  p=pathlib.Path(self.inbox.path)
  for suffix in ('','-journal','-wal','-shm'):
   q=pathlib.Path(str(p)+suffix)
   if q.exists():q.unlink()
 def export(self):return {'source':self.scope.source,'service_id':self.scope.service_id,'closed':self.closed,'run_bound':self.run_id is not None,'counts':dict(self.counts),'first_unknown':self.first_unknown,'raw_or_token_exported':False}
