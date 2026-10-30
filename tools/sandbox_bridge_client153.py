"""Single fixed HTTPS private channel. Secret never in URL/log/export."""
import base64,hashlib,http.client,json,ssl,time
from .sandbox_bridge153 import PRIVATE,Scope153,Capability153,InvalidData,UnknownResult
from .sandbox_chain151 import canonical

BOUNDS={'ready':8,'bootstrap':1,'webhook':1,'order':1,'event':24,'buyer':8,'buyer-status':60,'buyer-ack':1,'report_post':1,'report':4,'close':1}
for _op in ('order_create','capture','final_read','verify','event_read'):BOUNDS['evidence-'+_op]=1
class SyntheticBridgeTransport153:
 def __init__(self,receiver):self.receiver=receiver;self.calls=[]
 def request(self,method,path,headers,body,timeout):
  self.calls.append((method,path));status,raw,_=self.receiver.handle(method,path,list(headers.items()),body or b'');return status,raw
class FixedBridgeHTTPS153:
 def __init__(self,scope):
  if type(scope) is not Scope153 or scope.test_only:raise InvalidData('FAKE_NEVER_HTTPS153')
  self.scope=scope
 def request(self,method,path,headers,body,timeout):
  if not path.startswith(PRIVATE+'/') or '?' in path or '#' in path:raise InvalidData('FIXED_PRIVATE_PATH153')
  c=http.client.HTTPSConnection(self.scope.origin[8:],timeout=min(5,timeout),context=ssl.create_default_context())
  try:
   c.request(method,path,headers=headers,body=body);r=c.getresponse();raw=r.read(114689)
   if len(raw)>114688 or r.status in (301,302,303,307,308):raise UnknownResult('PRIVATE_RESPONSE_BOUND153')
   return r.status,raw
  finally:c.close()
class BridgeClient153:
 def __init__(self,scope,token,run_id,transport,*,clock=time.time,sleeper=time.sleep):
  self.cap=Capability153(scope,token,clock);self.scope=scope;self.run_id=str(run_id);self.transport=transport;self.clock=clock;self.sleeper=sleeper;self.counts={};self.first_unknown=None;self.closed=False
  import re
  if not re.fullmatch('[1-9][0-9]{0,19}',self.run_id):raise InvalidData('RUN153')
  if type(transport) is not (SyntheticBridgeTransport153 if scope.test_only else FixedBridgeHTTPS153):raise InvalidData('TYPED_BRIDGE_TRANSPORT153')
 def _call(self,name,method='GET',payload=None):
  if self.closed or self.first_unknown:raise UnknownResult('BRIDGE_FROZEN153')
  self.scope.require(self.clock());key='report_post' if name=='report' and method=='POST' else name
  if key not in BOUNDS or self.counts.get(key,0)>=BOUNDS[key]:raise InvalidData('PRIVATE_CALL_BUDGET153')
  self.counts[key]=self.counts.get(key,0)+1
  # The value remains in this process and the HTTPS Authorization header only.
  headers={'Authorization':'Bearer '+self.cap._token.decode(),'X-PayProof-Run':self.run_id,'X-PayProof-Session':self.scope.session,'X-PayProof-Source':self.scope.source,'X-PayProof-Service':self.scope.service_id,'Host':self.scope.origin[8:],'Content-Type':'application/json'}
  body=canonical(payload).encode() if payload is not None else b''
  headers['Content-Length']=str(len(body))
  try:
   status,raw=self.transport.request(method,PRIVATE+'/'+name,headers,body,min(5,self.scope.expires_at-self.clock()));self.scope.require(self.clock())
   if status==204:return None
   if status not in (200,201):raise UnknownResult('PRIVATE_RESPONSE_REFUSAL153')
   if not isinstance(raw,bytes) or len(raw)>114688:raise UnknownResult('PRIVATE_BODY_BOUND153')
   return json.loads(raw)
  except Exception:
   self.first_unknown='BRIDGE_UNKNOWN153';raise UnknownResult(self.first_unknown) from None
 def readiness(self):
  r=self._call('ready')
  for k,v in self.scope.public().items():
   if r.get(k)!=v:raise InvalidData('READINESS_BINDING153')
  if r.get('run_id') not in (None,self.run_id):raise InvalidData('READINESS_RUN153')
  return r
 def bootstrap(self):return self._call('bootstrap','POST',{'source':self.scope.source,'app_sha256':self.scope.app_sha256,'session':self.scope.session,'service_id':self.scope.service_id,'run_id':self.run_id,'expires_at':self.scope.expires_at})
 def webhook(self,webhook_id):return self._call('webhook','POST',{'webhook_id':webhook_id})
 def order(self,order_id,approval_url):return self._call('order','POST',{'order_id':order_id,'approval_url':approval_url})
 def await_buyer(self):
  for n in range(60):
   r=self._call('buyer-status')
   if r.get('acknowledged') is True:return r
   if n<59:
    if self.scope.expires_at-self.clock()<=2:raise InvalidData('NO_BUYER_WINDOW153')
    self.sleeper(2)
  raise InvalidData('BUYER_NOT_ACKNOWLEDGED_NO_CAPTURE153')
 def event(self):
  r=self._call('event')
  if r is None:return None
  raw=base64.b64decode(r['raw_base64'],validate=True)
  if not 0<len(raw)<=65536 or hashlib.sha256(raw).hexdigest()!=r['sha256'] or not isinstance(r.get('headers'),dict):raise InvalidData('ORIGINAL_TRANSFER_BINDING153')
  return r['headers'],raw
 def poll_event(self):
  for n in range(24):
   r=self.event()
   if r is not None:return r
   if n<23:
    if self.scope.expires_at-self.clock()<=2:raise InvalidData('NO_POLL_WINDOW153')
    self.sleeper(2)
  raise InvalidData('NO_EVENT_NOT_CAPTURE_SUCCESS153')
 def original(self,operation,status,raw):return self._call('evidence-'+operation,'POST',{'status':status,'raw_base64':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()})
 def report(self,r):return self._call('report','POST',r)
 def close_remote(self):
  r=self._call('close','POST',{});self.close();return r
 def close(self):self.closed=True;self.cap.close()
 def export(self):return {'counts':dict(self.counts),'first_unknown':self.first_unknown,'closed':self.closed,'token_or_raw_exported':False}
