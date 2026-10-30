"""Private bounded event receiver and optional TLS443 server, inactive by default."""
import hashlib,http.server,ipaddress,json,os,pathlib,sqlite3,ssl,threading
from .sandbox_http152 import BoundedHTTP152,Handler152
from .sandbox_ingress152 import LocalSignature152,SyntheticSignature152
from .sandbox_chain151 import InvalidData,UnknownResult,LIMIT,require_url

class NativeProxy151:
 """No public request header or callback can qualify a native TLS terminator."""
 def authorized_peer(self,peer,hostname):raise InvalidData('PROVIDER_TLS_PROXY_ADMISSION_UNBOUND151')

class EventInbox151:
 """Private byte-preserving inbox. Local storage is NOT an external once ledger."""
 def __init__(self,path):
  p=pathlib.Path(path)
  if p.parent.stat().st_mode&0o077:raise InvalidData('PRIVATE_INBOX_DIRECTORY151')
  fd=os.open(p,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
  try:
   import stat
   s=os.fstat(fd)
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise InvalidData('PRIVATE_INBOX_FILE151')
  finally:os.close(fd)
  self.path=str(p)
  with sqlite3.connect(self.path) as db:db.execute('CREATE TABLE IF NOT EXISTS inbox (digest TEXT PRIMARY KEY, raw BLOB NOT NULL, headers TEXT NOT NULL, state TEXT NOT NULL)')
 def retain(self,raw,headers):
  key=hashlib.sha256(raw).hexdigest()
  with sqlite3.connect(self.path) as db:
   db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT raw,headers FROM inbox WHERE digest=?',(key,)).fetchone()
   if row:
    if row[0]!=raw:raise InvalidData('INBOX_BINDING151')
    return key,False
   if db.execute('SELECT count(*) FROM inbox').fetchone()[0]>=1:raise InvalidData('ONE_EVENT_INBOX_BOUND151')
   db.execute('INSERT INTO inbox VALUES (?,?,?,?)',(key,raw,json.dumps(headers,sort_keys=True),'RECEIVED_UNVERIFIED'))
  return key,True
 def finish(self,key,state):
  with sqlite3.connect(self.path) as db:db.execute('UPDATE inbox SET state=? WHERE digest=?',(state,key))

class Receiver151:
 def __init__(self,chain,store,inbox,*,proxy_provenance=None,signature_prefilter=None):
  if proxy_provenance is not None and type(proxy_provenance) is not NativeProxy151:raise InvalidData('TYPED_NATIVE_PROXY151')
  if signature_prefilter is not None and type(signature_prefilter) not in (LocalSignature152,SyntheticSignature152):raise InvalidData('TYPED_SIGNATURE_PREFILTER152')
  if not chain.grant.test_only and (type(signature_prefilter) is not LocalSignature152 or signature_prefilter.webhook_id!=chain.webhook_id):raise InvalidData('NATIVE_SIGNATURE_PREFILTER_REQUIRED152')
  self.signature_prefilter=signature_prefilter;self._receive_lock=threading.Lock()
  self.chain=chain;self.store=store;self.inbox=inbox;self.proxy_provenance=proxy_provenance
 def receive(self,method,path,header_pairs,body,*,tls_verified=False,peer=None):
  if not self._receive_lock.acquire(blocking=False):return {'status':503,'state':'BUSY_NO_SLOT_CONSUMED152'}
  try:return self._receive(method,path,header_pairs,body,tls_verified=tls_verified,peer=peer)
  finally:self._receive_lock.release()
 def _receive(self,method,path,header_pairs,body,*,tls_verified=False,peer=None):
  self.chain.require()
  url=require_url(self.chain.grant.listener_url)
  from urllib.parse import urlsplit
  expected=urlsplit(url)
  if len(header_pairs)>32 or sum(len(k)+len(v) for k,v in header_pairs)>16384:raise InvalidData('TOTAL_HEADER_BOUNDS151')
  if method!='POST' or path!=expected.path:raise InvalidData('LISTENER_POST_PATH151')
  # A request's X-Forwarded-Proto is never a TLS authority signal.
  if not tls_verified and not (self.proxy_provenance and self.proxy_provenance.authorized_peer(peer,expected.hostname)):raise InvalidData('TLS443_PROVENANCE151')
  headers={}
  for k,v in header_pairs:
   k=k.lower()
   if k in headers or not isinstance(v,str) or len(v)>4096:raise InvalidData('HEADER_DUPLICATE_OR_BOUNDS151')
   headers[k]=v
  if headers.get('host') not in (expected.hostname,expected.hostname+':443') or headers.get('content-type','').split(';')[0].strip()!='application/json' or 'transfer-encoding' in headers:raise InvalidData('LISTENER_ENVELOPE151')
  if not isinstance(body,bytes) or not 0<len(body)<=LIMIT or headers.get('content-length')!=str(len(body)):raise InvalidData('RAW_EVENT_LENGTH151')
  signature_fields=['paypal-auth-algo','paypal-cert-url','paypal-transmission-id','paypal-transmission-sig','paypal-transmission-time']
  if any(not headers.get(k) for k in signature_fields):raise InvalidData('SIGNED_HEADERS151')
  # A concrete native prefilter only fetches bounded certificates from fixed
  # Sandbox PayPal origins with Web PKI; never an arbitrary header URL.
  self.chain.inspect_event(body)
  safe_headers={k:headers[k] for k in signature_fields}
  if self.signature_prefilter is not None and not self.signature_prefilter.verify(safe_headers,body):return {'status':400,'state':'INVALID_SIGNATURE_NO_INBOX_OR_API_SLOT152'}
  key,new=self.inbox.retain(body,safe_headers)
  if not new:return {'status':202,'state':'RETAINED_DUPLICATE_NO_PROVIDER_CALL','sha256':key}
  try:
   result=self.chain.webhook(self.store,safe_headers,body)
   state='VERIFIED_COMPLETE' if self.chain.verified_complete else 'NOT_VERIFIED'
   self.inbox.finish(key,state);return {'status':200 if state=='VERIFIED_COMPLETE' else 202,'state':state,'sha256':key}
  except UnknownResult:
   self.inbox.finish(key,'UNKNOWN_NO_RETRY');return {'status':202,'state':'UNKNOWN_NO_RETRY','sha256':key}
  except Exception:
   self.inbox.finish(key,'REJECTED_NO_PROMOTION');raise

def server151(receiver,*,host,port,tls_context=None,qualified_proxy=None):
 """An admitted existing TLS context or qualified provider proxy is mandatory."""
 if tls_context is None and qualified_proxy is None:raise InvalidData('DEPLOY_TLS_ADMISSION_REQUIRED151')
 if not receiver.chain.grant.test_only and tls_context is not None and port!=443:raise InvalidData('NATIVE_TLS_PORT443151')
 if qualified_proxy is not None and receiver.proxy_provenance is not qualified_proxy:raise InvalidData('EXACT_PROXY_CAPABILITY151')
 class Handler(Handler152):
  def log_message(self,*args):pass
  def do_POST(self):
   self.connection.settimeout(5)
   try:
    if len(self.headers.get_all('Content-Length',[]))!=1:raise InvalidData('CONTENT_LENGTH151')
    size=int(self.headers['Content-Length'])
    if not 0<size<=LIMIT:raise InvalidData('BODY_LIMIT151')
    body=self.rfile.read(size)
    if len(body)!=size:raise InvalidData('TRUNCATED_BODY152')
    result=receiver.receive('POST',self.path,list(self.headers.items()),body,tls_verified=isinstance(self.connection,ssl.SSLSocket),peer=self.client_address[0])
    status=result.pop('status');data=json.dumps(result).encode()
   except (InvalidData,ValueError):status=400;data=b'{"state":"REJECTED_NO_PROMOTION"}'
   except Exception:status=503;data=b'{"state":"UNKNOWN_NO_RETRY"}'
   self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 server=BoundedHTTP152((host,port),Handler,tls_context=tls_context)
 return server

if __name__=='__main__':raise SystemExit('INACTIVE151: exact independent native admission/custody/TLS/once binding required; no automatic start')
