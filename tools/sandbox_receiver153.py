"""Callable managed receiver entry, finite lifetime, no PayPal credentials."""
import hashlib,http.cookies,json,os,pathlib,signal,ssl,threading,time
from urllib.parse import parse_qs
from .sandbox_http152 import BoundedHTTP152,Handler152
from .sandbox_bridge153 import (Capability153,ManagedIngress153,Receiver153,EventInbox151,PRIVATE,InvalidData,UnknownResult)

class Server153(BoundedHTTP152):
 def __init__(self,address,receiver,*,managed=None,tls_context=None):
  if not receiver.scope.test_only and (type(managed) is not ManagedIngress153 or managed.scope!=receiver.scope or address!=('0.0.0.0',managed.port) or tls_context is not None):raise InvalidData('MANAGED_BACKEND153')
  if receiver.scope.test_only and address[0]!='127.0.0.1':raise InvalidData('TEST_LOOPBACK_ONLY153')
  self.receiver=receiver;self.managed=managed;self.accepted=0;super().__init__(address,self.handler153(),tls_context=tls_context)
 def get_request(self):
  conn,peer=super().get_request();self.accepted+=1
  if self.accepted>512 or self.receiver.closed:
   conn.close();raise OSError('CONNECTION_BUDGET153')
  return conn,peer
 def handle_error(self,request,client_address):pass # no raw headers/credentials/exception locals in provider logs
 def handler153(self):
  receiver=self.receiver;managed=self.managed
  class Handler(Handler152):
   def parse_request(self):
    ok=super().parse_request()
    if ok:self._bounded_raw.limit=16384+(1400000 if self.path.startswith(PRIVATE+'/evidence-') else 98304)
    return ok
   def _response(self,status,body,extra=None):
    self.send_response(status)
    for k,v in {'Content-Type':'application/json','Content-Length':str(len(body)),'Cache-Control':'no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; form-action 'self'; frame-ancestors 'none'",**(extra or {})}.items():self.send_header(k,v)
    self.end_headers();self.wfile.write(body)
   def _handle(self):
    try:
     if self.command=='GET' and self.path=='/healthz':
      self._response(503 if receiver.closed else 200,b'{"transport_only":true}');return
     if managed:managed.require(self.headers.get('Host',''))
     elif not isinstance(self.connection,ssl.SSLSocket):raise InvalidData('TEST_TLS_REQUIRED153')
     pairs=list(self.headers.items());h={k.lower():v for k,v in pairs};method=self.command;path=self.path
     if len(h)!=len(pairs) or len(pairs)>32 or sum(len(k)+len(v) for k,v in pairs)>16384:raise InvalidData('HEADER_BOUND153')
     if '?' in path or '#' in path or 'transfer-encoding' in h:raise InvalidData('NO_QUERY_OR_TE153')
     if method=='POST':
      if len(self.headers.get_all('Content-Length',[]))!=1:raise InvalidData('LENGTH153')
      size=int(h.get('content-length','0'))
      if not 0<size<=(1400000 if path.startswith(PRIVATE+'/evidence-') else 65536 if path=='/webhooks/payproof151' else 98304):raise InvalidData('BODY_BOUND153')
      body=self.rfile.read(size)
      if len(body)!=size:raise InvalidData('TRUNCATED153')
     else:body=b''
     # Native browser-only private portal: the token is entered by Owner, never URL.
     if (path in (PRIVATE+'/portal',PRIVATE+'/login',PRIVATE+'/ready',PRIVATE+'/buyer-ack',PRIVATE+'/close') or path.startswith(PRIVATE+'/evidence-')) and 'authorization' not in h:
      if h.get('host')!=receiver.scope.origin[8:]:raise InvalidData('PORTAL_HOST153')
      if method=='POST' and path==PRIVATE+'/login':
       if h.get('origin')!=receiver.scope.origin:raise InvalidData('PORTAL_ORIGIN153')
       value=parse_qs(body.decode(),strict_parsing=True)
       if set(value)!={'token'} or len(value['token'])!=1:raise InvalidData('PORTAL_FIELDS153')
       auth={'authorization':'Bearer '+value['token'][0],'x-payproof-source':receiver.scope.source,'x-payproof-service':receiver.scope.service_id,'x-payproof-session':receiver.scope.session};receiver.cap.authenticate(auth)
       maxage=max(0,int(receiver.scope.expires_at-receiver.cap.clock()));self._response(303,b'',{'Location':PRIVATE+'/portal','Set-Cookie':'pp153='+value['token'][0]+'; Secure; HttpOnly; SameSite=Strict; Path='+PRIVATE+'; Max-Age='+str(maxage)});return
      cookie=http.cookies.SimpleCookie();cookie.load(h.get('cookie',''));token=cookie['pp153'].value if 'pp153' in cookie else ''
      auth={'authorization':'Bearer '+token,'x-payproof-source':receiver.scope.source,'x-payproof-service':receiver.scope.service_id,'x-payproof-session':receiver.scope.session}
      try:receiver.cap.authenticate(auth)
      except InvalidData:
       page=('<!doctype html><meta charset="utf-8"><title>PayProof private Sandbox153</title><h1>Private Sandbox153</h1><form method="post" action="'+PRIVATE+'/login"><label>Temporary bridge token <input type="password" name="token" autocomplete="off" required></label><button>Open private session</button></form>').encode();self._response(200,page,{'Content-Type':'text/html; charset=utf-8'});return
      if method=='GET' and path==PRIVATE+'/ready':
       auth['host']=h['host']
       status,raw,extra=receiver.handle('GET',path,list(auth.items()),b'');self._response(status,raw,extra);return
      if method=='POST' and path in (PRIVATE+'/buyer-ack',PRIVATE+'/close'):
       if h.get('origin')!=receiver.scope.origin:raise InvalidData('PORTAL_ORIGIN153')
       if not receiver.run_id:raise InvalidData('BUYER_BEFORE_BOOTSTRAP153')
       auth.update({'x-payproof-run':receiver.run_id,'host':h['host'],'content-length':'2'})
       status,raw,extra=receiver.handle('POST',path,list(auth.items()),b'{}');self._response(status,raw,extra);return
      if method=='GET' and path.startswith(PRIVATE+'/evidence-'):
       if not receiver.run_id:raise InvalidData('RAW_BEFORE_BOOTSTRAP153')
       auth.update({'x-payproof-run':receiver.run_id,'host':h['host']})
       status,raw,extra=receiver.handle('GET',path,list(auth.items()),b'');self._response(status,raw,extra);return
      import html
      link='<a rel="noreferrer noopener" href="'+html.escape(receiver.approval,quote=True)+'">Approve this Sandbox test order</a>' if receiver.approval else '<p>Order not ready. No payment approved.</p>'
      report=html.escape(json.dumps(receiver.report,sort_keys=True)) if receiver.report else 'Pending — not completed'
      page=('<!doctype html><meta charset="utf-8"><title>PayProof private Sandbox153</title><h1>Private Sandbox153</h1><p><a href="'+PRIVATE+'/ready">Private readiness</a></p>'+link+''.join('<p><a href="'+PRIVATE+'/evidence-'+op+'">Private original '+op+'</a></p>' for op in ('order_create','capture','final_read','verify','event_read'))+'<form method="post" action="'+PRIVATE+'/buyer-ack"><button>Sandbox approval completed</button></form><pre>'+report+'</pre><form method="post" action="'+PRIVATE+'/close"><button>Close private test session</button></form>').encode();self._response(200,page,{'Content-Type':'text/html; charset=utf-8'});return
     status,raw,extra=receiver.handle(method,path,pairs,body);self._response(status,raw,extra)
    except (InvalidData,ValueError,KeyError):self._response(400,b'{"state":"REFUSED_NO_PROMOTION"}')
    except Exception:self._response(503,b'{"state":"UNKNOWN_NO_RETRY"}')
   do_POST=_handle;do_GET=_handle
  return Handler

def serve153(server,*,stop_event=None):
 """One finite server lifetime; all local worker/watch threads joined on exit."""
 stop=stop_event or threading.Event();receiver=server.receiver
 def expiry():
  while not stop.wait(.1):
   if receiver.closed or receiver.cap.clock()>=receiver.scope.expires_at:
    server.shutdown();return
 watcher=threading.Thread(target=expiry,name='payproof153-expiry',daemon=False);watcher.start()
 try:server.serve_forever(poll_interval=.1)
 finally:
  stop.set();server.server_close();watcher.join(timeout=6)
  if not receiver.closed:receiver.close()
  if watcher.is_alive():raise UnknownResult('SERVER_STOP_UNKNOWN153')

def prewarm153(port,*,test_only=False):
 """Deploy/install before the temporary token/payment clock starts; no secrets."""
 from http.server import BaseHTTPRequestHandler
 class Health(Handler152):
  def do_GET(self):
   body=b'{"transport_only":true,"private_ready":false}'
   self.send_response(200 if self.path=='/healthz' else 503);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 server=BoundedHTTP152(('127.0.0.1' if test_only else '0.0.0.0',port),Health);stop=threading.Event()
 def lifetime():
  if not stop.wait(.2 if test_only else 900):server.shutdown()
 watcher=threading.Thread(target=lifetime,daemon=False);watcher.start()
 try:server.serve_forever(poll_interval=.1)
 finally:stop.set();server.server_close();watcher.join(timeout=6)
 return {'closed':server.socket.fileno()==-1,'watcher_joined':not watcher.is_alive(),'test_only':test_only}

def main():
 # Fail before reading credentials or binding a socket in this review candidate.
 from . import sandbox_bridge153
 if not sandbox_bridge153.LIVE153:raise SystemExit('INACTIVE153: exact final independent native source/effect admission required')
 if any(k in os.environ for k in ('PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID','PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET','GITHUB_TOKEN')):raise InvalidData('PROVIDER_SECRETS_FORBIDDEN_IN_LISTENER153')
 if os.environ.get('PAYPROOF_PREWARM_ONLY')=='1':
  if os.environ.get('RENDER')!='true':raise InvalidData('NATIVE_RENDER_PREWARM153')
  return prewarm153(int(os.environ['PORT']))
 config=json.loads(os.environ['PAYPROOF_BRIDGE_CONFIG']);managed=ManagedIngress153.native(config,os.environ)
 token=os.environ.pop('PAYPROOF_BRIDGE_TOKEN','');cap=Capability153(managed.scope,token);token=None
 directory=pathlib.Path('/tmp/payproof153');directory.mkdir(mode=0o700,exist_ok=False)
 inbox=EventInbox151(directory/'inbox.sqlite');r=Receiver153(cap,inbox)
 try:serve153(Server153(('0.0.0.0',managed.port),r,managed=managed))
 finally:
  if not r.closed:r.close()
  directory.rmdir()

if __name__=='__main__':main()
