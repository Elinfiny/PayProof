"""One HTTPS receiver; separate OIDC worker and browser-local capability roles."""
import os,socket,ssl,threading,time,signal,pathlib,json,sys
from .common import *
from .http_bound import BoundedHTTP152,Handler152
from .state import State
from .oidc import verify_oidc
from .net import https
from .telemetry import Metrics,error_kind

class Server(BoundedHTTP152):
    def __init__(self,state,context,jwks,address=('0.0.0.0',443)):
        self.state=state;self.jwks=jwks;self.accepted=0;self.errors=0
        self.metrics=Metrics();self.phase=threading.local()
        require(address==('0.0.0.0',443),'LISTEN_SCOPE')
        super().__init__(address,Handler,tls_context=context)
    def get_request(self):
        if self.accepted>=512:self.state.stop.set();raise OSError('CONNECTION_CAP')
        conn,peer=super().get_request();self.accepted+=1
        if self.accepted==512:self.state.stop.set()
        return conn,peer
    def handle_error(self,request,client_address):
        self.errors=min(512,self.errors+1)
        phase=getattr(self.phase,'value','unknown')
        kind=error_kind(sys.exc_info()[1]);self.metrics.add(phase+'_'+kind)
        print(json.dumps({'schema':'PAYMENT202_TRANSPORT_ERROR','phase':phase,
              'kind':kind,'accepted':self.accepted,'errors':self.errors},sort_keys=True),flush=True)

class Handler(Handler152):
    def parse_request(self):
        ok=super().parse_request()
        if ok:self._bounded_raw.limit=16384+1500000
        return ok
    def reply(self,status,body=b'',content='application/json'):
        self.server.phase.value='response'
        self.send_response(status)
        for k,v in {'Content-Type':content,'Content-Length':str(len(body)),'X-Content-SHA256':sha(body),'Cache-Control':'no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cross-Origin-Opener-Policy':'same-origin','Content-Security-Policy':"default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"}.items():self.send_header(k,v)
        self.end_headers();self.wfile.write(body)
    def route(self):
        s=self.server.state;s.require()
        require(isinstance(self.connection,ssl.SSLSocket),'TLS')
        pairs=list(self.headers.items());h={k.lower():v for k,v in pairs}
        require(len(pairs)==len(h) and len(h)<=32 and sum(len(k)+len(v) for k,v in pairs)<=16384,'HEADERS')
        require(h.get('host')==HOST and 'transfer-encoding' not in h and '?' not in self.path and '#' not in self.path,'HOST_PATH')
        raw=b''
        if self.command=='POST':
            require(h.get('content-type','').split(';')[0]=='application/json' and h.get('content-length','').isdigit(),'BODY_HEADERS')
            size=int(h['content-length']);require(0<size<=1500000,'BODY_BOUND');raw=self.rfile.read(size);require(len(raw)==size,'TRUNCATED')
        if self.command=='GET' and self.path in ('/buyer186','/buyer186.js'):
            self.server.metrics.add('static')
            s.bounded('static',8);name='buyer.html' if self.path=='/buyer186' else 'buyer.js'
            self.reply(200,(pathlib.Path(__file__).parent/name).read_bytes(),'text/html; charset=utf-8' if name.endswith('html') else 'text/javascript; charset=utf-8');return
        auth=h.get('authorization','');require(auth.startswith('Bearer '),'AUTH') if self.path!='/webhooks/payproof186' else None
        with s.lock:
            s.require()
            if self.path.startswith('/buyer186/'):
                self.server.phase.value='browser'
                require(h.get('origin') in (None,'https://'+HOST),'BROWSER_ORIGIN')
                if self.command=='POST' and self.path=='/buyer186/key':out=s.bind_recipient(obj(raw,2048),auth[7:])
                elif self.command=='GET' and self.path=='/buyer186/envelope':
                    s.browser_auth(auth[7:])
                    self.server.metrics.add('buyer_poll_authorized')
                    s.bounded('buyer-poll',60)
                    if s.wire is None:self.reply(204);return
                    s.bounded('buyer-delivery');self.reply(200,s.wire,'application/octet-stream');return
                elif self.command=='POST' and self.path=='/buyer186/ack':s.browser_auth(auth[7:]);out=s.acknowledge_buyer(obj(raw,2048))
                else:raise Refused('BUYER_ROUTE')
            elif self.command=='POST' and self.path=='/webhooks/payproof186':
                self.server.phase.value='webhook';self.server.metrics.add('webhook_received')
                s.bounded('webhook-attempt',12);out=s.webhook_event(h,raw);self.reply(202,canonical(out));return
            elif self.path.startswith('/worker186/'):
                verify_oidc(auth[7:],self.server.jwks,s.g,time.time())
                name=self.path[len('/worker186/'):]
                self.server.phase.value='worker'
                self.server.metrics.add('worker_'+(name if name in ('grant','ready','buyer','event','reserve','result','webhook','order','ai','terminal') else 'other'))
                if self.command=='GET':
                    if name=='grant':s.bounded('grant',2);out=s.g
                    elif name=='ready':
                        s.bounded('ready',32)
                        out={'recipient_ready':s.browser_ready(),'grant_sha256':sha(canonical(s.g)),
                             'transport_ok':self.server.errors<16 and self.server.accepted<128}
                    elif name=='buyer':s.bounded('buyer-status',60);out={'acknowledged':s.buyer_ack}
                    elif name=='event':
                        s.bounded('event-read',24)
                        if s.event is None:self.reply(204);return
                        out=s.event
                    else:raise Refused('WORKER_GET')
                else:
                    methods={'reserve':s.reserve,'result':s.retain_result,'webhook':s.bind_webhook,'order':s.bind_order,'ai':s.ai,'terminal':s.terminal_report}
                    require(name in methods,'WORKER_POST');out=methods[name](obj(raw))
            else:raise Refused('ROUTE')
            self.reply(200,canonical(out))
    def run_route(self):
        try:self.route()
        except Exception as exc:
            self.server.metrics.add('route_'+('refused' if isinstance(exc,Refused) else error_kind(exc)))
            # No headers, request body, URL, peer or raw exception is logged.
            try:self.reply(400,b'{"state":"REFUSED_NO_RETRY"}')
            except Exception:pass
    do_GET=run_route;do_POST=run_route

def host():
    require(os.getuid()==0 and socket.gethostname()==HOSTNAME,'HOST_IDENTITY')
    private(ROOT,True);private(CERT.with_suffix('.key'));require(sha(CERT.read_bytes())==CERT_SHA,'TLS_PIN')
def admit(raw):
    host();g=obj(raw,32768);validate_grant(g,time.time(),source_binding());write_once(ROOT/'ADMISSION.json',canonical(g));return {'state':'ADMITTED','sha256':sha(canonical(g))}
def pair(digest):
    # Sole Master reads this nonsecret digest from the actual browser UI.
    # No web caller can authorize its own public key. No secret transcription.
    host();require(re.fullmatch('[a-f0-9]{64}',digest),'PAIRING_HASH');private(ROOT/'ADMISSION.json');private(ROOT/'RECIPIENT.json')
    g=obj((ROOT/'ADMISSION.json').read_bytes());validate_grant(g,time.time(),source_binding())
    require(g['start_at']<=time.time()<g['expires_at'] and sha((ROOT/'RECIPIENT.json').read_bytes())==digest,'ACTUAL_BROWSER_PAIRING')
    write_once(ROOT/'BROWSER_ADMITTED.json',canonical({'pairing_sha256':digest,'grant_sha256':sha(canonical(g))}));return {'state':'EXACT_BROWSER_BOUND','pairing_sha256':digest}
def close_access(server,thread):
    if server is None:return True
    # A shutdown error must not skip closing the listening descriptor.
    try:
        if thread and thread.is_alive():server.shutdown()
    except Exception:pass
    finally:
        try:server.server_close()
        except Exception:
            try:server.socket.close()
            except Exception:pass
    try:
        if thread and thread.ident is not None:thread.join(6)
        return server.socket.fileno()==-1 and (thread is None or not thread.is_alive())
    except Exception:return False
def native():
    host();private(ROOT/'ADMISSION.json');g=obj((ROOT/'ADMISSION.json').read_bytes(),32768);validate_grant(g,time.time(),source_binding())
    write_once(ROOT/'NATIVE_INTENT.json',canonical({'grant_sha256':sha(canonical(g))}))
    state=State(ROOT,g);server=thread=None;reason='PREFLIGHT_FAILURE';result={'status':'UNKNOWN','closed':False}
    previous=signal.getsignal(signal.SIGALRM)
    def expired(*_):raise TimeoutError('ABSOLUTE_EXPIRY')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,max(.001,g['expires_at']-time.time()))
    try:
        status,jwks,_=https('token.actions.githubusercontent.com','/.well-known/jwks',expires=g['expires_at'],limit=65536);require(status==200,'JWKS');obj(jwks);write_once(ROOT/'JWKS.json',jwks)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(CERT,CERT.with_suffix('.key'))
        wait=g['start_at']-time.time()
        if wait>0:time.sleep(wait)
        state.require();write_once(ROOT/'SERVER_INTENT.json',canonical({'at':time.time()}))
        server=Server(state,context,jwks);thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.1});thread.start()
        state.stop.wait(max(0,g['expires_at']-time.time()));reason='WORKER_TERMINAL' if state.terminal else 'CAP_OR_EXPIRY'
    except Exception:reason='FAILURE_OR_ABSOLUTE_EXPIRY'
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        # Access closure is independent of custody and payment success.
        try:
            result['closed']=close_access(server,thread)
        finally:
            try:
                try:
                    if server:state.save('TRANSPORT.json',{'accepted':server.accepted,'errors':server.errors,'counts':server.metrics.snapshot(),'peer_data_retained':False})
                finally:state.close(reason)
            except Exception:result['custody']='UNKNOWN_PRESERVE_FILES'
        result.update(status='COMPLETED' if state.terminal and state.terminal['state']=='COMPLETED' and result['closed'] and 'custody' not in result else 'UNKNOWN',reason=reason,accepted=server.accepted if server else 0,errors=server.errors if server else 0,run_id=g['run_id'])
        write_once(ROOT/'NATIVE_RESULT.json',canonical(result))
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='COMPLETED' else 1
if __name__=='__main__':
    import sys
    try:
        if sys.argv[1]=='admit':print(json.dumps(admit(sys.stdin.buffer.read(32769))));raise SystemExit(0)
        if sys.argv[1]=='pair':print(json.dumps(pair(sys.argv[2])));raise SystemExit(0)
        if sys.argv[1]=='native':raise SystemExit(native())
        raise Refused('MODE')
    except Exception:print('{"state":"REFUSED_OR_UNKNOWN","retry":false}');raise SystemExit(1)
