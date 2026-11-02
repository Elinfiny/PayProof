"""Dormant one-use Netcup loopback TLS probe; separate Owner admission required.

No PayPal, GitHub API, token, public listener, renewal or existing-run mutation.
The original failed operation remains closed. This diagnostic cannot qualify
the external GitHub-to-Netcup route or the private buyer-file transfer.
"""
import hashlib,http.client,json,os,pathlib,socket,ssl,stat,threading,time
from .sandbox_http152 import BoundedHTTP152,Handler152
from .netcup_host151 import HOST,HOSTNAME,CERT,KEY,CERT_SHA,canonical,write_once,private

ROOT=pathlib.Path('/root/payproof-diagnostic164')
LIMITS={'listener':'127.0.0.1:9443','seconds':180,'requests':3,'accepted_connections':12,
        'PayPal_calls':0,'workflow_dispatches':0,'new_credentials':0,'cost':'0.00'}

def validate_admission(row,source_hash,now):
    if type(row) is not dict or set(row)!={'schema','owner_request','source_sha256','limits','issued_at','expires_at'}:
        raise ValueError('DISTINCT_ADMISSION_REQUIRED164')
    import re,math
    if (row['schema']!='OWNER_NATIVE_TLS_DIAGNOSTIC164' or not isinstance(row['owner_request'],str)
        or re.fullmatch('[0-9a-f-]{36}',row['owner_request']) is None
        or row['source_sha256']!=source_hash or row['limits']!=LIMITS
        or any(type(row[k]) not in (int,float) or not math.isfinite(row[k]) for k in ('issued_at','expires_at'))
        or not row['issued_at']<=now<row['expires_at'] or row['expires_at']-row['issued_at']!=180):
        raise ValueError('DISTINCT_ADMISSION_REQUIRED164')

class LoopbackConnection(http.client.HTTPSConnection):
    def connect(self):
        if self.host!=HOST:raise ValueError('EXACT_CERTIFICATE_HOST164')
        raw=socket.create_connection(('127.0.0.1',9443),timeout=self.timeout)
        try:self.sock=self._context.wrap_socket(raw,server_hostname=HOST)
        except BaseException:raw.close();raise

class ProbeHandler(Handler152):
    def do_GET(self):
        if self.path!='/diagnostic164' or self.headers.get('Host')!=HOST:
            self.send_error(404);return
        raw=b'{"synthetic":true,"native_paypal":false}'
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store')
        self.end_headers();self.wfile.write(raw)

class ProbeServer(BoundedHTTP152):
    def __init__(self,context):
        self.accepted=0;self.errors=[]
        super().__init__(('127.0.0.1',9443),ProbeHandler,tls_context=context)
    def get_request(self):
        conn,peer=super().get_request();self.accepted+=1
        if self.accepted>12:conn.close();raise OSError('DIAGNOSTIC_BOUND164')
        return conn,peer
    def handle_error(self,request,client_address):
        # Only exception class, capped; never raw error, peer or input.
        import sys
        if len(self.errors)<12:
            error=sys.exception();self.errors.append('TLS' if isinstance(error,ssl.SSLError) else 'OTHER')

def source_hash():
    files=[pathlib.Path(__file__),pathlib.Path(__file__).with_name('sandbox_http152.py'),pathlib.Path(__file__).with_name('netcup_host151.py')]
    return hashlib.sha256(canonical({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files})).hexdigest()

def main():
    if os.getuid()!=0 or socket.gethostname()!=HOSTNAME:raise ValueError('EXACT_NATIVE_HOST164')
    private(ROOT,True);admission=ROOT/'ADMISSION.json';private(admission)
    row=json.loads(admission.read_bytes());validate_admission(row,source_hash(),time.time())
    if hashlib.sha256(CERT.read_bytes()).hexdigest()!=CERT_SHA:raise ValueError('EXISTING_CERTIFICATE164')
    private(KEY)
    # This file is never removed/replaced to rearm a completed or uncertain probe.
    write_once(ROOT/'INTENT.json',canonical({'state':'CONSUMED_BEFORE_BIND','source_sha256':row['source_sha256']}))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERT,KEY)
    server=ProbeServer(context);thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.1})
    thread.start();timer=threading.Timer(max(0,row['expires_at']-time.time()),server.shutdown);timer.start()
    results=[]
    try:
        for _ in range(3):
            if time.time()>=row['expires_at']:raise TimeoutError('ABSOLUTE_EXPIRY164')
            # Normal system trust and hostname verification remain enabled.
            conn=LoopbackConnection(HOST,timeout=min(5,row['expires_at']-time.time()),context=ssl.create_default_context())
            try:
                conn.request('GET','/diagnostic164');response=conn.getresponse();raw=response.read(1025)
                if response.status!=200 or raw!=b'{"synthetic":true,"native_paypal":false}':raise ValueError('PROBE_RESPONSE164')
                results.append('PASS')
            except Exception as error:
                results.append(type(error).__name__ if type(error).__name__ in ('SSLCertVerificationError','SSLEOFError','SSLError','TimeoutError','ConnectionResetError') else 'OTHER')
                break # No retry after uncertainty, even for this synthetic GET.
            finally:conn.close()
    finally:
        server.shutdown();server.server_close();thread.join(6);timer.cancel();timer.join(6)
        closed=not thread.is_alive() and not timer.is_alive() and server.socket.fileno()==-1
        receipt={'schema':'NATIVE_TLS_DIAGNOSTIC164','results':results,'closed':closed,'accepted':min(server.accepted,13),'errors':server.errors,'source_sha256':row['source_sha256'],'PayPal_calls':0,'workflow_dispatches':0}
        write_once(ROOT/'RESULT.json',canonical(receipt));print(json.dumps(receipt,sort_keys=True))
        if not closed:raise RuntimeError('PROBE_CLOSE_UNKNOWN164')

if __name__=='__main__':main()
