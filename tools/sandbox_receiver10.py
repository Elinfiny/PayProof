"""Direct-TLS self-hosted receiver. No Render environment or token-entry portal.

All native constructors/entry points refuse before socket, environment, key or
certificate access. Genuine target control/TLS/custody is a future dependency.
"""
import ssl
import threading
from .sandbox_bridge10 import Receiver153, InvalidData, PRIVATE
from .sandbox_http152 import BoundedHTTP152, Handler152


class Server10(BoundedHTTP152):
    def __init__(self, address, receiver, *, tls_context=None):
        if type(receiver) is not Receiver153:
            raise InvalidData('EXACT_RECEIVER10')
        receiver.scope.require(__import__('time').time())
        allowed=('127.0.0.1',address[1]) if receiver.scope.test_only else ('0.0.0.0',443)
        if address != allowed or type(tls_context) is not ssl.SSLContext or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise InvalidData('EXACT_NATIVE_OR_LOOPBACK_TLS151')
        self.receiver=receiver; self.accepted=0
        super().__init__(address,self.handler10(),tls_context=tls_context)

    def get_request(self):
        conn,peer=super().get_request();self.accepted+=1
        if self.accepted>512 or self.receiver.closed:
            if self.accepted==513:self.trace163('CONNECTION_LIMIT','OSError')
            conn.close();raise OSError('CONNECTION_BUDGET10')
        return conn,peer

    def trace163(self,kind,error_type):
        if not self.receiver.scope.test_only:
            try:
                from .netcup_host151 import retain_transport163
                retain_transport163(kind,min(self.accepted,513),error_type)
            except Exception:pass # Telemetry cannot loosen or bypass a guard.

    def handle_error(self,request,client_address):
        import sys
        error=sys.exception()
        self.trace163('HANDLER_ERROR',type(error).__name__)

    def handler10(self):
        receiver=self.receiver
        class Handler(Handler152):
            def parse_request(self):
                ok=super().parse_request()
                if ok:self._bounded_raw.limit=16384+(1400000 if self.path.startswith(PRIVATE+'/evidence-') else 98304)
                return ok
            def respond(self,status,raw,extra=None):
                self.send_response(status)
                safe={'Content-Type':'application/json','Content-Length':str(len(raw)),
                      'Cache-Control':'no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff',
                      'Referrer-Policy':'no-referrer',
                      'Content-Security-Policy':"default-src 'none'; form-action 'self'; frame-ancestors 'none'"}
                for k,v in safe.items():self.send_header(k,v)
                self.end_headers();self.wfile.write(raw)
            def handle10(self):
                try:
                    if not isinstance(self.connection,ssl.SSLSocket):raise InvalidData('ACTUAL_DIRECT_TLS10')
                    pairs=list(self.headers.items());headers={k.lower():v for k,v in pairs}
                    if len(pairs)!=len(headers) or len(pairs)>32 or sum(len(k)+len(v) for k,v in pairs)>16384:
                        raise InvalidData('HEADER_BOUND10')
                    # Forwarding headers convey no TLS identity or permission.
                    if 'transfer-encoding' in headers or '?' in self.path or '#' in self.path:
                        raise InvalidData('EXACT_ENVELOPE10')
                    raw=b''
                    if self.command=='POST':
                        if len(self.headers.get_all('Content-Length',[]))!=1:raise InvalidData('LENGTH10')
                        size=int(headers.get('content-length','0'))
                        if not 0<size<=(1400000 if self.path.startswith(PRIVATE+'/evidence-') else 98304):raise InvalidData('BODY_BOUND10')
                        raw=self.rfile.read(size)
                        if len(raw)!=size:raise InvalidData('TRUNCATED10')
                    code,body,extra=receiver.handle(self.command,self.path,pairs,raw)
                    self.respond(code,body)
                except (ValueError,InvalidData,KeyError):self.respond(400,b'{"state":"REFUSED_NO_PROMOTION"}')
                except Exception:self.respond(503,b'{"state":"UNKNOWN_NO_RETRY"}')
            do_GET=handle10;do_POST=handle10
        return Handler


def serve10(server):
    stop=threading.Event();receiver=server.receiver
    def expiry():
        while not stop.wait(.1):
            if receiver.closed or receiver.cap.clock()>=receiver.scope.expires_at:
                server.shutdown();return
    watcher=threading.Thread(target=expiry,name='payproof10-expiry',daemon=False);watcher.start()
    try:server.serve_forever(poll_interval=.1)
    finally:
        stop.set();server.server_close();watcher.join(timeout=6)
        if not receiver.closed:receiver.close()
        if watcher.is_alive():raise RuntimeError('SERVER_STOP_UNKNOWN10')


def main():
    raise InvalidData('NATIVE_RECEIVER10_ADMISSION_AND_TARGET_CONTROL_UNBOUND')


if __name__=='__main__':main()
