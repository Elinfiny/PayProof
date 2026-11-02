"""Small loopback-only TLS checks and mocked accounting; no external probes."""
import contextlib,http.client,io,json,pathlib,socket,ssl,tempfile,threading,time,unittest
from datetime import datetime,timedelta,timezone
from unittest.mock import Mock,patch
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes,serialization
import ipaddress
from payment186 import common as c,server
from payment186.http_bound import BoundedHTTP152
from payment186.telemetry import Metrics,error_kind

class LoopbackServer(server.Server):
    def server_bind(self):
        self.server_address=('127.0.0.1',0)
        super().server_bind()

class Transport202(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name)
    @contextlib.contextmanager
    def listener(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        now=datetime.now(timezone.utc);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(202).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(minutes=5)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256())
        cp=self.root/'cert';kp=self.root/'key';cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM));kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(cp,kp)
        client=ssl.create_default_context(cafile=str(cp))
        state=Mock();state.stop=threading.Event()
        srv=LoopbackServer(state,ctx,b'{}');thread=threading.Thread(target=srv.serve_forever,kwargs={'poll_interval':.01});thread.start()
        try:yield srv,client
        finally:self.assertTrue(server.close_access(srv,thread))
    def request(self,srv,ctx,headers=None):
        conn=http.client.HTTPSConnection(*srv.server_address,timeout=2,context=ctx)
        try:
            conn.request('GET','/buyer186',headers=headers or {'Host':c.HOST})
            r=conn.getresponse();data=r.read();return r.status,data
        finally:conn.close()
    def test_normal_tls_requests_have_no_hidden_connection_multiplier(self):
        with self.listener() as (srv,ctx):
            for _ in range(3):self.assertEqual(self.request(srv,ctx)[0],200)
            self.assertEqual((srv.accepted,srv.errors),(3,0))
            self.assertEqual(srv.metrics.snapshot(),{'static':3,'tls_established':3})
    def test_client_disconnect_during_handshake_is_classified_without_private_data(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out),self.listener() as (srv,ctx):
            conn=socket.create_connection(srv.server_address,timeout=2);conn.close()
            end=time.monotonic()+2
            while srv.errors==0 and time.monotonic()<end:time.sleep(.01)
            self.assertEqual((srv.accepted,srv.errors),(1,1))
            self.assertIn('tls_disconnect',srv.metrics.snapshot())
        record=json.loads(out.getvalue());self.assertEqual(set(record),{'schema','phase','kind','accepted','errors'})
    def test_host_refusal_separate_from_tls_error(self):
        with self.listener() as (srv,ctx):
            self.assertEqual(self.request(srv,ctx,{'Host':'invalid.example'})[0],400)
            self.assertEqual(srv.errors,0)
            self.assertEqual(srv.metrics.snapshot(),{'route_refused':1,'tls_established':1})
    def test_cap512_closes_without_accepting_513_mocked_no_traffic(self):
        srv=server.Server.__new__(server.Server);srv.state=Mock();srv.state.stop=threading.Event();srv.accepted=511
        with patch.object(BoundedHTTP152,'get_request',return_value=('mock','peer')) as accept:
            srv.get_request();self.assertEqual(srv.accepted,512);self.assertTrue(srv.state.stop.is_set())
            with self.assertRaises(OSError):srv.get_request()
            self.assertEqual(accept.call_count,1)
    def test_timeout_framing_and_eof_are_distinct_bounded_categories(self):
        self.assertEqual([error_kind(x) for x in (TimeoutError(),ValueError(),ssl.SSLEOFError())],['timeout','framing','disconnect'])
        m=Metrics()
        for _ in range(513):m.add('request_timeout')
        self.assertEqual(m.snapshot(),{'request_timeout':512})

if __name__=='__main__':unittest.main()
