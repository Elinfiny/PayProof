import contextlib,io,pathlib,socket,ssl,tempfile,threading,time,unittest
from datetime import datetime,timedelta,timezone
from unittest.mock import Mock
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes,serialization
from payment186 import server,common
class Loopback(server.Server):
 def server_bind(self):self.server_address=('127.0.0.1',0);super().server_bind()
class Ingress214(unittest.TestCase):
 def test_health_classifies_noise_but_preserves_thresholds_and_stop(self):
  s=Mock();s.state.stop=threading.Event();s.errors=100;s.expected_errors=0;s.accepted=127
  self.assertTrue(server.transport_ready(s));s.accepted=128;self.assertFalse(server.transport_ready(s))
  s.accepted=10;s.expected_errors=16;self.assertFalse(server.transport_ready(s));s.expected_errors=0;s.state.stop.set();self.assertFalse(server.transport_ready(s))
 def test_strict_sni_wire_expected_and_foreign_actual(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td);key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,common.HOST)]);now=datetime.now(timezone.utc)
   cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(214).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(minutes=5)).add_extension(x509.SubjectAlternativeName([x509.DNSName(common.HOST),x509.DNSName('wrong.example')]),False).sign(key,hashes.SHA256())
   cp=root/'cert';kp=root/'key';cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM));kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
   ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cp,kp);client=ssl.create_default_context(cafile=str(cp));state=Mock();state.stop=threading.Event();guard=Mock();srv=Loopback(state,ctx,b'{}');server.configure_ingress(ctx,srv,guard)
   t=threading.Thread(target=srv.serve_forever,kwargs={'poll_interval':.01});t.start();out=io.StringIO()
   try:
    with contextlib.redirect_stdout(out):
     with socket.create_connection(srv.server_address,2) as c:
      with self.assertRaises(ssl.SSLError):client.wrap_socket(c,server_hostname='wrong.example')
     end=time.monotonic()+2
     while srv.errors<1 and time.monotonic()<end:time.sleep(.01)
    self.assertEqual((srv.errors,srv.expected_errors),(1,0))
    with socket.create_connection(srv.server_address,2) as c:
     with client.wrap_socket(c,server_hostname=common.HOST) as w:
      w.sendall(('GET /buyer186 HTTP/1.0\r\nHost: '+common.HOST+'\r\n\r\n').encode());self.assertIn(b'200 OK',w.recv(4096))
    self.assertTrue(server.transport_ready(srv));self.assertEqual(srv.accepted,2)
    self.assertEqual([x.args[1] for x in guard.observe.call_args_list],[False,True])
   finally:self.assertTrue(server.close_access(srv,t))
if __name__=='__main__':unittest.main()
