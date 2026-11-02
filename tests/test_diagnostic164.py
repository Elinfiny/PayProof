"""New changed-interface tests only; external DNS/connect/bind denied."""
import base64,contextlib,datetime,hashlib,http.client,io,json,pathlib,socket,ssl,sys,tempfile,threading,time,types,unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.x509.oid import NameOID
from tools.sandbox_bridge10 import Scope153,Capability153,Receiver153,PRIVATE
from tools.sandbox_bridge_client10 import BridgeClient153,SyntheticBridgeTransport153,BOUNDS
from tools.sandbox_chain10 import APP,UnknownResult,InvalidData
from tools.sandbox_listener10 import EventInbox151
from tools.sandbox_receiver10 import Server10
from tools.sandbox_worker10 import run_chain153
from tools import buyer_envelope164 as envelope

def isolate(event,args):
    if event in ('socket.connect','socket.bind'):
        address=args[1]
        if not isinstance(address,tuple) or address[0] not in ('127.0.0.1','::1'):
            raise PermissionError('EXTERNAL_NETWORK_DENIED164')
    if event=='socket.getaddrinfo' and args[0] not in ('localhost','127.0.0.1','::1'):
        raise PermissionError('EXTERNAL_DNS_DENIED164')
sys.addaudithook(isolate)

def scope(issued=1000,expires=1600):
    return Scope153('a'*40,'PNC10-SYNTHETIC164',APP,'https://synthetic.example.test','nc-932863-synthetic164',issued,expires,True,'b'*64,'c'*64)

class Diagnostic164(unittest.TestCase):
    def client(self):
        s=scope();r=types.SimpleNamespace(scope=s)
        t=SyntheticBridgeTransport153(r)
        return BridgeClient153(s,'x'*64,'123',t,clock=lambda:1100),t

    def test_failure_categories_remain_frozen_and_redacted(self):
        cases=[(ssl.SSLCertVerificationError('SYNTHETIC_SECRET'),'TLS_CERTIFICATE'),
               (ssl.SSLEOFError('SYNTHETIC_SECRET'),'TLS_EOF'),
               (ssl.SSLError('SYNTHETIC_SECRET'),'TLS_PROTOCOL'),
               (TimeoutError('SYNTHETIC_SECRET'),'TIMEOUT'),
               (http.client.RemoteDisconnected('SYNTHETIC_SECRET'),'HTTP_PROTOCOL'),
               (ConnectionResetError('SYNTHETIC_SECRET'),'CONNECTION')]
        for error,category in cases:
            with self.subTest(category=category):
                c,t=self.client()
                with patch.object(t,'request',side_effect=error) as request:
                    with self.assertRaises(UnknownResult):c._call('buyer-status')
                    with self.assertRaises(UnknownResult):c._call('buyer-status')
                    self.assertEqual(request.call_count,1)
                self.assertEqual(c.first_diagnostic['category'],category)
                self.assertEqual(c.counts,{'buyer-status':1})
                self.assertNotIn('SYNTHETIC_SECRET',json.dumps(c.export()))

    def test_http_schema_and_body_failures_distinct(self):
        for response,category in [((503,b'PRIVATE_BODY'),'HTTP_STATUS'),((200,b'not-json'),'JSON_SCHEMA'),((200,b'[]'),'JSON_SCHEMA'),((200,b'x'*114689),'BODY_BOUND')]:
            with self.subTest(category=category,response_status=response[0]):
                c,t=self.client()
                with patch.object(t,'request',return_value=response):
                    with self.assertRaises(UnknownResult):c._call('buyer-status')
                self.assertEqual(c.first_diagnostic['category'],category)
                self.assertNotIn('PRIVATE_BODY',json.dumps(c.export()))

    def test_pending_then_ack_and_expiry_preserve_no_capture_authority(self):
        c,t=self.client();ticks=[];c.sleeper=ticks.append
        with patch.object(t,'request',side_effect=[(200,b'{"acknowledged":false}'),(200,b'{"acknowledged":true}')]):
            self.assertTrue(c.await_buyer()['acknowledged'])
        self.assertEqual(ticks,[2]);self.assertEqual(c.counts,{'buyer-status':2})
        c,t=self.client();c.clock=lambda:1599
        with patch.object(t,'request',return_value=(200,b'{"acknowledged":false}')) as request:
            with self.assertRaises(InvalidData):c.await_buyer()
        self.assertEqual(request.call_count,1);self.assertEqual(BOUNDS['buyer-status'],60)

    def test_receiver_busy_is_http_not_tls_and_does_not_ack(self):
        with tempfile.TemporaryDirectory() as td:
            s=scope();r=Receiver153(Capability153(s,'x'*64,clock=lambda:1100),EventInbox151(pathlib.Path(td)/'inbox'))
            r.lock.acquire()
            try:status,raw,_=r.handle('GET',PRIVATE+'/buyer-status',[],b'')
            finally:r.lock.release()
            self.assertEqual(status,503);self.assertFalse(r.buyer_ack)
            self.assertEqual(json.loads(raw)['state'],'BUSY_NO_SLOT')

    def test_worker_keeps_sanitized_cause_without_provider_replay(self):
        c,t=self.client();s=c.scope
        e=types.SimpleNamespace(grant=types.SimpleNamespace(listener_url=s.origin+'/webhooks/payproof151',app_sha256=APP,test_only=True),order=None,capture_id=None,first_unknown=None,used={},private_returns=[],close=lambda:None)
        out=io.StringIO()
        with patch.object(t,'request',side_effect=ssl.SSLEOFError('SYNTHETIC_SECRET')),contextlib.redirect_stdout(out),self.assertRaises(UnknownResult):run_chain153(e,c,None)
        row=json.loads(out.getvalue());self.assertEqual(row['bridge_diagnostic']['category'],'TLS_EOF');self.assertEqual(row['provider_slots'],{});self.assertNotIn('SYNTHETIC_SECRET',out.getvalue())

    def test_cipher_byte_transfer_roundtrip_and_transcription_refused(self):
        # Ephemeral SYNTHETIC key, no native credential or original private key.
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        plain=b'PP151BUYER|SYNTHETIC_ONLY'
        cipher=key.public_key().encrypt(plain,padding.PKCS1v15())
        binding={'source':'a'*40,'run_id':'123','expires_at':1600,'recipient_sha256':'b'*64}
        raw=envelope.pack(cipher,binding);digest=hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            source=pathlib.Path(td)/'private-cipher.bin';source.write_bytes(raw);source.chmod(0o600)
            transferred=source.read_bytes()
            recovered=envelope.unpack(transferred,binding,digest,1100)
        self.assertEqual(key.decrypt(recovered,padding.PKCS1v15()),plain)
        self.assertNotIn(plain,raw)
        for bad in (raw.decode(),raw[:-1],b' '+raw,raw.replace(b'123',b'124')):
            with self.subTest(kind=type(bad).__name__),self.assertRaises(envelope.EnvelopeError):envelope.unpack(bad,binding,digest,1100)
        # The original failure class: 65 + seven64 hex chars is not a 256B cipher.
        transcribed=cipher.hex()+'0'
        self.assertEqual(len(transcribed),513)
        with self.assertRaises(ValueError):bytes.fromhex(transcribed)
        with self.assertRaises(envelope.EnvelopeError):envelope.unpack(raw,binding,digest,1600)
        with self.assertRaises(envelope.EnvelopeError):envelope.unpack(raw,dict(binding,run_id='124'),digest,1100)

    def test_new_native_proposal_admission_is_separate_and_bounded(self):
        from tools.native_tls_diagnostic164 import validate_admission,LIMITS
        row={'schema':'OWNER_NATIVE_TLS_DIAGNOSTIC164','owner_request':'00000000-0000-0000-0000-000000000001','source_sha256':'a'*64,'limits':dict(LIMITS),'issued_at':1000,'expires_at':1180}
        validate_admission(row,'a'*64,1100)
        for changed in ({},dict(row,source_sha256='b'*64),dict(row,expires_at=1600),dict(row,limits=dict(LIMITS,PayPal_calls=1))):
            with self.assertRaises(ValueError):validate_admission(changed,'a'*64,1100)
        with self.assertRaises(ValueError):validate_admission(row,'a'*64,1180)

    def test_external_network_is_denied(self):
        with self.assertRaises(PermissionError):socket.getaddrinfo('example.invalid',443)
        with socket.socket() as sock,self.assertRaises(PermissionError):sock.connect(('192.0.2.1',443))

class RealLoopbackTLS164(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td=tempfile.TemporaryDirectory();cls.root=pathlib.Path(cls.td.name)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.datetime.now(datetime.timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False).sign(key,hashes.SHA256())
        cls.cert=cls.root/'synthetic.crt';cls.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM));pem=cls.root/'synthetic.key';pem.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));pem.chmod(0o600)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_2;tls.load_cert_chain(cls.cert,pem)
        n=time.time();cls.scope=scope(n-1,n+120);cls.receiver=Receiver153(Capability153(cls.scope,'x'*64),EventInbox151(cls.root/'inbox'))
        cls.server=Server10(('127.0.0.1',0),cls.receiver,tls_context=tls)
        cls.thread=threading.Thread(target=cls.server.serve_forever,kwargs={'poll_interval':.02});cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(2);cls.td.cleanup()
    def connection(self,trusted=True):
        ctx=ssl.create_default_context(cafile=str(self.cert)) if trusted else ssl.create_default_context()
        return http.client.HTTPSConnection('localhost',self.server.server_port,timeout=2,context=ctx)
    def headers(self):
        s=self.scope
        return {'Host':'synthetic.example.test','Authorization':'Bearer '+'x'*64,'X-PayProof-Source':s.source,'X-PayProof-Session':s.session,'X-PayProof-Service':s.service_id,'X-PayProof-Run':'123'}
    def test_real_tls_success_and_certificate_refusal(self):
        c=self.connection()
        try:
            c.request('GET',PRIVATE+'/ready',headers=self.headers());r=c.getresponse();self.assertEqual(r.status,200);self.assertEqual(json.loads(r.read())['source'],self.scope.source)
        finally:c.close()
        c=self.connection(False)
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):c.request('GET',PRIVATE+'/ready',headers=self.headers())
        finally:c.close()
    def test_connection_budget_can_yield_tls_eof_without_wrong_certificate(self):
        # Exercise one refusal at the configured boundary; no load generation.
        self.server.accepted=512
        c=self.connection()
        try:
            with self.assertRaises((ssl.SSLEOFError,ConnectionResetError)):c.request('GET',PRIVATE+'/ready',headers=self.headers())
        finally:c.close();self.server.accepted=0

    def test_tls_socket_closed_on_success_and_handshake_failure(self):
        from tools.sandbox_http152 import Handler152
        handlers=[];original=Handler152.setup
        def setup(handler):
            handlers.append(handler)
            return original(handler)
        with patch.object(Handler152,'setup',setup):
            c=self.connection()
            try:
                c.request('GET',PRIVATE+'/ready',headers=self.headers());c.getresponse().read()
            finally:c.close()
            c=self.connection(False)
            try:
                with self.assertRaises(ssl.SSLCertVerificationError):c.request('GET',PRIVATE+'/ready',headers=self.headers())
            finally:c.close()
        deadline=time.monotonic()+2
        while time.monotonic()<deadline and (len(handlers)<2 or any(h.connection.fileno()!=-1 for h in handlers)):
            time.sleep(.01)
        self.assertEqual(len(handlers),2)
        self.assertTrue(all(h.connection.fileno()==-1 for h in handlers))
        self.assertEqual(self.server.slots._value,8)

    def test_native_probe_complete_local_lifecycle_and_no_rearm(self):
        from tools import native_tls_diagnostic164 as probe
        from tools.sandbox_http152 import BoundedHTTP152
        actual_connect=socket.create_connection;actual_context=ssl.create_default_context;port=[]
        def init(server,context):
            server.accepted=0;server.errors=[]
            BoundedHTTP152.__init__(server,('127.0.0.1',0),probe.ProbeHandler,tls_context=context)
            port.append(server.server_port)
        def connect(address,*args,**kwargs):
            self.assertEqual(address,('127.0.0.1',9443))
            return actual_connect(('127.0.0.1',port[0]),*args,**kwargs)
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);root.chmod(0o700);now=time.time()
            row={'schema':'OWNER_NATIVE_TLS_DIAGNOSTIC164','owner_request':'00000000-0000-0000-0000-000000000001','source_sha256':probe.source_hash(),'limits':probe.LIMITS,'issued_at':now,'expires_at':now+180}
            admission=root/'ADMISSION.json';admission.write_text(json.dumps(row));admission.chmod(0o600)
            with patch.object(probe,'ROOT',root),patch.object(probe,'HOST','localhost'),patch.object(probe,'HOSTNAME',socket.gethostname()),patch.object(probe,'CERT',self.cert),patch.object(probe,'KEY',self.root/'synthetic.key'),patch.object(probe,'CERT_SHA',hashlib.sha256(self.cert.read_bytes()).hexdigest()),patch.object(probe.ProbeServer,'__init__',init),patch.object(socket,'create_connection',connect),patch.object(ssl,'create_default_context',side_effect=lambda:actual_context(cafile=str(self.cert))):
                out=io.StringIO()
                with contextlib.redirect_stdout(out):probe.main()
                receipt=json.loads(out.getvalue());self.assertTrue(receipt['closed']);self.assertEqual(receipt['results'],['PASS']*3);self.assertEqual(receipt['accepted'],3)
                before=(root/'RESULT.json').read_bytes()
                with self.assertRaises(FileExistsError):probe.main()
                self.assertEqual((root/'RESULT.json').read_bytes(),before)
                self.assertEqual(len(port),1)

if __name__=='__main__':unittest.main()
