"""Local PayPal-signature prefilter; official API verification still required.

Only certificate bytes obtained with Web PKI from fixed Sandbox PayPal origins
may supply a native verification key. No trust-key file, supplied public key,
redirect, general URL fetch or PayPal OAuth secret is accepted by this module.
"""
import base64,binascii,http.client,re,ssl,time,zlib
from datetime import datetime,timezone
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from .sandbox_chain151 import InvalidData,LIMIT,UnknownResult

CERT_HOSTS=('api.sandbox.paypal.com','api-m.sandbox.paypal.com')
def certificate_url152(url):
 try:p=urlsplit(url)
 except ValueError:raise InvalidData('CERT_ORIGIN152') from None
 if p.scheme!='https' or p.hostname not in CERT_HOSTS or p.netloc!=p.hostname or not re.fullmatch('/v1/notifications/certs/[A-Za-z0-9-]{1,160}',p.path) or p.query or p.fragment:raise InvalidData('CERT_ORIGIN152')
 return p.hostname,p.path

class LocalSignature152:
 test_only=False
 def __init__(self,webhook_id):self.webhook_id=webhook_id;self.cache={};self.fetches=0;self._window=[]
 def _certificate(self,url):
  host,path=certificate_url152(url)
  if url in self.cache:return self.cache[url]
  now=time.monotonic();self._window=[t for t in self._window if now-t<1]
  if len(self._window)>=2:raise InvalidData('TRANSIENT_CERT_RATE_LIMIT152')
  self._window.append(now);self.fetches+=1;c=http.client.HTTPSConnection(host,timeout=5,context=ssl.create_default_context())
  try:
   c.request('GET',path,headers={'Accept':'application/x-pem-file'});r=c.getresponse();pem=r.read(32769)
   if r.status!=200 or len(pem)>32768:raise InvalidData('CERT_UNAVAILABLE_NO_SLOT152')
   cert=x509.load_pem_x509_certificate(pem)
   if len(self.cache)>=2:self.cache.pop(next(iter(self.cache)))
   self.cache[url]=cert;return cert
  finally:c.close()
 def verify(self,headers,raw):
  if not isinstance(raw,bytes) or not 0<len(raw)<=LIMIT:raise InvalidData('ORIGINAL_BYTES152')
  try:
   h={k.lower():v for k,v in headers.items()}
   if h['paypal-auth-algo']!='SHA256withRSA':raise ValueError()
   tid=h['paypal-transmission-id'];stamp=h['paypal-transmission-time'];url=h['paypal-cert-url']
   if not re.fullmatch('[A-Za-z0-9-]{1,128}',tid) or not re.fullmatch('[A-Z0-9-]{1,64}',self.webhook_id):raise ValueError()
   at=datetime.fromisoformat(stamp.replace('Z','+00:00'));now=datetime.now(timezone.utc)
   if at.tzinfo is None or abs((now-at).total_seconds())>300:raise ValueError()
   sig=base64.b64decode(h['paypal-transmission-sig'],validate=True)
   if not 256<=len(sig)<=1024:raise ValueError()
   cert=self._certificate(url);key=cert.public_key()
   if not isinstance(key,rsa.RSAPublicKey) or key.key_size<2048 or not cert.not_valid_before_utc<=now<cert.not_valid_after_utc:raise ValueError()
   message=(tid+'|'+stamp+'|'+self.webhook_id+'|'+str(zlib.crc32(raw)&0xffffffff)).encode('utf-8')
   key.verify(sig,message,padding.PKCS1v15(),hashes.SHA256());return True
  except (KeyError,ValueError,TypeError,binascii.Error,InvalidSignature):return False

class SyntheticSignature152(LocalSignature152):
 """Fake certificate transport, never selectable by a native Receiver151."""
 test_only=True
 def __init__(self,webhook_id,certificates):super().__init__(webhook_id);self.certificates=dict(certificates)
 def _certificate(self,url):certificate_url152(url);return self.certificates[url]
