"""Bounded HTTP primitives: absolute read deadline applies BEFORE header parsing."""
import http.server,io,socketserver,ssl,threading,time

class DeadlineRaw152(io.RawIOBase):
 def __init__(self,raw,sock,deadline):super().__init__();self.raw=raw;self.sock=sock;self.deadline=deadline;self.total=0;self.limit=16384
 def readable(self):return True
 def readinto(self,b):
  remaining=self.deadline-time.monotonic()
  if remaining<=0:raise TimeoutError('ABSOLUTE_REQUEST_DEADLINE152')
  if self.total>=self.limit:raise ValueError('REQUEST_BYTE_BOUND152')
  self.sock.settimeout(min(5,remaining));n=self.raw.readinto(memoryview(b)[:min(len(b),self.limit-self.total)])
  if n:self.total+=n
  return n
 def close(self):
  try:self.raw.close()
  finally:super().close()

class BoundedHTTP152(socketserver.ThreadingMixIn,http.server.HTTPServer):
 daemon_threads=False;block_on_close=True;request_queue_size=8
 def __init__(self,address,handler,*,tls_context=None):
  self.slots=threading.BoundedSemaphore(8);self.tls_context=tls_context;super().__init__(address,handler)
 def get_request(self):
  conn,peer=super().get_request();conn.settimeout(5) # before TLS/request line/header parser
  return conn,peer
 def process_request(self,request,client_address):
  if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
  try:super().process_request(request,client_address)
  except BaseException:self.slots.release();raise
 def process_request_thread(self,request,client_address):
  try:super().process_request_thread(request,client_address)
  finally:self.slots.release()

class Handler152(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.0'
 def setup(self):
  self.connection=self.request;deadline=time.monotonic()+5
  if self.server.tls_context is not None:
   self.connection=self.server.tls_context.wrap_socket(self.connection,server_side=True,do_handshake_on_connect=False)
   self.connection.settimeout(max(.001,deadline-time.monotonic()));self.connection.do_handshake()
  self._bounded_raw=DeadlineRaw152(self.connection.makefile('rb',buffering=0),self.connection,deadline)
  self.rfile=io.BufferedReader(self._bounded_raw,buffer_size=4096);self.wfile=socketserver._SocketWriter(self.connection)
 def parse_request(self):
  ok=super().parse_request()
  if ok:self._bounded_raw.limit=16384+65536
  return ok
 def log_message(self,*args):pass
