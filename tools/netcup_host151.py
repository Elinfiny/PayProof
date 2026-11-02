"""One Owner-admitted Netcup151 receiver; no recurring or PayPal credential path.

Prepare copies an exact accepted application plus verified source delta into a
new root-private directory. Secret entry uses getpass; stdout never carries it.
Serve is single-use, root/host/source/TLS-bound and <=600s. Raw evidence is
preserved with full byte readback before the ephemeral inbox is cleared.
"""
import argparse,base64,getpass,hashlib,json,os,pathlib,re,shutil,socket,sqlite3,ssl,stat,subprocess,sys,time
ROOT=pathlib.Path('/root/payproof-native151')
HOST='v2202609412152514007.ultrasrv.de'
HOSTNAME='v2202609412152514007'
CERT=pathlib.Path('/root/payproof-tls144/state/certificates')/(HOST+'.crt')
KEY=CERT.with_suffix('.key')
CERT_SHA='21dee76d08b1c698809616845d3665b7375f6a98f5cb7e18075794f31175e10f'
HOST_PIN='tMqlz/hjGKUUlSkzhWMtNaTbpz69dYTo+QO/9ozVJ74'
OWNER_SCOPE='1b98223ac1a22c2be2dde458934eb620b2236c29048ef9cd567e128174b3154c'
APP_ID='b954b4c7eff1b9aac313ca9867e2d8fa31fb1782453b0ce583cb2dd1bb436e74'

def canonical(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def require(ok,code):
 if not ok:raise ValueError(code)
def private(p,directory=False):
 s=p.lstat();require(not p.is_symlink() and s.st_uid==0 and stat.S_IMODE(s.st_mode)==(0o700 if directory else 0o600),'PRIVATE_ROOT_CUSTODY151');return s

def write_once(p,raw):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 require(p.read_bytes()==raw,'ACTUAL_FILE_READBACK151')

def retain_binding163(receiver,kind):
 """Private recovery identifiers, durable before acknowledging a binding.

 Never include credentials or the approval URL. These records are evidence,
 not authority to repeat a provider operation or reopen an expired session.
 """
 require(kind in ('bootstrap','webhook','order'),'BINDING_KIND163')
 private(ROOT,True)
 row={'schema':'PAYPROOF_PRIVATE_BINDING163','kind':kind,
      'source':receiver.scope.source,'run_id':receiver.run_id,
      'expires_at':receiver.scope.expires_at,
      'webhook_id':receiver.webhook_id if kind in ('webhook','order') else None,
      'order_id':receiver.order_id if kind=='order' else None}
 write_once(ROOT/('BOUND_'+kind+'163.json'),canonical(row))

def retain_transport163(kind,accepted,error_type):
 """Bounded metadata only; no exception message, headers, peer or payload."""
 require(kind in ('CONNECTION_LIMIT','HANDLER_ERROR'),'TRANSPORT_KIND163')
 require(type(accepted) is int and 0<=accepted<=513,'TRANSPORT_COUNT163')
 safe=error_type if error_type in ('SSLError','SSLEOFError','TimeoutError','OSError','ValueError') else 'OTHER'
 private(ROOT,True)
 # One immutable first observation per kind; later failures never overwrite it.
 p=ROOT/('TRANSPORT_'+kind+'163.json')
 try:write_once(p,canonical({'kind':kind,'accepted':accepted,'error_type':safe}))
 except FileExistsError:pass

def actual_host():
 require(os.getuid()==0 and socket.gethostname()==HOSTNAME,'EXACT_NETCUP_ROOT151')
 require(sha(CERT.read_bytes())==CERT_SHA,'EXACT_EXISTING_TLS151');private(KEY)
 pub=pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
 key_hash=hashlib.sha256(base64.b64decode(pub[1])).digest()
 require(base64.b64encode(key_hash).decode().rstrip('=')==HOST_PIN,'ORIGINAL_HOST_PIN151')
 return key_hash.hex()

def source_manifest(root):
 rows=[]
 for p in sorted(root.rglob('*')):
  require(not p.is_symlink(),'NO_SOURCE_SYMLINK151')
  if p.is_file():rows.append({'path':p.relative_to(root).as_posix(),'size':p.stat().st_size,'sha256':sha(p.read_bytes())})
 return rows

def prepare(delta_path):
 actual_host();delta=json.loads(pathlib.Path(delta_path).read_bytes())
 require(delta.get('owner_scope151')==OWNER_SCOPE and delta.get('base_graph')=='a539fe48c29679d1c14fcc015fefaa45213c486538a82e71c49a3ecfc012629c','EXACT_DELTA151')
 base=pathlib.Path('/root/payproof-stage147/app');rows=source_manifest(base)
 require(sha(canonical(rows))==delta['base_graph'],'ACCEPTED_BASE_BYTES151')
 ROOT.mkdir(mode=0o700,exist_ok=False);private(ROOT,True)
 shutil.copytree(base,ROOT/'app')
 for name,text in delta['files'].items():
  require(re.fullmatch(r'(?:tools/[a-zA-Z0-9_]+\.py|deploy10/requirements\.lock|\.github/workflows/payproof-selfhosted10\.yml)',name) is not None,'SOURCE_DELTA_ALLOWLIST151')
  target=ROOT/'app'/name;require(not target.is_symlink(),'SOURCE_FILE151');target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
 rows=source_manifest(ROOT/'app');require(rows==delta['result_manifest'],'EXACT_POSTIMAGES151')
 receipt={'schema':'PAYPROOF151_HOST_SOURCE_PREPARED','state':'PASS','owner_scope151':OWNER_SCOPE,'runtime_sha256':sha(canonical(rows)),'source_manifest':rows,'server_id':'932863','TLS_sha256':CERT_SHA,'no_listener':True,'no_PayPal':True}
 write_once(ROOT/'PREPARED.json',canonical(receipt));print(json.dumps({'state':'PREPARED_PASS','runtime_sha256':receipt['runtime_sha256'],'files':len(rows),'token_created':False,'port_opened':False}))

def token():
 actual_host();private(ROOT,True);require(not (ROOT/'bridge.token').exists(),'NO_TOKEN_REPLACEMENT151')
 value=getpass.getpass('ENTER_CONFIRMED_BRIDGE_TOKEN_ONCE: ')
 require(re.fullmatch('[0-9a-f]{64}',value) is not None,'EXACT_256BIT_TOKEN_ENCODING151')
 write_once(ROOT/'bridge.token',value.encode());value=None;print('{"token_saved":true,"mode":"0600","value_exported":false}')

def make_scope(head,issued,runtime,guest,host_pin):
 require(re.fullmatch('[a-f0-9]{40}',head) is not None,'EXACT_PUBLIC_SOURCE151')
 target={'server_id':'932863','origin':'https://'+HOST,'service_id':'nc-932863-payproof151','source':head,'runtime_sha256':runtime,'guest_control_original_sha256':guest,'host_key_pin_sha256':host_pin,'tls_certificate_sha256':CERT_SHA,'observed_at':issued,'transport':'DIRECT_TLS443','cost':'TOTAL_INCREMENTAL_ZERO_PROVEN','private_backend':True}
 scope={'source':head,'session':'PNC10-OWNER151-20261102','app_sha256':APP_ID,'origin':'https://'+HOST,'service_id':'nc-932863-payproof151','issued_at':issued,'expires_at':issued+600,'target_binding_sha256':sha(canonical(target)),'runtime_sha256':runtime}
 return scope,target

def retain_private151(receiver):
 """Never purge the only original. New immutable backup + metadata readback."""
 private(ROOT,True);original=pathlib.Path(receiver.inbox.path)
 require(original==ROOT/'INBOX.sqlite','EXACT_INBOX_CUSTODY151')
 archive=ROOT/'RETAINED.sqlite';out=ROOT/'RETAINED.json'
 if archive.exists():
  r=json.loads(out.read_bytes());require(sha(archive.read_bytes())==r['archive_sha256'],'EXISTING_RETAINED_READBACK151');return r
 private(original);write_once(archive,b'')
 try:
  with sqlite3.connect(original) as src,sqlite3.connect(archive) as dst:src.backup(dst)
  with archive.open('rb') as f:os.fsync(f.fileno())
  raw=archive.read_bytes();r={'schema':'PAYPROOF151_PRIVATE_CUSTODY','source':receiver.scope.source,'run_id':receiver.run_id,'archive_sha256':sha(raw),'archive_bytes':len(raw),'event_retained':receiver._has_event(),'report':receiver.report,'originals_sha256':{},'AI_sha256':None,'whole_byte_readback':False}
  with sqlite3.connect(archive) as db:
   names={x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
   if 'originals153' in names:r['originals_sha256']={x[0]:x[1] for x in db.execute('SELECT operation,sha256 FROM originals153')}
   if 'ai151' in names:r['AI_sha256']=db.execute('SELECT sha256 FROM ai151').fetchone()[0]
  require(sha(archive.read_bytes())==r['archive_sha256'],'WHOLE_PRIVATE_ARCHIVE_READBACK151');r['whole_byte_readback']=True;write_once(out,canonical(r));return r
 except BaseException:
  # Preserve original and partial archive; do not retry/overwrite after uncertainty.
  raise

def serve(head):
 pin=actual_host();private(ROOT,True);private(ROOT/'bridge.token')
 receipt=json.loads((ROOT/'PREPARED.json').read_bytes());rows=source_manifest(ROOT/'app')
 require(receipt['runtime_sha256']==sha(canonical(rows)),'ACTUAL_SOURCE_DRIFT151')
 write_once(ROOT/'SERVE_INTENT.json',canonical({'source':head,'state':'CONSUMED_BEFORE_BIND','owner_scope151':OWNER_SCOPE}))
 issued=int(time.time());scope,target=make_scope(head,issued,receipt['runtime_sha256'],sha((ROOT/'PREPARED.json').read_bytes()),pin)
 write_once(ROOT/'SCOPE.json',canonical({'bridge10':scope,'target_readback10':target}))
 from .sandbox_bridge10 import Scope153,Capability153,Receiver153
 from .sandbox_listener10 import EventInbox151
 from .sandbox_receiver10 import Server10,serve10
 s=Scope153(**dict(scope,test_only=False));cap=Capability153(s,(ROOT/'bridge.token').read_text())
 inbox=EventInbox151(ROOT/'INBOX.sqlite');receiver=Receiver153(cap,inbox)
 tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_2;tls.load_cert_chain(CERT,KEY)
 server=Server10(('0.0.0.0',443),receiver,tls_context=tls)
 try:serve10(server)
 finally:
  cap.close()
  # The specific newly created ephemeral token is disposable after session close.
  (ROOT/'bridge.token').unlink(missing_ok=True)
  write_once(ROOT/'TERMINAL.json',canonical({'state':'RECEIVER_CLOSED','issued_at':issued,'expires_at':scope['expires_at'],'source':head,'secret_value_exported':False}))

def start(head):
 actual_host();require(not (ROOT/'SERVE_INTENT.json').exists(),'NO_RECEIVER_REPLAY151')
 env={'PATH':'/usr/bin:/bin','HOME':'/root','PYTHONDONTWRITEBYTECODE':'1','PYTHONPATH':str(ROOT/'app')}
 proc=subprocess.Popen([sys.executable,'-B','-m','tools.netcup_host151','serve',head],cwd=ROOT/'app',env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 write_once(ROOT/'PROCESS.json',canonical({'pid':proc.pid,'source':head}))
 for _ in range(50):
  if (ROOT/'SCOPE.json').exists():
   time.sleep(.2);require(proc.poll() is None,'RECEIVER_START_FAILED_NO_REPLAY151');print((ROOT/'SCOPE.json').read_text());return
  require(proc.poll() is None,'RECEIVER_START_FAILED_NO_REPLAY151');time.sleep(.1)
 raise RuntimeError('RECEIVER_START_UNKNOWN_NO_REPLAY151')

def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','token','start','serve']);p.add_argument('argument',nargs='?');a=p.parse_args()
 if a.action=='prepare':prepare(a.argument)
 elif a.action=='token':token()
 elif a.action=='start':start(a.argument)
 else:serve(a.argument)
if __name__=='__main__':main()
