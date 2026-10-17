"""Verified source-only fixture launcher. No native admission or dependency installer."""
import argparse
import csv
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import threading
import time

def verify_build(root):
 manifest=root/'MANIFEST.csv'
 if manifest.is_symlink() or not 0<manifest.stat().st_size<=16384:raise ValueError('Manifest bound')
 rows=list(csv.DictReader(manifest.open(newline='')));names=set()
 if len(rows)>32:raise ValueError('Manifest row bound')
 for row in rows:
  name=row['relative_path'];p=PurePosixPath(name)
  if p.is_absolute() or '..' in p.parts or str(p)!=name or name in names:raise ValueError('Unsafe manifest path')
  names.add(name);path=root
  for part in p.parts:
   path=path/part
   if path.is_symlink():raise ValueError('Symlink refused')
  s=path.stat()
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or not 0<s.st_size<=65536 or s.st_size!=int(row['size_bytes']):raise ValueError('Payload bound/type')
  b=path.read_bytes()
  if hashlib.sha256(b).hexdigest()!=row['sha256']:raise ValueError('Manifest digest mismatch')
 actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
 if actual!=names|{'MANIFEST.csv'}:raise ValueError('Unexpected build payload')
 source=json.loads((root/'SOURCE84.json').read_text())
 if source['schema']!='PAYPROOF_CONTEST_SOURCE_BUILD84' or source['actual_AI_integration'] or source['actual_PayPal_integration_qualified'] or source['contest_ready']:raise ValueError('Fixture build classification')
 return {'members':len(actual),'manifest_rows':len(rows),'source_commit':source['source_commit'],'source_tree':source['source_tree'],'metadata_is_not_authority':True}

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--data-dir',type=Path,required=True);parser.add_argument('--port',type=int,default=8765);parser.add_argument('--smoke',action='store_true');parser.add_argument('--event-id')
 args=parser.parse_args();os.umask(0o077);root=Path(__file__).absolute().parent.parent;verified=verify_build(root);data=args.data_dir.absolute();s=data.lstat()
 if data.is_symlink() or not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700 or list(data.iterdir()):raise ValueError('Existing empty owned0700 private data directory required')
 if not 0<=args.port<=65535:raise ValueError('Port bound')
 db=data/'fixture84.sqlite3'
 if db.exists() or db.is_symlink():raise ValueError('Fresh fixture DB required')
 sys.path.insert(0,str(root))
 from payproof import server
 if args.smoke and (not sys.flags.no_site or importlib.util.find_spec('cryptography') is not None):raise ValueError('Smoke requires clean -I -S dependency isolation')
 calls={'local_connects':0,'external_connects':0,'secret_opens':0}
 allowed_port=[None]
 def audit(event,arguments):
  if event=='socket.connect':
   address=arguments[1]
   if not isinstance(address,tuple) or address[:2]!=('127.0.0.1',allowed_port[0]):
    calls['external_connects']+=1;raise RuntimeError('External connection forbidden in fixture build')
   calls['local_connects']+=1
  if event=='open' and isinstance(arguments[0],str) and arguments[0].startswith('/run/secrets/'):
   calls['secret_opens']+=1;raise RuntimeError('Secret access forbidden in fixture build')
 sys.addaudithook(audit)
 if not args.smoke:
  sys.argv=['payproof.server','--mode','fixture','--db',str(db),'--port',str(args.port)]
  return server.main()
 if not args.event_id or len(args.event_id)>80:raise ValueError('A distinct explicit synthetic event ID is required')
 deadline=time.monotonic()+20;httpd=None;worker=None;primary=None;cleanup=[];observations=[];responses={};rollback=None
 try:
  httpd=server.make_server(port=0,db_path=db,mode='fixture');port=httpd.server_port;allowed_port[0]=port
  worker=threading.Thread(target=httpd.serve_forever,kwargs={'poll_interval':0.01});worker.start()
  print(json.dumps({'record':'PACKAGED_ENTRY_STARTED','manifest':verified,'bound_host':'127.0.0.1','port':port,'fresh_registered_order':'DEMO-ORDER-001','event_id':args.event_id,'site_packages_disabled':True}),flush=True)
  requests=[('initial','GET','/api/state',None),('event','POST','/api/fixture-event',{'scenario':'unknown','event_id':args.event_id,'verified':True}),('final','GET','/api/state',None)]
  for label,method,path,payload in requests:
   if time.monotonic()>=deadline:raise TimeoutError('Bounded smoke deadline')
   body=None if payload is None else json.dumps(payload).encode();connection=http.client.HTTPConnection('127.0.0.1',port,timeout=min(3,deadline-time.monotonic()));error=None
   try:
    headers={'Host':f'127.0.0.1:{port}'}
    if body is not None:headers.update({'Origin':f'http://127.0.0.1:{port}','Content-Type':'application/json','X-PayProof-Request':'fixture-ui'})
    connection.request(method,path,body=body,headers=headers);response=connection.getresponse();raw=response.read(16385)
    observation={'record':'ORIGINAL_HTTP_RESPONSE','label':label,'status':response.status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'body':raw.decode()};observations.append(observation);print(json.dumps(observation),flush=True)
   except BaseException as e:error=e;raise
   finally:
    try:connection.close()
    except BaseException as e:
     if error is None:raise
     cleanup.append({'stage':'HTTP_close','type':type(e).__name__,'message':str(e)})
   if len(raw)>16384 or response.status!=200:raise ValueError('Safe fixture response bound/status')
   responses[label]=json.loads(raw)
  assert responses['initial']['orders'][0]['state']=='UNKNOWN' and responses['initial']['contest_ready'] is False
  assert responses['event']['disposition']=='NEEDS_RECONCILIATION' and responses['event']['order']['state']=='UNKNOWN'
  assert responses['final']['orders'][0]['state']=='UNKNOWN' and responses['final']['ai_mode']=='DETERMINISTIC — NOT LIVE AI'
  with httpd.store.connect() as connection:
   counts={name:connection.execute('SELECT count(*) FROM '+name).fetchone()[0] for name in ['orders','events','effects']}
  assert counts=={'orders':1,'events':1,'effects':0} and calls['external_connects']==calls['secret_opens']==0
  assert not any(name=='cryptography' or name.startswith('cryptography.') for name in sys.modules)
 except BaseException as error:primary=error
 finally:
  if httpd is not None:
   try:httpd.shutdown()
   except BaseException as error:cleanup.append({'stage':'shutdown','type':type(error).__name__,'message':str(error)})
   finally:
    try:httpd.server_close()
    except BaseException as error:cleanup.append({'stage':'server_close','type':type(error).__name__,'message':str(error)})
  if worker is not None:
   worker.join(timeout=2)
   if worker.is_alive():cleanup.append({'stage':'join','type':'TimeoutError','message':'Server thread remains alive'})
 print(json.dumps({'record':'PACKAGED_SMOKE_TERMINAL','status':'PASS' if primary is None and not cleanup else 'FAIL_UNKNOWN','primary':None if primary is None else {'type':type(primary).__name__,'message':str(primary)},'cleanup':cleanup,'counts':None if primary else counts,'network':calls,'manifest':verified,'cryptography_imported':any(n=='cryptography' or n.startswith('cryptography.') for n in sys.modules),'new_fixture_DB_bytes':db.stat().st_size if db.exists() else None,'fixture_only':True,'actual_AI':False,'actual_PayPal':False,'contest_ready':False,'server_close_attempts':1 if httpd else 0}),flush=True)
 if primary is not None:raise primary.with_traceback(primary.__traceback__)
 if cleanup:raise RuntimeError('UNKNOWN cleanup; retain outputs, no retry')

if __name__=='__main__':main()
