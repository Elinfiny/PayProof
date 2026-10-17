"""Create a bounded, explicitly allowlisted source test-build. No installer/network."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import zipfile

MAX_ZIP = 786432
BASE_COMMIT = '3d7eb63fbfaf8c3cb9223effecac41f24c6623e3'
BASE_TREE = 'fc3f4ce717209193eeaf2591020abd28420ae154'
ALLOWLIST = (
 'LICENSE','README.md','pyproject.toml',
 'payproof/__init__.py','payproof/admission.py','payproof/bootstrap_bridge.py',
 'payproof/core.py','payproof/fixtures.py','payproof/github_oidc.py',
 'payproof/inactive_integration71.json','payproof/job_policy_source42.py',
 'payproof/paypal.py','payproof/server.py','payproof/service.py',
 'payproof/web/app.js','payproof/web/index.html','payproof/web/style.css',
 'tools/read_pilot_driver.py','tools/offline_report/export_fixture_report81.py',
 'tools/offline_report/reporter_contract81.json','tools/contest_build84.py',
 'tools/contest_launcher84.py','docs/CONTEST_BUILD84.md',
 'workflow_candidates/payproof-contest-build84.yml.disabled',
)

def git_object(kind, data):
 return hashlib.sha1(kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()

def tree_hash(entries):
 root={}
 for e in entries:
  p=PurePosixPath(e['path'])
  if p.is_absolute() or '..' in p.parts or str(p)!=e['path']:raise ValueError('Noncanonical tree path')
  at=root
  for part in p.parts[:-1]:at=at.setdefault(part,{})
  if p.name in at:raise ValueError('Duplicate tree entry')
  at[p.name]=e
 def walk(node):
  parts=[]
  for name,item in node.items():
   directory='sha' not in item
   mode='40000' if directory else item['mode'].lstrip('0')
   sha=walk(item) if directory else item['sha']
   parts.append((name.encode()+(b'/' if directory else b''),mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)))
  return git_object('tree',b''.join(data for _,data in sorted(parts)))
 return walk(root)

def bounded_source(root, relative):
 parts=PurePosixPath(relative).parts;fds=[];fd=None
 try:
  parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(parent)
  for name in parts[:-1]:
   parent=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);fds.append(parent)
  fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=65536:raise ValueError('Source type/link/size bound')
  chunks=[];at=0
  while at<before.st_size:
   chunk=os.pread(fd,min(4096,before.st_size-at),at)
   if not chunk:raise ValueError('Short source read')
   chunks.append(chunk);at+=len(chunk)
  after=os.fstat(fd);entry=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  if key(before)!=key(after) or key(before)!=key(entry):raise ValueError('Source identity drift')
  return b''.join(chunks)
 finally:
  if fd is not None:os.close(fd)
  for descriptor in reversed(fds):os.close(descriptor)

def inventory(root, commit, supplied):
 if supplied:
  p=Path(supplied)
  if p.is_symlink() or p.stat().st_size>65536:raise ValueError('Inventory bound')
  entries=json.loads(p.read_text())['entries']
 else:
  # Local checkout reads only: no fetch, checkout, install, hook or network command.
  call=subprocess.run(['git','-C',str(root),'ls-tree','-r','-z','--full-tree',commit],capture_output=True,timeout=10,check=True)
  if len(call.stdout)>65536:raise ValueError('Git inventory bound')
  entries=[]
  for row in call.stdout.split(b'\0'):
   if row:
    metadata,path=row.split(b'\t',1);mode,kind,sha=metadata.decode().split();entries.append({'path':path.decode(),'mode':mode,'type':kind,'sha':sha})
 if not isinstance(entries,list) or not 1<=len(entries)<=128:raise ValueError('Inventory entry bound')
 return entries

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
 parser.add_argument('--source-commit',required=True);parser.add_argument('--source-tree',required=True);parser.add_argument('--inventory')
 args=parser.parse_args();root=args.root.absolute();output=args.output.absolute()
 if root.is_symlink() or output.exists() or output.is_symlink():raise ValueError('Explicit stable source and absent output required')
 if any(len(v)!=40 or any(c not in '0123456789abcdef' for c in v) for v in [args.source_commit,args.source_tree]):raise ValueError('Exact Git source identifiers required')
 entries=inventory(root,args.source_commit,args.inventory)
 if tree_hash(entries)!=args.source_tree:raise ValueError('Complete inventory Merkle differs')
 known={e['path']:e for e in entries};payload={};pins=[]
 for name in ALLOWLIST:
  b=bounded_source(root,name);e=known[name]
  if e['type']!='blob' or e['mode']!='100644' or git_object('blob',b)!=e['sha']:raise ValueError('Source does not match exact Git inventory: '+name)
  payload[name]=b;pins.append({'path':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':e['sha']})
 provenance={'schema':'PAYPROOF_CONTEST_SOURCE_BUILD84','base_commit':BASE_COMMIT,'base_tree':BASE_TREE,'source_commit':args.source_commit,'source_tree':args.source_tree,'payload_pins':pins,'fixture_only':True,'actual_PayPal_integration_qualified':False,'actual_AI_integration':False,'contest_ready':False,'dependency':'Fixture source entry is qualified with -I -S; declared cryptography==50.0.2 remains required for native identity modules. No installer or crypto stub is bundled.','meaning':'Source-integrity metadata, never an admission or provider grant.'}
 payload['SOURCE84.json']=(json.dumps(provenance,sort_keys=True,indent=2)+'\n').encode()
 manifest=io.StringIO(newline='');writer=csv.writer(manifest);writer.writerow(['relative_path','size_bytes','sha256'])
 for name,b in sorted(payload.items()):writer.writerow([name,len(b),hashlib.sha256(b).hexdigest()])
 payload['MANIFEST.csv']=manifest.getvalue().encode()
 if sum(map(len,payload.values()))>MAX_ZIP:raise ValueError('Uncompressed build bound')
 fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 # Never remove/retry a partial output if writing or closing fails.
 with os.fdopen(fd,'wb') as stream:
  with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
   for name,b in sorted(payload.items()):
    info=zipfile.ZipInfo('PayProof_contest84/'+name,(2026,10,17,0,0,0));info.create_system=3;info.external_attr=(stat.S_IFREG|0o600)<<16;info.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(info,b)
 if output.stat().st_size>MAX_ZIP:raise RuntimeError('UNKNOWN oversized build: retain, do not retry')
 raw=output.read_bytes()
 with zipfile.ZipFile(io.BytesIO(raw)) as archive:
  if archive.testzip() is not None or len(archive.namelist())!=len(payload):raise RuntimeError('UNKNOWN archive readback')
  for name,b in payload.items():
   if archive.read('PayProof_contest84/'+name)!=b:raise RuntimeError('UNKNOWN body readback')
 print(json.dumps({'status':'BUILD_CREATED','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'members':len(payload),'source_commit':args.source_commit,'source_tree':args.source_tree,'fixture_only':True,'installer_calls':0,'provider_calls':0}))

if __name__=='__main__':main()
