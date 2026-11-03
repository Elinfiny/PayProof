"""Exclusive native source staging only. No admission, key or listener."""
import hashlib,json,os,pathlib,re,socket,subprocess,sys
ROOT=pathlib.Path('/root/payproof-payment186-c235');MIRROR='/root/ubc-mirror80/contr'
def main(commit):
    if os.getuid()!=0 or socket.gethostname()!='v2202609412152514007' or not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('IDENTITY')
    def read(name):
        if not re.fullmatch(r'[a-z0-9_]+\.(py|js|html|json|lock)',name):raise ValueError('PATH')
        r=subprocess.run(['git','-C',MIRROR,'show',commit+':payment186/'+name],capture_output=True,check=True,timeout=10)
        if len(r.stdout)>65536:raise ValueError('SIZE')
        return r.stdout
    manifest=read('manifest.json');m=json.loads(manifest)
    if m['schema']!='PAYMENT186_SOURCE':raise ValueError('MANIFEST')
    payloads={n:read(n) for n in m['files']}
    if {n:hashlib.sha256(v).hexdigest() for n,v in payloads.items()}!=m['files']:raise ValueError('HASH')
    ROOT.mkdir(mode=0o700);app=ROOT/'app';app.mkdir(mode=0o700);pkg=app/'payment186';pkg.mkdir(mode=0o700)
    for name,raw in {**payloads,'manifest.json':manifest}.items():
        fd=os.open(pkg/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        if (pkg/name).read_bytes()!=raw:raise ValueError('READBACK')
    print(json.dumps({'state':'PREPARED','files':len(payloads)+1,'listener':False,'admission':False,'source_commit':commit},sort_keys=True))
if __name__=='__main__':
    try:main(sys.argv[1])
    except Exception:print('{"state":"PREPARE_REFUSED_OR_PARTIAL","retry":false}');raise SystemExit(1)
