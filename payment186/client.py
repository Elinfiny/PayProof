"""Single native worker channel; frozen uncertainty never permits operation retry."""
import os,pathlib,subprocess,time,base64
from .common import *
from .net import https,token

def actual():
    expected={'GITHUB_REPOSITORY':REPO,'GITHUB_REPOSITORY_ID':REPO_ID,'GITHUB_REPOSITORY_OWNER':'Elinfiny','GITHUB_REPOSITORY_OWNER_ID':OWNER_ID,'GITHUB_ACTOR':'Elinfiny','GITHUB_ACTOR_ID':OWNER_ID,'GITHUB_RUN_ATTEMPT':'1','GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_JOB':'payment186','GITHUB_WORKFLOW_REF':WORKFLOW}
    require(all(os.environ.get(k)==v for k,v in expected.items()),'PROVIDER_IDENTITY')
    head=subprocess.run(['git','rev-parse','HEAD'],capture_output=True,text=True,check=True,timeout=5).stdout.strip()
    require(head==os.environ['GITHUB_SHA'] and re.fullmatch('[a-f0-9]{40}',head),'SOURCE_IDENTITY')
    require(not subprocess.run(['git','status','--porcelain','--untracked-files=all'],capture_output=True,text=True,check=True,timeout=5).stdout,'DIRTY_SOURCE')
    manifest=obj((pathlib.Path(__file__).parent/'manifest.json').read_bytes(),65536)
    require(sha(pathlib.Path('.github/workflows/payproof-payment186.yml').read_bytes())==manifest['workflow_active_sha256'],'EXACT_WORKFLOW_BYTES')
    for name,digest in manifest['accepted_payproof_files'].items():
        p=pathlib.Path(name);require(name.startswith('payproof/') and '..' not in p.parts and not p.is_symlink() and sha(p.read_bytes())==digest,'ACCEPTED_PRODUCT_DRIFT')
    return head,os.environ['GITHUB_RUN_ID']

class API:
    def __init__(self,bearer,expires):self.bearer=bearer;self.expires=expires;self.frozen=False;self.counts={}
    def call(self,name,row=None,*,terminal=False,cleanup=False):
        require(not self.frozen or terminal or cleanup,'FROZEN_NO_REPLAY')
        if terminal:require(name=='terminal','TERMINAL_ONLY')
        if cleanup:require(name in ('reserve','result') and (row.get('metadata',{}).get('operation') if name=='reserve' else row.get('operation'))=='subscription_delete','CLEANUP_ONLY')
        budgets={'grant':1,'ready':31,'reserve':10,'result':10,'webhook':1,'order':1,'buyer':60,'event':24,'ai':1,'terminal':1}
        n=self.counts.get(name,0);require(name in budgets and n<budgets[name],'API_BOUND');self.counts[name]=n+1
        body=canonical(row) if row is not None else b''
        try:
            status,raw,digest=https(HOST,'/worker186/'+name,'POST' if row is not None else 'GET',body,{'Authorization':'Bearer '+self.bearer,'Host':HOST,'Content-Type':'application/json','Content-Length':str(len(body))},expires=self.expires)
            require(sha(raw)==digest,'RESPONSE_BYTES')
            if status==204:require(name=='event','EMPTY_RESPONSE');return None
            require(status==200,'HTTP_STATUS');return obj(raw)
        except Exception:self.frozen=True;raise UnknownResult('BRIDGE_UNKNOWN_NO_RETRY') from None
    def close(self):self.bearer=''

def checked_grant(api):
    head,run=actual();g=api.call('grant');validate_grant(g,time.time(),source_binding())
    require(g['workflow_sha']==head and g['run_id']==run and g['owner_request']==os.environ['PAYMENT186_OWNER_REQUEST'] and g['start_at']==int(os.environ['PAYMENT186_START_EPOCH']),'ACTUAL_OWNER_RUN')
    return g

def preflight():
    actual();start=int(os.environ['PAYMENT186_START_EPOCH']);require(time.time()<=start+120 and start-time.time()<=360,'START_WINDOW')
    root=pathlib.Path(os.environ['RUNNER_TEMP'])/'payment186';root.mkdir(mode=0o700)
    write_once(root/'PREFLIGHT_INTENT.json',canonical({'start_at':start}))
    wait=start+1-time.time()
    if wait>0:time.sleep(wait)
    api=API(token(start+600),start+600)
    try:
        g=checked_grant(api)
        for n in range(30):
            ready=api.call('ready');require(ready['grant_sha256']==sha(canonical(g)),'GRANT_READINESS')
            if ready.get('recipient_ready') is True:break
            require(n<29,'BUYER_ROUTE_UNAVAILABLE');time.sleep(2)
        write_once(root/'PREFLIGHT.json',canonical(g));return 0
    finally:api.close()
