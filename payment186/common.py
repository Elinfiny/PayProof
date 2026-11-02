"""Nonsecret fixed scope and durable, exclusive evidence operations."""
import base64,hashlib,json,os,pathlib,re,stat,time

REPO='Elinfiny/PayProof'; REPO_ID='1419908202'; OWNER_ID='273768139'
HOST='v2202609412152514007.ultrasrv.de'; HOSTNAME='v2202609412152514007'
ISSUER='https://token.actions.githubusercontent.com'
AUDIENCE='urn:payproof:netcup932863:payment186'
WORKFLOW=REPO+'/.github/workflows/payproof-payment186.yml@refs/heads/main'
ROOT=pathlib.Path('/root/payproof-payment186-c202')
APP='b954b4c7eff1b9aac313ca9867e2d8fa31fb1782453b0ce583cb2dd1bb436e74'
OPS=('oauth','subscription_read','subscription_create','order_create','approval_read','capture','final_read','verify','event_read','subscription_delete')
LIMITS={'session_seconds':600,'job_minutes':10,'accepted_connections':512,'PayPal_calls':10,'certificate_GETs':2,'JWKS_GETs':1,'fake_USD':'1.00','real_USD':'0.00','extra_cost':'0.00','oidc_tokens':2,'browser_recipient_keys':1,'retries':0}
CERT=pathlib.Path('/root/payproof-tls144/state/certificates')/(HOST+'.crt')
CERT_SHA='21dee76d08b1c698809616845d3665b7375f6a98f5cb7e18075794f31175e10f'

class Refused(ValueError): pass
class UnknownResult(RuntimeError): pass
LIMIT=65536
def require(ok,code):
    if not ok: raise Refused(code)
def canonical(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def obj(b,limit=1500000):
    require(type(b) is bytes and 0<len(b)<=limit,'JSON_SIZE')
    def pairs(xs):
        d={}
        for k,v in xs: require(k not in d,'DUPLICATE_KEY');d[k]=v
        return d
    d=json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:require(False,'NONFINITE'))
    require(type(d) is dict,'OBJECT');return d
def private(p,directory=False):
    s=pathlib.Path(p).lstat()
    require(not pathlib.Path(p).is_symlink() and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==(0o700 if directory else 0o600),'PRIVATE_CUSTODY')
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode),'PRIVATE_TYPE')
def write_once(p,b):
    p=pathlib.Path(p);private(p.parent,True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    require(p.read_bytes()==b,'READBACK')
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def source_binding():
    p=pathlib.Path(__file__).parent;m=obj((p/'manifest.json').read_bytes(),65536)
    require(m['schema']=='PAYMENT186_SOURCE','SOURCE_SCHEMA')
    for name,h in m['files'].items():
        require(re.fullmatch(r'[a-z0-9_]+\.(py|js|html|lock)',name) and not (p/name).is_symlink(),'SOURCE_NAME')
        require(sha((p/name).read_bytes())==h,'SOURCE_DRIFT')
    return sha(canonical(m))
def proposal(source):
    return {'schema':'PAYMENT186_EXACT_PROPOSAL','source_sha256':source,'limits':LIMITS,
            'repository':REPO,'workflow':WORKFLOW,'environment':'payproof-sandbox-readonly',
            'native_root':str(ROOT),'host':HOST,'listener_port':443,'once_namespace':'P186',
            'one_new_order':True,'one_capture_after_provider_APPROVED':True,
            'payment_operations':list(OPS),'one_job_one_attempt':True,
            'closure':'terminal, failure or absolute expiry; preserve UNKNOWN and original files',
            'subscription_cleanup':'pre-reserved DELETE once for exact new hook; independent sanitized GitHub receipt survives main-channel loss',
            'browser':'one browser-local temporary capability and ephemeral RSA2048 key; Master binds public pairing SHA once on Netcup; automatic encrypted approval transfer',
            'custody':'existing GitHub Sandbox credentials; Netcup root-private originals; no public artifacts',
            'publication':'exact reviewed additive files and one workflow; disable workflow after dispatch',
            'old_effects_replay':False,'accepted177_requalification':False}
def validate_grant(g,now,source):
    fields={'schema','owner_request','source_sha256','workflow_sha','run_id','start_at','expires_at','limits','buyer_pairing','master_receipt','proposal_sha256'}
    require(set(g)==fields and g['schema']=='OWNER_PAYMENT186_ONCE' and g['limits']==LIMITS,'SCOPE')
    require(type(g['owner_request']) is str and re.fullmatch('[a-f0-9-]{36}',g['owner_request']),'OWNER')
    require(g['source_sha256']==source and re.fullmatch('[a-f0-9]{40}',g['workflow_sha']) and re.fullmatch('[1-9][0-9]{0,19}',g['run_id']),'SOURCE_RUN')
    require(type(g['start_at']) is int and type(g['expires_at']) is int and g['expires_at']-g['start_at']==600 and g['start_at']-360<=now<g['expires_at'],'TIME')
    require(g['buyer_pairing']=='PUBLIC_SHA_NATIVE_BIND_ONCE' and re.fullmatch('[a-f0-9]{64}',g['proposal_sha256']),'PAIRING_SCOPE')
    require(g['proposal_sha256']==sha(canonical(proposal(source))),'EXACT_PREPARED_PROPOSAL')
    r=g['master_receipt'];require(set(r)=={'version','raw_sha256','self_sha256'} and type(r['version']) is int and r['version']>186 and all(re.fullmatch('[a-f0-9]{64}',r[k]) for k in ('raw_sha256','self_sha256')),'REAL_OWNER_RECEIPT')
def identity(g):
    return {'head':g['workflow_sha'],'run_id':g['run_id'],'attempt':1,'repository_id':REPO_ID,'actor_id':OWNER_ID,'source_sha256':g['source_sha256']}
def engine_source(g):return sha(canonical(identity(g)))
def caller(g):return 'github:'+REPO+':'+g['run_id']+':1'
def once_prefix(g):return 'P186-'+g['run_id']
def approval(url,order):
    from urllib.parse import urlsplit
    require(type(order) is str and re.fullmatch('[A-Z0-9-]{1,64}',order),'ORDER_ID')
    p=urlsplit(url)
    require(p.scheme=='https' and p.netloc=='www.sandbox.paypal.com' and p.path=='/checkoutnow' and p.query=='token='+order and not p.fragment,'APPROVAL_ORIGIN')
    require(len(url.encode())<=190,'RSA_PAYLOAD_BOUND')
    return url
