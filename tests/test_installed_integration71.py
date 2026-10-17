"""Three new installed-source integration cases; no historical qualification replay."""
import sys,pathlib,argparse,json,hashlib,socket,ssl,tempfile,shutil
from unittest.mock import patch
p=argparse.ArgumentParser();p.add_argument('--installed-root',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);args=p.parse_args();ROOT=args.installed_root.resolve();sys.path.insert(0,str(ROOT))
from payproof import admission as a,bootstrap_bridge as b,job_policy_source42 as s,github_oidc as o
CASE=0

def observe(label,value):print(json.dumps({'pre_assertion_observation71':{'case':CASE,'check':label,'observed':value}},sort_keys=True),flush=True)
def require(value,label):
    observe(label,bool(value))
    if not value:raise AssertionError(label)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def refusal(fn,code=None):
    try:fn()
    except (ValueError,RuntimeError) as error:
        observe('REFUSAL71',{'type':type(error).__name__,'code':str(error)})
        if code is not None:require(str(error)==code,'EXACT_REFUSAL_CODE71')
        return
    raise AssertionError('REFUSAL_REQUIRED71')
class NeverEnvironment:
    def get(self,*args):raise AssertionError('ENVIRONMENT_READ71')
    def __getitem__(self,key):raise AssertionError('ENVIRONMENT_READ71')

def case1():
    manifest=json.loads((ROOT/'payproof/inactive_integration71.json').read_bytes());actual=a.runtime_manifest()
    require(pathlib.Path(a.__file__).resolve().parent==ROOT/'payproof','ACTUAL_INSTALLED_MODULE71')
    require(actual==manifest['runtime8'],'INSTALLED_RUNTIME8_BYTES71')
    require(sha(canonical(actual))==manifest['runtime8_sha256'],'INSTALLED_RUNTIME8_DIGEST71')
    require(a.source_fingerprint()==manifest['admission5_sha256'],'ACTUAL_ADMISSION5_FINGERPRINT71')
    require((ROOT/'tools/read_pilot_driver.py').is_file(),'INSTALLED_DRIVER71')
    require(s.APPROVED_CLIENT_ID_SHA256_67 is None and manifest['authority'] is False and manifest['native_activation'] is False,'INACTIVE_DEFAULTS71')
    return {'runtime8_sha256':manifest['runtime8_sha256'],'admission5_sha256':manifest['admission5_sha256'],'installed':True,'authority':False}

def case2():
    with patch.object(a.os,'environ',NeverEnvironment()):
        refusal(lambda:b.run_actions_step68(), 'UNADMITTED_STEP68')
        refusal(lambda:b.acquire_actions_oidc68(), 'VALIDATED_INVOCATION70_REQUIRED')
        refusal(lambda:s.load_step_authorization68())
    return {'installed_defaults_refused':True,'environment_token_network_reads':0,'native':False}

def case3():
    manifest=json.loads((ROOT/'payproof/inactive_integration71.json').read_bytes())
    policy=o.NativeIdentityPolicy(s.AUDIENCE,s.REPO+'/'+s.WORKFLOW+'@refs/heads/main','refs/heads/main','7'*40,'7'*40,'workflow_dispatch',s.SUBJECT,'7101','1',2010007100,2010007400)
    def evidence(rows):return a.JobPolicyEvidence(policy,a.canonical({'schema':a.JOB_NATIVE_SCHEMA,'bundle_manifest':rows}).encode(),'EXPLICIT_TEST_ONLY71',a._JOB_SYNTHETIC_SEAL)
    altered=json.loads(json.dumps(manifest['runtime8']));altered[0]['sha256']='1'*64
    with patch.object(a.os,'environ',NeverEnvironment()):refusal(lambda:evidence(altered).require(), 'JOB_SOURCE_MANIFEST')
    # Alter a separate installed-byte fixture; the frozen source and installation remain untouched.
    with tempfile.TemporaryDirectory(prefix='explicit_integration71_') as d:
        root=pathlib.Path(d)
        for row in manifest['runtime8']:
            q=root/row['path'];q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes((ROOT/row['path']).read_bytes())
        target=root/'payproof/core.py';target.write_bytes(target.read_bytes()+b'\n# EXPLICIT_ALTERED_INSTALLED_FIXTURE71\n')
        with patch.object(a,'__file__',str(root/'payproof/admission.py')),patch.object(a.os,'environ',NeverEnvironment()):
            require(a.runtime_manifest()!=manifest['runtime8'],'ACTUAL_ALTERED_INSTALLED_BYTES71')
            refusal(lambda:evidence(manifest['runtime8']).require(),'JOB_SOURCE_MANIFEST')
    return {'altered_manifest_and_independent_installed_source_refused':True,'synthetic_policy_only':True,'environment_token_network_reads':0,'native':False}

if __name__=='__main__':
    rows=[];status='PASS'
    def no_network(*args,**kwargs):raise AssertionError('REAL_NETWORK_OR_TLS71')
    with patch.object(socket,'create_connection',no_network),patch.object(socket,'getaddrinfo',no_network),patch.object(socket.socket,'connect',no_network),patch.object(ssl,'create_default_context',no_network):
        for ordinal,fn in enumerate((case1,case2,case3),1):
            CASE=ordinal;observe('CASE_START71',{'integration_only':True,'native':False})
            try:detail=fn();row={'case':ordinal,'status':'PASS','detail':detail}
            except BaseException as error:row={'case':ordinal,'status':'FAIL','error_type':type(error).__name__};status='PARTIAL'
            rows.append(row);print(json.dumps({'case_receipt':row},sort_keys=True),flush=True)
            if status!='PASS':break
    print(json.dumps({'schema':'NEW_INVOKER71_GROUP','status':status,'cases':rows,'real_project_env_TLS_DNS_credentials_OAuth_PayPalHTTP':0,'native':False},sort_keys=True),flush=True)
    sys.exit(0 if status=='PASS' and len(rows)==3 else 1)
