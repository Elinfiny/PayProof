"""Use ONLY after exact new Owner approval. No actual grant in this package.

Runs on the Master cloud workspace, not the Owner PC. Contains no secret.
The browser generates its capability/key in memory; Master binds only the
public pairing digest observed on that browser, through the native console.
"""
import argparse,secrets,time,pathlib
from .common import *
def prepare(root,owner,source_commit,run_id,start,receipt,proposal_sha):
    root=pathlib.Path(root);root.mkdir(mode=0o700)
    g={'schema':'OWNER_PAYMENT186_ONCE','owner_request':owner,'workflow_sha':source_commit,'run_id':run_id,'source_sha256':source_binding(),'start_at':start,'expires_at':start+600,'limits':LIMITS,'buyer_pairing':'PUBLIC_SHA_NATIVE_BIND_ONCE','master_receipt':receipt,'proposal_sha256':proposal_sha}
    validate_grant(g,time.time(),source_binding())
    write_once(root/'admission.json',canonical(g))
    return {'admission_sha256':sha(canonical(g)),'secret_printed':False,'state':'PREPARED_NOT_NATIVE_ADMITTED'}
if __name__=='__main__':
    import sys,json
    try:
        p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('owner_request');p.add_argument('workflow_sha');p.add_argument('run_id');p.add_argument('start',type=int);p.add_argument('master_receipt');p.add_argument('proposal_sha256');a=p.parse_args()
        print(json.dumps(prepare(a.root,a.owner_request,a.workflow_sha,a.run_id,a.start,obj(pathlib.Path(a.master_receipt).read_bytes()),a.proposal_sha256)))
    except Exception:print('{"state":"REFUSED_OR_PARTIAL","retry":false}');raise SystemExit(1)
