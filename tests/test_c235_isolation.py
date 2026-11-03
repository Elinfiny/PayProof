"""C235 admission isolation from expired or late C230; synthetic only."""
import base64, copy, unittest
from payment186.common import *
from payment186.oidc import verify_oidc
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class IsolationC235(unittest.TestCase):
    def setUp(self):
        self.source=source_binding(); self.now=2000000000
        self.g={'schema':'OWNER_PAYMENT186_ONCE','owner_request':'e5331753-f4bc-4ce9-9b55-7cef8bdb2d26','source_sha256':self.source,'workflow_sha':'2'*40,'run_id':'235','start_at':self.now,'expires_at':self.now+600,'limits':LIMITS,'buyer_pairing':'PUBLIC_SHA_NATIVE_BIND_ONCE','master_receipt':{'version':235,'raw_sha256':'a'*64,'self_sha256':'b'*64},'proposal_sha256':sha(canonical(proposal(self.source)))}
    def test_expired_window_rejected(self):
        validate_grant(self.g,self.now,self.source)
        with self.assertRaisesRegex(Refused,'TIME'):validate_grant(self.g,self.now+600,self.source)
    def test_c230_source_cannot_enter_c235(self):
        old=copy.deepcopy(self.g);old['source_sha256']='65ff25f35901f424c17a0ad0b598bc60bb218f29475ecd0ef59758790303b7c4'
        with self.assertRaisesRegex(Refused,'SOURCE_RUN'):validate_grant(old,self.now,self.source)
    def test_signed_late_run_cannot_use_new_receiver(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048);pub=key.public_key().public_numbers()
        enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        num=lambda n:enc(n.to_bytes((n.bit_length()+7)//8,'big'))
        jwks=canonical({'keys':[{'kid':'synthetic','kty':'RSA','alg':'RS256','use':'sig','n':num(pub.n),'e':num(pub.e)}]})
        claims={'iss':ISSUER,'aud':AUDIENCE,'repository':REPO,'repository_id':REPO_ID,'repository_owner':'Elinfiny','repository_owner_id':OWNER_ID,'repository_visibility':'public','actor':'Elinfiny','actor_id':OWNER_ID,'workflow_ref':WORKFLOW,'workflow_sha':self.g['workflow_sha'],'sha':self.g['workflow_sha'],'ref':'refs/heads/main','ref_type':'branch','event_name':'workflow_dispatch','run_id':'235','run_attempt':'1','runner_environment':'github-hosted','sub':'repo:'+REPO+':environment:payproof-sandbox-readonly','iat':self.now,'nbf':self.now,'exp':self.now+600,'jti':'synthetic-c235'}
        def signed(c):
            raw=enc(canonical({'alg':'RS256','typ':'JWT','kid':'synthetic'}))+'.'+enc(canonical(c))
            return raw+'.'+enc(key.sign(raw.encode(),padding.PKCS1v15(),hashes.SHA256()))
        verify_oidc(signed(claims),jwks,self.g,self.now)
        for field,value in [('run_id','230'),('workflow_sha','17ec3512b28dfd259351bedbb44aa89f0df31556'),('sha','17ec3512b28dfd259351bedbb44aa89f0df31556')]:
            bad={**claims,field:value}
            with self.subTest(field=field),self.assertRaisesRegex(Refused,'IDENTITY'):verify_oidc(signed(bad),jwks,self.g,self.now)

if __name__=='__main__':unittest.main()
