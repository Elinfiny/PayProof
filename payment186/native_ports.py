"""Existing GitHub environment custody; separate186 durable remote once slots."""
import base64,os,pathlib,time
from dataclasses import dataclass
from .common import *
from .chain import Grant151,PROFILE,_NATIVE,InvalidData
from .client import API,actual

class NativePorts152:
    def __init__(self,api,grant,root):
        require(type(api) is API,'EXACT_NATIVE_API');self.api=api;self.g=grant;self.root=pathlib.Path(root);private(self.root,True);self.released=False;self.used=set()
    def current_source(self):
        validate_grant(self.g,time.time(),source_binding());head,run=actual();require((head,run)==(self.g['workflow_sha'],self.g['run_id']),'SOURCE_RUN_DRIFT');return engine_source(self.g)
    def current_caller(self):self.current_source();return caller(self.g)
    def release(self):
        self.current_source();require(not self.released,'CUSTODY_ONCE');ready=self.api.call('ready');require(ready=={'recipient_ready':True,'grant_sha256':sha(canonical(self.g))},'BUYER_READY_BEFORE_CUSTODY')
        self.released=True
        client=os.environ.pop('PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID','');secret=os.environ.pop('PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET','')
        require(client and secret and sha(client.encode())==APP and len(client)<=512 and len(secret)<=512,'EXISTING_APP')
        g=Grant151(PROFILE,APP,self.current_source(),self.current_caller(),self.g['start_at'],self.g['expires_at'],once_prefix(self.g),'https://'+HOST+'/webhooks/payproof186',False,_NATIVE)
        return g,(client,secret)
    def reserve_and_readback(self,key,metadata):
        self.current_source();op=metadata.get('operation');require(op in OPS and op not in self.used and key==once_prefix(self.g)+':'+op,'LOCAL_SLOT')
        self.used.add(op);row={'key':key,'metadata':metadata}
        write_once(self.root/('INTENT_'+op+'.json'),canonical(row))
        result=self.api.call('reserve',row,cleanup=op=='subscription_delete')
        require(self.matches_receipt(result,key,metadata),'REMOTE_RECEIPT');return result
    def matches_receipt(self,result,key,metadata):return result=={'state':'CONSUMED','grant_sha256':sha(canonical(self.g)),'key':key,'metadata':metadata}
    def retain_result(self,op,status,raw,client,secret,oauth):
        require(op in self.used and type(raw) is bytes,'RESULT_SCOPE')
        safe=b'' if op=='oauth' else raw
        require(not any(v and v.encode() in safe for v in (client,secret,oauth)),'CREDENTIAL_EXCLUDED')
        receipt=self.api.call('result',{'operation':op,'status':status,'raw_base64':base64.b64encode(safe).decode()},cleanup=op=='subscription_delete')
        require(receipt=={'operation':op,'status':status,'bytes':len(safe),'sha256':sha(safe)},'RESULT_ACK')
        write_once(self.root/('RETAINED_'+op+'.json'),canonical(receipt))

@dataclass(frozen=True,repr=False)
class ProviderEvidence152:
    engine:object
    def require(self):
        e=self.engine;e.require()
        if e.grant.test_only or type(e.ledger) is not NativePorts152 or not e.webhook_id or not e.client or not e.token:raise InvalidData('PROVIDER_EVIDENCE186')

@dataclass(frozen=True,repr=False)
class SyntheticProviderEvidence152(ProviderEvidence152):
    def require(self):
        from .chain import SyntheticTransport151
        e=self.engine;e.require()
        if not e.grant.test_only or type(e.transport) is not SyntheticTransport151 or not e.webhook_id or not e.client or not e.token:raise InvalidData('SYNTHETIC_ONLY186')

def provider_webhook152(engine,store,headers,raw):
    import json
    cap=engine.evidence_context
    if type(cap) not in (ProviderEvidence152,SyntheticProviderEvidence152) or cap.engine is not engine:raise InvalidData('EXACT_EVIDENCE186')
    cap.require();event=json.loads(raw);h={k.lower():v for k,v in headers.items()}
    mapping={'auth_algo':'paypal-auth-algo','cert_url':'paypal-cert-url','transmission_id':'paypal-transmission-id','transmission_sig':'paypal-transmission-sig','transmission_time':'paypal-transmission-time'}
    if any(not isinstance(h.get(v),str) or not h[v] or len(h[v])>4096 for v in mapping.values()):raise InvalidData('SIGNED_HEADERS186')
    envelope={k:h[v] for k,v in mapping.items()};envelope['webhook_id']=engine.webhook_id
    body=json.dumps(envelope).encode()[:-1]+b', "webhook_event": '+raw+b'}'
    engine._active_raw=raw
    try:reply=engine.effect('verify','POST','/v1/notifications/verify-webhook-signature',body);verified=isinstance(reply,dict) and reply.get('verification_status')=='SUCCESS'
    finally:engine._active_raw=None
    if not verified:raise InvalidData('AUTHENTICITY_NOT_VERIFIED186')
    result=store.event(event,True,lambda order_id:engine.effect('event_read','GET','/v2/checkout/orders/'+order_id),'SANDBOX_CONTRACT_TEST' if engine.grant.test_only else 'PAYPAL_SANDBOX')
    from payproof.service import annotated_order,explanation_request
    from payproof.core import explain
    from payproof.local_ai_view import enable_local_assistance
    order=result['order'];assistance=None if engine.grant.test_only else enable_local_assistance()
    view={'mode':'SANDBOX_CONTRACT_TEST' if engine.grant.test_only else 'PAYPAL_SANDBOX','order':annotated_order(order,assistance,engine.grant.test_only),'explanation':explain(order),'explanation_request':explanation_request(order),'live_ai':False,'payment_mutation_actions':[]}
    return {'disposition':result['disposition'],'view':view}
