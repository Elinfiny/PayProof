"""One order/capture/webhook/local-model chain; durable originals before ACK."""
import base64,json,os,pathlib,time,signal
from .common import *
from .client import API,checked_grant,preflight
from .net import token
from .chain import Chain151,FixedSandboxNetwork151
from .native_ports import NativePorts152,ProviderEvidence152

from .compensation import cleanup,arm

def execute():
    from payproof.core import Store
    root=pathlib.Path(os.environ['RUNNER_TEMP'])/'payment186';private(root,True);private(root/'PREFLIGHT.json')
    saved=obj((root/'PREFLIGHT.json').read_bytes());write_once(root/'WORKER_INTENT.json',canonical({'grant_sha256':sha(canonical(saved))}))
    api=engine=ports=None;state='UNKNOWN';clean='NOT_COMPLETED';report=None
    old=signal.getsignal(signal.SIGALRM)
    def expired(*_):raise TimeoutError('ABSOLUTE_EXPIRY186')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,max(.001,saved['expires_at']-time.time()))
    try:
        api=API(token(saved['expires_at']),saved['expires_at']);g=checked_grant(api);require(g==saved,'PREFLIGHT_DRIFT')
        ports=NativePorts152(api,g,root);grant,credentials=ports.release()
        engine=Chain151(grant,FixedSandboxNetwork151(grant),ports,source_sha256=ports.current_source(),caller=ports.current_caller())
        engine.credentials(*credentials);credentials=None;engine.oauth();engine.subscription()
        api.call('webhook',{'webhook_id':engine.webhook_id});arm(engine,ports)
        engine.bind_evidence(ProviderEvidence152(engine))
        store=Store(root/'evidence.sqlite');url=engine.create_order();store.register(engine.order,'1.00','USD')
        api.call('order',{'order_id':engine.order,'approval_url':url});url=None
        for n in range(60):
            if api.call('buyer').get('acknowledged') is True:break
            require(n<59,'BUYER_NOT_ACKNOWLEDGED');time.sleep(2)
        # UI acknowledgement is never sufficient payment proof.
        engine.capture_approved();engine.read_final()
        event=None
        for n in range(24):
            event=api.call('event')
            if event:break
            require(n<23,'WEBHOOK_NOT_RECEIVED');time.sleep(2)
        raw=base64.b64decode(event['raw_base64'],validate=True);require(sha(raw)==event['sha256'],'WEBHOOK_BYTES')
        result=engine.webhook(store,event['headers'],raw);require(engine.verified_complete,'VERIFIED_COMPLETION')
        api.call('ai',result['service_result']['view']);state='COMPLETED'
    except Exception:state='UNKNOWN'
    finally:
        # Do not let elapsed admission create any late compensation effect.
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
        if engine and ports:clean=cleanup(engine,ports)
        if state=='COMPLETED' and clean=='UNKNOWN_NO_RETRY':state='UNKNOWN'
        report={'state':state,'provider_slots':dict(engine.used) if engine else {},'bridge_unknown':bool(api and api.frozen),'cleanup':clean,'order_sha256':sha(engine.order.encode()) if engine and engine.order else None,'capture_sha256':sha(engine.capture_id.encode()) if engine and engine.capture_id else None}
        try:
            if api:api.call('terminal',report,terminal=True)
        except Exception:report['state']='UNKNOWN'
        finally:
            if engine:engine.close()
            if api:api.close()
            for k in ('PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID','PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET'):os.environ.pop(k,None)
            write_once(root/'RESULT.json',canonical(report))
        print(json.dumps({'schema':'PAYMENT186_SANITIZED_RESULT','state':report['state'],'provider_slots':report['provider_slots'],'cleanup':report['cleanup'],'private_originals_exported':False},sort_keys=True))
    return 0 if report['state']=='COMPLETED' else 1

def main(mode):
    try:
        return preflight() if mode=='preflight' else execute() if mode=='execute' else 1
    except Exception as exc:
        # Only fixed, nonsecret diagnostics; never serialize arbitrary exceptions.
        allowed={'BUYER_ROUTE_UNAVAILABLE','TRANSPORT_UNHEALTHY_BEFORE_PAYPAL','START_WINDOW'}
        reason=exc.args[0] if isinstance(exc,Refused) and len(exc.args)==1 and isinstance(exc.args[0],str) and exc.args[0] in allowed else 'UNCLASSIFIED_PRESERVE_UNKNOWN'
        print(json.dumps({'state':'REFUSED_OR_UNKNOWN','retry':False,'reason':reason},sort_keys=True))
        return 1

if __name__=='__main__':
    import sys
    raise SystemExit(main(sys.argv[1] if len(sys.argv)>1 else ''))
