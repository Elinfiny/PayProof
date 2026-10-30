"""ONE inert direction107 group, five scenarios; no real ENV/HTTP/provider."""
from dataclasses import replace
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import pickle
import sys
import tempfile
from unittest.mock import patch
from payproof.admission import (OperatorProfile107,OperatorConfiguration107,
    _open_operator_session107, SandboxContext)
from payproof.core import Store, InvalidData, UnknownResult
from payproof.paypal import SandboxPayPal
from payproof.local_ai_view import enable_local_assistance
from tools.sandbox_delivery107 import (source_digest107, open_operator107,
    OnceJournal107,OperatorOrderReader107,reconcile_operator107,run_operator107)

FAKE_ID='PUBLIC-SYNTHETIC-CLIENT107'
FAKE_SECRET='PUBLIC-SYNTHETIC-SECRET107'
FAKE_TOKEN='PUBLIC-SYNTHETIC-TOKEN107'

def emit(name, facts):
    print(json.dumps({'record':'ORIGINAL_SYNTHETIC107','scenario':name,'facts':facts},sort_keys=True),flush=True)

def refused(call):
    try:call()
    except (InvalidData,UnknownResult,TypeError):return True
    return False

def configuration(now):
    return OperatorConfiguration107(OperatorProfile107.SYNTHETIC_FIXTURE,
        source_digest107(),'1'*40,'2'*40,'SYNTHETIC_OPERATOR107','PUBLIC_FIXTURE107',
        hashlib.sha256(FAKE_ID.encode()).hexdigest(),'SYNTHETIC107','10.00','EUR',
        '3'*64,'SYNTHETIC_ONCE107',now-timedelta(seconds=1),now+timedelta(seconds=119))

def synthetic_session(cfg, clock, journal, reads):
    def credentials():reads.append('PUBLIC_FAKE_PAIR');return (FAKE_ID,FAKE_SECRET)
    return _open_operator_session107(cfg,actual_source=source_digest107,
        credential_reader=credentials,reserve_once=journal.reserve,clock=clock,
        profile=OperatorProfile107.SYNTHETIC_FIXTURE)

def late_unknown_case144(root, cfg, now, reads):
    results=[]
    time=[now];session=synthetic_session(cfg,lambda:time[0],OnceJournal107(root/'late.sqlite'),reads)
    def late(method,path,headers,body):
        time[0]=now+timedelta(seconds=200)
        return {'access_token':FAKE_TOKEN}
    reader=OperatorOrderReader107(session,fake_transport=late);store=Store(root/'late-orders.sqlite');store.register(cfg.order_id,cfg.amount,cfg.currency)
    try:
        report=reconcile_operator107(store,reader)
        first=reader.first_cause;again=refused(lambda:reader.get_order(cfg.order_id))
        replay=refused(lambda:synthetic_session(cfg,lambda:now,OnceJournal107(root/'late.sqlite'),reads))
        facts={'receipt':report,'second_read_refused':again,'journal_replay_refused':replay,'first_cause_retained':reader.first_cause==first,'calls':reader.calls}
        emit('late_unknown_first_cause_no_next_call',facts)
        assert report['state']=='UNKNOWN' and first=='OPERATOR_WINDOW_OR_ALLOWANCE107' and reader.calls==1 and again and replay and reader.first_cause==first
        results.append('PASS')
    finally:reader.close()
    return results

def group():
    now=datetime.now(timezone.utc);cfg=configuration(now);results=[]
    with tempfile.TemporaryDirectory(prefix='payproof-inert107-') as td:
        root=Path(td);reads=[];network=[]
        # All ENV access and network calls are tripwires, never credentials.
        with patch('os.getenv',side_effect=AssertionError('ENV_FORBIDDEN107')),patch('os.environ',{}),patch('urllib.request.build_opener',side_effect=AssertionError('NETWORK_FORBIDDEN107')):
            default = refused(lambda:open_operator107())
            report=run_operator107()
            facts={'default_refused':default,'run':report,'credential_reads':len(reads),'network_calls':len(network)}
            emit('unconfigured_before_credentials_or_network',facts)
            assert default and report['primary'] and not reads and not network
            results.append('PASS')

            session=synthetic_session(cfg,lambda:now,OnceJournal107(root/'routes.sqlite'),reads)
            reader=OperatorOrderReader107(session,fake_transport=lambda *a:network.append(a))
            try:
                checks=[refused(lambda:reader.request('POST','/v2/checkout/orders')),
                    refused(lambda:reader.request('GET','https://api-m.paypal.com/v2/checkout/orders/SYNTHETIC107')),
                    refused(lambda:reader.request('GET','/v2/checkout/orders/OTHER'))]
                facts={'fixed_route_refusals':checks,'calls':reader.calls,'network_calls':len(network)}
                emit('production_arbitrary_route_wrong_method',facts)
                assert all(checks) and reader.calls==0 and not network
                results.append('PASS')
            finally:reader.close()

            before=len(reads)
            checks=[refused(lambda:synthetic_session(replace(cfg,source_sha256='0'*64),lambda:now,OnceJournal107(root/'wrong.sqlite'),reads)),
                refused(lambda:_open_operator_session107(cfg,actual_source=source_digest107,
                    credential_reader=lambda:reads.append('BAD'),reserve_once=lambda k:None,
                    clock=lambda:now,profile=OperatorProfile107.OWNER_MANAGED_SANDBOX))]
            session=synthetic_session(cfg,lambda:now,OnceJournal107(root/'mix.sqlite'),reads)
            try:
                checks += [refused(lambda:OperatorOrderReader107(session)),
                    refused(lambda:SandboxPayPal(session,transport=lambda *a:None)),
                    refused(lambda:session.require('orders:read',profile=OperatorProfile107.OWNER_MANAGED_SANDBOX)),
                    refused(lambda:pickle.dumps(session))]
                facts={'source_and_profile_refusals':checks,'wrong_source_credential_reads':len(reads)-before-1,'legacy_context_type':type(session) is SandboxContext,'serialized':False}
                emit('wrong_source_trust_and_no_synthetic_to_native_conversion',facts)
                assert all(checks) and len(reads)==before+1 and type(session) is not SandboxContext
                results.append('PASS')
            finally:session.close()

            results.extend(late_unknown_case144(root, cfg, now, reads))

            session=synthetic_session(cfg,lambda:now,OnceJournal107(root/'valid.sqlite'),reads);paths=[]
            def valid(method,path,headers,body):
                paths.append([method,path])
                if path=='/v1/oauth2/token':return {'access_token':FAKE_TOKEN}
                return {'id':cfg.order_id,'status':'APPROVED','update_time':(now-timedelta(seconds=2)).isoformat(),
                    'purchase_units':[{'amount':{'value':cfg.amount,'currency_code':cfg.currency}}],
                    'access_token':FAKE_TOKEN,'payer':{'secret':FAKE_SECRET}}
            reader=OperatorOrderReader107(session,fake_transport=valid);store=Store(root/'valid-orders.sqlite');store.register(cfg.order_id,cfg.amount,cfg.currency)
            try:
                handle=enable_local_assistance();report=reconcile_operator107(store,reader,assistance=handle)
                encoded=json.dumps(report);safe=all(v not in encoded for v in (FAKE_ID,FAKE_SECRET,FAKE_TOKEN))
                with store.connect() as db:effects=db.execute('SELECT count(*) FROM effects').fetchone()[0]
                facts={'receipt':report,'fake_calls':paths,'secret_free':safe,'model_status':handle.status,'effects':effects,'legacy_host_qualified':False}
                emit('synthetic_reconciliation_local_advisory_sanitized',facts)
                assert report['state']=='APPROVED' and report['synthetic'] is True and report['actual_paypal'] is False
                assert report['payment_actions']==[] and effects==0 and reader.calls==2 and safe and handle.status=='READY'
                assert report['local_assistance']['financial_authority'] is False
                results.append('PASS')
            finally:
                reader.close()
                emit('valid_cleanup',{'session_closed':session._closed,'reader_credentials_dropped':reader.client_id==reader.client_secret=='','cleanup':[]})
    return results

if __name__=='__main__':
    primary=None;result=[]
    try:
        if '--maintenance144' in sys.argv:
            now=datetime.now(timezone.utc)
            with tempfile.TemporaryDirectory(prefix='payproof-late144-') as td:
                result=late_unknown_case144(Path(td),configuration(now),now,[])
        else:result=group()
    except Exception as exc:primary=type(exc).__name__  # Never exception payload/credential bytes.
    print(json.dumps({'record':'INERT107_TERMINAL','scenario_results':result,'primary':primary,'cleanup':[],
        'actual_credentials':False,'actual_provider':False,'external_connects':0,'old_suites_replayed':False},sort_keys=True),flush=True)
    raise SystemExit(0 if primary is None and len(result)==(1 if '--maintenance144' in sys.argv else 5) else 1)
