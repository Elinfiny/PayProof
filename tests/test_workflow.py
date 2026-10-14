import copy
import json
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from payproof.core import Store, InvalidData, UnknownResult, money, project_order, canonical
from payproof import fixtures
from payproof.paypal import SandboxPayPal, BASE
from payproof.server import make_server
from host_contract_fixture import context


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name)/'state.db')
        self.store.register(fixtures.ORDER_ID, '120.00', 'EUR')

    def tearDown(self):
        self.tmp.cleanup()

    def observe(self, scenario):
        return self.store.reconcile(fixtures.ORDER_ID, lambda _: fixtures.order(scenario), 'SYNTHETIC_FIXTURE')

    def test_complete_capture_is_required(self):
        self.assertEqual(self.observe('approved')['state'], 'APPROVED')
        self.assertEqual(self.observe('incomplete')['state'], 'UNKNOWN')
        self.assertEqual(self.observe('pending')['state'], 'PENDING')
        self.assertEqual(self.observe('completed')['state'], 'COMPLETED')

    def test_conflict_is_not_paid(self):
        self.assertEqual(self.observe('conflict')['state'], 'CONFLICT')

    def test_unknown_preserves_historical_evidence_not_current_paid(self):
        self.observe('completed')
        current = self.observe('unknown')
        self.assertEqual(current['state'], 'UNKNOWN')
        self.assertEqual(current['last_verified']['facts']['state'], 'COMPLETED')
        self.assertIsNone(current['facts'])

    def test_refund_requires_review(self):
        self.assertEqual(self.observe('refunded')['state'], 'REVIEW_REQUIRED')

    def test_unverified_event_changes_nothing(self):
        before = self.store.order(fixtures.ORDER_ID)
        for verified in [False, 1, 'SUCCESS', None]:
            with self.assertRaises(InvalidData):
                self.store.event(fixtures.event('completed', 'EV-1'), verified, lambda _: fixtures.order('completed'), 'STUB')
        self.assertEqual(before, self.store.order(fixtures.ORDER_ID))

    def test_duplicate_event_fetches_only_once(self):
        calls=[]
        def fetch(order_id):
            calls.append(order_id);return fixtures.order('completed')
        event=fixtures.event('completed', 'EV-1')
        self.assertEqual(self.store.event(event, True, fetch, 'STUB')['disposition'], 'APPLIED')
        self.assertEqual(self.store.event(event, True, fetch, 'STUB')['disposition'], 'DUPLICATE')
        self.assertEqual(len(calls), 1)

    def test_event_tamper_same_id_is_rejected(self):
        event=fixtures.event('completed', 'EV-1')
        self.store.event(event, True, lambda _: fixtures.order('completed'), 'STUB')
        event['synthetic_scenario']='conflict'
        with self.assertRaises(InvalidData):self.store.event(event, True, lambda _: fixtures.order('conflict'), 'STUB')
        self.assertEqual(self.store.order(fixtures.ORDER_ID)['state'], 'COMPLETED')

    def test_capture_resource_id_is_not_order_id(self):
        result=self.store.event(fixtures.event('completed','EV-1'),True,lambda _:fixtures.order('completed'),'STUB')
        self.assertEqual(result['order']['id'], fixtures.ORDER_ID)

    def test_malformed_webhook_nested_fields_are_rejected(self):
        for malformed in [[],None,{'event_type':'PAYMENT.CAPTURE.COMPLETED','id':'E1','resource':[]},
                          {'event_type':'PAYMENT.CAPTURE.COMPLETED','id':'E1','resource':{'supplementary_data':[]}}]:
            with self.assertRaises(InvalidData):self.store.event(malformed,True,lambda _:fixtures.order('completed'),'STUB')

    def test_unknown_duplicate_requires_explicit_read_reconciliation(self):
        event=fixtures.event('unknown','EV-1')
        first=self.store.event(event,True,lambda _:fixtures.order('unknown'),'STUB')
        self.assertEqual(first['disposition'],'NEEDS_RECONCILIATION')
        duplicate=self.store.event(event,True,lambda _:fixtures.order('completed'),'STUB')
        self.assertEqual(duplicate['order']['state'],'UNKNOWN')
        self.assertEqual(self.observe('completed')['state'],'COMPLETED')
        self.assertEqual(self.store.event(event,True,lambda _:fixtures.order('completed'),'STUB')['original_disposition'],'RECONCILED')

    def test_concurrent_duplicates_have_single_effect(self):
        event=fixtures.event('completed','EV-1')
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:self.store.event(event,True,lambda _:fixtures.order('completed'),'STUB'),range(8)))
        self.assertEqual(sum(r['disposition']=='APPLIED' for r in results),1)
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)

    def test_pii_never_leaves_projection(self):
        result=self.observe('completed')
        self.assertNotIn('email_address',canonical(result))
        self.assertNotIn('example.invalid',canonical(result))

    def test_expectation_cannot_be_overwritten(self):
        with self.assertRaises(InvalidData):self.store.register(fixtures.ORDER_ID,'99.00','EUR')

    def test_money_invalid(self):
        for v in ['NaN','1e3','-1.00','0.00','12.345','1','1000001.00',True,12]:
            with self.assertRaises(InvalidData):money(v)

    def test_currency_and_identity_conflicts(self):
        for change in ['currency','id','duplicate','overcapture','missingtime']:
            raw=fixtures.order('completed')
            if change=='currency':raw['purchase_units'][0]['payments']['captures'][0]['amount']['currency_code']='USD'
            if change=='id':raw['id']='OTHER'
            if change=='duplicate':raw['purchase_units'][0]['payments']['captures']*=2
            if change=='overcapture':raw['purchase_units'][0]['payments']['captures'][0]['amount']['value']='121.00'
            if change=='missingtime':del raw['update_time']
            self.assertEqual(self.store.observe(fixtures.ORDER_ID,raw,'STUB')['state'],'CONFLICT')

    def test_stale_order_read_cannot_regress_verified_state(self):
        old=fixtures.order('approved');old['update_time']='2026-10-01T10:00:00Z'
        new=fixtures.order('completed');new['update_time']='2026-10-01T11:00:00Z'
        self.store.observe(fixtures.ORDER_ID,new,'STUB')
        self.assertEqual(self.store.observe(fixtures.ORDER_ID,old,'STUB')['state'],'COMPLETED')

    def test_equal_timestamp_conflicting_facts_fail_closed(self):
        new=fixtures.order('completed');old=fixtures.order('approved')
        new['update_time']=old['update_time']='2026-10-01T11:00:00Z'
        self.store.observe(fixtures.ORDER_ID,new,'STUB')
        self.assertEqual(self.store.observe(fixtures.ORDER_ID,old,'STUB')['state'],'CONFLICT')

    def test_stale_webhook_does_not_claim_applied(self):
        new=fixtures.order('completed');new['update_time']='2026-10-01T11:00:00Z'
        old=fixtures.order('approved');old['update_time']='2026-10-01T10:00:00Z'
        self.store.observe(fixtures.ORDER_ID,new,'STUB')
        result=self.store.event(fixtures.event('approved','EV-OLD'),True,lambda _:old,'STUB')
        self.assertEqual(result['disposition'],'STALE_IGNORED')
        self.assertEqual(result['order']['state'],'COMPLETED')

    def test_adapter_default_gate_closed(self):
        for value in [True,False,{'admitted':True},None]:
            with self.assertRaises(InvalidData):SandboxPayPal(value)

    def adapter(self, reply=None, fail_create=False):
        calls=[]
        def transport(method,path,headers,body):
            calls.append((method,path,headers,body))
            if path=='/v1/oauth2/token':return {'access_token':'TEST-ONLY'}
            if path=='/v2/checkout/orders':
                if fail_create:raise UnknownResult('synthetic timeout')
                return {'id':'TESTORDER1','status':'CREATED'}
            return reply or {'verification_status':'SUCCESS'}
        return SandboxPayPal(context(),transport=transport),calls

    def test_create_unknown_is_consumed_no_retry(self):
        adapter,calls=self.adapter(fail_create=True)
        with self.assertRaises(UnknownResult):adapter.create_order(self.store,'REQ-1','120.00','EUR')
        with self.assertRaises(InvalidData):adapter.create_order(self.store,'REQ-1','120.00','EUR')
        self.assertEqual(sum(path=='/v2/checkout/orders' for _,path,_,_ in calls),1)
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT state FROM effects').fetchone()[0],'UNKNOWN')

    def test_create_idempotency_header_and_applied_reservation(self):
        adapter,calls=self.adapter()
        self.assertEqual(adapter.create_order(self.store,'REQ-1','120.00','EUR')['id'],'TESTORDER1')
        self.assertEqual(calls[-1][2]['PayPal-Request-Id'],'REQ-1')
        with self.assertRaises(InvalidData):adapter.create_order(self.store,'REQ-1','120.00','EUR')

    def test_payment_mutation_endpoint_is_not_exposed(self):
        adapter,calls=self.adapter()
        with self.assertRaises(InvalidData):adapter.request('POST','/v2/checkout/orders/TESTORDER1/capture',{})
        self.assertEqual(calls,[])
        self.assertEqual(BASE,'https://api-m.sandbox.paypal.com')

    def test_webhook_verification_headers_and_failure(self):
        headers={k:'synthetic' for k in ['PAYPAL-AUTH-ALGO','PAYPAL-CERT-URL','PAYPAL-TRANSMISSION-ID','PAYPAL-TRANSMISSION-SIG','PAYPAL-TRANSMISSION-TIME']}
        for status,expected in [('SUCCESS',True),('FAILURE',False),('UNKNOWN',False)]:
            adapter,calls=self.adapter({'verification_status':status})
            self.assertEqual(adapter.verify_webhook(headers,b'{ "id" : "EV-1" }'),expected)
            payload=json.loads(calls[-1][3]);self.assertEqual(payload['webhook_id'],'fake-hook');self.assertEqual(payload['webhook_event'],{'id':'EV-1'})
            self.assertIn(b'{ "id" : "EV-1" }',calls[-1][3])
        adapter,calls=self.adapter();self.assertFalse(adapter.verify_webhook({},b'{}'));self.assertEqual(calls,[])

    def test_ambiguous_webhook_json_is_rejected_before_network(self):
        adapter,calls=self.adapter()
        for raw in [b'{"id":"EV-1","id":"EV-2"}',b'[]',b'not json']:
            with self.assertRaises(InvalidData):adapter.verify_webhook({},raw)
        self.assertEqual(calls,[])


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.server=make_server(0,Path(self.tmp.name)/'state.db')
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base=f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown();self.thread.join();self.server.server_close();self.tmp.cleanup()

    def post(self,path,data,origin=True):
        headers={'Content-Type':'application/json','X-PayProof-Request':'fixture-ui'}
        if origin:headers['Origin']=self.base
        return urllib.request.urlopen(urllib.request.Request(self.base+path,data=json.dumps(data).encode(),headers=headers))

    def test_http_workflow_and_mode_truth(self):
        with urllib.request.urlopen(self.base+'/api/state') as response:
            data=json.load(response);self.assertFalse(data['contest_ready']);self.assertIn('SYNTHETIC',data['mode']);self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])
        with self.post('/api/fixture',{'scenario':'completed'}) as response:self.assertEqual(json.load(response)['state'],'COMPLETED')
        with self.post('/api/fixture',{'scenario':'unknown'}) as response:self.assertEqual(json.load(response)['state'],'UNKNOWN')

    def test_csrf_and_invalid_input_and_live_route_rejected(self):
        for path,data,origin,status in [('/api/fixture',{'scenario':'completed'},False,403),('/api/fixture',{'scenario':'bad'},True,400),('/api/fixture-event',{'scenario':'completed','event_id':'E1','verified':False},True,400),('/api/capture',{},True,404)]:
            with self.assertRaises(urllib.error.HTTPError) as ctx:self.post(path,data,origin)
            self.assertEqual(ctx.exception.code,status)

    def test_frontend_assets_and_path_traversal(self):
        for path in ['/','/app.js','/style.css']:
            with urllib.request.urlopen(self.base+path) as response:self.assertGreater(len(response.read()),100)
        with self.assertRaises(urllib.error.HTTPError):urllib.request.urlopen(self.base+'/../payproof/core.py')


if __name__=='__main__':unittest.main()
