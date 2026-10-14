import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from payproof.admission import SandboxContext, _verify_receipt, _host_file, source_fingerprint
from payproof.core import Store, InvalidData, UnknownResult, canonical
from payproof.fixtures import order, event
from payproof.paypal import SandboxPayPal
from payproof.service import PaymentEvidenceService, explanation_request, inspect_candidate
from host_contract_fixture import context, signed_fixture, TEST_KEY


HEADERS={name:'SYNTHETIC-HEADER' for name in ['PAYPAL-AUTH-ALGO','PAYPAL-CERT-URL','PAYPAL-TRANSMISSION-ID','PAYPAL-TRANSMISSION-SIG','PAYPAL-TRANSMISSION-TIME']}


class ServiceContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'db.sqlite')
        self.store.register('TESTORDER1','120.00','EUR')

    def tearDown(self):self.tmp.cleanup()

    def raw_event(self):
        e=event('completed','EV-1');e['resource']['supplementary_data']['related_ids']['order_id']='TESTORDER1'
        return canonical(e).encode()

    def service(self,verification='SUCCESS',get_unknown=False,context_overrides=None):
        calls=[]
        raw=order('completed');raw['id']='TESTORDER1'
        def transport(method,path,headers,body):
            calls.append(path)
            if path=='/v1/oauth2/token':return {'access_token':'TEST-ONLY'}
            if path=='/v1/notifications/verify-webhook-signature':
                if verification=='TIMEOUT':raise UnknownResult('synthetic verification timeout')
                return {'verification_status':verification}
            if method=='GET':
                if get_unknown:raise UnknownResult('synthetic GET timeout')
                return raw
            return {'id':'TESTORDER2','status':'CREATED'}
        return PaymentEvidenceService(self.store,SandboxPayPal(context(context_overrides),transport=transport)),calls

    def test_authenticity_then_fresh_get_then_ledger(self):
        service,calls=self.service()
        result=service.webhook(HEADERS,self.raw_event())
        self.assertEqual(calls,['/v1/oauth2/token','/v1/notifications/verify-webhook-signature','/v1/oauth2/token','/v2/checkout/orders/TESTORDER1'])
        self.assertEqual(result['view']['order']['state'],'COMPLETED')
        self.assertEqual(result['view']['mode'],'SANDBOX_CONTRACT_TEST')
        self.assertFalse(result['view']['live_ai'])
        self.assertEqual(result['view']['payment_mutation_actions'],[])

    def test_public_verified_flag_does_not_supply_authenticity(self):
        service,calls=self.service(verification='FAILURE')
        e=json.loads(self.raw_event());e['verified']=True;e['admitted']=True
        with self.assertRaises(InvalidData):service.webhook(HEADERS,canonical(e).encode())
        self.assertFalse(any('/v2/checkout/orders/' in path for path in calls))
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)

    def test_verification_unknown_does_not_fetch_or_mutate(self):
        service,calls=self.service(verification='TIMEOUT')
        result=service.webhook(HEADERS,self.raw_event())
        self.assertEqual(result['disposition'],'VERIFICATION_UNKNOWN')
        self.assertFalse(result['ledger_effect'])
        self.assertFalse(any('/v2/checkout/orders/' in path for path in calls))

    def test_get_unknown_and_duplicate_do_not_repeat_get_or_create(self):
        service,calls=self.service(get_unknown=True)
        self.assertEqual(service.webhook(HEADERS,self.raw_event())['disposition'],'NEEDS_RECONCILIATION')
        self.assertEqual(service.webhook(HEADERS,self.raw_event())['disposition'],'DUPLICATE')
        self.assertEqual(calls.count('/v2/checkout/orders/TESTORDER1'),1)
        self.assertEqual(calls.count('/v2/checkout/orders'),0)
        self.assertEqual(self.store.order('TESTORDER1')['state'],'UNKNOWN')

    def test_read_reconciles_and_projects_no_pii(self):
        service,calls=self.service();result=service.read('TESTORDER1')
        self.assertEqual(result['order']['state'],'COMPLETED')
        self.assertNotIn('email_address',canonical(result));self.assertNotIn('fake-secret',canonical(result))
        self.assertEqual(result['explanation_request']['tools'],[])

    def test_live_ai_gate_never_invokes_provider(self):
        service,_=self.service()
        class Provider:
            called=False
            def explain_facts(self,request):self.called=True;return {}
        provider=Provider()
        with self.assertRaises(InvalidData):service.explain_with_live_ai('TESTORDER1',provider)
        self.assertFalse(provider.called)

    def test_ai_contract_rejects_tools_mismatched_facts_and_false_certainty(self):
        request=explanation_request(self.store.order('TESTORDER1'))
        good={'facts_sha256':request['facts_sha256'],'summary':'Outcome is unknown.','uncertainty':True}
        self.assertIn('NOT LIVE AI',inspect_candidate(good,request)['mode'])
        for extra in [{'tool_calls':[{'name':'capture'}]},{'admitted':True},{'live_ai':True}]:
            with self.assertRaises(InvalidData):inspect_candidate(good|extra,request)
        for change in [{'facts_sha256':'0'*64},{'uncertainty':False}]:
            with self.assertRaises(InvalidData):inspect_candidate(good|change,request)

    def test_unsigned_tampered_or_wrong_scope_receipts_are_rejected(self):
        receipt,credentials=signed_fixture();envelope=json.loads(receipt);envelope['grant']['live_ai']=True
        with self.assertRaises(InvalidData):_verify_receipt(canonical(envelope).encode(),TEST_KEY,credentials,test_only=True)
        for change in [{'environment':'live'},{'project':'Other'},{'live_ai':True},{'external_budget_usd':'5.00'},
                       {'source_sha256':'0'*64},{'expires_at':'2000-01-01T00:00:00Z'},
                       {'operations':['orders:capture']},{'operations':['orders:read','orders:read']}]:
            raw,creds=signed_fixture(change)
            with self.assertRaises(InvalidData):_verify_receipt(raw,TEST_KEY,creds,test_only=True)

    def test_application_binding_and_context_seal_required(self):
        receipt,credentials=signed_fixture();creds=json.loads(credentials);creds['webhook_id']='OTHER'
        with self.assertRaises(InvalidData):_verify_receipt(receipt,TEST_KEY,canonical(creds).encode(),test_only=True)
        values=dict(context().__dict__);values['_seal']=True
        with self.assertRaises(InvalidData):SandboxContext(**values)

    def test_test_context_cannot_reach_real_network(self):
        with self.assertRaises(InvalidData):SandboxPayPal(context())

    def test_operation_scope_blocks_before_network_and_reservation(self):
        service,calls=self.service(context_overrides={'operations':['orders:read']})
        with self.assertRaises(InvalidData):service.create('REQ-2','120.00','EUR')
        self.assertEqual(calls,[])
        with self.store.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM effects').fetchone()[0],0)

    def test_source_drift_blocks_before_network(self):
        service,calls=self.service()
        with patch('payproof.admission.source_fingerprint',return_value='0'*64):
            with self.assertRaises(InvalidData):service.read('TESTORDER1')
        self.assertEqual(calls,[])

    def test_fixed_host_paths_have_no_public_argument_and_missing_loader_fails_closed(self):
        with patch('payproof.admission._host_file',side_effect=InvalidData('synthetic missing host receipt')):
            with self.assertRaises(InvalidData):PaymentEvidenceService.from_host(self.store)
        with self.assertRaises(TypeError):PaymentEvidenceService.from_host(self.store,admitted=True)

    def test_host_file_rejects_symlink_and_world_readable(self):
        file=Path(self.tmp.name)/'host-test';file.write_bytes(b'EXPLICIT-SYNTHETIC-HOST-FILE')
        file.chmod(0o644)
        with self.assertRaises(InvalidData):_host_file(file,128)
        link=Path(self.tmp.name)/'link';link.symlink_to(file)
        with self.assertRaises(InvalidData):_host_file(link,128)


if __name__=='__main__':unittest.main()
