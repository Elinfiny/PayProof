"""Prospective safe diagnostics, synthetic transport only; no old effect replay."""
import copy,json,hashlib,tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone,timedelta
from payproof.core import Store,UnknownResult
from tools.sandbox_delivery107 import OperatorOrderReader107,reconcile_operator107
from test_sandbox_delivery107 import configuration,synthetic_session,OnceJournal107,FAKE_TOKEN,FAKE_SECRET

class OperatorDiagnostic150Tests(unittest.TestCase):
 def run_fixture(self, mutate=None, late=False):
  now=datetime.now(timezone.utc);cfg=configuration(now);clock=[now];raw={'id':cfg.order_id,'status':'COMPLETED','update_time':(now-timedelta(seconds=2)).isoformat(),'purchase_units':[{'amount':{'value':cfg.amount,'currency_code':cfg.currency},'payments':{'captures':[{'id':'CAPTURE150','status':'COMPLETED','amount':{'value':cfg.amount,'currency_code':cfg.currency}}]}}],'payer':{'email_address':FAKE_SECRET},'access_token':FAKE_TOKEN}
  if mutate:mutate(raw)
  with tempfile.TemporaryDirectory() as td:
   session=synthetic_session(cfg,lambda:clock[0],OnceJournal107(Path(td)/'once.sqlite'),[])
   def fake(method,path,headers,body):
    if path=='/v1/oauth2/token':return {'access_token':FAKE_TOKEN}
    if late:clock[0]=now+timedelta(seconds=200)
    return copy.deepcopy(raw)
   reader=OperatorOrderReader107(session,fake_transport=fake);store=Store(Path(td)/'store.sqlite');store.register(cfg.order_id,cfg.amount,cfg.currency)
   try:
    report=reconcile_operator107(store,reader)
    self.assertNotIn(FAKE_SECRET,json.dumps(report));self.assertNotIn(FAKE_TOKEN,json.dumps(report));self.assertEqual(reader.calls,2)
    with store.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM effects').fetchone()[0],0)
    with self.assertRaises(UnknownResult):reader.get_order(cfg.order_id)
    self.assertEqual(reader.calls,2)
   finally:
    reader.close();self.assertEqual(reader._private_returns,[]);self.assertEqual(reader.client_secret,'')
   return report,raw
 def test_valid_completed_capture_readonly_and_sanitized(self):
  report,raw=self.run_fixture();self.assertEqual(report['state'],'COMPLETED');self.assertEqual(report['payment_actions'],[]);self.assertFalse(report['actual_paypal']);self.assertTrue(report['diagnostic150']['projection_valid']);self.assertEqual(len(report['response_binding150']['parsed_order_sha256']),64);self.assertFalse(report['response_binding150']['oauth_response_hashed']);self.assertNotIn('oauth_or_credentials_hashed',report['response_binding150']);self.assertEqual(report['response_binding150']['parsed_order_sha256'],hashlib.sha256(json.dumps(raw,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest())
 def test_missing_freshness_keeps_precise_cause_without_inventing_timestamp(self):
  report,_=self.run_fixture(lambda r:r.pop('update_time'));self.assertEqual(report['state'],'CONFLICT');self.assertEqual(report['diagnostic150']['code'],'FRESHNESS_MISSING114');self.assertFalse(report['diagnostic150']['fields']['freshness']['valid'])
 def test_amount_and_capture_conflicts_never_promote(self):
  for mutate,expected in [(lambda r:r['purchase_units'][0]['amount'].update(value='11.00'),'AMOUNT_CURRENCY_CONFLICT114'),(lambda r:r['purchase_units'][0]['payments']['captures'][0]['amount'].update(currency_code='USD'),'CAPTURE_CONFLICT114')]:
   with self.subTest(expected=expected):
    report,_=self.run_fixture(mutate);self.assertEqual(report['state'],'CONFLICT');self.assertEqual(report['diagnostic150']['code'],expected);self.assertFalse(report['diagnostic150']['projection_valid'])
 def test_late_get_keeps_unknown_no_diagnostic_or_followup(self):
  report,_=self.run_fixture(late=True);self.assertEqual(report['state'],'UNKNOWN');self.assertIsNone(report['diagnostic150']);self.assertIsNone(report['response_binding150']);self.assertEqual(report['first_cause'],'OPERATOR_WINDOW_OR_ALLOWANCE107')
 def test_malformed_nested_shape_stays_conflict_and_private(self):
  report,_=self.run_fixture(lambda r:r['purchase_units'][0].update(payments=['PRIVATE_SHAPE150']));self.assertEqual(report['state'],'CONFLICT');self.assertEqual(report['diagnostic150']['code'],'PROJECTION_SHAPE_REJECTED114');self.assertNotIn('PRIVATE_SHAPE150',json.dumps(report))

if __name__=='__main__':unittest.main()
