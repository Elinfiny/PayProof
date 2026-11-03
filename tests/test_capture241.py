import copy,unittest
from datetime import datetime,timezone
from payment186.capture241 import completed_capture241
from payment186.common import Refused
from payproof.core import project_order,InvalidData

class Capture241(unittest.TestCase):
    def setUp(self):
        self.start=1793700000;self.now=self.start+300
        stamp=datetime.fromtimestamp(self.start+90,timezone.utc).isoformat()
        self.raw={'id':'ORDER-SYNTHETIC','status':'COMPLETED','purchase_units':[{'reference_id':'default','payments':{'captures':[{'id':'CAPTURE-SYNTHETIC','status':'COMPLETED','final_capture':True,'amount':{'value':'1.00','currency_code':'USD'},'create_time':stamp,'update_time':stamp}]}}]}
        self.expected={'id':'ORDER-SYNTHETIC','amount':'1.00','currency':'USD'}
    def call(self,r):return completed_capture241(r,self.expected,self.start,self.now)
    def test_actual_shape_without_order_fields(self):
        before=copy.deepcopy(self.raw)
        self.assertEqual(self.call(self.raw),'CAPTURE-SYNTHETIC');self.assertEqual(self.raw,before)
        with self.assertRaises(InvalidData):project_order(self.raw,self.expected)
    def test_optional_order_amount_conflict_fails(self):
        self.raw['purchase_units'][0]['amount']={'value':'2.00','currency_code':'USD'}
        with self.assertRaises(Refused):self.call(self.raw)
    def test_chain_retains_capture_then_requires_full_final_read(self):
        from payment186.chain import Chain151
        from types import SimpleNamespace
        e=object.__new__(Chain151);e.require=lambda:None;e.order=self.expected['id']
        e.grant=SimpleNamespace(not_before=self.start);e.clock=lambda:self.now
        stamp=self.raw['purchase_units'][0]['payments']['captures'][0]['create_time']
        approval={'id':e.order,'status':'APPROVED','create_time':stamp,'purchase_units':[{'amount':{'value':'1.00','currency_code':'USD'}}]}
        final=copy.deepcopy(self.raw);final['update_time']=stamp;final['purchase_units'][0]['amount']={'value':'1.00','currency_code':'USD'}
        replies=[approval,self.raw,final];calls=[]
        def effect(operation,*args):calls.append(operation);return replies.pop(0)
        e.effect=effect;e.capture_approved();self.assertEqual(e.capture_id,'CAPTURE-SYNTHETIC')
        self.assertEqual(e.read_final()['state'],'COMPLETED')
        self.assertEqual(calls,['approval_read','capture','final_read'])
    def test_wrong_order_and_collections_fail(self):
        mutations=[lambda r:r.update(id='OTHER'),lambda r:r.update(status='APPROVED'),lambda r:r.update(purchase_units=[]),lambda r:r['purchase_units'].append(copy.deepcopy(r['purchase_units'][0])),lambda r:r['purchase_units'][0]['payments']['captures'].append(copy.deepcopy(r['purchase_units'][0]['payments']['captures'][0])),lambda r:r['purchase_units'][0]['payments'].update(refunds=[{}])]
        for i,change in enumerate(mutations):
            r=copy.deepcopy(self.raw);change(r)
            with self.subTest(i=i),self.assertRaises(Refused):self.call(r)
    def test_capture_status_amount_identity_time_negatives(self):
        mutations=[{'status':'PENDING'},{'status':'DECLINED'},{'final_capture':False},{'id':''},{'amount':{'value':'1.01','currency_code':'USD'}},{'amount':{'value':'1.00','currency_code':'EUR'}},{'create_time':None},{'update_time':'bad'},{'update_time':'2000-01-01T00:00:00Z'},{'update_time':'2099-01-01T00:00:00Z'},{'update_time':'2026-11-03T00:00:00'}]
        for change in mutations:
            r=copy.deepcopy(self.raw);r['purchase_units'][0]['payments']['captures'][0].update(change)
            with self.subTest(change=change),self.assertRaises(Refused):self.call(r)

if __name__=='__main__':unittest.main()
