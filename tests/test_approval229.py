"""C222-shaped synthetic responses only; sockets forbidden by the harness."""
import copy,datetime,unittest
from unittest.mock import patch
import test_payment186 as h
from payment186 import chain
from payproof.core import InvalidData,project_order

class Approval229(h.Base):
    run_flow=h.EndToEnd.run_flow

    def shaped(self,mutate=None):
        original=h.order
        def fixture(completed=False,approved=False):
            row=original(completed,approved)
            if approved:
                row.pop('update_time')
                row['create_time']=datetime.datetime.fromtimestamp(self.g['start_at'],datetime.timezone.utc).isoformat()
                if mutate:mutate(row)
            return row
        return patch.object(h,'order',side_effect=fixture)

    def test_missing_optional_update_time_complete_chain(self):
        with self.shaped():code,r,calls,bridges,native=self.run_flow()
        self.assertEqual((code,r['state'],r['cleanup']),(0,'COMPLETED','DELETED_NEW'))
        self.assertEqual(len(calls),10)
        self.assertEqual(sum(p.endswith('/capture') for m,p in calls),1)
        self.assertTrue((native/'AI.json').is_file())
        self.assertTrue((native/'BOUND_CAPTURE.json').is_file())
        self.assertNotIn('update_time',h.c.obj((native/'HTTP_approval_read.bin').read_bytes()))

    def test_present_timestamp_accepted_flow_unchanged(self):
        code,r,calls,_,_=self.run_flow()
        self.assertEqual((code,r['state'],len(calls)),(0,'COMPLETED',10))

    def test_missing_timestamp_capture_timeout_consumed_cleanup_once(self):
        with self.shaped():code,r,calls,_,_=self.run_flow(fail='provider_capture')
        self.assertEqual((code,r['state'],r['cleanup']),(1,'UNKNOWN','DELETED_NEW'))
        self.assertEqual(sum(p.endswith('/capture') for m,p in calls),1)
        self.assertEqual(sum(m=='DELETE' for m,p in calls),1)

    def test_wrong_amount_no_capture_cleanup(self):
        with self.shaped(lambda r:r['purchase_units'][0]['amount'].update(value='2.00')):
            code,r,calls,_,_=self.run_flow()
        self.assertEqual((code,r['state'],r['cleanup']),(1,'UNKNOWN','DELETED_NEW'))
        self.assertFalse(any(p.endswith('/capture') for m,p in calls))

    def test_negative_approval_matrix(self):
        row={'id':'SYNTHETIC-ORDER','status':'APPROVED','create_time':'2026-11-03T08:48:45Z','purchase_units':[{'amount':{'value':'1.00','currency_code':'USD'}}]}
        expected={'id':row['id'],'amount':'1.00','currency':'USD'}
        start=datetime.datetime(2026,11,3,8,47,38,tzinfo=datetime.timezone.utc).timestamp();now=start+150
        mutations=[lambda r:r.update(id='OTHER'),lambda r:r.update(status='COMPLETED'),lambda r:r.update(status='CREATED'),lambda r:r.update(purchase_units=[]),lambda r:r.update(purchase_units=[{},{}]),lambda r:r['purchase_units'][0]['amount'].update(value='2.00'),lambda r:r['purchase_units'][0]['amount'].update(currency_code='EUR'),lambda r:r.update(create_time=None),lambda r:r.update(create_time='2026-11-03T08:48:45'),lambda r:r.update(create_time='2026-11-03T08:00:00Z'),lambda r:r.update(create_time='2026-11-03T09:00:00Z'),lambda r:r.update(update_time=None),lambda r:r['purchase_units'][0].update(payments={'captures':[{}]}),lambda r:r['purchase_units'][0].update(payments={'authorizations':[{}]}),lambda r:r['purchase_units'][0].update(payments={'captures':None})]
        for i,mutate in enumerate(mutations):
            with self.subTest(case=i):
                bad=copy.deepcopy(row);mutate(bad)
                with self.assertRaises((InvalidData,TypeError)):chain.approved_order229(bad,expected,start,now)
        chain.approved_order229(row,expected,start,now)
        self.assertNotIn('update_time',row)

    def test_final_payment_projection_still_requires_freshness(self):
        row=h.order(completed=True);row.pop('update_time')
        with self.assertRaisesRegex(InvalidData,'timestamp missing'):
            project_order(row,{'id':row['id'],'amount':'1.00','currency':'USD'})

if __name__=='__main__':unittest.main()
