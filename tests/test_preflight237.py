"""Synthetic timing and failure regression; no network or native effects."""
import os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from payment186 import client

class Preflight237(unittest.TestCase):
    def run_case(self,ready_at=78,fail_ready=False,fail_terminal=False,unhealthy=False,bad_grant=False):
        now=[1000.0]; calls=[]; g={'synthetic':True}; clock=lambda:now[0]
        def sleep(n):now[0]+=n
        class Fake:
            frozen=False
            def call(self,name,row=None,**kw):
                calls.append((name,now[0],row))
                if name=='terminal':
                    if fail_terminal:raise client.UnknownResult('TERMINAL_UNKNOWN')
                    return {}
                if fail_ready:self.frozen=True;raise client.UnknownResult('READ_UNKNOWN')
                return {'grant_sha256':client.sha(client.canonical(g)), 'transport_ok':not unhealthy,'recipient_ready':now[0]>=1000+ready_at}
            def close(self):self.closed=True
        api=Fake()
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{'RUNNER_TEMP':tmp,'PAYMENT186_START_EPOCH':'1000'}),patch.object(client,'actual'),patch.object(client,'token',return_value='synthetic'),patch.object(client,'API',return_value=api),patch.object(client.time,'time',side_effect=clock),patch.object(client.time,'sleep',side_effect=sleep),patch.object(client,'checked_grant',side_effect=client.Refused('BAD_GRANT') if bad_grant else None,return_value=g):
            error=None
            try:client.preflight()
            except Exception as e:error=e
            retained=(Path(tmp)/'payment186'/'PREFLIGHT.json').exists()
        self.assertTrue(api.closed)
        self.assertLessEqual(sum(n=='ready' for n,_,_ in calls),30)
        self.assertLessEqual(sum(n=='terminal' for n,_,_ in calls),1)
        self.assertTrue(all(n in ('ready','terminal') for n,_,_ in calls))
        return error,calls,retained,now[0]
    def test_pairing_at_observed_78_seconds_succeeds(self):
        error,calls,retained,end=self.run_case()
        self.assertIsNone(error);self.assertTrue(retained)
        self.assertLessEqual(end,1082);self.assertFalse(any(n=='terminal' for n,_,_ in calls))
    def test_no_pairing_finite_and_terminal_once(self):
        error,calls,retained,end=self.run_case(ready_at=999)
        self.assertIn('BUYER_ROUTE_UNAVAILABLE',str(error));self.assertFalse(retained)
        self.assertLess(end,1120);self.assertEqual(calls[-1][0],'terminal')
        self.assertEqual(calls[-1][2]['provider_slots'],{})
    def test_transport_failure_closes_once(self):
        error,calls,_,_=self.run_case(unhealthy=True)
        self.assertIn('TRANSPORT_UNHEALTHY',str(error));self.assertEqual([c[0] for c in calls],['ready','terminal'])
    def test_uncertain_read_preserved_not_retried(self):
        error,calls,_,_=self.run_case(fail_ready=True)
        self.assertIsInstance(error,client.UnknownResult)
        self.assertEqual([c[0] for c in calls],['ready','terminal']);self.assertTrue(calls[-1][2]['bridge_unknown'])
    def test_uncertain_terminal_not_retried(self):
        error,calls,_,_=self.run_case(fail_ready=True,fail_terminal=True)
        self.assertEqual(str(error),'READ_UNKNOWN');self.assertEqual([c[0] for c in calls],['ready','terminal'])
    def test_unbound_grant_does_not_mutate_receiver(self):
        error,calls,_,_=self.run_case(bad_grant=True)
        self.assertEqual(str(error),'BAD_GRANT');self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
