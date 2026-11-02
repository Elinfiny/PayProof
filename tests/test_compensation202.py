"""Affected paths only, synthetic provider doubles and sockets forbidden."""
import contextlib,io,json,time,unittest,os
from unittest.mock import patch
import test_payment186 as h
from payment186 import compensation as cp,worker,state as st,common as c

class Compensation202(h.Base):
    run_flow=h.EndToEnd.run_flow

    def interrupted(self,**kw):
        def close_before_ack(s,row):
            s.close('SYNTHETIC_CHANNEL_CLOSED');raise TimeoutError('synthetic')
        with patch.object(st.State,'acknowledge_buyer',close_before_ack):
            return self.run_flow(**kw)

    def test_prearmed_new_hook_is_deleted_after_receiver_closes(self):
        code,r,calls,bridges,native=self.interrupted()
        self.assertEqual((code,r['state'],r['cleanup']),(1,'UNKNOWN','DELETED_NEW'))
        self.assertEqual(sum(m=='DELETE' for m,p in calls),1)
        self.assertFalse(any(p.endswith('/capture') for m,p in calls))
        self.assertTrue((native/'SLOT_subscription_delete.json').is_file())
        self.assertFalse((native/'HTTP_subscription_delete.json').exists())
        receipt=c.obj((self.root/'payment186/COMPENSATION_RECEIPT.json').read_bytes())
        self.assertEqual((receipt['status'],receipt['bytes']),(204,0))
        self.assertEqual(receipt['sha256'],c.sha(b''))

    def test_old_hook_is_never_reserved_or_deleted(self):
        code,r,calls,bridges,native=self.interrupted(existing=True)
        self.assertEqual(r['cleanup'],'PRESERVED_EXISTING')
        self.assertFalse(any(m=='DELETE' for m,p in calls))
        self.assertFalse((native/'SLOT_subscription_delete.json').exists())

    def test_lost_delete_response_is_unknown_and_never_repeated(self):
        actual=cp.cleanup
        def twice(e,p):
            first=actual(e,p);self.assertEqual(actual(e,p),'UNKNOWN_NO_RETRY');return first
        with patch.object(worker,'cleanup',twice):
            code,r,calls,bridges,native=self.interrupted(fail='cleanup')
        self.assertEqual(r['cleanup'],'UNKNOWN_NO_RETRY')
        self.assertEqual(sum(m=='DELETE' for m,p in calls),1)

    def test_lost_reservation_ack_blocks_delete_and_order(self):
        real=h.native_ports.NativePorts152.reserve_and_readback
        def lost(p,key,metadata):
            r=real(p,key,metadata)
            if metadata['operation']=='subscription_delete':raise TimeoutError('synthetic ack lost')
            return r
        with patch.object(h.native_ports.NativePorts152,'reserve_and_readback',lost):
            code,r,calls,bridges,native=self.run_flow()
        self.assertEqual(r['cleanup'],'UNKNOWN_NO_RETRY')
        self.assertTrue((native/'SLOT_subscription_delete.json').exists())
        self.assertFalse(any(m=='DELETE' or p=='/v2/checkout/orders' for m,p in calls))

    def test_target_drift_refuses_compensation(self):
        real=cp.cleanup
        def changed(e,p):
            e.webhook_id='SYNTHETIC-OTHER';return real(e,p)
        with patch.object(worker,'cleanup',changed):code,r,calls,bridges,native=self.interrupted()
        self.assertEqual(r['cleanup'],'UNKNOWN_NO_RETRY')
        self.assertFalse(any(m=='DELETE' for m,p in calls))

    def test_expired_token_does_not_start_delete(self):
        real=cp.cleanup
        def expired(e,p):
            e.token_until=time.time()-1;return real(e,p)
        with patch.object(worker,'cleanup',expired):code,r,calls,bridges,native=self.interrupted()
        self.assertEqual(r['cleanup'],'UNKNOWN_NO_RETRY')
        self.assertFalse(any(m=='DELETE' for m,p in calls))

    def test_successful_chain_retains_remote_and_independent_cleanup(self):
        code,r,calls,bridges,native=self.run_flow()
        self.assertEqual((code,r['state'],r['cleanup']),(0,'COMPLETED','DELETED_NEW'))
        self.assertEqual(len(calls),10)
        self.assertTrue((native/'HTTP_subscription_delete.json').exists())
        self.assertTrue((native/'AI.json').exists())
        arm=c.obj((self.root/'payment186/COMPENSATION_ARMED.json').read_bytes())
        reserve=c.obj((native/'SLOT_subscription_delete.json').read_bytes())
        self.assertEqual(arm['receipt']['key'],reserve['key'])

    def test_completed_chain_with_lost_delete_is_not_success(self):
        code,r,calls,bridges,native=self.run_flow(fail='cleanup')
        self.assertEqual((code,r['state'],r['cleanup']),(1,'UNKNOWN','UNKNOWN_NO_RETRY'))
        self.assertEqual(sum(m=='DELETE' for m,p in calls),1)

    def test_expiry_after_exclusive_intent_still_prevents_delete(self):
        real_write=cp.write_once
        def expire_after_intent(path,raw):
            real_write(path,raw)
            if path.name=='COMPENSATION_DELETE_INTENT.json':
                raise TimeoutError('synthetic expiry after fsync')
        with patch.object(cp,'write_once',expire_after_intent):
            code,r,calls,bridges,native=self.interrupted()
        self.assertEqual(r['cleanup'],'UNKNOWN_NO_RETRY')
        self.assertFalse(any(m=='DELETE' for m,p in calls))
        self.assertTrue((self.root/'payment186/COMPENSATION_DELETE_INTENT.json').exists())

    def test_unhealthy_transport_stops_before_credential_release(self):
        calls=[];g=self.g
        class FakeAPI:
            def __init__(self,*a):pass
            def close(self):pass
            def call(self,name,row=None,**kw):
                calls.append((name,row))
                if name=='grant':return g
                if name=='ready':return {'recipient_ready':False,'grant_sha256':c.sha(c.canonical(g)),'transport_ok':False}
                if name=='terminal':return {'state':'TERMINAL_DURABLE_CLOSING'}
                raise AssertionError('unexpected')
        env={'RUNNER_TEMP':str(self.root),'PAYMENT186_START_EPOCH':str(g['start_at']),'PAYMENT186_OWNER_REQUEST':g['owner_request']}
        with patch.dict(os.environ,env),patch.object(h.client,'actual',return_value=(g['workflow_sha'],g['run_id'])),patch.object(h.client,'token',return_value='SYNTHETIC'),patch.object(h.client,'API',FakeAPI),self.assertRaises(c.Refused):
            h.client.preflight()
        self.assertEqual([n for n,r in calls],['grant','ready','terminal'])
        self.assertEqual(calls[-1][1]['provider_slots'],{})
        self.assertFalse((self.root/'payment186/PREFLIGHT.json').exists())

if __name__=='__main__':unittest.main()
