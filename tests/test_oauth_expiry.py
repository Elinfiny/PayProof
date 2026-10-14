"""Four bounded synthetic cases for PAYPAL-EXPIRY-AFTER-OAUTH."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from host_contract_fixture import context
from payproof.core import Store, InvalidData
from payproof.paypal import SandboxPayPal


HEADERS={name:'SYNTHETIC-HEADER' for name in ['PAYPAL-AUTH-ALGO','PAYPAL-CERT-URL','PAYPAL-TRANSMISSION-ID','PAYPAL-TRANSMISSION-SIG','PAYPAL-TRANSMISSION-TIME']}


class Clock(datetime):
    current=datetime(2030,1,1,tzinfo=timezone.utc)

    @classmethod
    def now(cls,tz=None):
        return cls.current if tz else cls.current.replace(tzinfo=None)


class OAuthExpiryTests(unittest.TestCase):
    def setUp(self):
        Clock.current=datetime(2030,1,1,tzinfo=timezone.utc)
        self.clock_patch=patch('payproof.admission.datetime',Clock);self.clock_patch.start()
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name)/'db.sqlite')

    def tearDown(self):
        self.tmp.cleanup();self.clock_patch.stop()

    def adapter(self,operation,elapsed):
        grant=context({'operations':[operation],'expires_at':(Clock.current+timedelta(seconds=10)).isoformat()})
        calls=[]
        def transport(method,path,headers,body):
            calls.append(path)
            if path=='/v1/oauth2/token':
                Clock.current+=timedelta(seconds=elapsed)
                return {'access_token':'SYNTHETIC-TOKEN-NEVER-LOGGED'}
            if path=='/v1/notifications/verify-webhook-signature':return {'verification_status':'SUCCESS'}
            return {'id':'TESTORDER1','status':'CREATED'}
        return SandboxPayPal(grant,transport=transport),calls

    def test_late_oauth_create_blocks_endpoint_and_keeps_consumed_claim(self):
        adapter,calls=self.adapter('orders:create',15)
        with self.assertRaises(InvalidData) as error:adapter.create_order(self.store,'REQ-EXPIRY','120.00','EUR')
        self.assertNotIn('SYNTHETIC-TOKEN',str(error.exception))
        self.assertEqual(calls,['/v1/oauth2/token'])
        with self.store.connect() as db:
            row=db.execute('SELECT state,order_id FROM effects WHERE request_id=?',('REQ-EXPIRY',)).fetchone()
            self.assertEqual(row['state'],'UNKNOWN');self.assertIsNone(row['order_id'])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM orders').fetchone()[0],0)
        # The durable reservation stays consumed even without an endpoint call.
        with self.assertRaises(InvalidData):self.store.reserve_effect('REQ-EXPIRY',{'attempt':'rearm'})
        self.assertEqual(calls,['/v1/oauth2/token'])

    def test_late_oauth_read_blocks_endpoint(self):
        adapter,calls=self.adapter('orders:read',15)
        with self.assertRaises(InvalidData):adapter.get_order('TESTORDER1')
        self.assertEqual(calls,['/v1/oauth2/token'])

    def test_late_oauth_verify_blocks_endpoint(self):
        adapter,calls=self.adapter('webhooks:verify',15)
        with self.assertRaises(InvalidData):adapter.verify_webhook(HEADERS,b'{"id":"EV-EXPIRY"}')
        self.assertEqual(calls,['/v1/oauth2/token'])

    def test_timely_oauth_preserves_all_three_admitted_paths(self):
        for operation in ['orders:create','orders:read','webhooks:verify']:
            with self.subTest(operation=operation):
                adapter,calls=self.adapter(operation,1)
                if operation=='orders:create':
                    result=adapter.create_order(self.store,'REQ-TIMELY','120.00','EUR');self.assertEqual(result['state'],'CREATED')
                    expected='/v2/checkout/orders'
                    with self.store.connect() as db:self.assertEqual(db.execute('SELECT state FROM effects WHERE request_id=?',('REQ-TIMELY',)).fetchone()[0],'APPLIED')
                elif operation=='orders:read':
                    self.assertEqual(adapter.get_order('TESTORDER1')['id'],'TESTORDER1');expected='/v2/checkout/orders/TESTORDER1'
                else:
                    self.assertTrue(adapter.verify_webhook(HEADERS,b'{"id":"EV-TIMELY"}'));expected='/v1/notifications/verify-webhook-signature'
                self.assertEqual(calls,['/v1/oauth2/token',expected])


if __name__=='__main__':unittest.main()
