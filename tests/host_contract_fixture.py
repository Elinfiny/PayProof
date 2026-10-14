"""Synthetic signing fixture for tests only; never runtime custody."""
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from payproof.admission import source_fingerprint, _verify_receipt
from payproof.core import canonical

TEST_KEY = b'payproof-synthetic-test-key-00001'


def signed_fixture(overrides=None):
    credentials={'client_id':'fake-client','client_secret':'fake-secret','webhook_id':'fake-hook'}
    grant={'schema':'PAYPROOF_SANDBOX_ADMISSION_V1','admission_id':'SYNTHETIC-HOST-1','project':'PayProof',
           'environment':'sandbox','source_sha256':source_fingerprint(),
           'expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
           'operations':['orders:read','orders:create','webhooks:verify'],
           'client_id_sha256':hashlib.sha256(credentials['client_id'].encode()).hexdigest(),
           'webhook_id':credentials['webhook_id'],'external_budget_usd':'0.00','live_ai':False}
    grant.update(overrides or {})
    envelope={'grant':grant,'signature':hmac.new(TEST_KEY,canonical(grant).encode(),hashlib.sha256).hexdigest()}
    return canonical(envelope).encode(),canonical(credentials).encode()


def context(overrides=None):
    receipt,credentials=signed_fixture(overrides)
    return _verify_receipt(receipt,TEST_KEY,credentials,test_only=True)
