"""Six TEST_ONLY groups. Ephemeral RSA keys remain in memory; no production grant."""
import base64
import hashlib
import json
import os
import unittest
from dataclasses import replace
from unittest.mock import Mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from payproof.github_oidc import (ISSUER, JWKS_URL, IdentityPolicy, JWKSSnapshot,
                                  GitHubOIDCVerifier, IdentityRefused)
from payproof.bootstrap_bridge import SourceBinding, ReservationPlan, BootstrapBridge

NOW = 1800000100


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def integer(value):
    return b64(value.to_bytes((value.bit_length() + 7) // 8, 'big'))


class BootstrapIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Fixture keys only: never serialized, printed, persisted or used as a root issuer.
        cls.fixture_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_fixture_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = cls.fixture_key.public_key().public_numbers()
        cls.jwk = {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'SYNTHETIC_ONLY',
                   'n': integer(numbers.n), 'e': integer(numbers.e)}

    @classmethod
    def tearDownClass(cls):
        cls.fixture_key = cls.other_fixture_key = None

    def setUp(self):
        self.policy = IdentityPolicy('urn:payproof:read-bootstrap:test-only',
            'Elinfiny/PayProof/.github/workflows/payproof-read-pilot.yml@refs/heads/main',
            'refs/heads/main', 'a' * 40, 'a' * 40, 'workflow_dispatch',
            'repo:Elinfiny@273768139/PayProof@1419908202:ref:refs/heads/main',
            '123456', '1', NOW - 100, NOW + 200)
        self.claims = {'iss': ISSUER, 'aud': self.policy.audience,
            'repository': 'Elinfiny/PayProof', 'repository_id': '1419908202',
            'repository_owner_id': '273768139', 'repository_owner': 'Elinfiny',
            'repository_visibility': 'private', 'workflow_ref': self.policy.workflow_ref,
            'workflow_sha': self.policy.workflow_sha, 'ref': self.policy.ref, 'sha': self.policy.sha,
            'event_name': self.policy.event_name, 'sub': self.policy.subject,
            'run_id': self.policy.run_id, 'run_attempt': '1', 'runner_environment': 'github-hosted',
            'ref_type': 'branch', 'iat': NOW - 10, 'nbf': NOW - 10, 'exp': NOW + 120,
            'jti': 'SYNTHETIC_MEMORY_ONLY_TOKEN'}
        self.snapshot = self.snapshot_of({'keys': [dict(self.jwk)]})
        self.verifier = GitHubOIDCVerifier()

    def snapshot_of(self, value):
        return JWKSSnapshot.synthetic_for_test(json.dumps(value).encode(), observed_at=NOW)

    def token(self, claims=None, header=None, key=None):
        h = b64(json.dumps(header or {'typ': 'JWT', 'alg': 'RS256', 'kid': 'SYNTHETIC_ONLY'},
                           separators=(',', ':')).encode())
        p = b64(json.dumps(self.claims if claims is None else claims, separators=(',', ':')).encode())
        signature = (key or self.fixture_key).sign((h + '.' + p).encode(), padding.PKCS1v15(), hashes.SHA256())
        return h + '.' + p + '.' + b64(signature)

    def verify(self, token, snapshot=None, now=NOW):
        return self.verifier.verify_for_test(token, policy=self.policy,
                                            snapshot=snapshot or self.snapshot, now=now)

    def bridge_inputs(self):
        digest = lambda x: hashlib.sha256(x.encode()).hexdigest()
        bundle = os.environ['PAYPROOF_BOOTSTRAP_TEST_SOURCE_SHA256']
        admission = os.environ['PAYPROOF_ADMISSION_TEST_SOURCE_SHA256']
        binding = SourceBinding('SYNTHETIC_GRANT', bundle, admission, digest('SYNTHETIC_ID'),
                                digest('SYNTHETIC_EXISTING_ORDER'), digest('SYNTHETIC_REGISTRY'))
        key = digest(binding.grant_id + ':' + binding.order_id_sha256)
        return {'policy': self.policy, 'snapshot': self.snapshot, 'now': NOW,
            'source_binding': binding, 'actual_bundle_sha256': bundle,
            'admission_source_sha256': admission,
            'credentials': {'client_id': 'SYNTHETIC_ID', 'client_secret': 'SYNTHETIC_MEMORY_ONLY'},
            'registry_entry': {'order_id_sha256': binding.order_id_sha256,
                'registry_receipt_sha256': binding.registry_receipt_sha256, 'preexisting': True},
            'reservation': ReservationPlan(key)}

    def test_01_default_unbound_never_uses_payload_or_callbacks(self):
        callback = Mock(side_effect=AssertionError('No production adapter'))
        for alleged in (None, True, {'admitted': True, 'PID': 123}, {'HMAC': 'local'}, callback):
            with self.assertRaisesRegex(IdentityRefused, 'UNBOUND'):
                GitHubOIDCVerifier(alleged, callback).verify_production(self.token(), now=NOW)
            with self.assertRaisesRegex(IdentityRefused, 'UNBOUND'):
                BootstrapBridge(alleged).activate(self.token(), job_token=callback,
                                                   order_id='SYNTHETIC_EXISTING_ORDER')
        callback.assert_not_called()
        with self.assertRaises(IdentityRefused): self.verify(self.token(), snapshot={'url': JWKS_URL, 'admitted': True})

    def test_02_signed_identity_and_finite_inactive_bridge_plan(self):
        token = self.token()
        identity = self.verify(token)
        self.assertTrue(identity.test_only)
        report = BootstrapBridge().inspect_for_test(token, **self.bridge_inputs())
        self.assertEqual(report['operations'], ['orders:read'])
        self.assertFalse(report['production_context'])
        self.assertFalse(report['host_receipt_generated'])
        self.assertFalse(report['issuer_generated'])
        self.assertEqual(report['reservation_durability'], 'NOT_IMPLEMENTED_OR_CLAIMED')
        exported = json.dumps(report)
        for forbidden in (token, 'SYNTHETIC_ID', 'SYNTHETIC_MEMORY_ONLY', 'SYNTHETIC_EXISTING_ORDER', 'SYNTHETIC_MEMORY_ONLY_TOKEN'):
            self.assertNotIn(forbidden, exported)
        self.assertNotIn('job_id', self.claims)
        with self.assertRaises(IdentityRefused): BootstrapBridge().activate(identity)

    def test_03_signature_algorithm_kid_keytype_and_untrusted_key_urls_refused(self):
        with self.assertRaises(IdentityRefused): self.verify(self.token(key=self.other_fixture_key))
        for alteration in ({'alg': 'none'}, {'alg': 'HS256'}, {'kid': 'wrong'},
                           {'jku': 'https://untrusted.invalid'}, {'x5u': JWKS_URL}, {'jwk': dict(self.jwk)}, {'crit': []}):
            header = {'typ': 'JWT', 'alg': 'RS256', 'kid': 'SYNTHETIC_ONLY'} | alteration
            with self.assertRaises(IdentityRefused): self.verify(self.token(header=header))
        for alteration in ({'kty': 'oct'}, {'alg': 'HS256'}, {'use': 'enc'}, {'e': integer(3)}):
            with self.assertRaises(IdentityRefused):
                self.verify(self.token(), self.snapshot_of({'keys': [self.jwk | alteration]}))
        with self.assertRaises(IdentityRefused):
            self.verify(self.token(), self.snapshot_of({'keys': [self.jwk, self.jwk]}))
        with self.assertRaises(IdentityRefused):
            self.verify(self.token(), replace(self.snapshot, url='https://untrusted.invalid/jwks'))
        with self.assertRaises(IdentityRefused): self.verify(self.token(), replace(self.snapshot, observed_at=NOW - 301))

    def test_04_issuer_audience_and_absolute_numeric_dates_refused(self):
        for alteration in ({'iss': 'https://untrusted.invalid'}, {'aud': 'wrong'},
                           {'aud': [self.policy.audience]}, {'exp': NOW}, {'nbf': NOW + 1},
                           {'iat': NOW + 1}, {'iat': NOW - 301}, {'exp': NOW + 201},
                           {'iat': True}, {'nbf': 'not-a-number'}, {'jti': ''}):
            with self.assertRaises(IdentityRefused): self.verify(self.token(self.claims | alteration))
        with self.assertRaises(IdentityRefused): self.verify(self.token(), now=self.policy.expires_at)
        with self.assertRaises(IdentityRefused): self.verify(self.token(), now=True)
        with self.assertRaises(IdentityRefused): replace(self.policy, expires_at=NOW + 201)

    def test_05_each_documented_identity_binding_and_immutable_subject_refused(self):
        for name in ('repository', 'repository_id', 'repository_owner_id', 'repository_owner',
                     'repository_visibility', 'workflow_ref', 'workflow_sha', 'ref', 'sha',
                     'event_name', 'sub', 'run_id', 'run_attempt', 'runner_environment', 'ref_type'):
            with self.subTest(claim=name):
                with self.assertRaises(IdentityRefused): self.verify(self.token(self.claims | {name: 'wrong'}))
        for sub in ('repo:Elinfiny/PayProof:ref:refs/heads/main',
                    'repo:Elinfiny@1/PayProof@2:ref:refs/heads/main'):
            with self.assertRaises(IdentityRefused): self.verify(self.token(self.claims | {'sub': sub}))
        with self.assertRaises(IdentityRefused): replace(self.policy, subject='legacy-sub')

    def test_06_source_custody_registry_and_durable_restart_contract_refused(self):
        token = self.token(); args = self.bridge_inputs(); bridge = BootstrapBridge()
        for change in ({'actual_bundle_sha256': '0' * 64}, {'admission_source_sha256': '0' * 64},
                       {'source_binding': {'admitted': True}}, {'reservation': {'consumed': True}},
                       {'credentials': {'client_id': 'SYNTHETIC_ID', 'client_secret': 'SYNTHETIC', 'webhook_id': 'not-needed'}},
                       {'credentials': {'client_id': 'wrong', 'client_secret': 'SYNTHETIC'}},
                       {'registry_entry': args['registry_entry'] | {'preexisting': False}},
                       {'registry_entry': args['registry_entry'] | {'order_id_sha256': '0' * 64}},
                       {'reservation': replace(args['reservation'], initial_state='CONSUMED_BEFORE_OAUTH')},
                       {'reservation': replace(args['reservation'], maximum_attempts=3)},
                       {'reservation': replace(args['reservation'], restart='ALLOW')}):
            with self.assertRaises(IdentityRefused): bridge.inspect_for_test(token, **(args | change))
        # Token/run changes must not change reservation scope across a restart.
        report1 = bridge.inspect_for_test(token, **args)
        report2 = bridge.inspect_for_test(self.token(self.claims | {'jti': 'SECOND_SYNTHETIC_JTI'}), **args)
        self.assertEqual(report1['reservation_scope_key_sha256'], report2['reservation_scope_key_sha256'])
