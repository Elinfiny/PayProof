"""Reused inert fixture definitions for eight NEW native36 cases. All keys/data are public SYNTHETIC fixtures.
No native host loader, credentials, network, subprocess, CI or production activation.
"""
import base64, hashlib, hmac, json, pathlib, ssl, sys, time, unittest
from copy import deepcopy
from unittest.mock import patch, Mock
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from payproof import admission
from payproof.core import InvalidData, canonical
from payproof.github_oidc import ISSUER, IdentityRefused, TransportUnknown
from payproof.bootstrap_bridge import ConsumerProvider, BootstrapBridge, _canonical, _sha1_object
from tools.read_pilot_driver import ReadPilotDriver
REPO = '/repos/Elinfiny/PayProof'
ORDER = 'SYNTHETICEXISTINGORDER'
PUBLIC_KEY = b'PUBLIC_TEST_ONLY_HMAC_FIXTURE_29_000000000000'
SENTINEL = 'PUBLIC_SYNTHETIC_SECRET_DO_NOT_EXPORT'
COUNTS = []

def deny(event, args):
    if event.startswith(('socket.', 'subprocess.')) or event in ('os.system', 'os.posix_spawn'):
        raise AssertionError('INERT_HARNESS_DENIES_NATIVE_IO')
    if event == 'open' and args and isinstance(args[0], (str, bytes)):
        path = str(args[0])
        if path.startswith('/run/') or '/.env' in path or 'payproof_admission_key' in path:
            raise AssertionError('INERT_HARNESS_DENIES_HOST_FILE')
sys.addaudithook(deny)

class Clock:

    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds

class FakeResponse:

    def __init__(self, status, raw):
        self.status, self.raw = (status, raw)

    def read(self, limit):
        return self.raw[:limit]

class FakeHTTPS:
    """Explicit fixture provider, never actual TLS/caller/durability proof."""

    def __init__(self, backend):
        self.backend = backend

    def __call__(self, host, port, *, timeout, context):
        assert port == 443 and 0 < timeout <= 300
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        self.backend.hosts.append(host)
        backend = self.backend

        class Connection:

            def request(self, method, path, body=None, headers=None):
                self.method, self.path, self.body = (method, path, body)
                backend.calls.append((host, method, path))

            def getresponse(self):
                result = backend.handle(self.method, self.path, self.body)
                backend.responses.append(result)
                return result

            def close(self):
                if backend.close_failure and self.path == backend.close_failure_path:
                    backend.clock.advance(301)
                    raise backend.cleanup_error
                return None
        return Connection()

class FakeBackend:

    def __init__(self, clock):
        self.clock = clock
        self.calls, self.hosts, self.responses = ([], [], [])
        self.refs = {}
        self.trees, self.commits, self.blobs = ({}, {}, {})
        self.jwks_raw = b'{"keys":[{"kid":"SYNTHETIC"}]}'
        self.jwks_status = 200
        self.jwks_late = False
        self.race_at_ref_create = False
        self.ref_validation_failure = False
        self.raise_commit = False
        self.raise_ref_after_create = False
        self.close_failure = False
        self.close_failure_path = REPO + '/git/commits'
        self.primary_error = RuntimeError('SYNTHETIC_PRIVATE_PRIMARY')
        self.cleanup_error = RuntimeError('SYNTHETIC_PRIVATE_CLEANUP')

    def reply(self, status, value):
        return FakeResponse(status, _canonical(value))

    def ref_reply(self, ref):
        return self.reply(200, {'ref': ref, 'object': {'sha': self.refs[ref], 'type': 'commit'}})

    def handle(self, method, path, raw):
        if path == '/.well-known/jwks':
            if self.jwks_late:
                self.clock.advance(301)
            return FakeResponse(self.jwks_status, self.jwks_raw)
        if method == 'GET' and path == REPO:
            return self.reply(200, {'id': 1419908202, 'full_name': 'Elinfiny/PayProof', 'private': True, 'owner': {'id': 273768139}})
        if method == 'GET' and path.startswith(REPO + '/git/ref/'):
            ref = 'refs/' + path.split('/git/ref/', 1)[1]
            return self.ref_reply(ref) if ref in self.refs else self.reply(404, {'message': 'Not Found'})
        data = json.loads(raw) if raw is not None else None
        if method == 'POST' and path == REPO + '/git/trees':
            entry = data['tree'][0]
            content = entry['content'].encode()
            blob = _sha1_object('blob', content)
            tree = _sha1_object('tree', b'100644 reservation.json\x00' + bytes.fromhex(blob))
            self.blobs[blob] = content
            result = {'sha': tree, 'truncated': False, 'tree': [{'path': 'reservation.json', 'mode': '100644', 'type': 'blob', 'sha': blob, 'size': len(content)}]}
            self.trees[tree] = result
            return self.reply(201, result)
        if method == 'POST' and path == REPO + '/git/commits':
            if self.raise_commit:
                raise self.primary_error
            sha = hashlib.sha1(b'SYNTHETIC_NATIVE_SHAPED_COMMIT:' + raw).hexdigest()
            result = {'sha': sha, 'tree': {'sha': data['tree']}, 'parents': [{'sha': p} for p in data['parents']], 'message': data['message']}
            self.commits[sha] = result
            return self.reply(201, result)
        if method == 'POST' and path == REPO + '/git/refs':
            ref = data['ref']
            if self.ref_validation_failure:
                return self.reply(422, {'message': 'Validation Failed'})
            if self.race_at_ref_create:
                self.refs[ref] = 'f' * 40
            if ref in self.refs:
                return self.reply(422, {'message': 'Reference already exists'})
            self.refs[ref] = data['sha']
            if self.raise_ref_after_create:
                raise self.primary_error
            response = self.ref_reply(ref)
            return FakeResponse(201, response.raw)
        for kind, values in [('commits', self.commits), ('trees', self.trees)]:
            prefix = REPO + '/git/' + kind + '/'
            if method == 'GET' and path.startswith(prefix):
                return self.reply(200, values[path.removeprefix(prefix)])
        prefix = REPO + '/git/blobs/'
        if method == 'GET' and path.startswith(prefix):
            sha = path.removeprefix(prefix)
            content = self.blobs[sha]
            return self.reply(200, {'sha': sha, 'encoding': 'base64', 'size': len(content), 'content': base64.b64encode(content).decode()})
        raise AssertionError('Unplanned fake endpoint')

class Backend(FakeBackend):

    def __init__(self, clock):
        super().__init__(clock)
        self.closes = 0
        self.late = None
        self.badparse = False
        self.source = 'a' * 40
        self.revision = 'c' * 40
        self.workflow = b'PUBLIC_SYNTHETIC_ONE_JOB_WORKFLOW'
        self.old = []
        self.badjob = False
        self.badregistry = False
        self.after_oauth = None
        self.oauth_done = False
        self.trace = []
        self.ref_mutation = False
        self.late_dynamic = False
        self.unknown_dynamic = False

    def add_blob(self, raw):
        sha = _sha1_object('blob', raw)
        self.blobs[sha] = raw
        return sha

    def tree(self, entries):
        sha = hashlib.sha1(b'SYNTHETIC_TREE' + _canonical(entries)).hexdigest()
        self.trees[sha] = {'sha': sha, 'tree': entries, 'truncated': False}
        return sha

    def fixtures(self, registry):
        wf = self.add_blob(self.workflow)
        inn = self.tree([{'path': 'payproof-read-pilot.yml', 'mode': '100644', 'type': 'blob', 'sha': wf, 'size': len(self.workflow)}])
        mid = self.tree([{'path': 'workflows', 'mode': '040000', 'type': 'tree', 'sha': inn}])
        source_dirs = {}
        for row in admission.runtime_manifest():
            directory, filename = row['path'].split('/')
            content = (pathlib.Path(admission.__file__).parent.parent / row['path']).read_bytes()
            source_dirs.setdefault(directory, []).append({'path': filename, 'mode': '100644', 'type': 'blob', 'sha': self.add_blob(content), 'size': len(content)})
        root = self.tree([{'path': '.github', 'mode': '040000', 'type': 'tree', 'sha': mid}] + [{'path': d, 'mode': '040000', 'type': 'tree', 'sha': self.tree(entries)} for d, entries in source_dirs.items()])
        self.commits[self.source] = {'sha': self.source, 'tree': {'sha': root}}
        rb = self.add_blob(_canonical(registry))
        rr = self.tree([{'path': 'payproof-orders-registry.json', 'mode': '100644', 'type': 'blob', 'sha': rb, 'size': len(_canonical(registry))}])
        self.commits[self.revision] = {'sha': self.revision, 'tree': {'sha': rr}}
        return root

    def handle(self, method, path, raw):
        self.trace.append((method, path))
        if self.oauth_done and '/git/ref/tags/payproof-reservations/v2/' in path:
            if self.late_dynamic:
                self.clock.advance(301)
            if self.unknown_dynamic:
                return self.reply(503, {'message': 'SYNTHETIC_UNKNOWN'})
            if self.ref_mutation:
                ref = 'refs/' + path.split('/git/ref/', 1)[1]
                return self.reply(200, {'ref': ref, 'object': {'sha': self.refs.get(ref), 'type': 'tag'}})
        if self.late == 'reservation' and path == REPO + '/git/commits' and (method == 'POST'):
            self.clock.advance(301)
        if path == REPO and method == 'GET':
            return self.reply(200, {'id': 1419908202, 'private': True, 'fork': False, 'full_name': 'Elinfiny/PayProof', 'owner': {'id': 273768139}})
        if path == REPO + '/branches/main':
            return self.reply(200, {'commit': {'sha': self.source}})
        if path == REPO + '/actions/runs/123':
            return self.reply(200, {'id': 123, 'run_attempt': 1, 'head_sha': self.source, 'event': 'workflow_dispatch', 'actor': {'id': 273768139}, 'head_repository': {'fork': False}})
        if path == REPO + '/actions/runs/123/attempts/1/jobs':
            return self.reply(200, {'total_count': 1, 'jobs': [{'id': 999 if self.badjob else 456, 'name': 'read_only', 'run_id': 123, 'head_sha': self.source}]})
        if path == REPO + '/git/matching-refs/tags/payproof-reservations/v1/':
            return self.reply(200, self.old)
        if path.startswith('/v1/oauth2/') or path.startswith('/v2/checkout/'):
            if method == 'POST':
                self.oauth_done = True
                if self.after_oauth:
                    self.after_oauth()
            if self.late == 'paypal':
                self.clock.advance(301)
            if self.badparse:
                return FakeResponse(200, b'not-json:' + SENTINEL.encode())
            return self.reply(200, {'access_token': 'PUBLIC_SYNTHETIC_BEARER'} if method == 'POST' else {'id': ORDER, 'payer': {'private': SENTINEL}})
        result = super().handle(method, path, raw)
        if self.badregistry and path.startswith(REPO + '/git/blobs/') and (SENTINEL not in str(path)):
            return FakeResponse(200, b'{}')
        return result

class Factory(FakeHTTPS):

    def __call__(self, *a, **kw):
        c = super().__call__(*a, **kw)
        close = c.close

        def once():
            self.backend.closes += 1
            return close()
        c.close = once
        return c
from datetime import datetime, timezone
from payproof.github_oidc import NativeIdentityPolicy, JobLifetime, NativeOIDCVerifier
from payproof.bootstrap_bridge import JobNativeProvider, job_native_entrypoint
from payproof.admission import JobPolicyEvidence, JobCredentials, JOB_NATIVE_SCHEMA
REPORTS = []

class Native37Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        global KEY_GENERATIONS, PUBLIC_JWK
        cls.test_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        KEY_GENERATIONS += 1
        pub = cls.test_rsa.public_key().public_numbers()
        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        cls.public_jwk = {'kid': 'SYNTHETIC', 'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'n': enc(pub.n.to_bytes(256, 'big')), 'e': enc(pub.e.to_bytes(3, 'big'))}
        PUBLIC_JWK = dict(cls.public_jwk)

    def setUp(self):
        self.n = int(time.time())
        self.cleanup_calls = []

    def rig(self, *, cleanup_error=False):
        clock = Clock()
        b = Backend(clock)

        def cleanup():
            self.cleanup_calls.append('owned-once')
            if cleanup_error:
                raise b.cleanup_error
        life = JobLifetime(clock=clock, seconds=240, cleanup=cleanup)
        enc = lambda v: base64.urlsafe_b64encode(v).rstrip(b'=').decode()
        b.jwks_raw = _canonical({'keys': [self.public_jwk]})
        sha = lambda v: hashlib.sha256(v).hexdigest()
        app = sha(b'PUBLIC_SYNTHETIC_APP')
        oh = sha(ORDER.encode())
        key = admission.canonical_effect_key(app, oh)
        registry = {'schema': 'PAYPROOF_PREEXISTING_REGISTRY_V3', 'client_id_sha256': app, 'order_id_sha256': oh, 'canonical_effect_key_sha256': key, 'legacy_refs_sha256': sha(_canonical([])), 'legacy_grant_ids': [], 'provenance': {'provider': 'paypal', 'environment': 'sandbox', 'receipt_sha256': 'd' * 64}}
        tree = b.fixtures(registry)
        manifest = admission.runtime_manifest()
        policy = NativeIdentityPolicy(admission.V3_AUDIENCE, 'Elinfiny/PayProof/.github/workflows/payproof-read-pilot.yml@refs/heads/main', 'refs/heads/main', 'a' * 40, 'a' * 40, 'workflow_dispatch', 'repo:Elinfiny@273768139/PayProof@1419908202:environment:payproof-sandbox-readonly', '123', '1', self.n - 10, self.n + 240)
        g = {'schema': JOB_NATIVE_SCHEMA, 'admission_id': 'PUBLIC_SYNTHETIC_JOB36', 'project': 'PayProof', 'environment': 'sandbox', 'source_sha256': admission.source_fingerprint(), 'expires_at': datetime.fromtimestamp(self.n + 220, timezone.utc).isoformat(), 'operations': ['orders:read'], 'client_id_sha256': app, 'external_budget_usd': '0.00', 'live_ai': False, 'bundle_manifest': manifest, 'bundle_sha256': sha(canonical(manifest).encode()), 'caller': {'repository_id': '1419908202', 'owner_id': '273768139', 'actor': 'Elinfiny', 'actor_id': '273768139', 'fork': False, 'visibility': 'private', 'source_commit': 'a' * 40, 'source_tree': tree, 'workflow_path': '.github/workflows/payproof-read-pilot.yml', 'workflow_sha256': sha(b.workflow), 'run_id': '123', 'job_id': '456', 'job_name': 'read_only', 'attempt': '1', 'ref': 'refs/heads/main', 'event': 'workflow_dispatch', 'issuer': ISSUER, 'audience': admission.V3_AUDIENCE, 'not_before': self.n - 10, 'environment': 'payproof-sandbox-readonly'}, 'registry': {'provider': 'github', 'revision': 'c' * 40, 'path': 'payproof-orders-registry.json', 'sha256': sha(_canonical(registry)), 'order_id_sha256': oh, 'legacy_refs_sha256': sha(_canonical([]))}, 'canonical_effect_key_sha256': key, 'legacy_grant_ids': []}
        ev = JobPolicyEvidence.synthetic(policy, g)
        p = JobNativeProvider.synthetic(ev, Factory(b), life)
        claims = {'iss': ISSUER, 'aud': admission.V3_AUDIENCE, 'repository': 'Elinfiny/PayProof', 'repository_id': '1419908202', 'repository_owner_id': '273768139', 'repository_owner': 'Elinfiny', 'repository_visibility': 'private', 'workflow_ref': policy.workflow_ref, 'workflow_sha': policy.sha, 'ref': policy.ref, 'sha': policy.sha, 'event_name': 'workflow_dispatch', 'sub': policy.subject, 'environment': 'payproof-sandbox-readonly', 'run_id': '123', 'run_attempt': '1', 'runner_environment': 'github-hosted', 'ref_type': 'branch', 'iat': self.n - 5, 'nbf': self.n - 5, 'exp': self.n + 200, 'jti': 'PUBLIC_SYNTHETIC_JTI36', 'actor': 'Elinfiny', 'actor_id': '273768139'}

        def token(changes=None, *, bad=False, payload_tamper=False, kid='SYNTHETIC'):
            head = enc(_canonical({'typ': 'JWT', 'alg': 'RS256', 'kid': kid}))
            payload = enc(_canonical(claims | (changes or {})))
            signature = self.test_rsa.sign((head + '.' + payload).encode(), padding.PKCS1v15(), hashes.SHA256())
            if bad:
                signature = bytes([signature[0] ^ 1]) + signature[1:]
            if payload_tamper:
                payload = enc(_canonical(claims | {'aud': 'AFTER_SIGN_TAMPER'}))
            raw = head + '.' + payload + '.' + enc(signature)
            VECTOR_HASHES.append(hashlib.sha256(raw.encode()).hexdigest())
            return raw
        return (p, b, clock, life, ev, JobCredentials.synthetic('PUBLIC_SYNTHETIC_APP', SENTINEL), token, g)

    def report(self, name, b=None):
        row = {'case': name, 'scope': 'SYNTHETIC_TEST_REAL_RS256', 'native_admitted': False, 'calls': len(b.calls) if b else 0, 'subcases_total': len(SUBCASES)}
        REPORTS.append(row)
        print('CASE ' + json.dumps(row, sort_keys=True))

    def no_paypal(self, b):
        self.assertFalse(any((h == 'api-m.sandbox.paypal.com' for h, m, p in b.calls)))

    def test_01_signature_issuer_audience_subject_environment_main(self):
        changes = [('issuer', {'iss': 'https://invalid.example'}), ('audience', {'aud': 'wrong'}), ('ref_subject', {'sub': 'repo:Elinfiny@273768139/PayProof@1419908202:ref:refs/heads/main'}), ('environment', {'environment': 'other'}), ('main_ref', {'ref': 'refs/heads/other'}), ('expiry', {'exp': self.n - 1}), ('future_nbf', {'nbf': self.n + 1}), ('issued_before_policy', {'iat': self.n - 20})]
        for label, change in changes:
            self.mark('claims_resigned_' + label)
            p, b, c, l, e, cred, t, g = self.rig()
            with self.assertRaises(IdentityRefused):
                p.bind(t(change), cred, now=self.n)
            self.no_paypal(b)
            self.assertIsNone(p._source_identity)
        for label in ('signature_tamper', 'payload_tamper', 'kid', 'duplicate_kid', 'wrong_public_key'):
            self.mark(label)
            p, b, c, l, e, cred, t, g = self.rig()
            if label == 'duplicate_kid':
                b.jwks_raw = _canonical({'keys': [self.public_jwk, self.public_jwk]})
            if label == 'wrong_public_key':
                wrong = dict(self.public_jwk)
                raw = base64.urlsafe_b64decode(wrong['n'] + '==')
                number = int.from_bytes(raw, 'big') + 2
                wrong['n'] = base64.urlsafe_b64encode(number.to_bytes(256, 'big')).rstrip(b'=').decode()
                b.jwks_raw = _canonical({'keys': [wrong]})
            raw = t(bad=label == 'signature_tamper', payload_tamper=label == 'payload_tamper', kid='OTHER' if label == 'kid' else 'SYNTHETIC')
            with self.assertRaises(IdentityRefused):
                p.bind(raw, cred, now=self.n)
            self.no_paypal(b)
            self.assertIsNone(p._source_identity)
        self.report('01_real_math_signature_claims', b)

    def test_02_dict_and_synthetic_cannot_mint_native(self):
        p, b, c, l, e, cred, t, g = self.rig()
        for label, policy in [('none', None), ('dict', {}), ('synthetic', e)]:
            self.mark('native_policy_' + label)
            with self.assertRaises((IdentityRefused, InvalidData)):
                JobNativeProvider.from_native(policy=policy, job_token='PUBLIC', lifetime=l)
        self.mark('custody_dict')
        with self.assertRaises(InvalidData):
            admission.intake_step_scoped_credentials(b'PUBLIC', custody={})
        self.mark('entrypoint_none')
        with self.assertRaises(IdentityRefused):
            job_native_entrypoint()
        self.assertEqual(b.calls, [])
        self.report('02_synthetic_not_native', b)

    def test_03_single_deadline_late_owned_return(self):
        from payproof.github_oidc import TransportUnknown
        for label, value in [('bool', True), ('nan', float('nan')), ('backwards', float('-1'))]:
            self.mark('clock_original_' + label)
            responses = [float('0'), value]
            effect = []

            def clock():
                return responses.pop(0) if responses else value
            life = JobLifetime(clock=clock, seconds=240)
            with self.assertRaises(TransportUnknown):
                life.invoke('NO_NEXT_EFFECT', lambda: effect.append('forbidden'))
            self.assertIs(life.clock_originals[1], value)
            first = dict(life.first_unknown)
            life.cleanup_once()
            self.assertIs(life.clock_originals[1], value)
            self.assertEqual(first, life.first_unknown)
            self.assertEqual(effect, [])
            self.assertEqual(set(life.first_unknown), {'code', 'original_index'})
        self.mark('clock_exception_original')
        error = RuntimeError('PUBLIC_TEST_CLOCK_EXCEPTION')
        calls = []
        effects = []

        def throwing():
            calls.append(1)
            if len(calls) == 1:
                return 0.0
            raise error
        life = JobLifetime(clock=throwing)
        with self.assertRaises(TransportUnknown):
            life.invoke('NO_NEXT_EFFECT', lambda: effects.append(1))
        self.assertTrue(any((row[2] is error for row in life.originals)))
        self.assertEqual(effects, [])
        first = dict(life.first_unknown)
        life.cleanup_once()
        self.assertEqual(first, life.first_unknown)
        self.mark('shared_deadline_late')
        p, b, c, l, e, cred, t, g = self.rig()
        p.bind(t(), cred, now=self.n)
        b.late = 'reservation'
        with self.assertRaises(TransportUnknown):
            p.consume_native(ORDER)
        self.assertIs(p._wire.lifetime, p._reservation._wire.lifetime)
        self.assertEqual(p._wire._deadline, l.deadline)
        self.assertEqual(p._reservation._wire._deadline, l.deadline)
        self.assertIsNotNone(l.first_unknown)
        self.assertTrue(p._reservation._wire._per_call_originals)
        self.assertEqual(self.cleanup_calls, ['owned-once'])
        self.no_paypal(b)
        self.report('03_exact_clock_original_and_late', b)

    def test_04_once_loser_and_replay(self):
        self.mark('reservation_loser')
        p, b, c, l, e, cred, t, g = self.rig()
        p.bind(t(), cred, now=self.n)
        b.race_at_ref_create = True
        with self.assertRaises(IdentityRefused):
            p.consume_native(ORDER)
        calls = len(b.calls)
        self.mark('loser_replay')
        with self.assertRaises(IdentityRefused):
            p.consume_native(ORDER)
        self.assertEqual(len(b.calls), calls)
        self.assertEqual(p._reservation.state, 'COLLISION_RECORD_REFUSED')
        self.no_paypal(b)
        self.report('04_loser_replay_no_adoption', b)

    def test_05_missing_credentials_registry_policy(self):
        p, b, c, l, e, cred, t, g = self.rig()
        self.mark('credentials_none')
        with self.assertRaises(IdentityRefused):
            p.bind(t(), None, now=self.n)
        self.assertEqual(b.calls, [])
        bad = deepcopy(g)
        bad['registry'] = None
        self.mark('registry_none')
        with self.assertRaises(IdentityRefused):
            JobPolicyEvidence.synthetic(e.policy, bad)
        p.bind(t(), cred, now=self.n)
        b.badregistry = True
        self.mark('registry_provider_mismatch')
        with self.assertRaises(IdentityRefused):
            p.consume_native(ORDER)
        self.no_paypal(b)
        self.report('05_absent_genuine_inputs', b)

    def test_06_primary_and_cleanup_errors_sticky(self):
        self.mark('primary_cleanup_separate_originals')
        p, b, c, l, e, cred, t, g = self.rig(cleanup_error=True)
        p.bind(t(), cred, now=self.n)
        b.raise_commit = True
        with self.assertRaises(TransportUnknown):
            p.consume_native(ORDER)
        first = dict(l.first_unknown)
        clock_first = l.clock_originals[0]
        l.cleanup_once()
        self.assertEqual(l.first_unknown, first)
        self.assertIs(l.clock_originals[0], clock_first)
        self.assertEqual(l.cleanup_errors, [b.cleanup_error])
        self.assertEqual(self.cleanup_calls, ['owned-once'])
        self.assertTrue(any((x.error is b.primary_error for x in p._reservation._wire._per_call_originals)))
        self.no_paypal(b)
        self.report('06_primary_cleanup_sticky', b)

    def test_07_v3_exact_prefix_and_type_gates(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        self.mark('v3_exact_prefix_hashes')
        for path, pin in LEGACY_PREFIX_PINS.items():
            raw = (root / path).read_bytes()[:pin['bytes']]
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pin['sha256'])
        for path in ('payproof/core.py', 'payproof/paypal.py', 'payproof/service.py', 'payproof/server.py'):
            self.assertEqual((root / path).read_bytes(), (root.parent / 'before' / path).read_bytes())
        p, b, c, l, e, cred, t, g = self.rig()
        ctx = p.bind(t(), cred, now=self.n)
        self.mark('old_bridge_rejects_native_type')
        with self.assertRaises(IdentityRefused):
            BootstrapBridge(p).activate(t(), order_id=ORDER)
        self.mark('old_driver_rejects_native_type')
        with self.assertRaises(InvalidData):
            ReadPilotDriver.from_consumer(ctx, None, p)
        self.mark('test_identity_never_production')
        with self.assertRaises((IdentityRefused, InvalidData)):
            ctx.require(production=True)
        self.assertTrue(ctx.identity.test_only)
        self.no_paypal(b)
        self.report('07_v3_prefix_scope_preserved', b)

    def test_08_strict_synthetic_chain_happy_and_consumed(self):
        self.mark('real_rs256_signed_test_happy')
        p, b, c, l, e, cred, t, g = self.rig()
        ctx = p.bind(t(), cred, now=self.n)
        out = p.consume_native(ORDER)
        self.assertEqual(out['status'], 'SYNTHETIC_RETURNED')
        self.assertEqual(out['transport_calls'], 2)
        self.assertFalse(out['real_runtime_admitted'])
        self.assertTrue(ctx.test_only)
        self.assertTrue(ctx.identity.test_only)
        self.assertIs(p._driver._lifetime, l)
        self.assertIs(p._reservation._wire.lifetime, l)
        self.assertEqual(self.cleanup_calls, ['owned-once'])
        for private in (SENTINEL, ORDER, t(), 'PUBLIC_SYNTHETIC_BEARER'):
            self.assertNotIn(private, json.dumps(out))
        counts = len(b.calls)
        self.mark('happy_consumed_restart_refused')
        with self.assertRaises(IdentityRefused):
            p.consume_native(ORDER, restart=True)
        self.assertEqual(len(b.calls), counts)
        self.assertEqual(sum((h == 'api-m.sandbox.paypal.com' and m == 'POST' for h, m, path in b.calls)), 1)
        self.assertEqual(sum((h == 'api-m.sandbox.paypal.com' and m == 'GET' for h, m, path in b.calls)), 1)
        self.report('08_real_math_test_only_happy', b)

    def mark(self, label):
        SUBCASES.append(label)
        self.assertLessEqual(len(SUBCASES), 40)
SUBCASES=[]
VECTOR_HASHES=[]
KEY_GENERATIONS=0
PUBLIC_JWK=None
LEGACY_PREFIX_PINS={'payproof/admission.py': {'bytes': 14933, 'sha256': '794cb869f665de2372a6c2422c1edd62c1abc01ae95a71fbc3f63abe0704f4f7'}, 'payproof/github_oidc.py': {'bytes': 23882, 'sha256': 'ecba546a350a37596940324976d23dbcd2bb7cc8e1bbafe0f55c19618bd8f616'}, 'payproof/bootstrap_bridge.py': {'bytes': 34303, 'sha256': 'c7bd6dc19ac639a54a56af5b1c43b84b6a1b5f4e238f3e837ef5cd6e43ddf5f4'}, 'tools/read_pilot_driver.py': {'bytes': 10658, 'sha256': 'ddccdef0361b4cdce33907ea9e3113eb7f4bbf10449e34fd19e95835bc03067a'}}

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Native37Tests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print('SUMMARY '+json.dumps({'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'subcase_count':len(SUBCASES),'subcases':SUBCASES,'ephemeral_TEST_RSA2048_keys':KEY_GENERATIONS,'production_keys':0,'private_key_serialized':False,'zeroization_claimed':False,'signature_primitive':'REAL_CRYPTOGRAPHY_RS256_PKCS1v15_SHA256','public_JWK':PUBLIC_JWK,'vector_sha256':VECTOR_HASHES,'cases':REPORTS},sort_keys=True))
    del Native37Tests.test_rsa
    raise SystemExit(0 if result.wasSuccessful() and KEY_GENERATIONS==1 and len(SUBCASES)<=40 else 1)
