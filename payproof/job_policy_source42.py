"""Private pre-admission source preparation. Never issues native authority."""
import base64
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

REPO = 'Elinfiny/PayProof'
PREFIX = '/repos/' + REPO
HOST = 'https://api.github.com'
WORKFLOW = '.github/workflows/payproof-read-pilot.yml'
ENVIRONMENT = 'payproof-sandbox-readonly'
SUBJECT = 'repo:Elinfiny@273768139/PayProof@1419908202:environment:' + ENVIRONMENT
AUDIENCE = 'urn:payproof:orders-read:consumer-v3'
PATHS = ('payproof/admission.py', 'payproof/core.py', 'payproof/paypal.py',
         'payproof/service.py', 'payproof/server.py', 'payproof/github_oidc.py',
         'payproof/bootstrap_bridge.py', 'tools/read_pilot_driver.py')
REGISTRY_PATH = 'payproof-orders-registry.json'
OFFICIAL_METHOD = 'mcp__codex_apps__github_fetch'
NATIVE_SOURCE_FACTORY = None
NATIVE_POLICY_ADAPTER = None


class SourceRefused(ValueError):
    pass


class SourceUnknown(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _pin(value, length=64):
    if type(value) is not str or re.fullmatch('[0-9a-f]{%d}' % length, value) is None:
        raise SourceRefused('EXACT_DIGEST_REQUIRED')
    return value


def _number(value):
    if type(value) is not str or re.fullmatch('[1-9][0-9]{0,19}', value) is None:
        raise SourceRefused('EXACT_RUN_OR_JOB_ID_REQUIRED')
    return value


def _object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SourceRefused('DUPLICATE_JSON_MEMBER')
            result[key] = value
        return result
    if type(raw) is not bytes or len(raw) > 65536:
        raise SourceRefused('WHOLE_BOUNDED_BYTES_REQUIRED')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except SourceRefused:
        raise
    except (ValueError, UnicodeError):
        raise SourceRefused('STRICT_JSON_REQUIRED') from None
    if type(value) is not dict:
        raise SourceRefused('OBJECT_REQUIRED')
    return value


def _endpoint(path):
    patterns = ('', '/branches/main', r'/git/commits/[0-9a-f]{40}',
                r'/git/trees/[0-9a-f]{40}\?recursive=1',
                r'/git/blobs/[0-9a-f]{40}', r'/actions/runs/[1-9][0-9]{0,19}',
                r'/actions/runs/[1-9][0-9]{0,19}/attempts/1/jobs')
    if type(path) is not str or not any(re.fullmatch(p, path) for p in patterns):
        raise SourceRefused('FIXED_GET_ENDPOINT_REQUIRED')
    return HOST + PREFIX + path


def official_backend_plan(source_commit, source_tree, run_id):
    """Data-only supported connector plan; no REST/client/token escape hatch."""
    _pin(source_commit, 40); _pin(source_tree, 40); _number(run_id)
    return {'classification': 'INCOMPLETE', 'factory': 'UNBOUND',
            'method': OFFICIAL_METHOD, 'transport': 'OFFICIAL_CONNECTOR_MANAGED_HTTPS_TLS',
            'tls_override': False, 'credential_probe': False,
            'requests': [{'method': 'GET', 'url': _endpoint(p)} for p in (
                '', '/branches/main', '/git/commits/' + source_commit,
                '/git/trees/' + source_tree + '?recursive=1',
                '/actions/runs/' + run_id, '/actions/runs/' + run_id + '/attempts/1/jobs')]}


@dataclass(frozen=True)
class TestResponse:
    """Caller data, always TEST_ONLY; not an authenticated vendor receipt."""
    status: object
    raw: object


@dataclass(frozen=True)
class PreparedJobPolicySource:
    structural_test_closure: bool
    source_commit: str
    source_tree: str
    manifest_sha256: str
    fingerprint: str
    receipt_pins: tuple

    @property
    def classification(self):
        return 'INCOMPLETE'

    @property
    def test_only(self):
        return True

    def export(self):
        return {'type': 'PreparedJobPolicySource', 'classification': 'INCOMPLETE',
                'test_only': True, 'structural_test_closure': self.structural_test_closure,
                'source_commit': self.source_commit, 'source_tree': self.source_tree,
                'manifest_sha256': self.manifest_sha256, 'fingerprint': self.fingerprint,
                'receipt_count': len(self.receipt_pins),
                'authentic_grant': 'UNBOUND', 'protected_manifest_delivery': 'UNBOUND',
                'runtime_identity': 'UNBOUND', 'registry_origin': 'UNBOUND',
                'CredentialCustody': {'binding': 'UNBOUND',
                    'known_legacy_locator': '/run/secrets/payproof_paypal_sandbox.json'},
                'OrderRegistry': {'binding': 'UNBOUND', 'provider': 'github',
                                  'known_path': REGISTRY_PATH}}


def to_native_policy(prepared):
    # No imported native seal, no local substitute, no data-to-authority adapter.
    raise SourceRefused('AUTHENTIC_SOURCE_FACTORY_AND_POLICY_ADAPTER_UNBOUND')


def collect_native(*, admission=None, protected_token=None, manifest_delivery=None,
                   runtime_identity=None, registry=None):
    # None is refused before source access. Even non-None caller data grants nothing.
    if any(x is None for x in (admission, protected_token, manifest_delivery,
                               runtime_identity, registry)):
        raise SourceRefused('PRE_ADMISSION_INPUTS_UNBOUND')
    raise SourceRefused('NATIVE_SOURCE_FACTORY_UNBOUND')


def _tree_digest(rows):
    leaves = {}; directories = {}; root = {}
    for row in rows:
        path = row.get('path')
        if (type(path) is not str or path.startswith('/') or '\\' in path
                or any(p in ('', '.', '..') for p in path.split('/'))
                or path in leaves or path in directories):
            raise SourceRefused('TREE_PATH_OR_DUPLICATE')
        _pin(row.get('sha'), 40)
        if row.get('type') == 'tree' and row.get('mode') == '040000':
            directories[path] = row['sha']; continue
        if row.get('type') != 'blob' or row.get('mode') != '100644' or type(row.get('size')) is not int:
            raise SourceRefused('REGULAR_COMPLETE_SOURCE_TREE_REQUIRED')
        leaves[path] = row
        node = root
        for name in path.split('/')[:-1]:
            existing = node.setdefault(name, {})
            if not isinstance(existing, dict):
                raise SourceRefused('TREE_PATH_COLLISION')
            node = existing
        if path.split('/')[-1] in node:
            raise SourceRefused('TREE_PATH_COLLISION')
        node[path.split('/')[-1]] = (row['sha'], '100644')
    computed_dirs = {}
    def walk(node, prefix=''):
        raw = b''
        for name, value in sorted(node.items(), key=lambda item: (item[0] + ('/' if type(item[1]) is dict else '')).encode()):
            if type(value) is dict:
                sha = walk(value, prefix + name + '/'); mode = '40000'
                computed_dirs[prefix + name] = sha
            else:
                sha, mode = value
            raw += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    result = walk(root)
    if directories != computed_dirs:
        raise SourceRefused('COMPLETE_DIRECTORY_MERKLE_REQUIRED')
    return result, leaves


class PreparedSourceCollector:
    """In-memory TEST_ONLY protocol mechanics, separated from JobPolicyEvidence.

    The native source factory and protected origin are deliberately unavailable.
    Supplying a callback or response object cannot change that classification.
    """
    def __init__(self, test_api, *, clock=time.monotonic, seconds=30, cleanup=None):
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 30:
            raise SourceRefused('BOUNDED_WINDOW_REQUIRED')
        self.api = test_api; self.clock = clock; self.originals = []; self.clock_originals = []
        self.first_unknown = None; self.cleanup_errors = []; self.cleanup_guard_faults = []; self.ledger = []
        self.calls = 0; self.used = False; self.closed = False; self.cleanup = cleanup
        self._last = None; self.deadline = self._now() + seconds; self.pins = []

    def _mark(self, phase):
        if self.first_unknown is None:
            self.first_unknown = {'phase': phase, 'request_index': self.calls}

    def _now(self):
        try:
            value = self.clock(); self.clock_originals.append(value)
        except BaseException as original:
            self.originals.append(original); self._mark('CLOCK_EXCEPTION')
            raise SourceUnknown('CLOCK_UNKNOWN') from None
        if (type(value) not in (int, float) or not math.isfinite(value)
                or (self._last is not None and value < self._last)):
            self._mark('CLOCK_VALUE'); raise SourceUnknown('CLOCK_UNKNOWN')
        self._last = value; return value

    def _guard(self, phase):
        if self.first_unknown is not None:
            raise SourceUnknown('FIRST_UNKNOWN_STICKY')
        if self._now() >= self.deadline:
            self._mark(phase); raise SourceUnknown('ABSOLUTE_DEADLINE')

    def _get(self, path):
        url = _endpoint(path); self.ledger.append(('PRE_REQUEST', path)); self._guard('PRE_REQUEST')
        if self.calls >= 64:
            raise SourceRefused('READ_COUNT_BOUND')
        self.ledger.append(('PRE_INVOKE', path)); self._guard('PRE_INVOKE'); self.calls += 1
        try:
            original = self.api.request('GET', url)
            self.originals.append(original)  # Before clock, status, type, bytes or parsing.
        except BaseException as original:
            self.originals.append(original); self._mark('HTTP_EXCEPTION')
            raise SourceUnknown('PROVIDER_RETURN_UNKNOWN') from None
        self.ledger.append(('POST_RETURN', path)); self._guard('POST_RETURN')
        if type(original) is not TestResponse:
            raise SourceRefused('TEST_RESPONSE_ONLY_NO_VENDOR_AUTHORITY')
        if type(original.status) is not int or original.status != 200:
            self._mark('HTTP_STATUS'); raise SourceUnknown('PROVIDER_STATUS_UNKNOWN')
        value = _object(original.raw); self.pins.append((path, len(original.raw), digest(original.raw)))
        return value

    def _file(self, leaves, path, expected_sha):
        leaf = leaves.get(path)
        if leaf is None:
            raise SourceRefused('IMMUTABLE_PATH_ABSENT')
        obj = self._get('/git/blobs/' + leaf['sha'])
        if obj.get('sha') != leaf['sha'] or obj.get('encoding') != 'base64':
            raise SourceRefused('WHOLE_BLOB_PROVENANCE')
        if type(obj.get('content')) is not str or len(obj['content']) > 131072:
            raise SourceRefused('WHOLE_BLOB_ENCODING')
        try:
            raw = base64.b64decode(obj['content'].replace('\n', ''), validate=True)
        except (KeyError, ValueError, TypeError):
            raise SourceRefused('WHOLE_BLOB_ENCODING') from None
        if (len(raw) > 65536 or len(raw) != leaf['size'] or len(raw) != obj.get('size')
                or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != leaf['sha']
                or digest(raw) != expected_sha):
            raise SourceRefused('WHOLE_SOURCE_PIN_DRIFT')
        return raw

    def _leaves(self, revision, tree_sha):
        commit = self._get('/git/commits/' + _pin(revision, 40))
        if commit.get('sha') != revision or commit.get('tree', {}).get('sha') != tree_sha:
            raise SourceRefused('SOURCE_COMMIT_TREE_DRIFT')
        tree = self._get('/git/trees/' + _pin(tree_sha, 40) + '?recursive=1')
        if (tree.get('sha') != tree_sha or tree.get('truncated') is not False
                or type(tree.get('tree')) is not list or len(tree['tree']) > 512):
            raise SourceRefused('WHOLE_TREE_REQUIRED')
        computed, leaves = _tree_digest(tree['tree'])
        if computed != tree_sha:
            raise SourceRefused('TREE_MERKLE_DRIFT')
        return leaves

    def collect_test(self, *, grant_raw, protected_manifest, test_identity, expected_manifest,
                     registry_tree, now):
        if self.used or self.first_unknown is not None:
            raise SourceUnknown('CONSUMED_OR_UNKNOWN_NO_NEXT')
        self.used = True
        try:
            g = _object(grant_raw); c = g.get('caller', {}); r = g.get('registry', {})
            if (g.get('schema') != 'PAYPROOF_JOB_NATIVE_CONTEXT_V1' or g.get('project') != 'PayProof'
                    or g.get('environment') != 'sandbox' or g.get('operations') != ['orders:read']
                    or g.get('external_budget_usd') != '0.00' or g.get('live_ai') is not False):
                raise SourceRefused('EXACT_READ_SCOPE_REQUIRED')
            if type(g.get('admission_id')) is not str or re.fullmatch('[A-Za-z0-9_-]{1,128}', g['admission_id']) is None:
                raise SourceRefused('SOURCE_GRANT_REFERENCE_REQUIRED')
            fixed = {'repository_id': '1419908202', 'owner_id': '273768139', 'actor': 'Elinfiny',
                     'actor_id': '273768139', 'fork': False, 'visibility': 'private', 'attempt': '1',
                     'workflow_path': WORKFLOW, 'job_name': 'read_only', 'ref': 'refs/heads/main',
                     'event': 'workflow_dispatch', 'environment': ENVIRONMENT,
                     'issuer': 'https://token.actions.githubusercontent.com', 'audience': AUDIENCE}
            if any(type(c.get(k)) is not type(v) or c[k] != v for k, v in fixed.items()):
                raise SourceRefused('FIXED_CALLER_REQUIRED')
            commit = _pin(c.get('source_commit'), 40); tree = _pin(c.get('source_tree'), 40)
            run_id = _number(c.get('run_id')); _number(c.get('job_id')); _pin(c.get('workflow_sha256'))
            if type(now) is not int or type(c.get('not_before')) is not int:
                raise SourceRefused('ABSOLUTE_WINDOW_REQUIRED')
            try:
                expiry = datetime.fromisoformat(g['expires_at'])
                expires = expiry.timestamp()
            except (KeyError, ValueError, TypeError):
                raise SourceRefused('EXPIRY_REQUIRED') from None
            if expiry.tzinfo is None or not c['not_before'] <= now < expires <= c['not_before'] + 300:
                raise SourceRefused('EXPIRED_OR_OVERSIZED_WINDOW')
            if (g.get('bundle_manifest') != expected_manifest
                    or type(expected_manifest) is not list or len(expected_manifest) != 8
                    or [x.get('path') for x in expected_manifest] != list(PATHS)
                    or g.get('bundle_sha256') != digest(canonical(expected_manifest))
                    or type(protected_manifest) is not bytes
                    or protected_manifest != canonical(expected_manifest)):
                raise SourceRefused('EXACT_PROTECTED_TEST_MANIFEST')
            if (type(test_identity) is not dict or test_identity.get('test_only') is not True
                    or test_identity.get('sha') != commit or test_identity.get('workflow_sha') != commit
                    or test_identity.get('run_id') != run_id or test_identity.get('run_attempt') != '1'
                    or test_identity.get('ref') != 'refs/heads/main'
                    or test_identity.get('environment') != ENVIRONMENT
                    or test_identity.get('sub') != SUBJECT):
                raise SourceRefused('TEST_IDENTITY_NOT_NATIVE_OR_EXACT')
            identity_fixed = {'iss': c['issuer'], 'aud': AUDIENCE, 'repository': REPO,
                'repository_id': '1419908202', 'repository_owner_id': '273768139',
                'workflow_ref': REPO + '/' + WORKFLOW + '@refs/heads/main',
                'event_name': 'workflow_dispatch', 'actor': 'Elinfiny', 'actor_id': '273768139'}
            if any(type(test_identity.get(k)) is not type(v) or test_identity[k] != v
                   for k, v in identity_fixed.items()):
                raise SourceRefused('TEST_IDENTITY_SOURCE_CLAIMS')
            repo = self._get('')
            if (type(repo.get('id')) is not int or repo['id'] != 1419908202
                    or repo.get('owner', {}).get('id') != 273768139
                    or repo.get('private') is not True or repo.get('fork') is not False):
                raise SourceRefused('EXACT_PRIVATE_REPO_OWNER')
            branch = self._get('/branches/main')
            if branch.get('commit', {}).get('sha') != commit:
                raise SourceRefused('SOURCE_PIN_DRIFT')
            leaves = self._leaves(commit, tree)
            actual = []
            for row in expected_manifest:
                if set(row) != {'path', 'bytes', 'sha256'} or type(row['bytes']) is not int:
                    raise SourceRefused('EXACT_MANIFEST_ROW')
                raw = self._file(leaves, row['path'], _pin(row['sha256']))
                if len(raw) != row['bytes']:
                    raise SourceRefused('MANIFEST_SIZE_DRIFT')
                actual.append({'path': row['path'], 'bytes': len(raw), 'sha256': digest(raw)})
            five = [[row['path'].split('/')[-1], row['sha256']] for row in actual[:5]]
            if g.get('source_sha256') != digest(canonical(five)):
                raise SourceRefused('ADMISSION5_FINGERPRINT_DRIFT')
            self._file(leaves, WORKFLOW, c['workflow_sha256'])
            run = self._get('/actions/runs/' + run_id)
            if (str(run.get('id')) != run_id or type(run.get('run_attempt')) is not int
                    or run['run_attempt'] != 1 or run.get('head_sha') != commit
                    or run.get('event') != 'workflow_dispatch' or run.get('actor', {}).get('id') != 273768139
                    or run.get('head_repository', {}).get('fork') is not False):
                raise SourceRefused('RUN_SOURCE_ATTEMPT_DRIFT')
            jobs = self._get('/actions/runs/' + run_id + '/attempts/1/jobs'); rows = jobs.get('jobs')
            if (jobs.get('total_count') != 1 or type(rows) is not list or len(rows) != 1
                    or str(rows[0].get('id')) != c['job_id'] or rows[0].get('name') != 'read_only'
                    or str(rows[0].get('run_id')) != run_id or rows[0].get('head_sha') != commit):
                raise SourceRefused('SOLE_PINNED_JOB_REQUIRED')
            if r.get('provider') != 'github' or r.get('path') != REGISTRY_PATH:
                raise SourceRefused('EXISTING_REGISTRY_LOCATOR_UNBOUND')
            registry_leaves = self._leaves(_pin(r.get('revision'), 40), _pin(registry_tree, 40))
            registry = _object(self._file(registry_leaves, REGISTRY_PATH, _pin(r.get('sha256'))))
            expected_registry = {'schema': 'PAYPROOF_PREEXISTING_REGISTRY_V3',
                'client_id_sha256': _pin(g.get('client_id_sha256')),
                'order_id_sha256': _pin(r.get('order_id_sha256')),
                'canonical_effect_key_sha256': _pin(g.get('canonical_effect_key_sha256')),
                'legacy_refs_sha256': _pin(r.get('legacy_refs_sha256')),
                'legacy_grant_ids': g.get('legacy_grant_ids')}
            if type(expected_registry['legacy_grant_ids']) is not list or any(registry.get(k) != v for k, v in expected_registry.items()):
                raise SourceRefused('REGISTRY_GRANT_REFERENCE_DRIFT')
            provenance = registry.get('provenance', {})
            if provenance.get('provider') != 'paypal' or provenance.get('environment') != 'sandbox':
                raise SourceRefused('PREEXISTING_REGISTRY_PROVENANCE')
            _pin(provenance.get('receipt_sha256'))
            key = digest(canonical(['PayProof', 'sandbox', '1419908202', g['client_id_sha256'],
                                     r['order_id_sha256'], 'orders:read']))
            if key != g['canonical_effect_key_sha256']:
                raise SourceRefused('CANONICAL_EFFECT_KEY_DRIFT')
            self._guard('PRE_RESULT')
            result = PreparedJobPolicySource(True, commit, tree, digest(canonical(actual)),
                                             g['source_sha256'], tuple(self.pins))
        except BaseException as original:
            self.originals.append(original)  # Own the primary before cleanup can fail.
            raise
        finally:
            self.cleanup_once()
        if self.first_unknown is not None:
            raise SourceUnknown('CLEANUP_OR_PRIMARY_UNKNOWN_NO_RESULT')
        return result

    def cleanup_once(self):
        if self.closed:
            return
        self.closed = True
        if self.cleanup is not None:
            try:
                original = self.cleanup(); self.originals.append(original)
            except BaseException as original:
                self.originals.append(original); self.cleanup_errors.append(original)
                self._mark('CLEANUP_EXCEPTION')
        # Always close against the original deadline, even with no callback or
        # an existing primary UNKNOWN. Never let cleanup replace that primary.
        self.ledger.append(('POST_CLEANUP', None))
        try:
            now = self._now()
            if now >= self.deadline:
                self.cleanup_guard_faults.append({'phase': 'POST_CLEANUP', 'type': 'LATE'})
                self._mark('POST_CLEANUP')
        except BaseException as original:
            self.originals.append(original); self.cleanup_errors.append(original)
            self.cleanup_guard_faults.append({'phase': 'POST_CLEANUP', 'type': 'CLOCK_UNKNOWN'})
            self._mark('POST_CLEANUP')

    def export(self):
        return {'classification': 'INCOMPLETE', 'test_only': True, 'calls': self.calls,
                'original_count': len(self.originals), 'clock_original_count': len(self.clock_originals),
                'first_UNKNOWN': self.first_unknown, 'cleanup_errors': len(self.cleanup_errors),
                'cleanup_guard_faults': tuple(dict(row) for row in self.cleanup_guard_faults),
                'closed': self.closed, 'native_source_factory': 'UNBOUND',
                'native_policy_adapter': 'UNBOUND', 'raw_exceptions_exported': False}
