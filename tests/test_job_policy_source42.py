"""Select only three new cleanup43 methods / six cases; historical42 class inert."""
import sys, os, pathlib, json, hashlib, base64, copy, unittest, signal, importlib.util, sysconfig
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
ATTEMPTS = {'socket': 0, 'subprocess': 0, 'host_file': 0, 'write': 0, 'device': 0}
PRIVATE_IO = []; CACHE_PROBES = []; ORIGINALS = []; CASES = []
STDLIB = pathlib.Path(sysconfig.get_path('stdlib')).resolve()
SOURCES = {ROOT/'payproof/__init__.py', ROOT/'payproof/job_policy_source42.py',
           pathlib.Path(__file__).resolve()}
CACHES = {pathlib.Path(importlib.util.cache_from_source(str(p))) for p in SOURCES}
for p in CACHES:
    try: os.lstat(p)
    except FileNotFoundError: pass
    else: raise AssertionError('CACHE_PRESENT_BEFORE')
def denied(kind):
    ATTEMPTS[kind] += 1
    raise PermissionError('INERT42_AUDIT_REFUSAL')
def audit(event, args):
    if event == 'open' or event.startswith(('socket.', 'subprocess.')):
        PRIVATE_IO.append((event, args))
    if event.startswith('socket.'): denied('socket')
    if event.startswith(('subprocess.', 'os.exec', 'os.spawn', 'os.posix_spawn', 'os.fork')) or event == 'os.system': denied('subprocess')
    if event == 'open':
        path, mode, flags = args
        if isinstance(path, int): denied('host_file')
        p = pathlib.Path(os.fsdecode(path)).resolve()
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND): denied('write')
        if p == pathlib.Path('/dev') or pathlib.Path('/dev') in p.parents: denied('device')
        if p in CACHES:
            try: os.lstat(p)
            except FileNotFoundError:
                CACHE_PROBES.append(hashlib.sha256(os.fsencode(p)).hexdigest()); return
            else: denied('host_file')
        if p in SOURCES or p == STDLIB or STDLIB in p.parents: return
        denied('host_file')
    if event in ['os.remove','os.rename','os.mkdir','os.rmdir','os.chmod','os.symlink','os.link','os.truncate']: denied('write')
signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('CHILD30')))
signal.alarm(30); sys.addaudithook(audit)
from payproof import job_policy_source42 as p

def tree_for(files):
    root = {}; flat = []; blobs = {}
    for name, raw in files.items():
        sha = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        blobs[sha] = {'sha': sha, 'size': len(raw), 'encoding': 'base64',
                      'content': base64.b64encode(raw).decode()}
        parts = name.split('/'); node = root
        for part in parts[:-1]: node = node.setdefault(part, {})
        node[parts[-1]] = (sha, len(raw))
    def visit(node, prefix=''):
        raw = b''
        for name in sorted(node, key=lambda n: (n + ('/' if isinstance(node[n],dict) else '')).encode()):
            value = node[name]
            if isinstance(value, dict):
                sha = visit(value, prefix+name+'/'); mode = '40000'
                flat.append({'path':prefix+name,'type':'tree','mode':'040000','sha':sha})
            else:
                sha, size = value; mode = '100644'
                flat.append({'path':prefix+name,'type':'blob','mode':mode,'sha':sha,'size':size})
            raw += mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(sha)
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    sha = visit(root)
    return sha, {'sha':sha,'truncated':False,'tree':flat}, blobs

class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value

class MemoryAPI:
    def __init__(self, routes, clock):
        self.routes=routes; self.clock=clock; self.calls=[]; self.responses=[]
        self.late=False; self.primary=None; self.override=None
    def request(self, method, url):
        self.calls.append((method,url))
        assert method=='GET' and url.startswith(p.HOST+p.PREFIX)
        if self.primary is not None: raise self.primary
        response = self.override if self.override is not None else p.TestResponse(200,p.canonical(self.routes[url[len(p.HOST+p.PREFIX):]]))
        self.responses.append(response)
        if self.late: self.clock.value=31.0
        return response

def fixture():
    clock=Clock(); files={name:('# PUBLIC_TEST_ONLY_SOURCE42 '+name+'\n').encode() for name in p.PATHS}
    manifest=[{'path':name,'bytes':len(files[name]),'sha256':p.digest(files[name])} for name in p.PATHS]
    workflow=b'name: PUBLIC_TEST_ONLY_INACTIVE\non: workflow_dispatch\njobs: {}\n'
    files[p.WORKFLOW]=workflow; tree, treebody, blobs=tree_for(files)
    client=p.digest(b'PUBLIC_TEST_ONLY_CLIENT'); order=p.digest(b'PUBLIC_TEST_ONLY_EXISTING_ORDER')
    key=p.digest(p.canonical(['PayProof','sandbox','1419908202',client,order,'orders:read']))
    registry={'schema':'PAYPROOF_PREEXISTING_REGISTRY_V3','client_id_sha256':client,
        'order_id_sha256':order,'canonical_effect_key_sha256':key,
        'legacy_refs_sha256':p.digest(p.canonical([])),'legacy_grant_ids':[],
        'provenance':{'provider':'paypal','environment':'sandbox','receipt_sha256':'d'*64}}
    rt, rbody, rblobs=tree_for({p.REGISTRY_PATH:p.canonical(registry)})
    caller={'repository_id':'1419908202','owner_id':'273768139','actor':'Elinfiny','actor_id':'273768139',
        'fork':False,'visibility':'private','attempt':'1','workflow_path':p.WORKFLOW,'workflow_sha256':p.digest(workflow),
        'job_name':'read_only','ref':'refs/heads/main','event':'workflow_dispatch','environment':p.ENVIRONMENT,
        'issuer':'https://token.actions.githubusercontent.com','audience':p.AUDIENCE,'source_commit':'a'*40,
        'source_tree':tree,'run_id':'123','job_id':'456','not_before':1700000000}
    grant={'schema':'PAYPROOF_JOB_NATIVE_CONTEXT_V1','admission_id':'PUBLIC_TEST_ONLY_GRANT42',
        'project':'PayProof','environment':'sandbox','operations':['orders:read'],'external_budget_usd':'0.00',
        'live_ai':False,'expires_at':'2023-11-14T22:17:00+00:00','bundle_manifest':manifest,
        'bundle_sha256':p.digest(p.canonical(manifest)),
        'source_sha256':p.digest(p.canonical([[x['path'].split('/')[-1],x['sha256']] for x in manifest[:5]])),
        'caller':caller,'client_id_sha256':client,'canonical_effect_key_sha256':key,'legacy_grant_ids':[],
        'registry':{'provider':'github','path':p.REGISTRY_PATH,'revision':'c'*40,
            'sha256':p.digest(p.canonical(registry)),'order_id_sha256':order,
            'legacy_refs_sha256':registry['legacy_refs_sha256']}}
    identity={'test_only':True,'sha':'a'*40,'workflow_sha':'a'*40,'run_id':'123','run_attempt':'1',
        'ref':'refs/heads/main','environment':p.ENVIRONMENT,'sub':p.SUBJECT,'iss':caller['issuer'],
        'aud':p.AUDIENCE,'repository':p.REPO,'repository_id':'1419908202','repository_owner_id':'273768139',
        'workflow_ref':p.REPO+'/'+p.WORKFLOW+'@refs/heads/main','event_name':'workflow_dispatch',
        'actor':'Elinfiny','actor_id':'273768139'}
    routes={'':{'id':1419908202,'private':True,'fork':False,'owner':{'id':273768139}},
        '/branches/main':{'commit':{'sha':'a'*40}},
        '/git/commits/'+'a'*40:{'sha':'a'*40,'tree':{'sha':tree}},
        '/git/trees/'+tree+'?recursive=1':treebody,
        '/git/commits/'+'c'*40:{'sha':'c'*40,'tree':{'sha':rt}},
        '/git/trees/'+rt+'?recursive=1':rbody,
        '/actions/runs/123':{'id':123,'run_attempt':1,'head_sha':'a'*40,'event':'workflow_dispatch',
            'actor':{'id':273768139},'head_repository':{'fork':False}},
        '/actions/runs/123/attempts/1/jobs':{'total_count':1,'jobs':[{'id':456,'name':'read_only','run_id':123,'head_sha':'a'*40}]}}
    for sha, body in dict(blobs,**rblobs).items(): routes['/git/blobs/'+sha]=body
    api=MemoryAPI(routes,clock)
    args={'grant_raw':p.canonical(grant),'protected_manifest':p.canonical(manifest),
          'test_identity':identity,'expected_manifest':manifest,'registry_tree':rt,'now':1700000010}
    return api, clock, args, grant

class NewSource42(unittest.TestCase):
    def test01_default_none_and_forged_inputs_before_http(self):
        with self.subTest('default_none'):
            with self.assertRaisesRegex(p.SourceRefused,'PRE_ADMISSION_INPUTS_UNBOUND'): p.collect_native()
            CASES.append('defaultNone_before_HTTP')
        with self.subTest('forged_non_none'):
            with self.assertRaisesRegex(p.SourceRefused,'NATIVE_SOURCE_FACTORY_UNBOUND'):
                p.collect_native(admission={},protected_token='PUBLIC_TEST_ONLY',manifest_delivery={},runtime_identity={},registry={})
            self.assertIsNone(p.NATIVE_SOURCE_FACTORY); self.assertIsNone(p.NATIVE_POLICY_ADAPTER)
            CASES.append('caller_JSON_cannot_bind_native_factory')

    def test02_originals_drift_and_unknown(self):
        with self.subTest('raw_before_parse'):
            api,clock,args,g=fixture(); api.override=p.TestResponse(200,b'{bad-json')
            col=p.PreparedSourceCollector(api,clock=clock)
            with self.assertRaises(p.SourceRefused): col.collect_test(**args)
            self.assertIs(col.originals[0],api.responses[0]); self.assertEqual(len(api.calls),1)
            CASES.append('original_receipt_before_parse_refusal')
        with self.subTest('source_pin'):
            api,clock,args,g=fixture(); api.routes['/branches/main']['commit']['sha']='b'*40
            col=p.PreparedSourceCollector(api,clock=clock)
            with self.assertRaisesRegex(p.SourceRefused,'SOURCE_PIN_DRIFT'): col.collect_test(**args)
            self.assertEqual(len(api.calls),2); CASES.append('source_pin_drift_no_next')
        with self.subTest('status_unknown'):
            api,clock,args,g=fixture(); api.override=p.TestResponse(503,b'PUBLIC_TEST_ONLY')
            col=p.PreparedSourceCollector(api,clock=clock)
            with self.assertRaises(p.SourceUnknown): col.collect_test(**args)
            self.assertEqual(col.first_unknown['phase'],'HTTP_STATUS'); self.assertIs(col.originals[0],api.responses[0])
            self.assertEqual(col.pins,[]); CASES.append('unknown_status_retained_before_parse')

    def test03_structural_test_only_manifest_closure(self):
        with self.subTest('positive_test_only'):
            api,clock,args,g=fixture(); col=p.PreparedSourceCollector(api,clock=clock); result=col.collect_test(**args)
            self.assertTrue(result.structural_test_closure); self.assertTrue(result.test_only)
            self.assertEqual(result.classification,'INCOMPLETE'); self.assertEqual(result.export()['registry_origin'],'UNBOUND')
            self.assertTrue(all(x[0]=='GET' for x in api.calls)); self.assertLessEqual(len(api.calls),64)
            self.assertEqual(result.manifest_sha256,g['bundle_sha256']); CASES.append('TEST_ONLY_positive_complete_source_manifest')
        with self.subTest('wholeblob_drift'):
            api,clock,args,g=fixture()
            blobsha=hashlib.sha1(b'blob '+str(len(('# PUBLIC_TEST_ONLY_SOURCE42 '+p.PATHS[0]+'\n').encode())).encode()+b'\0'+('# PUBLIC_TEST_ONLY_SOURCE42 '+p.PATHS[0]+'\n').encode()).hexdigest()
            api.routes['/git/blobs/'+blobsha]['content']=base64.b64encode(b'PUBLIC_TEST_ONLY_DRIFT').decode()
            with self.assertRaisesRegex(p.SourceRefused,'WHOLE_SOURCE_PIN_DRIFT'):
                p.PreparedSourceCollector(api,clock=clock).collect_test(**args)
            CASES.append('whole_source_byte_pin_drift')
        with self.subTest('fingerprint'):
            api,clock,args,g=fixture(); g['source_sha256']='f'*64; args['grant_raw']=p.canonical(g)
            with self.assertRaisesRegex(p.SourceRefused,'ADMISSION5_FINGERPRINT_DRIFT'):
                p.PreparedSourceCollector(api,clock=clock).collect_test(**args)
            CASES.append('admission5_fingerprint_drift')

    def test04_late_exception_clock_and_no_conversion(self):
        with self.subTest('late_no_next'):
            api,clock,args,g=fixture(); api.late=True; col=p.PreparedSourceCollector(api,clock=clock)
            with self.assertRaises(p.SourceUnknown): col.collect_test(**args)
            self.assertIs(col.originals[0],api.responses[0]); self.assertEqual(col.first_unknown['phase'],'POST_RETURN')
            with self.assertRaises(p.SourceUnknown): col.collect_test(**args)
            self.assertEqual(len(api.calls),1); CASES.append('late_original_no_next_or_replay')
        with self.subTest('primary_cleanup'):
            api,clock,args,g=fixture(); primary=RuntimeError('PRIVATE_PRIMARY42'); cleanup_error=RuntimeError('PRIVATE_CLEANUP42'); api.primary=primary
            def cleanup(): raise cleanup_error
            col=p.PreparedSourceCollector(api,clock=clock,cleanup=cleanup)
            with self.assertRaises(p.SourceUnknown): col.collect_test(**args)
            self.assertIs(col.originals[0],primary); self.assertIs(col.cleanup_errors[0],cleanup_error)
            self.assertEqual(col.first_unknown['phase'],'HTTP_EXCEPTION'); self.assertNotIn('PRIVATE_PRIMARY42',json.dumps(col.export()))
            CASES.append('primary_original_and_cleanup_separate_sticky')
        with self.subTest('invalid_clock_original'):
            api,clock,args,g=fixture(); col=p.PreparedSourceCollector.__new__(p.PreparedSourceCollector)
            with self.assertRaises(p.SourceUnknown): col.__init__(api,clock=lambda:True)
            self.assertIs(col.clock_originals[0],True); self.assertEqual(len(api.calls),0)
            CASES.append('invalid_clock_original_before_guard')
        with self.subTest('no_native_conversion'):
            made=p.PreparedJobPolicySource(True,'a'*40,'b'*40,'c'*64,'d'*64,())
            with self.assertRaisesRegex(p.SourceRefused,'AUTHENTIC_SOURCE_FACTORY_AND_POLICY_ADAPTER_UNBOUND'): p.to_native_policy(made)
            plan=p.official_backend_plan('a'*40,'b'*40,'123'); self.assertEqual(plan['factory'],'UNBOUND')
            self.assertTrue(all(x['method']=='GET' and x['url'].startswith('https://api.github.com/repos/Elinfiny/PayProof') for x in plan['requests']))
            CASES.append('prepared_or_dataclass_never_native_authority')


def fixture43():
    api, clock, args, grant = fixture()
    grant['admission_id'] = 'PUBLIC_TEST_ONLY_GRANT43'
    grant['caller'].update(run_id='843', job_id='943', not_before=1700000005)
    args['test_identity']['run_id'] = '843'; args['now'] = 1700000020
    run = api.routes.pop('/actions/runs/123'); run['id'] = 843
    jobs = api.routes.pop('/actions/runs/123/attempts/1/jobs')
    jobs['jobs'][0].update(id=943, run_id=843)
    api.routes['/actions/runs/843'] = run
    api.routes['/actions/runs/843/attempts/1/jobs'] = jobs
    args['grant_raw'] = p.canonical(grant)
    return api, clock, args, grant

class CleanupClock43(Clock):
    def __init__(self):
        super().__init__(); self.owner = None; self.close_late = False; self.fault = None
    def __call__(self):
        if self.fault is not None: raise self.fault
        if self.close_late and self.owner is not None and self.owner.closed: return 31.0
        return self.value

class NewCleanup43(unittest.TestCase):
    def no_replay(self, col, api, args):
        before = len(api.calls); deadline = col.deadline
        with self.assertRaises(p.SourceUnknown): col.collect_test(**args)
        col.cleanup_once()
        self.assertEqual(len(api.calls), before); self.assertEqual(col.deadline, deadline)
        self.assertTrue(col.closed)

    def test01_late_callback_and_no_callback(self):
        with self.subTest('late_callback_original'):
            api, clock, args, _ = fixture43(); original = object(); calls = []
            def cleanup(): calls.append('once'); clock.value = 31.0; return original
            col = p.PreparedSourceCollector(api, clock=clock, cleanup=cleanup)
            with self.assertRaises(p.SourceUnknown): col.collect_test(**args)
            self.assertIs(col.originals[-1], original)
            self.assertEqual(col.clock_originals[-1], 31.0)
            self.assertEqual(col.first_unknown['phase'], 'POST_CLEANUP')
            self.assertEqual(col.export()['cleanup_guard_faults'][0]['type'], 'LATE')
            self.no_replay(col, api, args); self.assertEqual(calls, ['once'])
            CASES.append('43_late_callback_retained_no_result_no_replay')
        with self.subTest('late_no_callback_unit_close'):
            api, _, args, _ = fixture43(); clock = CleanupClock43(); clock.close_late = True
            col = p.PreparedSourceCollector(api, clock=clock); clock.owner = col
            with self.assertRaises(p.SourceUnknown): col.collect_test(**args)
            self.assertEqual(col.first_unknown['phase'], 'POST_CLEANUP')
            self.assertEqual(col.clock_originals[-1], 31.0)
            self.no_replay(col, api, args)
            CASES.append('43_no_callback_still_POST_CLEANUP')

    def test02_invalid_or_throwing_cleanup_clock_preserves_primary(self):
        with self.subTest('HTTP_primary_invalid_cleanup_clock'):
            api, clock, args, _ = fixture43(); primary = RuntimeError('PRIVATE_HTTP43')
            api.primary = primary; original = object(); calls = []
            def cleanup(): calls.append('once'); clock.value = True; return original
            col = p.PreparedSourceCollector(api, clock=clock, cleanup=cleanup)
            with self.assertRaisesRegex(p.SourceUnknown, 'PROVIDER_RETURN_UNKNOWN'): col.collect_test(**args)
            self.assertIs(col.originals[0], primary); self.assertIn(original, col.originals)
            self.assertIs(col.clock_originals[-1], True)
            self.assertEqual(col.first_unknown['phase'], 'HTTP_EXCEPTION')
            self.assertEqual(col.cleanup_guard_faults, [{'phase':'POST_CLEANUP','type':'CLOCK_UNKNOWN'}])
            self.assertEqual(len(col.cleanup_errors), 1)
            self.assertNotIn('PRIVATE_HTTP43', json.dumps(col.export()))
            self.no_replay(col, api, args); self.assertEqual(calls, ['once'])
            CASES.append('43_HTTP_primary_retained_invalid_cleanup_clock')
        with self.subTest('parse_primary_throwing_cleanup_clock'):
            api, _, args, _ = fixture43(); clock = CleanupClock43()
            api.override = p.TestResponse(200, b'{bad-json43')
            original = object(); clock_error = RuntimeError('PRIVATE_CLOCK43'); calls = []
            def cleanup(): calls.append('once'); clock.fault = clock_error; return original
            col = p.PreparedSourceCollector(api, clock=clock, cleanup=cleanup)
            with self.assertRaisesRegex(p.SourceRefused, 'STRICT_JSON_REQUIRED') as caught: col.collect_test(**args)
            self.assertIs(col.originals[0], api.responses[0]); self.assertIn(caught.exception, col.originals)
            self.assertLess(col.originals.index(caught.exception), col.originals.index(original))
            self.assertIn(clock_error, col.originals); self.assertEqual(len(col.cleanup_errors), 1)
            self.assertEqual(col.first_unknown['phase'], 'CLOCK_EXCEPTION')
            self.assertNotIn('PRIVATE_CLOCK43', json.dumps(col.export()))
            self.no_replay(col, api, args); self.assertEqual(calls, ['once'])
            CASES.append('43_parse_primary_retained_clock_exception_separate')

    def test03_timely_result_and_forged_nonconvertible(self):
        with self.subTest('timely_structural_only'):
            api, clock, args, _ = fixture43(); original = object(); calls = []
            def cleanup(): calls.append('once'); clock.value = 1.0; return original
            col = p.PreparedSourceCollector(api, clock=clock, cleanup=cleanup)
            result = col.collect_test(**args)
            self.assertTrue(result.structural_test_closure); self.assertTrue(result.test_only)
            self.assertEqual(result.classification, 'INCOMPLETE'); self.assertIsNone(col.first_unknown)
            self.assertIs(col.originals[-1], original); self.assertEqual(col.clock_originals[-1], 1.0)
            self.no_replay(col, api, args); self.assertEqual(calls, ['once'])
            CASES.append('43_timely_cleanup_INCOMPLETE_TEST_ONLY')
        with self.subTest('forged_prepared_never_native'):
            forged = p.PreparedJobPolicySource(True, 'e'*40, 'f'*40, '7'*64, '8'*64, ())
            with self.assertRaisesRegex(p.SourceRefused, 'AUTHENTIC_SOURCE_FACTORY_AND_POLICY_ADAPTER_UNBOUND'): p.to_native_policy(forged)
            with self.assertRaisesRegex(p.SourceRefused, 'NATIVE_SOURCE_FACTORY_UNBOUND'):
                p.collect_native(admission=forged, protected_token=object(), manifest_delivery=object(), runtime_identity=object(), registry=object())
            self.assertIsNone(p.NATIVE_SOURCE_FACTORY); self.assertIsNone(p.NATIVE_POLICY_ADAPTER)
            self.assertEqual(forged.classification, 'INCOMPLETE')
            CASES.append('43_forged_prepared_no_native_conversion')

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(NewCleanup43)
    result=unittest.TextTestRunner(stream=sys.stderr,verbosity=2).run(suite)
    for path in CACHES:
        try: os.lstat(path)
        except FileNotFoundError: pass
        else: raise AssertionError('CACHE_PRESENT_AFTER')
    assert not any(ATTEMPTS.values()),'UNEXPECTED_REAL_IO'
    ok=result.wasSuccessful() and result.testsRun==3 and len(CASES)==6
    signal.alarm(0)
    print(json.dumps({'schema':'NEW_POST_CLEANUP43_INERT_GROUP','status':'PASS' if ok else 'FAIL',
        'methods':result.testsRun,'subcases':len(CASES),'cases':CASES,'real_IO_attempts':ATTEMPTS,
        'expected_missing_cache_probes':len(CACHE_PROBES),'native_factory':'UNBOUND','native_adapter':'UNBOUND',
        'TEST_ONLY_positive':'INCOMPLETE_NO_NATIVE_AUTHORITY','old_suites_rerun':False,'private_io_events':len(PRIVATE_IO)},sort_keys=True))
    sys.exit(0 if ok else 1)
