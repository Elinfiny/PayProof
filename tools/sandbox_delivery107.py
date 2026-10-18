"""Explicit private operator Sandbox read. Unconfigured import performs no work."""
import argparse
import copy
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from payproof.admission import (OperatorConfiguration107, OperatorProfile107,
    OperatorSession107, _open_operator_session107, _json, OwnedDispatch108,
    load_owned_dispatch108, WorkflowLaunch109, _WORKFLOW_OWNER109, _WORKFLOW_SYNTHETIC109)
from payproof.core import InvalidData, UnknownResult, Store, canonical, explain
from payproof.paypal import SandboxPayPal, BASE
from payproof.service import annotated_order
from payproof.local_ai_view import enable_local_assistance

SOURCE_PATHS107 = ('payproof/__init__.py','payproof/admission.py','payproof/core.py',
    'payproof/paypal.py','payproof/service.py','payproof/local_ai.py',
    'payproof/local_ai_view.py','payproof/local_ai_training91.json','tools/sandbox_delivery107.py')
ROOT107 = Path(__file__).resolve().parents[1]

def source_digest107():
    rows = [(p, hashlib.sha256((ROOT107/p).read_bytes()).hexdigest()) for p in SOURCE_PATHS107]
    return hashlib.sha256(canonical(rows).encode()).hexdigest()

class OnceJournal107:
    """Operator-owned durable local journal, not a hosted attestation/lease."""
    def __init__(self, path):
        self.path = str(path)
    def reserve(self, key, metadata):
        target = Path(self.path)
        if target.parent.stat().st_mode & 0o022:
            raise InvalidData('OPERATOR_PRIVATE_JOURNAL_DIRECTORY107')
        fd = os.open(target,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            import stat
            info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise InvalidData('OPERATOR_PRIVATE_JOURNAL107')
        finally:os.close(fd)
        with sqlite3.connect(self.path, timeout=2) as db:
            db.execute('CREATE TABLE IF NOT EXISTS operator_once107 (effect_key TEXT PRIMARY KEY, state TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS operator_metadata108 (effect_key TEXT PRIMARY KEY, metadata TEXT NOT NULL)')
            db.execute('BEGIN IMMEDIATE')
            legacy=db.execute('SELECT 1 FROM operator_once107 o LEFT JOIN operator_metadata108 m ON o.effect_key=m.effect_key WHERE m.effect_key IS NULL LIMIT 1').fetchone()
            if legacy:
                raise InvalidData('OPERATOR_LEGACY_JOURNAL_REVIEW_REQUIRED108')
            try:
                db.execute('INSERT INTO operator_once107 VALUES (?,?)', (key,'ATTEMPTING_NO_RETRY'))
                db.execute('INSERT INTO operator_metadata108 VALUES (?,?)',(key,canonical(metadata)))
            except sqlite3.IntegrityError:
                raise InvalidData('OPERATOR_ONCE_CONSUMED107') from None

def open_operator107(configuration=None, *, journal=None):
    """Private terminal only. No ENV, HTTP, JSON authority, native-host claim."""
    if type(configuration) is not OperatorConfiguration107 or type(journal) is not OnceJournal107:
        raise InvalidData('OPERATOR_UNCONFIGURED107')
    if configuration.profile is not OperatorProfile107.OWNER_MANAGED_SANDBOX:
        raise InvalidData('OPERATOR_PROFILE_MIX107')
    # Configuration hashes alone cannot establish which public release is running.
    def git_ref(arg):
        result = subprocess.run(['git','-C',str(ROOT107),'rev-parse',arg],
            capture_output=True,text=True,timeout=3,check=True)
        return result.stdout.strip()
    configuration.validate(source_digest107(), datetime.now(timezone.utc))
    if (git_ref('HEAD') != configuration.source_commit
            or git_ref('HEAD^{tree}') != configuration.source_tree):
        raise InvalidData('OPERATOR_ACTUAL_SOURCE_REF107')
    if not sys.stdin.isatty():
        raise InvalidData('OPERATOR_PRIVATE_TERMINAL_REQUIRED107')
    def private_credentials():
        return (getpass.getpass('Sandbox client ID (private): '),
                getpass.getpass('Sandbox client secret (private): '))
    return _open_operator_session107(configuration, actual_source=source_digest107,
        credential_reader=private_credentials, reserve_once=journal.reserve,
        clock=lambda:datetime.now(timezone.utc), profile=OperatorProfile107.OWNER_MANAGED_SANDBOX)

class OperatorOrderReader107:
    """Compose unchanged SandboxPayPal methods under a distinct explicit profile.

    No inheritance, legacy SandboxContext construction, global patches or host seal.
    All I/O passes the two-call state machine before the existing fixed transport.
    """
    def __init__(self, session, *, fake_transport=None):
        if type(session) is not OperatorSession107:
            raise InvalidData('OPERATOR_SESSION_REQUIRED107')
        session.require('orders:read')
        if session.test_only != (fake_transport is not None):
            raise InvalidData('OPERATOR_SYNTHETIC_TRANSPORT_MIX107')
        self.context = session
        self.client_id, self.client_secret = session._client_id, session._client_secret
        self.webhook_id = None
        self.mode = 'SANDBOX_CONTRACT_TEST' if session.test_only else 'PAYPAL_SANDBOX'
        self._raw_transport = fake_transport
        self._phase = 0
        self.calls = 0
        self.first_cause = None
        self.first_stage = None
        self._private_returns = []
        self._used = False

    def _stop(self, cause, stage='READ'):
        if self.first_cause is None:self.first_cause,self.first_stage = cause,stage
        raise UnknownResult(self.first_cause)

    def transport(self, method, path, headers, body):
        if self.first_cause:self._stop(self.first_cause)
        expected = ('POST','/v1/oauth2/token') if self._phase == 0 else ('GET','/v2/checkout/orders/'+self.context._configuration.order_id)
        if self._phase >= 2 or (method,path) != expected:
            raise InvalidData('OPERATOR_FIXED_ROUTE107')
        try:self.context.require('orders:read')
        except InvalidData as exc:self._stop(sanitized_code108(exc),'PRE_CALL')
        self._phase += 1  # Consume BEFORE call; exception/late result never rearms.
        self.calls += 1
        try:
            value = self._raw_transport(method,path,headers,body) if self._raw_transport else SandboxPayPal._network(self,method,path,headers,body)
        except Exception:
            self._stop('PROVIDER_OUTCOME_UNKNOWN107','OAUTH' if self._phase==1 else 'ORDER')
        # Original parsed provider return remains RAM-private before late guards.
        # OAuth originals/token bytes/hashes are NEVER exported or persisted.
        self._private_returns.append(('OAUTH_RETURN' if self._phase==1 else 'ORDER_RETURN',copy.deepcopy(value)))
        try:
            if len(json.dumps(value,allow_nan=False).encode())>1024*1024:
                self._stop('PROVIDER_RESULT_BOUNDS108','RETURN_CAPTURE')
        except (ValueError,TypeError):self._stop('PROVIDER_RESULT_BOUNDS108','RETURN_CAPTURE')
        try:self.context.require('orders:read')
        except InvalidData as exc:self._stop(sanitized_code108(exc),'POST_RETURN')
        return value

    def _token(self):
        return SandboxPayPal._token(self)

    def request(self, method, path, payload=None, request_id=None):
        if method != 'GET' or path != '/v2/checkout/orders/'+self.context._configuration.order_id or payload is not None or request_id is not None:
            raise InvalidData('OPERATOR_EXACT_READ_ONLY107')
        return SandboxPayPal.request(self,method,path)

    def get_order(self, order_id):
        if order_id != self.context._configuration.order_id:
            raise InvalidData('OPERATOR_REGISTERED_ORDER107')
        if self._used:self._stop(self.first_cause or 'READ_ALREADY_CONSUMED107')
        self._used = True
        try:return SandboxPayPal.get_order(self,order_id)
        except UnknownResult:self._stop(self.first_cause or 'PROVIDER_OUTCOME_UNKNOWN107')
        except InvalidData as exc:self._stop(self.first_cause or sanitized_code108(exc),'VALIDATION')
        except Exception:self._stop(self.first_cause or 'INVALID_PROVIDER_RESULT107','RESULT')

    def close(self):
        self.client_id = self.client_secret = ''
        self._raw_transport = None
        self._private_returns.clear()
        self.context.close()

def reconcile_operator107(store, reader, *, assistance=None):
    if type(store) is not Store or type(reader) is not OperatorOrderReader107:
        raise InvalidData('OPERATOR_CONCRETE_RECONCILIATION107')
    config = reader.context._configuration
    existing = store.order(config.order_id)  # Must already be registered.
    if (existing['amount'],existing['currency']) != (config.amount,config.currency):
        raise InvalidData('OPERATOR_EXPECTATION_MISMATCH107')
    order = store.reconcile(config.order_id, reader.get_order, reader.mode)
    view = annotated_order(order,assistance,reader.context.test_only)
    return {'schema':'PAYPROOF_OPERATOR_RECEIPT107','trust_origin':config.profile.value,
        'host_attestation':False,'synthetic':reader.context.test_only,
        'order_id_sha256':hashlib.sha256(config.order_id.encode()).hexdigest(),
        'state':view['state'],'amount':view['amount'],'currency':view['currency'],
        'explanation':explain(order),'local_assistance':view['local_assistance'],
        'calls':reader.calls,'first_cause':reader.first_cause,'payment_actions':[],
        'first_stage':reader.first_stage,
        'actual_paypal':not reader.context.test_only,'contest_ready':False}

def run_operator107(configuration=None, *, store=None, journal=None, assistance=None):
    session = None;reader = None;primary = None;cleanup = [];receipt = None
    stage='CONFIGURATION'
    try:
        if type(configuration) is not OperatorConfiguration107 or type(store) is not Store:
            raise InvalidData('OPERATOR_UNCONFIGURED107')
        # Check pre-registration before credential delivery/OAuth.
        order = store.order(configuration.order_id)
        if (order['amount'],order['currency']) != (configuration.amount,configuration.currency):
            raise InvalidData('OPERATOR_EXPECTATION_MISMATCH107')
        stage='PRIVATE_TERMINAL';session = open_operator107(configuration,journal=journal)
        reader = OperatorOrderReader107(session)
        stage='RECONCILIATION';receipt = reconcile_operator107(store,reader,assistance=assistance)
        if reader.first_cause:primary={'code':reader.first_cause,'stage':reader.first_stage}
    except Exception as exc:
        primary = sanitized_failure108(exc,stage,reader)
    finally:
        if reader:
            try:reader.close()
            except Exception:cleanup.append('READER_CLOSE107')
        elif session:
            try:session.close()
            except Exception:cleanup.append('SESSION_CLOSE107')
    return {'primary':primary,'cleanup':cleanup,'receipt':receipt}

def configuration107(raw):
    # This parses data only; invocation must still cross the private terminal.
    if type(raw) is not dict:raise InvalidData('OPERATOR_CONFIGURATION_DATA107')
    fields = dict(raw)
    try:
        fields['profile'] = OperatorProfile107(fields['profile'])
        for key in ('not_before','expires_at'):fields[key]=datetime.fromisoformat(fields[key].replace('Z','+00:00'))
        return OperatorConfiguration107(**fields)
    except (ValueError,TypeError,KeyError,AttributeError):
        raise InvalidData('OPERATOR_CONFIGURATION_DATA107') from None

# Only fixed, reviewed codes leave the process; never arbitrary exception text.
_PUBLIC_CODES108=frozenset({
    'OPERATOR_UNCONFIGURED107','OPERATOR_PROFILE_MIX107','OPERATOR_SOURCE_MISMATCH107',
    'OPERATOR_WINDOW_OR_ALLOWANCE107','OPERATOR_MONOTONIC_EXPIRED108',
    'OPERATOR_APPLICATION_MISMATCH107','OPERATOR_CREDENTIAL_INPUT107',
    'OPERATOR_ONCE_CONSUMED107','OPERATOR_EXPECTATION_MISMATCH107',
    'OPERATOR_ACTUAL_SOURCE_REF107','OPERATOR_PRIVATE_TERMINAL_REQUIRED107',
    'OPERATOR_LEGACY_JOURNAL_REVIEW_REQUIRED108','OPERATOR_TYPED_CONFIGURATION107',
    'OPERATOR_READ_ONLY_OR_CLOSED107','OPERATOR_REGISTERED_DATABASE_REQUIRED107',
    'MISSING_OWN_CAS_FIRST_RUN_JOB_ADAPTER108','EXTERNAL_DISPATCH_PROVIDER_BINDING_REQUIRED108',
    'EXTERNAL_DISPATCH_PROFILE_MIX108','EXTERNAL_DISPATCH_RECORD108','EXTERNAL_DISPATCH_CHAIN108',
    'EXTERNAL_DISPATCH_RUN_JOB108','EXTERNAL_DISPATCH_ACTUAL_FIRST_RUN108','EXTERNAL_DISPATCH_CALLER108',
    'EXTERNAL_DISPATCH_ADMISSION108','GITHUB_CALLER_BINDING_MISMATCH108',
    'GITHUB_SOURCE_BINDING_MISMATCH108','GITHUB_STABLE_EFFECT_BINDING108',
    'GITHUB_LINEAGE_BINDING108','PUBLIC_CALLER_CLAIM_REFUSED108',
    'GITHUB_PROTECTED_CREDENTIAL_INPUT108','GITHUB_EXPECTED_WORKFLOW_MISSING108',
    'PROVIDER_OUTCOME_UNKNOWN107','INVALID_PROVIDER_RESULT107','READ_ALREADY_CONSUMED107',
    'PROVIDER_RESULT_BOUNDS108','VALIDATION_REFUSED108'})

def sanitized_code108(exc):
    code=exc.args[0] if type(exc) in (InvalidData,UnknownResult) and len(exc.args)==1 else None
    return code if type(code) is str and code in _PUBLIC_CODES108 else 'VALIDATION_REFUSED108'

def sanitized_failure108(exc,stage,reader=None):
    return {'code':reader.first_cause if reader and reader.first_cause else sanitized_code108(exc),
            'stage':reader.first_stage if reader and reader.first_stage else stage}

def _actual_github108(record):
    # Ordinary GitHub context is configuration, not an attestation; the separate
    # provider-bound OwnedDispatch108 is mandatory even when these values match.
    names={'repository_id':'GITHUB_REPOSITORY_ID','owner_id':'GITHUB_REPOSITORY_OWNER_ID',
        'actor_id':'GITHUB_ACTOR_ID','attempt':'GITHUB_RUN_ATTEMPT','ref':'GITHUB_REF',
        'event':'GITHUB_EVENT_NAME','run_id':'GITHUB_RUN_ID','job_name':'GITHUB_JOB'}
    actual={k:os.environ.get(v) for k,v in names.items()}
    actual['job_id']=record['job_id']  # Actual numeric job was independently bound by the producer.
    def git(arg):return subprocess.run(['git','-C',str(ROOT107),'rev-parse',arg],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    actual.update(source_commit=git('HEAD'),source_tree=git('HEAD^{tree}'),source_sha256=source_digest107())
    actual['workflow_path']='.github/workflows/payproof-sandbox-delivery108.yml'
    workflow=ROOT107/actual['workflow_path']
    if not workflow.is_file():raise InvalidData('GITHUB_EXPECTED_WORKFLOW_MISSING108')
    actual['workflow_sha256']=hashlib.sha256(workflow.read_bytes()).hexdigest()
    return actual

def preflight_github108(configuration=None, *, admission=None, synthetic_actual=None):
    if type(configuration) is not OperatorConfiguration107:
        raise InvalidData('OPERATOR_UNCONFIGURED107')
    if configuration.profile not in (OperatorProfile107.GITHUB_OWNER_MANAGED_SANDBOX,OperatorProfile107.SYNTHETIC_FIXTURE):
        raise InvalidData('OPERATOR_PROFILE_MIX107')
    if admission is None:admission=load_owned_dispatch108() # Missing adapter refuses BEFORE ENV.
    if type(admission) is not OwnedDispatch108:
        raise InvalidData('EXTERNAL_DISPATCH_PROVIDER_BINDING_REQUIRED108')
    synthetic=configuration.profile is OperatorProfile107.SYNTHETIC_FIXTURE
    record=admission.require(synthetic=synthetic)
    if not synthetic and synthetic_actual is not None:
        raise InvalidData('PUBLIC_CALLER_CLAIM_REFUSED108')
    actual=synthetic_actual if synthetic else _actual_github108(record)
    if type(actual) is not dict:raise InvalidData('GITHUB_CALLER_BINDING_MISMATCH108')
    for key in ('repository_id','owner_id','actor_id','attempt','ref','event','run_id','job_id','job_name','workflow_path'):
        if type(actual.get(key)) is not str or actual[key]!=record[key]:raise InvalidData('GITHUB_CALLER_BINDING_MISMATCH108')
    for key in ('source_commit','source_tree','source_sha256','workflow_sha256'):
        if actual.get(key)!=record[key]:raise InvalidData('GITHUB_SOURCE_BINDING_MISMATCH108')
    if any(getattr(configuration,k)!=record[k] for k in ('source_commit','source_tree','source_sha256')):
        raise InvalidData('GITHUB_SOURCE_BINDING_MISMATCH108')
    key=hashlib.sha256(canonical(['PayProof','sandbox','orders:read',configuration.client_id_sha256,configuration.order_id]).encode()).hexdigest()
    if key!=record['stable_effect_key']:raise InvalidData('GITHUB_STABLE_EFFECT_BINDING108')
    if configuration.order_lineage_sha256!=record['registered_lineage_sha256']:raise InvalidData('GITHUB_LINEAGE_BINDING108')
    attached={'client_id_sha256':configuration.client_id_sha256,
        'order_id_sha256':hashlib.sha256(configuration.order_id.encode()).hexdigest(),
        'expected_amount':configuration.amount,'expected_currency':configuration.currency,
        'operator_allocation':configuration.operator_allocation,'credential_provenance':configuration.credential_provenance}
    if any(record[k]!=v for k,v in attached.items()):raise InvalidData('GITHUB_LINEAGE_BINDING108')
    return admission

def open_github_operator108(configuration=None, *, journal=None, admission=None,
        synthetic_actual=None, fake_credential_reader=None, clock=None, monotonic=None):
    admission=preflight_github108(configuration,admission=admission,synthetic_actual=synthetic_actual)
    synthetic=admission.test_only
    if type(journal) is not OnceJournal107:raise InvalidData('OPERATOR_UNCONFIGURED107')
    if not synthetic and (fake_credential_reader is not None or clock is not None or monotonic is not None):
        raise InvalidData('GITHUB_PROTECTED_CREDENTIAL_INPUT108')
    def protected_pair():
        # Exactly two credential reads, only after complete preflight and local
        # durable reserve in _open. No job-wide secret mapping or token output.
        return (os.environ.get('PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID'),
                os.environ.get('PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET'))
    if synthetic and fake_credential_reader is None:raise InvalidData('GITHUB_PROTECTED_CREDENTIAL_INPUT108')
    return _open_operator_session107(configuration,actual_source=source_digest107,
        credential_reader=fake_credential_reader if synthetic else protected_pair,
        reserve_once=journal.reserve,clock=clock or (lambda:datetime.now(timezone.utc)),
        profile=configuration.profile,monotonic=monotonic or time.monotonic)

def run_github_operator108(configuration=None, *, store=None, journal=None, admission=None,
        synthetic_actual=None, fake_credential_reader=None, fake_transport=None,
        clock=None,monotonic=None,assistance=None):
    session=None;reader=None;primary=None;cleanup=[];receipt=None;stage='CONFIGURATION'
    try:
        if type(configuration) is not OperatorConfiguration107 or type(store) is not Store:
            raise InvalidData('OPERATOR_UNCONFIGURED107')
        row=store.order(configuration.order_id)
        if (row['amount'],row['currency'])!=(configuration.amount,configuration.currency):
            raise InvalidData('OPERATOR_EXPECTATION_MISMATCH107')
        stage='EXTERNAL_ONCE_SOURCE_CALLER_PREFLIGHT'
        session=open_github_operator108(configuration,journal=journal,admission=admission,
            synthetic_actual=synthetic_actual,fake_credential_reader=fake_credential_reader,clock=clock,monotonic=monotonic)
        stage='READER';reader=OperatorOrderReader107(session,fake_transport=fake_transport)
        stage='RECONCILIATION';receipt=reconcile_operator107(store,reader,assistance=assistance)
        if reader.first_cause:primary={'code':reader.first_cause,'stage':reader.first_stage}
    except Exception as exc:primary=sanitized_failure108(exc,stage,reader)
    finally:
        if reader:
            try:reader.close()
            except Exception:cleanup.append('READER_CLOSE108')
        elif session:
            try:session.close()
            except Exception:cleanup.append('SESSION_CLOSE108')
    return {'primary':primary,'cleanup':cleanup,'receipt':receipt,
        'lifecycle':{'session_closed':session._closed if session else None,
            'private_returns_released':not reader._private_returns if reader else None,
            'reader_credentials_dropped':reader.client_id==reader.client_secret=='' if reader else None}}

_PUBLIC_CODES108 |= frozenset({'WORKFLOW_PRIVATE_LAUNCH_REQUIRED109','WORKFLOW_PROFILE_MIX109',
    'WORKFLOW_CONFIGURATION_MIX109','WORKFLOW_ADMISSION_SHAPE109','WORKFLOW_ADMISSION_BOUNDS109',
    'WORKFLOW_CALLER_MISMATCH109','WORKFLOW_SOURCE_MISMATCH109','WORKFLOW_OPERATION_MISMATCH109',
    'WORKFLOW_WINDOW_MISMATCH109','WORKFLOW_ACTUAL_RUN_REQUIRED109','WORKFLOW_ENVIRONMENT_MISSING109',
    'WORKFLOW_SOURCE_FILE_MISSING109','WORKFLOW_ENVELOPE_SHAPE109'})

_WORKFLOW_PUBLIC_KEYS109=frozenset({'schema','profile','admission_id','intent_version',
    'consumed_version','intent_sha256','consumed_sha256','stable_effect_key',
    'repository','repository_id','owner_id','actor_id','ref','event','attempt','job_slug',
    'source_commit','source_tree','source_sha256','workflow_path','workflow_sha256',
    'client_id_sha256','order_id_sha256','amount','currency','order_lineage_sha256',
    'operator_allocation','credential_provenance','not_before','expires_at','call_budget','cash_usd'})
_WORKFLOW_FIXED109={'repository':'Elinfiny/PayProof','repository_id':'1419908202',
    'owner_id':'273768139','actor_id':'273768139','ref':'refs/heads/main',
    'event':'workflow_dispatch','attempt':'1','job_slug':'sandbox_read',
    'workflow_path':'.github/workflows/payproof-sandbox-delivery108.yml'}

def _provider_process_context109():
    # Explicit provider context fields only. Never serialize github context/token.
    # Matching ENV is consistency, not independent proof of provider execution.
    fields={'repository':'GITHUB_REPOSITORY','repository_id':'GITHUB_REPOSITORY_ID',
        'owner_id':'PAYPROOF_OWNER_ID109','actor_id':'GITHUB_ACTOR_ID','ref':'GITHUB_REF',
        'event':'GITHUB_EVENT_NAME','attempt':'GITHUB_RUN_ATTEMPT','job_slug':'GITHUB_JOB',
        'run_id':'GITHUB_RUN_ID','github_sha':'GITHUB_SHA',
        'workflow_ref':'PAYPROOF_WORKFLOW_REF109','workflow_source_sha':'PAYPROOF_WORKFLOW_SHA109'}
    actual={k:os.environ.get(v) for k,v in fields.items()}
    def git(ref):return subprocess.run(['git','-C',str(ROOT107),'rev-parse',ref],capture_output=True,text=True,timeout=3,check=True).stdout.strip()
    actual.update(source_commit=git('HEAD'),source_tree=git('HEAD^{tree}'),source_sha256=source_digest107())
    actual['workflow_path']=_WORKFLOW_FIXED109['workflow_path']
    path=ROOT107/actual['workflow_path']
    if not path.is_file():raise InvalidData('WORKFLOW_SOURCE_FILE_MISSING109')
    actual['workflow_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    return actual

def _validate_workflow109(configuration,admission,actual):
    if type(configuration) is not OperatorConfiguration107:raise InvalidData('OPERATOR_UNCONFIGURED107')
    if type(admission) is not dict or set(admission)!=_WORKFLOW_PUBLIC_KEYS109:
        raise InvalidData('WORKFLOW_ADMISSION_SHAPE109')
    if len(canonical(admission).encode())>8192:raise InvalidData('WORKFLOW_ADMISSION_BOUNDS109')
    if admission['schema']!='PAYPROOF_PROVIDER_OWNER_WORKFLOW109' or admission['profile']!='GITHUB_OWNER_WORKFLOW109':
        raise InvalidData('WORKFLOW_PROFILE_MIX109')
    import re
    string_keys=_WORKFLOW_PUBLIC_KEYS109-{'intent_version','consumed_version','call_budget'}
    if any(type(admission[k]) is not str or not 0<len(admission[k])<=256 for k in string_keys):
        raise InvalidData('WORKFLOW_ADMISSION_BOUNDS109')
    for k in ('intent_version','consumed_version','call_budget'):
        if type(admission[k]) is not int:raise InvalidData('WORKFLOW_ADMISSION_BOUNDS109')
    if (not 0<=admission['intent_version']<10**9 or admission['consumed_version']!=admission['intent_version']+1
            or admission['call_budget']!=2 or admission['cash_usd']!='0.00'
            or not re.fullmatch('[A-Za-z0-9_-]{1,128}',admission['admission_id'])):
        raise InvalidData('WORKFLOW_ADMISSION_BOUNDS109')
    for k in ('intent_sha256','consumed_sha256','stable_effect_key','source_sha256','workflow_sha256','client_id_sha256','order_id_sha256','order_lineage_sha256'):
        if not re.fullmatch('[a-f0-9]{64}',admission[k]):raise InvalidData('WORKFLOW_ADMISSION_BOUNDS109')
    for k in ('source_commit','source_tree'):
        if not re.fullmatch('[a-f0-9]{40}',admission[k]):raise InvalidData('WORKFLOW_ADMISSION_BOUNDS109')
    # Public external-CAS identifiers are descriptive consistency data. The
    # sender's actual CAS controls its own dispatch; this runtime does not verify
    # private Library bytes or turn public hashes into an authority.
    expected_actual_keys=set(_WORKFLOW_FIXED109)|{'run_id','github_sha','workflow_ref',
        'workflow_source_sha','source_commit','source_tree','source_sha256','workflow_sha256'}
    if type(actual) is not dict or set(actual)!=expected_actual_keys:
        raise InvalidData('WORKFLOW_CALLER_MISMATCH109')
    if any(type(actual[k]) is not str or not 0<len(actual[k])<=256 for k in actual):
        raise InvalidData('WORKFLOW_CALLER_MISMATCH109')
    if any(admission[k]!=v or actual[k]!=v for k,v in _WORKFLOW_FIXED109.items()):
        raise InvalidData('WORKFLOW_CALLER_MISMATCH109')
    if not re.fullmatch('[1-9][0-9]{0,19}',actual['run_id']):raise InvalidData('WORKFLOW_ACTUAL_RUN_REQUIRED109')
    expected_workflow_ref='Elinfiny/PayProof/'+_WORKFLOW_FIXED109['workflow_path']+'@refs/heads/main'
    if (actual['workflow_ref']!=expected_workflow_ref or actual['github_sha']!=admission['source_commit']
            or actual['workflow_source_sha']!=admission['source_commit']):
        raise InvalidData('WORKFLOW_SOURCE_MISMATCH109')
    for key in ('source_commit','source_tree','source_sha256','workflow_sha256'):
        if actual[key]!=admission[key]:raise InvalidData('WORKFLOW_SOURCE_MISMATCH109')
    if any(getattr(configuration,k)!=admission[k] for k in ('source_commit','source_tree','source_sha256','client_id_sha256','amount','currency','order_lineage_sha256','operator_allocation','credential_provenance')):
        raise InvalidData('WORKFLOW_OPERATION_MISMATCH109')
    stable=hashlib.sha256(canonical(['PayProof','sandbox','orders:read',configuration.client_id_sha256,configuration.order_id]).encode()).hexdigest()
    if stable!=admission['stable_effect_key'] or hashlib.sha256(configuration.order_id.encode()).hexdigest()!=admission['order_id_sha256']:
        raise InvalidData('WORKFLOW_OPERATION_MISMATCH109')
    if admission['not_before']!=configuration.not_before.isoformat() or admission['expires_at']!=configuration.expires_at.isoformat():
        raise InvalidData('WORKFLOW_WINDOW_MISMATCH109')
    configuration.validate(source_digest107(),datetime.now(timezone.utc))

def _synthetic_workflow_launch109(configuration,admission,actual):
    # Inert helper ALWAYS test-sealed; it cannot satisfy the real109 profile.
    if type(configuration) is not OperatorConfiguration107 or configuration.profile is not OperatorProfile107.SYNTHETIC_FIXTURE:
        raise InvalidData('WORKFLOW_PROFILE_MIX109')
    _validate_workflow109(configuration,admission,actual)
    return WorkflowLaunch109(configuration,canonical(admission).encode(),canonical(actual).encode(),_WORKFLOW_SYNTHETIC109)

def preflight_owner_workflow109(configuration=None,admission=None,*,launch=None):
    if type(configuration) is not OperatorConfiguration107:raise InvalidData('OPERATOR_UNCONFIGURED107')
    if launch is not None:
        if type(launch) is not WorkflowLaunch109:raise InvalidData('WORKFLOW_PRIVATE_LAUNCH_REQUIRED109')
        record,actual=launch.require(configuration)
        if record!=admission:raise InvalidData('WORKFLOW_CONFIGURATION_MIX109')
        _validate_workflow109(configuration,record,actual);return launch
    if configuration.profile is not OperatorProfile107.GITHUB_OWNER_WORKFLOW109:
        raise InvalidData('WORKFLOW_PRIVATE_LAUNCH_REQUIRED109')
    # Explicitly selected, reviewed operator-owned workflow process. No old
    # OwnedDispatch108 loader, native seal, broker, signing service or numeric job.
    actual=_provider_process_context109()
    _validate_workflow109(configuration,admission,actual)
    return WorkflowLaunch109(configuration,canonical(admission).encode(),canonical(actual).encode(),_WORKFLOW_OWNER109)

def open_owner_workflow109(configuration=None,admission=None,*,journal=None,launch=None,
        fake_credential_reader=None,clock=None,monotonic=None):
    launch=preflight_owner_workflow109(configuration,admission,launch=launch)
    if type(journal) is not OnceJournal107:raise InvalidData('OPERATOR_UNCONFIGURED107')
    if not launch.test_only and any(x is not None for x in (fake_credential_reader,clock,monotonic)):
        raise InvalidData('WORKFLOW_PROFILE_MIX109')
    if launch.test_only and fake_credential_reader is None:raise InvalidData('WORKFLOW_PRIVATE_LAUNCH_REQUIRED109')
    def protected_pair():
        return (os.environ.get('PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID'),os.environ.get('PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET'))
    session=_open_operator_session107(configuration,actual_source=source_digest107,
        credential_reader=fake_credential_reader if launch.test_only else protected_pair,
        reserve_once=journal.reserve,clock=clock or (lambda:datetime.now(timezone.utc)),
        profile=configuration.profile,monotonic=monotonic or time.monotonic)
    return session,launch

def run_owner_workflow109(configuration=None,admission=None,*,store=None,journal=None,
        launch=None,fake_credential_reader=None,fake_transport=None,clock=None,monotonic=None,
        assistance=None):
    session=None;reader=None;primary=None;cleanup=[];receipt=None;stage='WORKFLOW_PREFLIGHT'
    try:
        if type(configuration) is not OperatorConfiguration107 or type(store) is not Store:raise InvalidData('OPERATOR_UNCONFIGURED107')
        row=store.order(configuration.order_id)
        if (row['amount'],row['currency'])!=(configuration.amount,configuration.currency):raise InvalidData('OPERATOR_EXPECTATION_MISMATCH107')
        session,launch=open_owner_workflow109(configuration,admission,journal=journal,launch=launch,
            fake_credential_reader=fake_credential_reader,clock=clock,monotonic=monotonic)
        stage='WORKFLOW_READ';reader=OperatorOrderReader107(session,fake_transport=fake_transport)
        receipt=reconcile_operator107(store,reader,assistance=assistance)
        if reader.first_cause:primary={'code':reader.first_cause,'stage':reader.first_stage}
        _,actual=launch.require(configuration)
        receipt['workflow109']={'trust_origin':launch.trust_origin,'run_id':actual['run_id'],
            'job_slug':actual['job_slug'],'numeric_job_id':None,
            'numeric_job_id_status':'POST_RUN_CANONICAL_READBACK',
            'provider_execution_independently_verified':False}
    except Exception as exc:primary=sanitized_failure108(exc,stage,reader)
    finally:
        if reader:
            try:reader.close()
            except Exception:cleanup.append('READER_CLOSE109')
        elif session:
            try:session.close()
            except Exception:cleanup.append('SESSION_CLOSE109')
    return {'primary':primary,'cleanup':cleanup,'receipt':receipt,
        'lifecycle':{'session_closed':session._closed if session else None,
            'private_returns_released':not reader._private_returns if reader else None,
            'reader_credentials_dropped':reader.client_id==reader.client_secret=='' if reader else None}}

def workflow_envelope109(raw):
    if type(raw) is not dict or set(raw)!={'configuration','admission'}:raise InvalidData('WORKFLOW_ENVELOPE_SHAPE109')
    if len(canonical(raw).encode())>16384:raise InvalidData('WORKFLOW_ADMISSION_BOUNDS109')
    return configuration107(raw['configuration']),raw['admission']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('fingerprint')
    hosted=sub.add_parser('hosted-preflight');hosted.add_argument('--config',required=True)
    cloud=sub.add_parser('github-owner-managed');cloud.add_argument('--config',required=True)
    cloud.add_argument('--database',required=True);cloud.add_argument('--journal',required=True)
    cloud.add_argument('--local-ai',action='store_true')
    for command in ('owner-workflow-preflight109','github-owner-workflow109'):
        cmd=sub.add_parser(command);cmd.add_argument('--envelope',required=True)
        if command=='github-owner-workflow109':
            cmd.add_argument('--database',required=True);cmd.add_argument('--journal',required=True);cmd.add_argument('--local-ai',action='store_true')
    run = sub.add_parser('operator-managed')
    run.add_argument('--config',required=True);run.add_argument('--database',required=True)
    run.add_argument('--journal',required=True);run.add_argument('--local-ai',action='store_true')
    args = parser.parse_args()
    if args.command=='fingerprint':print(source_digest107());return 0
    if args.command in ('owner-workflow-preflight109','github-owner-workflow109'):
        try:
            with open(args.envelope,'rb') as stream:raw=stream.read(16385)
            if len(raw)>16384:raise InvalidData('WORKFLOW_ADMISSION_BOUNDS109')
            cfg,admission=workflow_envelope109(_json(raw))
            if args.command=='owner-workflow-preflight109':
                preflight_owner_workflow109(cfg,admission);result={'primary':None,'cleanup':[],'stage':'PUBLIC_PREFLIGHT109'}
            else:
                if not Path(args.database).is_file():raise InvalidData('OPERATOR_REGISTERED_DATABASE_REQUIRED107')
                result=run_owner_workflow109(cfg,admission,store=Store(args.database),journal=OnceJournal107(args.journal),
                    assistance=enable_local_assistance() if args.local_ai else None)
        except Exception as exc:result={'primary':sanitized_failure108(exc,'WORKFLOW_ENTRY109'),'cleanup':[],'receipt':None}
        print(json.dumps(result,sort_keys=True));return 0 if result['primary'] is None else 2
    if args.command in ('hosted-preflight','github-owner-managed'):
        try:
            with open(args.config,'rb') as stream:raw=stream.read(16385)
            if len(raw)>16384:raise InvalidData('OPERATOR_CONFIG_BOUNDS107')
            cfg=configuration107(_json(raw))
            if args.command=='hosted-preflight':
                preflight_github108(cfg);result={'primary':None,'cleanup':[],'stage':'PREFLIGHT'}
            else:
                if not Path(args.database).is_file():raise InvalidData('OPERATOR_REGISTERED_DATABASE_REQUIRED107')
                result=run_github_operator108(cfg,store=Store(args.database),journal=OnceJournal107(args.journal),
                    assistance=enable_local_assistance() if args.local_ai else None)
        except Exception as exc:result={'primary':sanitized_failure108(exc,'CLOUD_ENTRY'),'cleanup':[],'receipt':None}
        print(json.dumps(result,sort_keys=True));return 0 if result['primary'] is None else 2
    if args.command!='operator-managed':
        print(json.dumps({'primary':{'code':'OPERATOR_UNCONFIGURED107','stage':'CONFIGURATION'},'cleanup':[]}));return 2
    try:
        with open(args.config,'rb') as stream:raw=stream.read(16385)
        if len(raw)>16384:raise InvalidData('OPERATOR_CONFIG_BOUNDS107')
        cfg=configuration107(_json(raw))
        # An actual existing pre-registered operator database is required.
        if not Path(args.database).is_file():raise InvalidData('OPERATOR_REGISTERED_DATABASE_REQUIRED107')
        result=run_operator107(cfg,store=Store(args.database),journal=OnceJournal107(args.journal),
            assistance=enable_local_assistance() if args.local_ai else None)
    except Exception as exc:result={'primary':sanitized_failure108(exc,'CONFIGURATION'),'cleanup':[],'receipt':None}
    print(json.dumps(result,sort_keys=True));return 0 if result['primary'] is None else 2

if __name__=='__main__':raise SystemExit(main())
