"""Explicit private operator Sandbox read. Unconfigured import performs no work."""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from payproof.admission import (OperatorConfiguration107, OperatorProfile107,
    OperatorSession107, _open_operator_session107, _json)
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
    def reserve(self, key):
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
            try:
                db.execute('INSERT INTO operator_once107 VALUES (?,?)', (key,'ATTEMPTING_NO_RETRY'))
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
        self._used = False

    def _stop(self, cause):
        if self.first_cause is None:self.first_cause = cause
        raise UnknownResult(self.first_cause)

    def transport(self, method, path, headers, body):
        if self.first_cause:self._stop(self.first_cause)
        expected = ('POST','/v1/oauth2/token') if self._phase == 0 else ('GET','/v2/checkout/orders/'+self.context._configuration.order_id)
        if self._phase >= 2 or (method,path) != expected:
            raise InvalidData('OPERATOR_FIXED_ROUTE107')
        try:self.context.require('orders:read')
        except InvalidData:self._stop('WINDOW_OR_SOURCE_UNAVAILABLE107')
        self._phase += 1  # Consume BEFORE call; exception/late result never rearms.
        self.calls += 1
        try:
            value = self._raw_transport(method,path,headers,body) if self._raw_transport else SandboxPayPal._network(self,method,path,headers,body)
        except Exception:
            self._stop('PROVIDER_OUTCOME_UNKNOWN107')
        try:self.context.require('orders:read')
        except InvalidData:self._stop('LATE_OR_SOURCE_CHANGED107')
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
        except Exception:self._stop(self.first_cause or 'INVALID_PROVIDER_RESULT107')

    def close(self):
        self.client_id = self.client_secret = ''
        self._raw_transport = None
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
        'actual_paypal':not reader.context.test_only,'contest_ready':False}

def run_operator107(configuration=None, *, store=None, journal=None, assistance=None):
    session = None;reader = None;primary = None;cleanup = [];receipt = None
    try:
        if type(configuration) is not OperatorConfiguration107 or type(store) is not Store:
            raise InvalidData('OPERATOR_UNCONFIGURED107')
        # Check pre-registration before credential delivery/OAuth.
        order = store.order(configuration.order_id)
        if (order['amount'],order['currency']) != (configuration.amount,configuration.currency):
            raise InvalidData('OPERATOR_EXPECTATION_MISMATCH107')
        session = open_operator107(configuration,journal=journal)
        reader = OperatorOrderReader107(session)
        receipt = reconcile_operator107(store,reader,assistance=assistance)
    except Exception:
        primary = 'OPERATOR_RUN_REFUSED_OR_UNKNOWN107'
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

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('fingerprint')
    sub.add_parser('hosted-preflight')
    run = sub.add_parser('operator-managed')
    run.add_argument('--config',required=True);run.add_argument('--database',required=True)
    run.add_argument('--journal',required=True);run.add_argument('--local-ai',action='store_true')
    args = parser.parse_args()
    if args.command=='fingerprint':print(source_digest107());return 0
    if args.command=='hosted-preflight':
        print(json.dumps({'primary':'MISSING_REVIEWED_EXTERNAL_ONCE_AND_CUSTODY_ADMISSION107','cleanup':[]}));return 2
    if args.command!='operator-managed':
        print(json.dumps({'primary':'OPERATOR_UNCONFIGURED107','cleanup':[]}));return 2
    try:
        with open(args.config,'rb') as stream:raw=stream.read(16385)
        if len(raw)>16384:raise InvalidData('OPERATOR_CONFIG_BOUNDS107')
        cfg=configuration107(_json(raw))
        # An actual existing pre-registered operator database is required.
        if not Path(args.database).is_file():raise InvalidData('OPERATOR_REGISTERED_DATABASE_REQUIRED107')
        result=run_operator107(cfg,store=Store(args.database),journal=OnceJournal107(args.journal),
            assistance=enable_local_assistance() if args.local_ai else None)
    except Exception:result={'primary':'OPERATOR_CONFIGURATION_REFUSED107','cleanup':[],'receipt':None}
    print(json.dumps(result,sort_keys=True));return 0 if result['primary'] is None else 2

if __name__=='__main__':raise SystemExit(main())
