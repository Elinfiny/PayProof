"""Netcup-specific custody/identity/readiness barrier; no authority issuer."""
import re
from .deployment10 import (SERVER_ID10, ROUTE10, origin10, hex10, finite10,
                           require10, hash10)

MASTER10 = 'MASTER61_PRIVATE_CONTROL_REFERENCE'
ADMISSION10 = 'OWNER_NETCUP_PAYPROOF151_20261102'


def inspect_readiness10(w, identity, ready, scope, now):
    require10(all(type(v) is dict for v in (w, identity, ready, scope)), 'GATE_OBJECTS10')
    require10(finite10(now), 'CLOCK10')
    cp = w.get('master_checkpoint')
    require10(type(cp) is dict and set(cp) == {'stable_id', 'version', 'raw_sha256', 'self_sha256'}, 'MASTER_FIELDS10')
    require10(cp['stable_id'] == MASTER10 and type(cp['version']) is int and cp['version'] >= 16
              and hex10(cp['raw_sha256']) and hex10(cp['self_sha256']), 'MASTER_CUSTODY10')
    require10(w.get('schema') == 'PAYPROOF_MASTER_EXTERNAL_BATCH10'
              and w.get('state') == 'CONSUMED' and w.get('identity') == identity
              and w.get('candidate_route10') == ROUTE10
              and w.get('independent_admission') == ADMISSION10, 'NEW_ROUTE_NOT_OLD_ADMISSION10')
    require10(isinstance(w.get('once_prefix'), str)
              and re.fullmatch('P151-NC10-[A-Z0-9-]{1,14}', w['once_prefix']) is not None,
              'DISTINCT_ONCE_NAMESPACE_NOT_BUDGET10')
    require10(hex10(identity.get('head'), 40) and hex10(identity.get('tree'), 40)
              and type(identity.get('attempt')) is int and identity['attempt'] == 1
              and isinstance(identity.get('run_id'), str)
              and re.fullmatch('[1-9][0-9]{0,19}', identity['run_id']) is not None, 'WORKER_IDENTITY10')
    keys = {'source', 'session', 'app_sha256', 'origin', 'service_id', 'expires_at',
            'target_binding_sha256', 'runtime_sha256'}
    require10(set(scope) == keys and scope['source'] == identity['head']
              and scope['app_sha256'] == w.get('app_sha256'), 'SOURCE_SCOPE10')
    origin10(scope['origin'])
    require10(isinstance(scope['service_id'], str)
              and re.fullmatch('nc-932863-[a-z0-9]{8,32}', scope['service_id']) is not None
              and isinstance(scope['session'], str)
              and re.fullmatch('PNC10-[A-Z0-9-]{1,24}', scope['session']) is not None, 'SELFHOSTED_NAMESPACE10')
    require10(all(hex10(scope[k]) for k in ('app_sha256', 'target_binding_sha256', 'runtime_sha256')), 'SCOPE_DIGEST10')
    cfg = w.get('bridge10')
    require10(type(cfg) is dict and all(cfg.get(k) == v for k,v in scope.items()), 'WITNESS_SCOPE10')
    nb = w.get('not_before'); ex = w.get('expires_at'); issued = cfg.get('issued_at')
    require10(all(finite10(v) for v in (issued, nb, ex))
              and issued <= nb <= now < ex == scope['expires_at']
              and 0 < ex-issued <= 600, 'EXPIRY10')
    require10(w.get('listener_url') == scope['origin'] + '/webhooks/payproof151'
              and cfg.get('buyer_preflight') == 'OWNER_SANDBOX_BUYER_AND_ADMITTED_BROWSER_ROUTE_READY', 'LISTENER_BUYER10')
    expected = dict(scope, issued_at=issued, bound=True, webhook_ready=False,
                    order_ready=False, run_id=identity.get('run_id'))
    require10(ready == expected and all(type(ready[k]) is bool for k in ('bound','webhook_ready','order_ready')), 'BOUND_READY10')
    rb = w.get('target_readback10')
    fields = {'server_id', 'origin', 'service_id', 'source', 'runtime_sha256',
              'guest_control_original_sha256', 'host_key_pin_sha256', 'tls_certificate_sha256',
              'observed_at', 'transport', 'cost', 'private_backend'}
    require10(type(rb) is dict and set(rb) == fields, 'TARGET_READBACK_FIELDS10')
    require10(rb['server_id'] == SERVER_ID10
              and all(rb[k] == scope[k] for k in ('origin','service_id','source','runtime_sha256'))
              and hash10(rb) == scope['target_binding_sha256'], 'ACTUAL_TARGET_BINDING10')
    require10(all(hex10(rb[k]) for k in ('guest_control_original_sha256','host_key_pin_sha256','tls_certificate_sha256'))
              and finite10(rb['observed_at']) and issued <= rb['observed_at'] <= nb
              and rb['transport'] == 'DIRECT_TLS443'
              and rb['cost'] == 'TOTAL_INCREMENTAL_ZERO_PROVEN'
              and rb['private_backend'] is True, 'CONTROL_TLS_COST10')
    return {'state': 'CONSISTENT_PRIVATE_CANDIDATE_NOT_AUTHORIZATION', 'route': ROUTE10,
            'server_id': SERVER_ID10, 'run_id': identity.get('run_id'),
            'target_authentication': 'MUST_EXIST_ON_LEGITIMATELY_ADMITTED_ORIGINAL_CONTROL_ROUTE',
            'native_admission': 'NOT_GRANTED'}
