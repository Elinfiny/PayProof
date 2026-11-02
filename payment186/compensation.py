"""Once-only cleanup with an acknowledged reservation predating channel loss.

The existing runner is the actuator, not a second executor. Its provider-owned
job log retains only a minimal receipt; original private bytes stay local.
No deferred daemon, extra credential, new endpoint or retry is introduced.
"""
import json,time
from .common import *

OP='subscription_delete'

def scope(engine,ports):
    require(engine.created_subscription and engine.webhook_id,'KNOWN_NEW_ONLY')
    require(re.fullmatch('[A-Z0-9-]{1,64}',engine.webhook_id),'TARGET_ID')
    source=ports.current_source()
    require(source==engine.source and ports.current_caller()==engine.caller,'COMPENSATION_SOURCE')
    path='/v1/notifications/webhooks/'+engine.webhook_id
    metadata={'profile':engine.grant.profile,'app_sha256':engine.grant.app_sha256,
              'source_sha256':source,'caller':ports.current_caller(),
              'target_sha256':sha(path.encode()),'operation':OP,'fake_usd':'1.00',
              'real_usd':'0.00','expires_at':engine.grant.expires_at}
    return path,engine.grant.once_prefix+':'+OP,metadata

def arm(engine,ports):
    if not engine.created_subscription:return None
    path,key,metadata=scope(engine,ports)
    receipt=ports.reserve_and_readback(key,metadata)
    require(ports.matches_receipt(receipt,key,metadata),'COMPENSATION_ACK')
    row={'receipt':receipt,'receipt_sha256':sha(canonical(receipt))}
    write_once(ports.root/'COMPENSATION_ARMED.json',canonical(row))
    return row

def cleanup(engine,ports):
    if not engine.created_subscription:return 'PRESERVED_EXISTING'
    if not engine.webhook_id:return 'UNKNOWN_NO_RETRY'
    attempted=False;status=None;raw=None;record=None
    try:
        path,key,metadata=scope(engine,ports)
        # A reservation that failed to return is never repeated or reconstructed.
        armed=ports.root/'COMPENSATION_ARMED.json'
        if not armed.exists():
            if OP in ports.used:return 'UNKNOWN_NO_RETRY'
            arm(engine,ports)
        private(armed);record=obj(armed.read_bytes())
        receipt=record['receipt']
        require(sha(canonical(receipt))==record['receipt_sha256'] and
                ports.matches_receipt(receipt,key,metadata),'COMPENSATION_BINDING')
        require(OP in ports.used and not engine.used.get(OP),'COMPENSATION_ONCE')
        remaining=min(engine.token_until,engine.grant.expires_at)-time.time()
        require(remaining>0 and bool(engine.token),'COMPENSATION_EXPIRY')
        # Exclusive fsynced local intent and the previous remote consumed slot
        # both precede I/O. GitHub run_attempt=1 is revalidated by scope().
        write_once(ports.root/'COMPENSATION_DELETE_INTENT.json',canonical(record))
        remaining=min(engine.token_until,engine.grant.expires_at)-time.time()
        require(remaining>0,'COMPENSATION_EXPIRED_AFTER_INTENT')
        engine.used[OP]=1;attempted=True
        status,raw=engine.transport.request('DELETE',path,
            {'Authorization':'Bearer '+engine.token,'Content-Type':'application/json'},
            None,min(5,remaining))
        require(type(status) is int and type(raw) is bytes and len(raw)<=1048576,'COMPENSATION_REPLY')
        require(not any(v and v.encode() in raw for v in (engine.client,engine.secret,engine.token)),
                'COMPENSATION_SECRET_EXCLUDED')
        # Full original result survives locally even if remote receipt delivery
        # fails. A successful DELETE is strictly 204 with an empty body.
        write_once(ports.root/'COMPENSATION_HTTP.bin',raw)
        original={'status':status,'bytes':len(raw),'sha256':sha(raw)}
        write_once(ports.root/'COMPENSATION_HTTP.json',canonical(original))
        clean='DELETED_NEW' if status==204 and raw==b'' else 'UNKNOWN_NO_RETRY'
        independent={'schema':'PAYMENT202_COMPENSATION_RECEIPT','state':clean,
                     'grant_sha256':sha(canonical(ports.g)),
                     'reservation_sha256':record['receipt_sha256'],
                     'target_sha256':metadata['target_sha256'],**original}
        write_once(ports.root/'COMPENSATION_RECEIPT.json',canonical(independent))
        # This existing GitHub log channel does not use the Netcup listener.
        # No ID, URL, key, credential, header or response body is printed.
        print(json.dumps(independent,sort_keys=True),flush=True)
        try:ports.retain_result(OP,status,raw,engine.client,engine.secret,engine.token)
        except Exception:pass  # no DELETE retry; independent receipt is retained
        return clean
    except Exception:
        if attempted:
            print(json.dumps({'schema':'PAYMENT202_COMPENSATION_RECEIPT',
                'state':'UNKNOWN_NO_RETRY','grant_sha256':sha(canonical(ports.g)),
                'reservation_sha256':record['receipt_sha256'] if record else None,
                'provider_attempted':True},sort_keys=True),flush=True)
        return 'UNKNOWN_NO_RETRY'
