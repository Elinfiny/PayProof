"""Persistent local containment sequencing, not an external transaction/CAS.

Only the explicit synthetic transport is executable in this private candidate.
The native output-custody and containment route is unadmitted and unbound.
"""
import json
import os
from pathlib import Path
import sqlite3
from .deployment10 import canonical10, hash10, require10, validate_custody_ack10


class Lifecycle10:
    def __init__(self, path, scope, run_id):
        self.scope=scope; self.run_id=run_id; self.path=Path(path)
        require10(scope.test_only is True, 'NATIVE_LIFECYCLE_ROUTE_UNBOUND10')
        require10(not self.path.is_symlink() and self.path.parent.is_dir()
                  and not self.path.parent.stat().st_mode & 0o077, 'PRIVATE_LIFECYCLE_PATH10')
        fd=os.open(self.path, os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0), 0o600)
        try:
            import stat
            s=os.fstat(fd)
            require10(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==os.getuid()
                      and stat.S_IMODE(s.st_mode)==0o600, 'LIFECYCLE_FILE10')
        finally: os.close(fd)
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS effects (k TEXT PRIMARY KEY, binding TEXT, state TEXT, result TEXT)')
        self.key=hash10({'route':'PAYPROOF10_NETCUP_DISTINCT_SOURCE','run':run_id,
                         'source':scope.source,'target':scope.target_binding_sha256,
                         'runtime':scope.runtime_sha256,'effect':'receiver_close'})

    def close_after_evidence(self, bridge, ack, hashes):
        from .sandbox_bridge_client10 import BridgeClient153, SyntheticBridgeTransport153
        require10(type(bridge) is BridgeClient153 and bridge.scope == self.scope
                  and bridge.run_id == self.run_id
                  and type(bridge.transport) is SyntheticBridgeTransport153, 'EXACT_SYNTHETIC_CLOSE_PORT10')
        self.scope.require(bridge.clock())
        validate_custody_ack10(self.scope,self.run_id,ack,hashes)
        binding=canonical10({'scope':self.scope.public(),'run_id':self.run_id,'ack':ack})
        with sqlite3.connect(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            try: db.execute('INSERT INTO effects VALUES (?,?,?,?)',(self.key,binding,'INTENT_CONSUMED',''))
            except sqlite3.IntegrityError: raise ValueError('CLOSE_ALREADY_CONSUMED_NO_REPLAY10') from None
        try:
            result=bridge.close_remote(ack)
            require10(result == {'state':'CLOSED_DATA_AND_TOKEN_DROPPED'}, 'CLOSE_READBACK10')
        except BaseException:
            try:
                with sqlite3.connect(self.path) as db:
                    db.execute('UPDATE effects SET state=?,result=? WHERE k=?',('UNKNOWN_NO_REPLAY','First close outcome remains uncertain',self.key))
            except BaseException:
                # The original exception remains primary. The already committed
                # INTENT_CONSUMED also prohibits replay if this update fails.
                self.secondary_error='LEDGER_UPDATE_UNCERTAIN10'
            raise
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE effects SET state=?,result=? WHERE k=?',('APPLIED',canonical10(result),self.key))
        return {'state':'SYNTHETIC_CONTAINMENT_READBACK','effect':self.key,'native_proof':False}

    def observation(self):
        with sqlite3.connect(self.path) as db:
            row=db.execute('SELECT state FROM effects WHERE k=?',(self.key,)).fetchone()
        return {'state':row[0] if row else 'NOT_ATTEMPTED','effect':self.key,
                'external_CAS':False,'native_proof':False}
