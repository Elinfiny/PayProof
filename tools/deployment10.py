"""Self-hosted source/target preparation. No install, SSH, secret or native port.

Provider-origin/readback authentication must be established on the existing
admitted control route. JSON and this consistency code cannot establish it.
"""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from urllib.parse import urlsplit

SERVER_ID10 = '932863'
ROUTE10 = 'PAYPROOF10_NETCUP_DISTINCT_SOURCE'
NATIVE10_ENABLED = False


def canonical10(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def hash10(value):
    return hashlib.sha256(canonical10(value).encode()).hexdigest()


def require10(ok, code):
    if not ok:
        raise ValueError(code)


def hex10(v, n=64):
    return isinstance(v, str) and re.fullmatch('[a-f0-9]{%d}' % n, v) is not None


def finite10(v):
    return type(v) in (int, float) and math.isfinite(v)


def origin10(value):
    try:
        u = urlsplit(value)
        host = u.hostname
        good = (u.scheme == 'https' and isinstance(host, str) and u.netloc == host
                and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', host)
                and not host.endswith('.onrender.com') and host != 'onrender.com'
                and not re.fullmatch(r'[0-9.]+', host)
                and not (u.path or u.query or u.fragment))
    except (ValueError, TypeError, AttributeError):
        good = False
    require10(good, 'SELFHOSTED_EXACT_HTTPS_ORIGIN10')
    return value


def validate_source_manifest10(rows):
    require10(type(rows) is list and 0 < len(rows) <= 256, 'MANIFEST_COUNT10')
    seen = set()
    for row in rows:
        require10(type(row) is dict and set(row) == {'path', 'size', 'sha256'}, 'MANIFEST_ROW10')
        name = row['path']
        require10(isinstance(name, str) and '\\' not in name and '\x00' not in name, 'SOURCE_PATH10')
        path = PurePosixPath(name)
        require10(not path.is_absolute() and name == path.as_posix()
                  and not any(p in ('..', '.') for p in path.parts)
                  and name not in seen and path.parts, 'SOURCE_PATH10')
        require10(type(row['size']) is int and 0 <= row['size'] <= 2_000_000
                  and hex10(row['sha256']), 'SOURCE_PIN10')
        seen.add(name)
    return hash10(sorted(rows, key=lambda r: r['path']))


def verify_staging10(root, rows):
    """Read-only exact source staging, not an installation/admission receipt."""
    expected = validate_source_manifest10(rows)
    root = Path(root)
    require10(not root.is_symlink() and root.is_dir(), 'STAGE_ROOT10')
    actual = []
    for row in rows:
        p = root
        for part in PurePosixPath(row['path']).parts:
            p = p / part
            require10(not p.is_symlink(), 'STAGE_SYMLINK10')
        s = p.lstat()
        require10(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'STAGE_REGULAR10')
        raw = p.read_bytes()
        require10(len(raw) == row['size'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'STAGE_BYTES10')
        actual.append(row['path'])
    observed = []
    for p in root.rglob('*'):
        require10(not p.is_symlink(), 'STAGE_SYMLINK10')
        if p.is_file(): observed.append(p.relative_to(root).as_posix())
    require10(set(observed) == set(actual), 'UNMANIFESTED_SOURCE10')
    return {'source_manifest_sha256': expected, 'files': len(actual), 'state': 'SOURCE_ONLY_NOT_INSTALLATION'}


def deployment_plan10(source_rows, target):
    """Complete proposed target envelope; missing real facts remain explicit."""
    digest = validate_source_manifest10(source_rows)
    require10(type(target) is dict and target.get('server_id') == SERVER_ID10, 'OWNED_TARGET_SELECTION10')
    needed = ('guest_control_receipt', 'host_key_pin', 'origin', 'tls_custody_receipt',
              'runtime_provenance', 'current_target_version', 'cost_receipt', 'private_output_custody')
    gaps = [k for k in needed if target.get(k) is None]
    if target.get('origin') is not None: origin10(target['origin'])
    return {'route': ROUTE10, 'server_id': SERVER_ID10,
            'decision': 'ADAPT_EXISTING_NETCUP_SOURCE_ONLY', 'source_manifest_sha256': digest,
            'native_admission': 'NONE', 'native_ready': False,
            'missing_actual_evidence': gaps,
            'transport': 'DIRECT_TLS443_NO_HEADER_OR_PROXY_ATTESTATION',
            'install': 'NEW_ISOLATED_IMMUTABLE_SOURCE_NO_REPLACE_LIVE_SERVICE',
            'rollback': 'EXACT_ADMITTED_OWNED_INSTANCE_AND_PREIMAGE_ONLY_NO_UNKNOWN_REPLAY',
            'full_backup_dependency': 'SEPARATE_OBJECTIVE_NOT_A_GLOBAL_PRIVATE_WORK_GATE'}


def apply_native10(*args, **kwargs):
    # No JSON, variable, hostname or mutable local admission file is a grant.
    raise ValueError('ACTUAL_NETCUP_CONTROL_INSTALL_CUSTODY_ADMISSION_UNBOUND10')


def validate_custody_ack10(scope, run_id, ack, hashes):
    """Consistency only; the current native route is independently disarmed."""
    keys = {'kind', 'run_id', 'source', 'target_binding_sha256', 'runtime_sha256',
            'originals_sha256', 'durable_receipt_sha256'}
    require10(type(ack) is dict and set(ack) == keys, 'CUSTODY_ACK_FIELDS10')
    kind = 'SYNTHETIC_TEST_ONLY' if scope.test_only else 'ADMITTED_PRIVATE_CUSTODY_READBACK_REQUIRED'
    require10(ack['kind'] == kind and ack['run_id'] == run_id
              and ack['source'] == scope.source
              and ack['target_binding_sha256'] == scope.target_binding_sha256
              and ack['runtime_sha256'] == scope.runtime_sha256, 'CUSTODY_ACK_BINDING10')
    require10(set(hashes) == {'order_create', 'capture', 'final_read', 'verify', 'event_read'}
              and all(hex10(v) for v in hashes.values())
              and ack['originals_sha256'] == hashes
              and hex10(ack['durable_receipt_sha256']), 'FIVE_ORIGINALS_BEFORE_PURGE10')
    return True
