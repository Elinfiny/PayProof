"""Byte-exact ciphertext framing. No network, key creation, decrypt or replay.

The caller must obtain bytes through an authorized private file transfer and
bind the whole-file SHA256 from that transfer. Screenshots/transcribed strings
are not accepted transport. This codec does not establish native file access.
"""
import base64
import hashlib
import json
import re

class EnvelopeError(ValueError):
    pass

def _require(ok):
    if not ok:
        raise EnvelopeError('ENVELOPE_REFUSED164')

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def _binding(value):
    _require(type(value) is dict and set(value)=={'source','run_id','expires_at','recipient_sha256'})
    _require(isinstance(value['source'],str) and re.fullmatch('[0-9a-f]{40}',value['source']) is not None)
    _require(isinstance(value['run_id'],str) and re.fullmatch('[1-9][0-9]{0,19}',value['run_id']) is not None)
    _require(type(value['expires_at']) is int and value['expires_at']>0)
    _require(isinstance(value['recipient_sha256'],str) and re.fullmatch('[0-9a-f]{64}',value['recipient_sha256']) is not None)

def pack(ciphertext,binding):
    _binding(binding)
    _require(type(ciphertext) is bytes and len(ciphertext)==256)
    return _canonical({'schema':'PAYPROOF_BUYER_CIPHERTEXT164','binding':binding,
                       'bytes':256,'sha256':hashlib.sha256(ciphertext).hexdigest(),
                       'ciphertext_base64':base64.b64encode(ciphertext).decode('ascii')})

def unpack(transferred_bytes,expected_binding,expected_file_sha256,now):
    _binding(expected_binding)
    _require(type(transferred_bytes) is bytes and 0<len(transferred_bytes)<=2048)
    _require(hashlib.sha256(transferred_bytes).hexdigest()==expected_file_sha256)
    try:
        row=json.loads(transferred_bytes)
        _require(_canonical(row)==transferred_bytes)
        _require(type(row) is dict and set(row)=={'schema','binding','bytes','sha256','ciphertext_base64'})
        _require(row['schema']=='PAYPROOF_BUYER_CIPHERTEXT164' and row['binding']==expected_binding)
        _require(type(now) in (int,float) and now<expected_binding['expires_at'])
        _require(type(row['bytes']) is int and row['bytes']==256)
        raw=base64.b64decode(row['ciphertext_base64'],validate=True)
        _require(len(raw)==256 and hashlib.sha256(raw).hexdigest()==row['sha256'])
        return raw
    except Exception:
        raise EnvelopeError('ENVELOPE_REFUSED164') from None
