from .common import *
import base64,re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa
def b64url(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_-]+', value), 'BASE64URL')
    try:
        raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        require(base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == value, 'BASE64_CANONICAL')
        return raw
    except ValueError:
        raise Refused('BASE64URL') from None


def verify_oidc(token, jwks_raw, grant, now):
    """JWKS provenance belongs to fixed HTTPS loader; no URL from JWT is used."""
    require(type(token) is str and len(token) <= 16384 and token.count('.') == 2, 'TOKEN_SHAPE')
    h, p, sig = token.split('.')
    header = obj(b64url(h), 2048)
    require(header.get('alg') == 'RS256' and header.get('typ') == 'JWT'
            and {'alg', 'typ', 'kid'} <= set(header)
            and set(header) <= {'alg', 'typ', 'kid', 'x5t', 'x5t#S256'}, 'TOKEN_HEADER')
    jwks = obj(jwks_raw, 65536)
    keys = jwks.get('keys')
    require(type(keys) is list and 1 <= len(keys) <= 32
            and all(type(k) is dict and type(k.get('kid')) is str for k in keys), 'JWKS')
    require(len({k['kid'] for k in keys}) == len(keys), 'DUPLICATE_KID')
    matches = [k for k in keys if k['kid'] == header.get('kid')]
    require(len(matches) == 1, 'KID')
    key = matches[0]
    require(key.get('kty') == 'RSA' and key.get('alg') == 'RS256' and key.get('use') == 'sig', 'KEY_TYPE')
    nraw, eraw = b64url(key['n']), b64url(key['e'])
    require(len(nraw) <= 1024 and len(eraw) <= 4 and nraw[0] != 0 and eraw[0] != 0, 'KEY_SIZE')
    n, e = int.from_bytes(nraw, 'big'), int.from_bytes(eraw, 'big')
    require(2048 <= n.bit_length() <= 8192 and e == 65537, 'KEY_POLICY')
    try:
        rsa.RSAPublicNumbers(e, n).public_key().verify(
            b64url(sig), (h + '.' + p).encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise Refused('SIGNATURE') from None
    claims = obj(b64url(p), 12288)
    expected = {'iss': ISSUER, 'aud': AUDIENCE, 'repository': REPO, 'repository_id': REPO_ID,
                'repository_owner': 'Elinfiny', 'repository_owner_id': OWNER_ID,
                'repository_visibility': 'public', 'actor': 'Elinfiny', 'actor_id': OWNER_ID,
                'workflow_ref': WORKFLOW, 'workflow_sha': grant['workflow_sha'],
                'sha': grant['workflow_sha'], 'ref': 'refs/heads/main', 'ref_type': 'branch',
                'event_name': 'workflow_dispatch', 'run_id': grant['run_id'], 'run_attempt': '1',
                'runner_environment': 'github-hosted'}
    require(all(type(claims.get(k)) is str and claims[k] == v for k, v in expected.items()), 'IDENTITY')
    # Exact repository IDs, workflow, source and run above remain mandatory for
    # either documented GitHub default subject format. Custom subjects refuse.
    subjects = {'repo:' + REPO + ':environment:payproof-sandbox-readonly',
                f'repo:Elinfiny@{OWNER_ID}/PayProof@{REPO_ID}:environment:payproof-sandbox-readonly'}
    require(claims.get('sub') in subjects, 'SUBJECT')
    require(all(type(claims.get(k)) is int for k in ('iat', 'nbf', 'exp')), 'TOKEN_TIME_TYPE')
    require(grant['start_at'] <= now < grant['expires_at']
            and grant['start_at'] - 60 <= claims['iat'] <= now
            and claims['nbf'] <= now < claims['exp']
            and 0 < claims['exp'] - claims['iat'] <= 600, 'TOKEN_TIME')
    require(type(claims.get('jti')) is str and 0 < len(claims['jti']) <= 256, 'JTI')
    # Provider JWT may expire later; the stricter absolute grant always wins.
    return sha(token.encode())

