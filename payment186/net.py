"""Fixed peers, verified TLS, bounded single requests, no automatic retry."""
import http.client,ssl,time,os,urllib.parse
from .common import *

def https(host,path,method='GET',body=b'',headers=None,limit=1500000,expires=None):
    left=min(5,expires-time.time()) if expires else 5;require(left>0,'EXPIRED')
    conn=http.client.HTTPSConnection(host,timeout=left,context=ssl.create_default_context());response=None
    deadline=time.monotonic()+left
    try:
        conn.request(method,path,body=body if method in ('POST','DELETE') else None,headers=headers or {})
        require(time.monotonic()<deadline,'REQUEST_DEADLINE')
        if conn.sock:conn.sock.settimeout(max(.001,deadline-time.monotonic()))
        response=conn.getresponse();out=bytearray()
        while len(out)<=limit:
            remaining=deadline-time.monotonic();require(remaining>0,'HTTP_DEADLINE')
            if conn.sock:conn.sock.settimeout(remaining)
            data=response.read1(min(4096,limit+1-len(out)))
            if not data:break
            out.extend(data)
        require(len(out)<=limit and time.monotonic()<deadline,'HTTP_BOUND')
        return response.status,bytes(out),response.getheader('X-Content-SHA256')
    finally:
        if response:response.close()
        conn.close()
def token(expires):
    p=urllib.parse.urlsplit(os.environ['ACTIONS_ID_TOKEN_REQUEST_URL'])
    require(p.scheme=='https' and p.hostname and p.hostname.endswith('.actions.githubusercontent.com') and not p.username and not p.password and p.port in (None,443) and not p.fragment,'OIDC_ORIGIN')
    require('audience' not in urllib.parse.parse_qs(p.query),'OIDC_QUERY')
    query=p.query+('&' if p.query else '')+urllib.parse.urlencode({'audience':AUDIENCE})
    status,raw,_=https(p.hostname,p.path+'?'+query,headers={'Authorization':'Bearer '+os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']},expires=expires,limit=32768)
    require(status==200,'OIDC_STATUS');v=obj(raw)['value'];require(type(v) is str and len(v)<=16384 and v.count('.')==2,'OIDC_VALUE');return v
