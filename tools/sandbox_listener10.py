"""Exact EventInbox151 class from immutable714, private storage only."""
import hashlib,json,os,pathlib,sqlite3
from .sandbox_chain10 import InvalidData

class EventInbox151:
 """Private byte-preserving inbox. Local storage is NOT an external once ledger."""
 def __init__(self,path):
  p=pathlib.Path(path)
  if p.parent.stat().st_mode&0o077:raise InvalidData('PRIVATE_INBOX_DIRECTORY151')
  fd=os.open(p,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
  try:
   import stat
   s=os.fstat(fd)
   if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise InvalidData('PRIVATE_INBOX_FILE151')
  finally:os.close(fd)
  self.path=str(p)
  with sqlite3.connect(self.path) as db:db.execute('CREATE TABLE IF NOT EXISTS inbox (digest TEXT PRIMARY KEY, raw BLOB NOT NULL, headers TEXT NOT NULL, state TEXT NOT NULL)')
 def retain(self,raw,headers):
  key=hashlib.sha256(raw).hexdigest()
  with sqlite3.connect(self.path) as db:
   db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT raw,headers FROM inbox WHERE digest=?',(key,)).fetchone()
   if row:
    if row[0]!=raw:raise InvalidData('INBOX_BINDING151')
    return key,False
   if db.execute('SELECT count(*) FROM inbox').fetchone()[0]>=1:raise InvalidData('ONE_EVENT_INBOX_BOUND151')
   db.execute('INSERT INTO inbox VALUES (?,?,?,?)',(key,raw,json.dumps(headers,sort_keys=True),'RECEIVED_UNVERIFIED'))
  return key,True
 def finish(self,key,state):
  with sqlite3.connect(self.path) as db:db.execute('UPDATE inbox SET state=? WHERE digest=?',(state,key))
