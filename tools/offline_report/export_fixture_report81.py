"""Private synthetic reporter with descriptor-bound bounded I/O.

Authorized caller owns the quiescent fixture root. Ownership, hashes and JSON
are access/integrity checks, never provider or payment authority. Host ancestors
are held and rechecked; only the selected private root and its descendants are
required to be 0700. Same-UID races and cleanup fault branches require review.
"""
import argparse
import errno
import hashlib
import html
import json
import os
from pathlib import PurePosixPath
import sqlite3
import stat
import time

CONTRACT_SHA256='bb26df42f05560f818efad8f86e7e01c690482f9446170eb2775e06880aed622'
DIRFLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
FILEFLAGS=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC

class InputRefusal(ValueError):
    stage='PRE_PAYLOAD_PRE_SQLITE'

def flatten_failure(primary, cleanup):
    """Unwrap transport wrappers without replacing the first actual exception."""
    prior=[]
    while isinstance(primary, ExportUnknown):
        prior=list(primary.cleanup)+prior
        primary=primary.primary
    flat=[]
    for stage,error in prior+list(cleanup):
        if isinstance(error, ExportUnknown):
            actual, nested=flatten_failure(error.primary,error.cleanup)
            if actual is not None:flat.append((stage,actual))
            flat.extend((stage+'/'+s,e) for s,e in nested)
        else:flat.append((stage,error))
    return primary,flat

class ExportUnknown(RuntimeError):
    def __init__(self,primary,cleanup,deadline_uncertainty=False):
        self.primary,self.cleanup=flatten_failure(primary,cleanup)
        self.deadline_uncertainty=deadline_uncertainty
        super().__init__('UNKNOWN: retain primary/cleanup and partial outputs; never retry or adopt')

class Drift(RuntimeError):
    pass

def identity(s):
    return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),stat.S_IFMT(s.st_mode))

def file_identity(s):
    return identity(s)+(s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def parts(value):
    p=PurePosixPath(value)
    if p.is_absolute() or not p.parts or any(x in ('','..','.') for x in p.parts):
        raise InputRefusal('Only explicit relative fixture components are allowed')
    return p.parts

class Root:
    def __init__(self,path,trace):
        self.trace=trace;self.fds=[];self.links=[];self.private=[];self.fd=None
        p=PurePosixPath(os.fspath(path))
        if not p.is_absolute() or '..' in p.parts:raise InputRefusal('An explicit absolute private root is required')
        try:
            fd=os.open('/',DIRFLAGS);self.fds.append(fd)
            for name in p.parts[1:]:
                child=os.open(name,DIRFLAGS,dir_fd=fd);self.fds.append(child)
                s=os.fstat(child)
                if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid():raise InputRefusal('Unowned root component')
                self.links.append((fd,name,child,identity(s)));fd=child
            self.fd=fd;self.private.append(fd);self.verify()
        except BaseException as primary:
            failures=[]
            for fd in reversed(self.fds):
                try:os.close(fd)
                except BaseException as error:failures.append(('root_constructor_close',error))
            self.fds=[]
            if failures:raise ExportUnknown(primary,failures) from primary
            raise
    def verify(self):
        for parent,name,fd,expected in self.links:
            if identity(os.fstat(fd))!=expected or identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=expected:
                raise Drift('Held directory or parent entry identity changed')
        for fd in self.private:
            s=os.fstat(fd)
            if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:
                raise InputRefusal('Owned private directories must be exactly 0700')
    def effect_attempt(self,kind,label):
        # Conservative: a creating call can affect the namespace before raising.
        if time.monotonic()>=self.trace['deadline_monotonic']:
            self.trace['deadline_uncertainty']=True
            raise Drift('Absolute deadline before mutating call')
        self.trace['mutation_attempted']=True
        self.trace['effect_attempts'].append({'kind':kind,'label':label,'phase':'PRE_REQUEST','monotonic':time.monotonic()})
    def directory(self,names,create=False):
        fd=self.fd
        for name in names:
            if create:
                self.effect_attempt('mkdir',name)
                os.mkdir(name,0o700,dir_fd=fd);create=False
            child=os.open(name,DIRFLAGS,dir_fd=fd);self.fds.append(child);s=os.fstat(child)
            self.links.append((fd,name,child,identity(s)));self.private.append(child);self.verify();fd=child
        return fd
    def open_file(self,relative,maximum,label):
        names=parts(relative);parent=self.directory(names[:-1]);self.verify()
        try:fd=os.open(names[-1],FILEFLAGS,dir_fd=parent)
        except OSError as error:
            if error.errno in (errno.ELOOP,errno.ENOTDIR):
                refusal=InputRefusal('Input symlink or non-directory component refused before payload')
                refusal.original_os_error=error
                raise refusal from error
            raise
        try:return Pinned(self,parent,names[-1],fd,maximum,label)
        except BaseException as primary:
            try:os.close(fd)
            except BaseException as error:raise ExportUnknown(primary,[('input_fd_close',error)]) from primary
            raise
    def exclusive(self,parent,name,data,label):
        self.verify();self.effect_attempt('exclusive_open',label)
        fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600,dir_fd=parent)
        handle=None
        try:
            self.trace['files_created'].append(label)
            at=0
            while at<len(data):
                self.effect_attempt('write',label)
                n=os.write(fd,data[at:])
                if n<=0:raise OSError('Short output write')
                at+=n;self.trace['bytes_written'][label]=at
            handle=Pinned(self,parent,name,fd,len(data),label)
            actual=handle.read()
            if actual!=data:raise Drift('Exclusive output whole-byte readback differs')
            self.verify();return handle
        except BaseException as primary:
            try:os.close(fd)
            except BaseException as error:raise ExportUnknown(primary,[('partial_output_fd_close',error)]) from primary
            raise

class Pinned:
    def __init__(self,root,parent,name,fd,maximum,label):
        self.root=root;self.parent=parent;self.name=name;self.fd=fd;self.maximum=maximum;self.label=label;self.closed=False
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:
            raise InputRefusal('Input must be owned 0600 regular single-link')
        if not 0<s.st_size<=maximum:raise InputRefusal('Input size refused before payload: '+label)
        self.initial=file_identity(s);self.verify()
    def verify(self):
        self.root.verify()
        if file_identity(os.fstat(self.fd))!=self.initial or file_identity(os.stat(self.name,dir_fd=self.parent,follow_symlinks=False))!=self.initial:
            raise Drift('File descriptor, entry or parent identity changed: '+self.label)
    def read(self):
        self.verify();size=self.initial[-3];chunks=[];offset=0
        while offset<size:
            if len(chunks)>512:raise Drift('Finite payload read limit')
            self.root.trace['payload_read_calls'][self.label]=self.root.trace['payload_read_calls'].get(self.label,0)+1
            b=os.pread(self.fd,min(4096,size-offset),offset)
            if not b:raise Drift('Short payload read: '+self.label)
            chunks.append(b);offset+=len(b)
        self.verify();data=b''.join(chunks)
        if len(data)!=size or len(data)>self.maximum:raise Drift('Payload bound changed')
        return data
    def proof(self,data):
        return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'device':self.initial[0],'inode':self.initial[1],'mode':oct(self.initial[4]),'nlink':self.initial[6],'FD_identity_before':list(self.initial),'FD_identity_after':list(file_identity(os.fstat(self.fd))),'entry_identity_after':list(file_identity(os.stat(self.name,dir_fd=self.parent,follow_symlinks=False))),'held_parent_identity':list(identity(os.fstat(self.parent)))}
    def close(self):
        if self.closed:raise RuntimeError('Owned descriptor close attempted twice')
        self.closed=True;os.close(self.fd)

def query_snapshot(connection,contract):
    connection.row_factory=sqlite3.Row
    connection.execute('PRAGMA query_only=ON')
    if connection.execute('PRAGMA query_only').fetchone()[0]!=1:raise Drift('query_only unavailable')
    connection.execute('BEGIN')
    if connection.execute('PRAGMA application_id').fetchone()[0]!=contract['fixture_application_id']:raise InputRefusal('Fixture namespace differs')
    entries=[tuple(row) for row in connection.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
    if entries!=[('table','effects'),('table','events'),('table','orders')]:raise InputRefusal('Unexpected schema objects')
    rows={}
    for name in ('orders','events','effects'):
        columns=[[row['name'],row['type'],row['notnull'],row['pk']] for row in connection.execute('PRAGMA table_info('+name+')')]
        if columns!=contract['tables'][name]:raise InputRefusal('Schema fields differ')
        rows[name]=[dict(row) for row in connection.execute(contract['whitelisted_queries'][name]).fetchmany(17)]
        if len(rows[name])>16:raise InputRefusal('Row cap')
    if rows!={'orders':[contract['initial_order']],'events':[],'effects':[]}:raise InputRefusal('Only initial synthetic fixture is admitted')
    return rows

def render_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    order = report['orders'][0]
    rows = ''.join('<tr><th>' + esc(label) + '</th><td>' + esc(order[key]) + '</td></tr>'
                   for label, key in [('Comandă sintetică', 'id'), ('Sumă', 'amount'),
                                      ('Valută', 'currency'), ('Stare', 'state'), ('Sursa dovezii', 'source')])
    missing = ''.join('<li>' + esc(item) + '</li>' for item in report['missing_evidence'])
    gates = ''.join('<li>' + esc(item) + '</li>' for item in report['gates'])
    return ('<!doctype html><html lang="ro"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
            '<title>PayProof — raport sintetic de audit</title><style>'
            'body{font:17px/1.6 system-ui,sans-serif;max-width:850px;margin:40px auto;padding:0 24px;color:#172638;background:#f5f7fa}'
            'main{background:white;padding:28px;border:1px solid #d6dee8;border-radius:12px}h1{line-height:1.2}'
            '.label{font-weight:700;color:#284971}.unknown{padding:16px;background:#fff4d2;border-left:5px solid #c08500}'
            'table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #d6dee8}'
            'small{color:#4e5d6c;overflow-wrap:anywhere}</style></head><body><main>'
            '<p class="label">' + esc(report['mode']) + '</p><h1>Raport de audit PayProof</h1>'
            '<p>' + esc(report['ai_mode']) + '</p><p class="unknown"><strong>UNKNOWN</strong> — '
            + esc(report['summary']) + '</p><table><tbody>' + rows + '</tbody></table>'
            '<h2>Proveniență și limite</h2><p>' + esc(report['provenance_explanation']) + '</p>'
            '<p>Raportul nu poate executa plăți. Nu există dovadă autentică de la furnizor sau de autenticitate a unui webhook. '
            'Proiectul nu este declarat pregătit pentru concurs.</p>'
            '<h2>Ce dovezi lipsesc</h2><ul>' + missing + '</ul>'
            '<p>Această listă descrie dovezile necesare; generarea raportului nu trimite cereri și nu pornește reconcilierea.</p>'
            '<h2>Porți rămase</h2><ul>' + gates + '</ul><p><small>'
            + esc(report['integrity']['meaning']) + '<br>SHA-256: '
            + esc(report['integrity']['input_db_sha256']) + '</small></p></main></body></html>')

def public_report(rows,contract,digest):
    return {'schema':'PAYPROOF_SYNTHETIC_FD_AUDIT_REPORT81_V1','mode':contract['mode_label'],'ai_mode':contract['ai_label'],'contest_ready':False,'authority':False,'provenance':dict(contract['provenance']),
            'summary':'Nu există încă o verificare a comenzii. Starea necunoscută nu dovedește plata.',
            'orders':[{key:rows['orders'][0][key] for key in ('id','amount','currency','state','source')}],
            'counts':{name:len(rows[name]) for name in ('orders','events','effects')},'can_execute_payments':False,'authentic_provider_evidence':False,
            'provenance_explanation':'Date locale sintetice. Copia privată este un suport de citire, nu o dovadă autentică de la furnizor și nu un backup criptografic.',
            'missing_evidence':['O observație autorizată și recentă, cu proveniență și identitate verificate.','Concordanța verificată a sumei, valutei, stării și capturilor din sursa admisă.','Dovada autenticității webhook-ului, dacă este folosit ca sursă.'],
            'gates':list(contract['gates']),'integrity':{'input_db_sha256':digest,'meaning':'Integritate locală a sursei și a copiei; nu acordă autoritate și nu dovedește plata.'},'provider_requests_sent':0,'reconciliation_started':False}

def export_report(root_path,db_relative,provenance_relative,output_name,deadline,trace=None):
    trace={} if trace is None else trace
    trace.update(payload_read_calls={},files_created=[],bytes_written={},SQLite_deserialize=False,cleanup=[],rollback_attempts=0,connection_close_attempts=0,mutation_attempted=False,effect_attempts=[],deadline_monotonic=deadline,deadline_uncertainty=False)
    root=None;handles=[];connection=None;primary=None;cleanup=[];result=None
    try:
        if time.monotonic()>=deadline:raise Drift('Absolute deadline before effects')
        root=Root(root_path,trace)
        # All size/type/link/permission checks happen before ANY payload read.
        database=root.open_file(db_relative,2097152,'source_DB');handles.append(database)
        provenance=root.open_file(provenance_relative,4096,'provenance');handles.append(provenance)
        contract_file=root.open_file('inputs/contract81.json',4096,'contract');handles.append(contract_file)
        raw_contract=contract_file.read()
        if hashlib.sha256(raw_contract).hexdigest()!=CONTRACT_SHA256:raise InputRefusal('Frozen contract differs')
        contract=json.loads(raw_contract);prov=json.loads(provenance.read())
        if type(prov) is not dict or set(prov)!=set(contract['provenance']) or any(type(prov[k]) is not type(v) or prov[k]!=v for k,v in contract['provenance'].items()):raise InputRefusal('Only explicit synthetic provenance is admitted')
        source=database.read();digest=hashlib.sha256(source).hexdigest()
        if database.read()!=source:raise Drift('Source is not quiescent')
        # Explicit, exclusive local INTENT with held-FD/full-byte readback BEFORE the one snapshot copy.
        intent_data=(json.dumps({'schema':'SNAPSHOT81_COPY_INTENT','source':database.proof(source),'snapshot_name':'snapshot81.sqlite3','maximum_bytes':2097152,'purpose':'private consistent read copy only; no backup/auth grant'},sort_keys=True)+'\n').encode()
        intent=root.exclusive(root.fd,'snapshot-intent81.json',intent_data,'snapshot_INTENT');handles.append(intent)
        snapshot_dir=root.directory(('snapshots',))
        snapshot=root.exclusive(snapshot_dir,'snapshot81.sqlite3',source,'snapshot_DB');handles.append(snapshot)
        snapshot_bytes=snapshot.read()
        if snapshot_bytes!=source or database.read()!=source:raise Drift('Source/snapshot byte identity changed')
        if time.monotonic()>=deadline:raise Drift('Absolute deadline before SQLite')
        # Supported Python API consumes the exact pinned snapshot bytes, not an assumed /proc URI.
        connection=sqlite3.connect(':memory:',isolation_level=None)
        connection.deserialize(snapshot_bytes);trace['SQLite_deserialize']=True
        rows=query_snapshot(connection,contract)
        report=public_report(rows,contract,digest)
        outputs=[('report.json',(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()),('report.html',render_html(report).encode())]
        if any(len(data)>65536 for name,data in outputs):raise InputRefusal('Output bound exceeded')
        if database.read()!=source or snapshot.read()!=source:raise Drift('Source/snapshot changed before output')
        if len(parts(output_name))!=1:raise InputRefusal('One new output directory component is required')
        if time.monotonic()>=deadline:raise Drift('Absolute deadline before output')
        output_dir=root.directory(parts(output_name),create=True);output_proofs=[]
        for name,data in outputs:
            handle=root.exclusive(output_dir,name,data,'output_'+name);handles.append(handle);output_proofs.append(dict(name=name,**handle.proof(data)))
        if sorted(os.listdir(output_dir))!=['report.html','report.json']:raise Drift('Unexpected report entry')
        if database.read()!=source or snapshot.read()!=source:raise Drift('Final source/snapshot byte drift')
        for handle in handles:handle.verify()
        root.verify()
        if time.monotonic()>=deadline:raise Drift('Late result')
        result={'report':report,'outputs':output_proofs,'source_before_after':database.proof(source),'snapshot':snapshot.proof(snapshot_bytes),'snapshot_io':'one exclusive file copy from held bounded bytes; re-read via same heldFD; SQLite.deserialize exact pinnedbytes','snapshot_INTENT_sha256':hashlib.sha256(intent_data).hexdigest(),'query_only':True,'SQLite_read_transaction':True,'immutable_hint':False,'source_unchanged':True,'native_authority':False}
    except BaseException as error:
        primary,prior_cleanup=flatten_failure(error,[])
        cleanup.extend(prior_cleanup)  # Keep actual exception identities across wrappers.
    finally:
        if connection is not None:
            try:
                trace['rollback_attempts']+=1
                if connection.in_transaction:connection.rollback()
            except BaseException as error:cleanup.append(('rollback',error))
            finally:
                try:trace['connection_close_attempts']+=1;connection.close()
                except BaseException as error:cleanup.append(('close',error))
        if root is not None:
            try:root.verify()
            except BaseException as error:
                if primary is None:primary=error
                else:cleanup.append(('final_identity',error))
        for handle in reversed(handles):
            try:handle.close()
            except BaseException as error:cleanup.append(('descriptor_close',error))
        if root is not None:
            for fd in reversed(root.fds):
                try:os.close(fd)
                except BaseException as error:cleanup.append(('directory_close',error))
    late=time.monotonic()>=deadline
    trace['deadline_uncertainty']=trace['deadline_uncertainty'] or late
    primary,cleanup=flatten_failure(primary,cleanup)
    trace['cleanup']=[{'stage':stage,'type':type(error).__name__,'message':str(error)} for stage,error in cleanup]
    trace['primary']=None if primary is None else {'type':type(primary).__name__,'message':str(primary)}
    if cleanup or trace['deadline_uncertainty'] or isinstance(primary,Drift) or (primary is not None and trace['mutation_attempted']):
        raise ExportUnknown(primary,cleanup,trace['deadline_uncertainty']) from primary
    if primary is not None:raise primary.with_traceback(primary.__traceback__)
    result['trace']=trace
    return result

def main():
    parser=argparse.ArgumentParser(description='Private synthetic FD-bound read-only report; no provider authority.')
    parser.add_argument('--root',required=True);parser.add_argument('--db',required=True);parser.add_argument('--provenance',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();export_report(args.root,args.db,args.provenance,args.output,time.monotonic()+60)
    print(json.dumps({'status':'CREATED_SYNTHETIC_REPORT','files':['report.json','report.html']}))

if __name__=='__main__':main()
