"""Short-lived, port-443-only rejection of peers that offer the wrong TLS SNI.
No addresses, names or credentials are printed or written to application logs.
Existing rules are never flushed. Kernel timeouts and a separate cleanup timer
bound the rules even if the receiver dies.
"""
import ipaddress,json,pathlib,re,subprocess,threading

class IngressGuard:
    def __init__(self,table,seconds,stop):
        assert re.fullmatch('payproof_[a-z0-9_]{1,32}',table)
        assert 1<=seconds<=600
        self.table=table;self.seconds=seconds;self.stop=stop;self.lock=threading.Lock()
        self.expected=set();self.denied=set();self.created=False;self.timer=False
        self.counters={'quarantined':0,'shared_peer_not_blocked':0,'guard_failures':0}
    def call(self,args,*,data=None,check=True):
        p=subprocess.run(args,input=data,capture_output=True,timeout=6,text=True)
        if check and p.returncode:raise RuntimeError('INGRESS_CONTROL_REFUSED')
        return p
    def nft(self,command,check=True):return self.call(['/usr/sbin/nft','-f','-'],data=command+'\n',check=check)
    def rules(self):
        p=self.call(['/usr/sbin/nft','-j','list','ruleset']);r=json.loads(p.stdout)
        return [x for x in r['nftables'] if 'metainfo' not in x]
    def open(self,root):
        # Exclusive operation root has already been created by the caller.
        before=self.rules();assert not before,'BASELINE_NOT_EMPTY_REVIEW_REQUIRED'
        path=pathlib.Path(root)/'INGRESS_BEFORE.json'
        with path.open('x') as f:json.dump(before,f)
        path.chmod(0o600)
        expiry=self.seconds+20
        self.call(['/usr/bin/systemd-run','--quiet','--collect','--unit='+self.table,
                   '--on-active='+str(expiry)+'s','--timer-property=AccuracySec=1s',
                   '/usr/sbin/nft','delete','table','inet',self.table]);self.timer=True
        assert self.call(['/usr/bin/systemctl','is-active',self.table+'.timer']).stdout.strip()=='active'
        rules=(f'create table inet {self.table}\n'
               f'add set inet {self.table} rejected {{ type ipv4_addr; flags timeout; timeout {expiry}s; size 128; }}\n'
               f'add chain inet {self.table} ingress {{ type filter hook input priority -5; policy accept; }}\n'
               f'add rule inet {self.table} ingress tcp dport 443 ip saddr @rejected counter drop')
        self.call(['/usr/sbin/nft','-c','-f','-'],data=rules+'\n')
        self.created=True # uncertain creation requires reconciliation, never another create
        self.nft(rules)
    def observe(self,peer,expected):
        addr=str(ipaddress.IPv4Address(peer))
        with self.lock:
            if expected:self.expected.add(addr);return
            if addr in self.expected:self.counters['shared_peer_not_blocked']+=1;return
            if addr in self.denied:return
            if len(self.denied)>=128:self.stop.set();return
            self.denied.add(addr) # reserve before external mutation; no retries
        try:
            self.nft(f'add element inet {self.table} rejected {{ {addr} timeout {self.seconds+20}s }}')
            with self.lock:self.counters['quarantined']+=1
        except Exception:
            with self.lock:self.counters['guard_failures']+=1
            self.stop.set()
    def close(self):
        # Independent timer remains live if closure cannot be verified.
        if self.created:
            current=self.rules()
            if any(x.get('table',{}).get('name')==self.table for x in current):
                self.nft(f'delete table inet {self.table}')
            assert self.rules()==[],'RULESET_RESTORE_UNVERIFIED'
        if self.timer:self.call(['/usr/bin/systemctl','stop',self.table+'.timer'])
        return True
