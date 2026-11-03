"""Root-private durable state; no network or credentials. ACK follows fsync."""
import base64,hmac,pathlib,threading,time
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from .common import *
from .envelope import pack

class State:
    def __init__(self,root,grant,clock=time.time,signature=None):
        self.root=pathlib.Path(root);private(self.root,True);self.g=grant;self.clock=clock
        self.lock=threading.RLock();self.closed=False;self.stop=threading.Event();self.counts={};self.signature=signature
        self.recipient=None;self.pairing=None;self.cap_sha=None;self.order=None;self.webhook=None;self.buyer_ack=False;self.wire=None;self.event=None;self.terminal=None
    def require(self):
        require(not self.closed and self.g['start_at']<=self.clock()<self.g['expires_at'],'CLOSED_OR_EXPIRED')
    def bounded(self,name,limit=1):
        n=self.counts.get(name,0);require(n<limit,'CALL_BOUND');self.counts[name]=n+1
    def save(self,name,value):
        raw=value if type(value) is bytes else canonical(value);write_once(self.root/name,raw);return sha(raw)
    def browser_auth(self,token):
        self.require();require(type(token) is str and re.fullmatch('[a-f0-9]{64}',token) and self.cap_sha and hmac.compare_digest(sha(token.encode()),self.cap_sha),'BROWSER_AUTH')
    def browser_ready(self):
        p=self.root/'BROWSER_ADMITTED.json'
        if not self.recipient or not p.is_file():return False
        private(p);return obj(p.read_bytes())=={'pairing_sha256':self.pairing,'grant_sha256':sha(canonical(self.g))}
    def bind_recipient(self,row,cap):
        require(type(cap) is str and re.fullmatch('[a-f0-9]{64}',cap),'NEW_BROWSER_CAPABILITY')
        self.bounded('recipient');require(set(row)=={'public_key_der'},'RECIPIENT_FIELDS')
        raw=base64.b64decode(row['public_key_der'],validate=True);require(0<len(raw)<=1024,'KEY_SIZE')
        key=serialization.load_der_public_key(raw);require(isinstance(key,rsa.RSAPublicKey) and key.key_size==2048 and key.public_numbers().e==65537,'RSA_KEY')
        binding={'source':self.g['workflow_sha'],'run_id':self.g['run_id'],'expires_at':self.g['expires_at'],'recipient_sha256':sha(raw)}
        self.cap_sha=sha(cap.encode());record={'binding':binding,'public_key_der':row['public_key_der'],'browser_cap_sha256':self.cap_sha}
        self.pairing=self.save('RECIPIENT.json',record)
        self.recipient=(key,binding);return {'binding':binding,'grant_sha256':sha(canonical(self.g)),'pairing_sha256':self.pairing}
    def reserve(self,row):
        require(set(row)=={'key','metadata'},'RESERVE_FIELDS');m=row['metadata'];op=m.get('operation');require(op in OPS,'OPERATION')
        expected={'profile':'PAYPROOF186_DISTINCT_SELFHOSTED_SANDBOX','app_sha256':APP,'source_sha256':engine_source(self.g),'caller':caller(self.g),'target_sha256':m.get('target_sha256'),'operation':op,'fake_usd':'1.00','real_usd':'0.00','expires_at':self.g['expires_at']}
        require(m==expected and re.fullmatch('[a-f0-9]{64}',m['target_sha256']) and row['key']==once_prefix(self.g)+':'+op,'EXACT_SLOT')
        if op=='oauth':require(self.browser_ready(),'BUYER_ROUTE_BEFORE_PAYPAL')
        if op=='subscription_delete':
            # Cleanup authority cannot be minted for an existing/unknown hook.
            require(self.webhook and m['target_sha256']==sha(('/v1/notifications/webhooks/'+self.webhook).encode()),'CLEANUP_TARGET')
            created=obj((self.root/'HTTP_subscription_create.bin').read_bytes())
            status=obj((self.root/'HTTP_subscription_create.json').read_bytes())['status']
            previous=obj((self.root/'HTTP_subscription_read.bin').read_bytes())['webhooks']
            require(200<=status<300 and created.get('id')==self.webhook and
                    not any(w.get('id')==self.webhook for w in previous),'CLEANUP_CREATED_THIS_RUN')
        self.bounded('reserve-'+op);self.save('SLOT_'+op+'.json',row)
        return {'state':'CONSUMED','grant_sha256':sha(canonical(self.g)),**row}
    def retain_result(self,row):
        require(set(row)=={'operation','status','raw_base64'},'RESULT_FIELDS');op=row['operation'];require(op in OPS and self.counts.get('reserve-'+op)==1,'RESERVED_FIRST')
        require(type(row['status']) is int and 100<=row['status']<=599,'STATUS');self.bounded('result-'+op)
        raw=base64.b64decode(row['raw_base64'],validate=True);require(len(raw)<=1048576,'RESULT_SIZE')
        if op=='oauth':require(raw==b'','OAUTH_SECRET_EXCLUDED')
        else:require(not any(s in raw.lower() for s in (b'"access_token"',b'"client_secret"',b'"refresh_token"')),'SECRET_EXCLUDED')
        digest=self.save('HTTP_'+op+'.bin',raw)
        meta={'operation':op,'status':row['status'],'bytes':len(raw),'sha256':digest}
        self.save('HTTP_'+op+'.json',meta)
        # Original bytes survive even if their schema is invalid. Bindings are
        # recovered only from the specific later validated bind requests.
        return meta
    def bind_webhook(self,row):
        require(set(row)=={'webhook_id'} and re.fullmatch('[A-Z0-9-]{1,64}',row['webhook_id']),'WEBHOOK_ID')
        candidates=[]
        for op in ('subscription_read','subscription_create'):
            p=self.root/('HTTP_'+op+'.bin')
            if p.is_file():
                original=obj(p.read_bytes())
                candidates.extend(original.get('webhooks',[]) if op=='subscription_read' else [original])
        # Provider event entries may also carry descriptive metadata. Bind the
        # exact event name while preserving the original identity and URL checks.
        matches=[w for w in candidates if type(w) is dict and w.get('id')==row['webhook_id'] and w.get('url')=='https://'+HOST+'/webhooks/payproof186' and type(w.get('event_types')) is list and any(type(e) is dict and e.get('name')=='PAYMENT.CAPTURE.COMPLETED' for e in w['event_types'])]
        require(len(matches)==1,'ORIGINAL_WEBHOOK_BINDING')
        self.bounded('bind-webhook');self.save('BOUND_WEBHOOK.json',row);self.webhook=row['webhook_id']
        if self.signature is None:
            from .signature import LocalSignature152
            self.signature=LocalSignature152(self.webhook)
        return {'state':'WEBHOOK_DURABLE'}
    def bind_order(self,row):
        require(set(row)=={'order_id','approval_url'} and self.webhook and self.browser_ready(),'ORDER_PREREQUISITES')
        url=approval(row['approval_url'],row['order_id']);self.bounded('bind-order')
        require((self.root/'HTTP_order_create.bin').is_file(),'ORIGINAL_BEFORE_BIND')
        original=obj((self.root/'HTTP_order_create.bin').read_bytes());require(original.get('id')==row['order_id'],'ORIGINAL_ORDER')
        links=[x.get('href') for x in original.get('links',[]) if x.get('rel') in ('approve','payer-action')]
        require(links==[url],'ORIGINAL_APPROVAL')
        self.save('BOUND_ORDER.json',row);self.order=row['order_id']
        key,binding=self.recipient
        wire=pack(key.encrypt(url.encode(),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)),binding)
        self.save('buyer-envelope.bin',wire);self.wire=wire
        return {'state':'ORDER_AND_ENCRYPTED_APPROVAL_DURABLE','order_sha256':sha(self.order.encode())}
    def acknowledge_buyer(self,row):
        require(self.order and self.wire and row=={'order_id':self.order,'file_sha256':sha(self.wire)},'BUYER_ACK_BINDING')
        self.bounded('buyer-ack');self.save('BUYER_ACK.json',row);self.buyer_ack=True
        return {'state':'GESTURE_RECORDED_PROVIDER_APPROVAL_STILL_REQUIRED'}
    def webhook_event(self,headers,raw):
        require(self.order and self.webhook and self.signature,'EVENT_READY');require(0<len(raw)<=65536,'EVENT_BOUND')
        event=obj(raw);r=event.get('resource',{});require(event.get('event_type')=='PAYMENT.CAPTURE.COMPLETED' and r.get('status')=='COMPLETED' and r.get('amount')=={'value':'1.00','currency_code':'USD'} and r.get('supplementary_data',{}).get('related_ids',{}).get('order_id')==self.order,'EVENT_ORDER')
        names=('paypal-auth-algo','paypal-cert-url','paypal-transmission-id','paypal-transmission-sig','paypal-transmission-time');safe={n:headers[n] for n in names if n in headers}
        require(len(safe)==5 and all(type(v) is str and 0<len(v)<=4096 for v in safe.values()),'SIGNATURE_HEADERS')
        require(self.signature.verify(safe,raw),'LOCAL_SIGNATURE')
        record={'sha256':sha(raw),'headers':safe,'raw_base64':base64.b64encode(raw).decode()}
        if self.event is not None:require(self.event==record,'EVENT_DRIFT');return {'state':'DUPLICATE_RETAINED','sha256':sha(raw)}
        self.save('WEBHOOK.bin',raw);self.save('WEBHOOK_HEADERS.json',safe);self.event=record
        return {'state':'DURABLE_BEFORE_ACK','sha256':sha(raw)}
    def ai(self,row):
        require(row.get('mode')=='PAYPAL_SANDBOX' and row.get('order',{}).get('source')=='PAYPAL_SANDBOX' and row.get('order',{}).get('state')=='COMPLETED' and row.get('order',{}).get('local_assistance',{}).get('model_ready') is True,'AI_EVIDENCE')
        self.bounded('ai');self.save('AI.json',row);return {'state':'AI_DURABLE'}
    def terminal_report(self,row):
        require(set(row)=={'state','provider_slots','bridge_unknown','cleanup','order_sha256','capture_sha256'} and row['state'] in ('COMPLETED','REFUSED','UNKNOWN'),'TERMINAL_SCHEMA')
        require(type(row['provider_slots']) is dict and all(k in OPS and v==1 for k,v in row['provider_slots'].items()),'TERMINAL_SLOTS')
        require(type(row['bridge_unknown']) is bool and row['cleanup'] in ('DELETED_NEW','PRESERVED_EXISTING','UNKNOWN_NO_RETRY','NOT_COMPLETED'),'TERMINAL_VALUES')
        require(all(row[k] is None or re.fullmatch('[a-f0-9]{64}',row[k]) for k in ('order_sha256','capture_sha256')),'TERMINAL_HASHES')
        if row['state']=='COMPLETED':
            require(not row['bridge_unknown'] and row['cleanup'] in ('DELETED_NEW','PRESERVED_EXISTING') and self.order and self.buyer_ack and self.event and self.counts.get('ai')==1,'COMPLETE_EVIDENCE')
            require(row['order_sha256']==sha(self.order.encode()) and (self.root/'HTTP_capture.bin').is_file(),'COMPLETE_ORDER')
            captured=obj((self.root/'HTTP_capture.bin').read_bytes())
            ids=[c.get('id') for u in captured.get('purchase_units',[]) for c in u.get('payments',{}).get('captures',[]) if c.get('status')=='COMPLETED']
            require(len(ids)==1 and type(ids[0]) is str and row['capture_sha256']==sha(ids[0].encode()),'COMPLETE_CAPTURE')
            for op in ('approval_read','capture','final_read','verify','event_read'):
                require((self.root/('HTTP_'+op+'.json')).is_file() and row['provider_slots'].get(op)==1,'COMPLETE_ORIGINALS')
            self.save('BOUND_CAPTURE.json',{'order_id':self.order,'capture_id':ids[0]})
        self.bounded('terminal');self.save('WORKER_TERMINAL.json',row);self.terminal=row;self.stop.set();return {'state':'TERMINAL_DURABLE_CLOSING'}
    def close(self,reason):
        if self.closed:return
        self.closed=True;self.stop.set();self.recipient=None;self.cap_sha=None;self.wire=None;self.signature=None
        # stdout is still open and receives the final result after this method.
        # NATIVE_RESULT.json and CLOSED.json are separate immutable receipts.
        manifest={p.name:{'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in self.root.iterdir() if p.is_file() and not p.is_symlink() and p.name not in ('CLOSED.json','CUSTODY.json','native.out','native.stdout')}
        self.save('CUSTODY.json',{'schema':'PAYMENT186_PRIVATE_CUSTODY','files':manifest})
        self.save('CLOSED.json',{'state':'ACCESS_CLOSED','reason':reason,'at':self.clock(),'provider_cleanup':'See WORKER_TERMINAL; unknown effects never retried','evidence_preserved':True})
