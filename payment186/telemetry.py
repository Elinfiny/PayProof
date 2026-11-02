"""Bounded aggregate diagnostics. No peers, request text or credentials."""
import collections,threading,ssl

class Metrics:
    def __init__(self):self.lock=threading.Lock();self.counts=collections.Counter()
    def add(self,name):
        with self.lock:self.counts[name]=min(512,self.counts[name]+1)
    def snapshot(self):
        with self.lock:return dict(sorted(self.counts.items()))

def error_kind(exc):
    if isinstance(exc,(TimeoutError,)):return 'timeout'
    if isinstance(exc,(ConnectionResetError,BrokenPipeError,ssl.SSLEOFError)):return 'disconnect'
    if isinstance(exc,ssl.SSLError):
        # Enumerated public protocol reasons only; never stringify an exception.
        reason=getattr(exc,'reason',None)
        known={'HTTP_REQUEST','HTTPS_PROXY_REQUEST','WRONG_VERSION_NUMBER',
               'TLSV1_ALERT_UNKNOWN_CA','SSLV3_ALERT_BAD_CERTIFICATE',
               'NO_SHARED_CIPHER','UNSUPPORTED_PROTOCOL','UNEXPECTED_EOF_WHILE_READING'}
        return 'tls_'+reason if reason in known else 'tls_other'
    if isinstance(exc,ValueError):return 'framing'
    return 'other'
