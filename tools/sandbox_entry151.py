"""Private protected-entry orchestration. Native ports unbound => zero effects."""
from .sandbox_chain151 import Chain151,FixedSandboxNetwork151,NativePorts151,load_native151

def begin151(ports):
 grant,credentials=load_native151(ports)
 # release() belongs to the existing protected host; no ENV/public-JSON fallback.
 engine=Chain151(grant,FixedSandboxNetwork151(grant),ports,source_sha256=ports.current_source(),caller=ports.current_caller())
 try:
  engine.credentials(*credentials);engine.oauth();engine.subscription()
  return engine
 except BaseException:engine.close();raise

def acquire151(engine,qualified_evidence_context):
 # Must finish listener/TLS/custody and exact evidence-context qualification
 # before creating the separate order or starting its approval window.
 engine.bind_evidence(qualified_evidence_context)
 return engine.create_order()

def after_buyer_approval151(engine):
 engine.capture_approved();return engine.read_final()

def finish151(engine,store,headers,raw_event):
 try:
  result=engine.webhook(store,headers,raw_event)
  if engine.created_subscription and engine.verified_complete:engine.cleanup_subscription()
  return result
 finally:engine.close()

if __name__=='__main__':begin151(NativePorts151())


def begin152(root,ledger_path):
 """New provider-managed profile; old109 orders:read stays untouched."""
 from .sandbox_native152 import NativePorts152,ProviderEvidence152
 ports=NativePorts152(root,ledger_path)
 grant,credentials=ports.release()
 engine=Chain151(grant,FixedSandboxNetwork151(grant),ports,source_sha256=ports.current_source(),caller=ports.current_caller())
 try:
  engine.credentials(*credentials);credentials=None
  engine.oauth();engine.subscription();engine.bind_evidence(ProviderEvidence152(engine))
  return engine
 except BaseException:
  engine.close();raise


def acquire152(engine,store):
 """Register the genuinely new order in the same private evidence Store."""
 from payproof.core import Store
 from .sandbox_chain151 import InvalidData
 from .sandbox_native152 import ProviderEvidence152,SyntheticProviderEvidence152
 if type(store) is not Store or type(engine.evidence_context) not in (ProviderEvidence152,SyntheticProviderEvidence152):raise InvalidData('EXACT_PROVIDER_STORE152')
 engine.evidence_context.require()
 approval=engine.create_order()
 try:store.register(engine.order,'1.00','USD')
 except Exception:engine.freeze() # the create remains consumed, never reconstruct/retry
 return approval
