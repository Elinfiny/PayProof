"""One isolated direction92 product-path group; no sockets or live providers."""
import sys
from pathlib import Path
import json
import hashlib
from dataclasses import replace
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from payproof import local_ai, local_ai_view, fixtures
from payproof.server import prepare_application, dispatch_post
from payproof.service import PaymentEvidenceService
from payproof.core import InvalidData, canonical

HTML = (ROOT / 'payproof/web/index.html').read_text()
JS = (ROOT / 'payproof/web/app.js').read_text()
DB = ROOT / '.integration92' / 'sole-group.sqlite3'
assert not DB.exists()
assert not local_ai_view._ATTEMPTED and local_ai_view._FIT_CALLS == 0
attempts = []
def audit(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'urllib.Request'):
        attempts.append(event)
        raise AssertionError('Forbidden external effect')
    if event == 'sqlite3.connect':
        assert str(args[0]) == str(DB)
sys.addaudithook(audit)

fit = local_ai.fit
fit_calls = []
def counted_fit(corpus):
    fit_calls.append(1)
    return fit(corpus)
local_ai.fit = counted_fit
predict = local_ai.predict_priority
inputs = []
def counted_predict(model, facts):
    inputs.append(facts)
    return predict(model, facts)
local_ai.predict_priority = counted_predict

def emit(number, detail):
    print(json.dumps({'case': 'INTEGRATION92-' + str(number), 'status': 'PASS', 'detail': detail}), flush=True)

def post(app, scenario, origin='http://127.0.0.1:19292', path='/api/fixture'):
    body = json.dumps({'scenario': scenario}).encode()
    headers = {'Host':'127.0.0.1:19292', 'Origin':origin, 'Content-Type':'application/json',
               'X-PayProof-Request':'fixture-ui', 'Content-Length':str(len(body))}
    return dispatch_post(app, path, headers, body, 19292)

def row(app):
    original = app.store.order(fixtures.ORDER_ID)
    viewed = app.state()['orders'][0]
    assert {k:v for k,v in viewed.items() if k != 'local_assistance'} == original
    advice = viewed['local_assistance']
    assert advice['financial_authority'] is False and advice['payment_actions'] == []
    assert advice['live_paypal_verified'] is False
    assert 'confidence' not in advice
    return original, advice

# Actual startup, Store reconciliation, service annotation and API state path.
app = prepare_application('fixture', DB, local_ai=True)
assert len(fit_calls) == 1 and local_ai_view._FIT_CALLS == 1
assert app.assistance.status == 'READY'
observations = []
for scenario, state, label in [('approved','APPROVED','approval_context'), ('completed','COMPLETED','capture_context')]:
    status, _ = post(app, scenario)
    assert status == 200
    original, advice = row(app)
    assert original['state'] == state and advice['priority'] == label
    assert advice['uncertainty'] is False
    assert advice['source_fields'] == ['state','provider_status','captures']
    observations.append({'financial_state':state, 'learned_priority':advice['priority']})
assert len(inputs) == 2
for facts in inputs:
    assert not any(c.isdigit() for c in facts.text)
    assert 'DEMO' not in facts.text and 'EUR' not in facts.text and '@' not in facts.text
emit(1, {'actual_path':'dispatch_post -> Store.reconcile/project_order -> HttpApplication.state -> service.annotated_order -> real learned prediction',
         'observations':observations, 'persisted_financial_fields_unchanged':True})

uncertain = []
for scenario, state in [('conflict','CONFLICT'), ('unknown','UNKNOWN'), ('incomplete','UNKNOWN')]:
    assert post(app, scenario)[0] == 200
    original, advice = row(app)
    assert original['state'] == state and advice['priority'] == 'unknown' and advice['uncertainty']
    assert advice['source_fields'] == []
    uncertain.append({'input':scenario, 'financial_state':state, 'advisory':'unknown'})
assert post(app, 'completed')[0] == 200
with app.store.connect() as db:
    db.execute('UPDATE orders SET source=? WHERE id=?', ('UNVERIFIED_INPUT', fixtures.ORDER_ID))
original, advice = row(app)
assert original['state'] == 'COMPLETED' and advice['priority'] == 'unknown'
assert advice['source_fields'] == []
emit(2, {'uncertain_evidence':uncertain, 'tampered_provenance':'unknown, no invented references',
         'historical_evidence_not_promoted':True, 'stored_financial_state_untouched':True})

# Stored-data attacks are rejected before constructing model facts.
assert post(app, 'completed')[0] == 200
clean = app.store.order(fixtures.ORDER_ID)['facts']
rejections = []
for bad in ('x' * 513, 'secret credential password token'):
    tampered = dict(clean, provider_status=bad)
    with app.store.connect() as db:
        db.execute('UPDATE orders SET facts=? WHERE id=?', (canonical(tampered), fixtures.ORDER_ID))
    before = len(inputs)
    original, advice = row(app)
    assert advice['priority'] == 'unknown' and advice['source_fields'] == []
    assert len(inputs) == before and bad not in canonical(advice)
    rejections.append('rejected before model')
assert post(app, 'completed')[0] == 200
unavailable = replace(app, assistance=local_ai_view.LocalAssistance(None, 'MODEL_UNAVAILABLE'))
assert row(unavailable)[1]['priority'] == 'unknown'
# Fault-inject OOD at model boundary, retaining actual app/API and real predictor.
def ood_predict(model, facts):
    return predict(model, local_ai.SanitizedFacts('orchard telescope velvet nebula', 'VALIDATED_SANITIZED_FACTS', ()))
local_ai.predict_priority = ood_predict
assert row(app)[1]['priority'] == 'unknown'
local_ai.predict_priority = counted_predict
assert not attempts
emit(3, {'oversized_and_possible_secret':rejections, 'model_unavailable':'unknown',
         'actual_predictor_ood_fault_injection':'abstained through API view', 'forbidden_external_events':attempts})

disabled = prepare_application('fixture', DB)
assert row(disabled)[1]['priority'] == 'unknown'
assert disabled.state()['ai_mode'] == 'DETERMINISTIC — NOT LIVE AI'
again = prepare_application('fixture', DB, local_ai=True)
assert again.assistance is app.assistance and local_ai_view.enable_local_assistance() is app.assistance
assert len(fit_calls) == 1 and local_ai_view._FIT_CALLS == 1
meta = app.state()['local_model']
assert meta['mode'] == 'LOCAL MODEL ASSISTANCE — SYNTHETIC DEMO'
assert meta['model_fingerprint'] == local_ai_view._MODEL_SHA256
assert meta['corpus_sha256'] == local_ai_view._CORPUS_CANONICAL_SHA256
class Elements(HTMLParser):
    def __init__(self):
        super().__init__(); self.ids = {}
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if 'id' in d:
            assert d['id'] not in self.ids
            self.ids[d['id']] = d
elements = Elements(); elements.feed(HTML); elements.close()
for id in ('ai-mode','local-priority','local-explanation','local-uncertainty','local-model-id'):
    assert id in elements.ids and ("byId('" + id + "').textContent") in JS
assert elements.ids['local-priority']['aria-live'] == 'polite'
assert 'innerHTML' not in JS and 'insertAdjacentHTML' not in JS and 'document.write' not in JS
assert 'not calibrated payment certainty' in HTML and 'verified live Sandbox' in HTML
assert post(app, 'approved', origin='https://foreign.invalid')[0] == 403
for path in ('/api/capture', '/api/refund', '/api/sandbox/read'):
    assert post(app, 'approved', path=path)[0] == 404
provider_calls = []
class Provider:
    def explain_facts(self, request):
        provider_calls.append(1); raise AssertionError('Provider invoked')
try:
    PaymentEvidenceService.explain_with_live_ai(None, fixtures.ORDER_ID, Provider())
    raise AssertionError('Live AI gate opened')
except InvalidData:
    pass
assert provider_calls == [] and attempts == []
emit(4, {'fit_on_import':0, 'fit_per_process':len(fit_calls), 'default_disabled':True,
         'model_identity':meta, 'safe_html_textContent_contract':True, 'actual_renderer':False,
         'unchanged_origin_and_route_rejections':True, 'live_ai_provider_calls':len(provider_calls)})
print(json.dumps({'status':'PASS','cases':4,'group_invocations':1,'synthetic_only':True,
                  'provider_calls':0,'socket_calls':0,'external_model_calls':0,'actual_renderer':False,
                  'native_paypal_qualified':False,'spend_usd':0}), flush=True)
