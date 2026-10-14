"""Private orchestration contract. This service is not exposed by the fixture HTTP app."""
import hashlib
from dataclasses import dataclass
from typing import Protocol
from .admission import _json, load_host_context
from .core import InvalidData, UnknownResult, canonical, explain
from .paypal import SandboxPayPal


class ExplanationPort(Protocol):
    """Future gateway gets facts only, never a store, PayPal client or tool capability."""
    def explain_facts(self, request: dict) -> dict: ...


def explanation_request(order):
    fields = {'state':order['state'],'amount':order['amount'],'currency':order['currency'],
              'provider_facts':order.get('facts'),'source':order['source'],'observed_at':order.get('observed_at')}
    return {'schema':'PAYPROOF_EXPLANATION_REQUEST_V1','facts':fields,
            'facts_sha256':hashlib.sha256(canonical(fields).encode()).hexdigest(),
            'tools':[], 'transaction_actions':[], 'mode':'LIVE_AI_NOT_ADMITTED'}


def inspect_candidate(candidate, request):
    """Validate a synthetic model-output contract, never grant live-AI status."""
    if not isinstance(candidate,dict) or set(candidate) != {'facts_sha256','summary','uncertainty'}:
        raise InvalidData('Explanations may not contain tools or transaction commands')
    if candidate['facts_sha256'] != request['facts_sha256']:
        raise InvalidData('Explanation source binding mismatch')
    if not isinstance(candidate['summary'],str) or not 0 < len(candidate['summary']) <= 1200 or not isinstance(candidate['uncertainty'],bool):
        raise InvalidData('Explanation output schema invalid')
    if request['facts']['state'] in ('UNKNOWN','CONFLICT','REVIEW_REQUIRED') and candidate['uncertainty'] is not True:
        raise InvalidData('Explanation must preserve uncertainty')
    return {'mode':'UNTRUSTED_CANDIDATE — NOT LIVE AI','text':candidate['summary'],
            'uncertainty':candidate['uncertainty'],'facts_sha256':candidate['facts_sha256'],'tools':[]}


@dataclass
class PaymentEvidenceService:
    store: object
    adapter: SandboxPayPal

    def __post_init__(self):
        if type(self.adapter) is not SandboxPayPal:
            raise InvalidData('A concrete host-qualified sandbox adapter is required')

    @classmethod
    def from_host(cls,store):
        return cls(store,SandboxPayPal(load_host_context()))

    def create(self,request_id,amount,currency):
        self.adapter.context.require('orders:create')
        return self.adapter.create_order(self.store,request_id,amount,currency)

    def read(self,order_id):
        self.adapter.context.require('orders:read')
        order = self.store.reconcile(order_id,self.adapter.get_order,self.adapter.mode)
        return self._view(order)

    def webhook(self,headers,raw_body):
        # Local validation does not consume an event or supply authenticity.
        if not isinstance(raw_body,bytes) or not 0 < len(raw_body) <= 65536:
            raise InvalidData('Bounded original webhook bytes required')
        event = _json(raw_body)
        self.adapter.context.require('webhooks:verify')
        self.adapter.context.require('orders:read')
        try:
            verified = self.adapter.verify_webhook(headers,raw_body)
        except UnknownResult:
            return {'disposition':'VERIFICATION_UNKNOWN','mode':self.adapter.mode,
                    'ledger_effect':False,'live_ai':False}
        # Neither the body nor a boolean in its fields can supply verified=True.
        result = self.store.event(event,verified,self.adapter.get_order,self.adapter.mode)
        return {'disposition':result['disposition'],'view':self._view(result['order'])}

    def explain_with_live_ai(self,order_id,provider:ExplanationPort):
        # No issuer/custody/numeric cap/enforcement has been qualified yet.
        # Do not even invoke the provider while the actual AI gate is OPEN.
        raise InvalidData('Live AI grant, custody and enforced cap are not admitted')

    def _view(self,order):
        return {'mode':self.adapter.mode,'order':order,'explanation':explain(order),
                'explanation_request':explanation_request(order),'live_ai':False,
                'payment_mutation_actions':[]}
