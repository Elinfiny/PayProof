"""Prepared server-side sandbox adapter. Not wired into the private fixture app."""
import base64
import json
import re
import urllib.error
import urllib.request
from .core import InvalidData, UnknownResult, identifier, money, currency
from .admission import SandboxContext

BASE = "https://api-m.sandbox.paypal.com"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise UnknownResult("Provider redirect rejected")


class SandboxPayPal:
    def __init__(self, context, transport=None):
        if type(context) is not SandboxContext:
            raise InvalidData("Verified host sandbox context required")
        if context.test_only and transport is None:
            raise InvalidData("Synthetic host context cannot use network transport")
        self.context = context
        self.client_id, self.client_secret, self.webhook_id = context.client_id, context.client_secret, context.webhook_id
        self.mode = "SANDBOX_CONTRACT_TEST" if transport is not None else "PAYPAL_SANDBOX"
        self.transport = transport or self._network

    def _network(self, method, path, headers, body):
        request = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
                data = response.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise UnknownResult("Provider response too large")
                return json.loads(data)
        except (OSError, ValueError, urllib.error.URLError):
            # Never log response bodies, headers or credentials.
            raise UnknownResult("Provider outcome unavailable; reconciliation required") from None

    def _token(self):
        self.context.require(next(iter(self.context.operations)))
        credential = base64.b64encode((self.client_id + ":" + self.client_secret).encode()).decode()
        result = self.transport("POST", "/v1/oauth2/token", {"Authorization": "Basic " + credential,
                   "Content-Type": "application/x-www-form-urlencoded"}, b"grant_type=client_credentials")
        if not isinstance(result, dict) or not isinstance(result.get("access_token"), str) or not result["access_token"]:
            raise UnknownResult("Sandbox authentication unavailable")
        return result["access_token"]

    def request(self, method, path, payload=None, request_id=None):
        allowed = ((method == "GET" and re.fullmatch(r"/v2/checkout/orders/[A-Z0-9]{1,36}", path)) or
                   (method == "POST" and path in ("/v2/checkout/orders", "/v1/notifications/verify-webhook-signature")))
        if not allowed:
            raise InvalidData("Endpoint outside the admitted sandbox adapter")
        operation = "orders:read" if method == "GET" else "orders:create" if path == "/v2/checkout/orders" else "webhooks:verify"
        self.context.require(operation)
        token = self._token()
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        if request_id:
            if len(request_id) > 38:
                raise InvalidData("Request ID too long")
            headers["PayPal-Request-Id"] = identifier(request_id)
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode() if payload is not None else None
        self.context.require(operation)
        return self.transport(method, path, headers, body)

    def get_order(self, order_id):
        identifier(order_id)
        if not re.fullmatch(r"[A-Z0-9]{1,36}", order_id):
            raise InvalidData("Invalid PayPal order ID")
        return self.request("GET", "/v2/checkout/orders/" + order_id)

    def create_order(self, store, request_id, amount, code):
        self.context.require("orders:create")
        identifier(request_id)
        if len(request_id) > 38:
            raise InvalidData("Request ID too long")
        payload = {"intent": "CAPTURE", "purchase_units": [{"amount": {"value": money(amount), "currency_code": currency(code)}}]}
        store.reserve_effect(request_id, payload)  # Durable before the first network effect.
        result = self.request("POST", "/v2/checkout/orders", payload, request_id)
        if not isinstance(result, dict) or not result.get("id") or result.get("status") not in ("CREATED", "PAYER_ACTION_REQUIRED"):
            raise UnknownResult("Create outcome unknown; do not retry")
        order_id = identifier(result["id"])
        store.register(order_id, amount, code)
        store.finish_effect(request_id, order_id)
        return {"id": order_id, "state": result["status"], "mode": "PAYPAL_SANDBOX"}

    def verify_webhook(self, headers, raw_event):
        if not isinstance(raw_event, bytes) or not 0 < len(raw_event) <= 65536:
            raise InvalidData("Original bounded webhook bytes required")
        def reject_duplicate_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise InvalidData("Duplicate JSON key")
                result[key] = value
            return result
        try:
            event = json.loads(raw_event, object_pairs_hook=reject_duplicate_keys)
        except (ValueError, UnicodeError):
            raise InvalidData("Invalid webhook JSON") from None
        if not isinstance(event, dict):
            raise InvalidData("Webhook object required")
        normalized = {k.lower(): v for k, v in headers.items()}
        mapping = {"auth_algo": "paypal-auth-algo", "cert_url": "paypal-cert-url", "transmission_id": "paypal-transmission-id",
                   "transmission_sig": "paypal-transmission-sig", "transmission_time": "paypal-transmission-time"}
        if any(not isinstance(normalized.get(v), str) or not normalized[v] or len(normalized[v]) > 4096 for v in mapping.values()):
            return False
        payload = {k: normalized[v] for k, v in mapping.items()}
        payload["webhook_id"] = self.webhook_id
        # Preserve the original event JSON bytes inside the verification envelope.
        body = json.dumps(payload).encode()[:-1] + b', "webhook_event": ' + raw_event + b'}'
        result = self.request("POST", "/v1/notifications/verify-webhook-signature", body)
        return isinstance(result, dict) and result.get("verification_status") == "SUCCESS"
