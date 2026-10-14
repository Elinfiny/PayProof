import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation


class InvalidData(ValueError):
    pass


class UnknownResult(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Z0-9-]{1,64}", value):
        raise InvalidData("Invalid identifier")
    return value


def money(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{1,9}\.\d{2}", value):
        raise InvalidData("Amount must have two decimal places")
    try:
        amount = Decimal(value)
    except InvalidOperation:
        raise InvalidData("Invalid amount") from None
    if amount <= 0 or amount > Decimal("1000000.00"):
        raise InvalidData("Amount outside the supported range")
    return value


def currency(value):
    if value not in ("USD", "EUR"):
        raise InvalidData("Only USD and EUR are supported in this slice")
    return value


def project_order(raw, expected):
    """Only allowlisted facts leave the backend. A completed order is not alone proof of paid funds."""
    if not isinstance(raw, dict) or raw.get("id") != expected["id"]:
        raise InvalidData("Order identity mismatch")
    units = raw.get("purchase_units")
    if not isinstance(units, list) or len(units) != 1:
        raise InvalidData("Exactly one purchase unit is supported")
    unit = units[0]
    amount = unit.get("amount", {})
    value, code = money(amount.get("value")), currency(amount.get("currency_code"))
    if (value, code) != (expected["amount"], expected["currency"]):
        raise InvalidData("Order amount/currency conflict")
    status = raw.get("status")
    if status not in ("CREATED", "SAVED", "APPROVED", "PAYER_ACTION_REQUIRED", "COMPLETED", "VOIDED"):
        raise InvalidData("Unrecognized order status")
    updated_at = raw.get("update_time")
    if not isinstance(updated_at, str):
        raise InvalidData("Provider freshness timestamp missing")
    try:
        updated = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        if updated.tzinfo is None or updated > datetime.now(timezone.utc):
            raise ValueError()
    except ValueError:
        raise InvalidData("Provider freshness timestamp invalid") from None
    captures = unit.get("payments", {}).get("captures", [])
    if not isinstance(captures, list) or len(captures) > 10:
        raise InvalidData("Unsupported capture collection")
    projected = []
    for capture in captures:
        a = capture.get("amount", {})
        projected.append({"id": identifier(capture.get("id")), "status": capture.get("status"),
                          "amount": money(a.get("value")), "currency": currency(a.get("currency_code"))})
    if len({c["id"] for c in projected}) != len(projected):
        raise InvalidData("Duplicate capture identity")
    if any(c["currency"] != code or c["status"] not in ("COMPLETED", "PENDING", "DECLINED", "FAILED", "REFUNDED", "PARTIALLY_REFUNDED") for c in projected):
        raise InvalidData("Capture currency/status conflict")
    if sum((Decimal(c["amount"]) for c in projected), Decimal(0)) > Decimal(value):
        raise InvalidData("Capture total exceeds expected amount")
    if any(c["status"] in ("REFUNDED", "PARTIALLY_REFUNDED") for c in projected):
        state = "REVIEW_REQUIRED"
    elif any(c["status"] in ("DECLINED", "FAILED") for c in projected):
        state = "REVIEW_REQUIRED"
    elif any(c["status"] == "PENDING" for c in projected):
        state = "PENDING"
    elif status == "COMPLETED" and projected and sum((Decimal(c["amount"]) for c in projected), Decimal(0)) == Decimal(value):
        state = "COMPLETED"
    elif status == "COMPLETED":
        state = "UNKNOWN"
    elif projected:
        state = "REVIEW_REQUIRED"
    else:
        state = status
    return {"id": expected["id"], "amount": value, "currency": code, "provider_status": status,
            "state": state, "captures": projected, "provider_updated_at": updated.isoformat()}


def explain(order):
    state = order["state"]
    messages = {
        "CREATED": ("Order created; no payment is verified.", "Wait for payer approval in the sandbox."),
        "APPROVED": ("Payer approval is recorded; this is not a completed payment.", "Check the authoritative order after sandbox checkout."),
        "PENDING": ("Capture is pending; do not treat it as settled.", "Reconcile using a fresh authoritative order read."),
        "COMPLETED": ("The order and completed captures match the expected total.", "Record this sandbox result; no real funds were moved by PayProof."),
        "VOIDED": ("The order is voided.", "Review the sandbox order; do not retry a payment here."),
        "SAVED": ("The order is saved; no payment is verified.", "Inspect its next sandbox step."),
        "PAYER_ACTION_REQUIRED": ("The provider reports that payer action is required.", "Complete the required action through the sandbox provider."),
        "REVIEW_REQUIRED": ("The evidence needs review; payment completion is not asserted.", "Inspect capture/refund facts through the sandbox provider."),
        "UNKNOWN": ("The current outcome is unknown; no completion is asserted.", "Reconcile with a fresh read. Do not repeat a financial operation."),
        "CONFLICT": ("Order facts conflict with the registered expectation.", "Inspect identity, amount and currency before relying on this result."),
    }
    message, action = messages.get(state, messages["UNKNOWN"])
    return {"mode": "DETERMINISTIC — NOT LIVE AI", "text": message, "next_step": action,
            "sources": ["state", "amount", "currency", "provider_status", "captures"],
            "can_execute_payments": False}


class Store:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, amount TEXT NOT NULL,
                  currency TEXT NOT NULL, state TEXT NOT NULL, facts TEXT, source TEXT,
                  observed_at TEXT, last_verified TEXT);
                CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, digest TEXT NOT NULL,
                  order_id TEXT NOT NULL, disposition TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS effects(request_id TEXT PRIMARY KEY, digest TEXT NOT NULL,
                  state TEXT NOT NULL, order_id TEXT);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def register(self, order_id, amount, code):
        identifier(order_id); money(amount); currency(code)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
            if row:
                if (row["amount"], row["currency"]) != (amount, code):
                    raise InvalidData("Registered expectation is immutable")
            else:
                db.execute("INSERT INTO orders(id,amount,currency,state,source) VALUES(?,?,?,'UNKNOWN','NONE')", (order_id, amount, code))

    def order(self, order_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not row:
            raise InvalidData("Order is not registered")
        row = dict(row)
        row["facts"] = json.loads(row["facts"]) if row["facts"] else None
        row["last_verified"] = json.loads(row["last_verified"]) if row["last_verified"] else None
        row["explanation"] = explain(row)
        return row

    def list_orders(self):
        with self.connect() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM orders ORDER BY id")]
        return [self.order(i) for i in ids]

    def observe(self, order_id, raw, source):
        expected = self.order(order_id)
        try:
            facts = project_order(raw, expected)
            state = facts["state"]
        except (InvalidData, TypeError, AttributeError, KeyError):
            facts, state = None, "CONFLICT"
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._update(db, order_id, facts, state, source)
        return self.order(order_id)

    def _update(self, db, order_id, facts, state, source):
        now = datetime.now(timezone.utc).isoformat()
        old = db.execute("SELECT facts,state,last_verified FROM orders WHERE id=?", (order_id,)).fetchone()
        last = old["last_verified"]
        previous = json.loads(last)["facts"] if last else None
        if facts and previous:
            before = datetime.fromisoformat(previous["provider_updated_at"])
            after = datetime.fromisoformat(facts["provider_updated_at"])
            if after < before:
                return "STALE_IGNORED"  # Delayed read/event cannot roll back newer verified evidence.
            if after == before and canonical(facts) != canonical(previous):
                facts, state = None, "CONFLICT"
        if facts and state not in ("UNKNOWN", "CONFLICT"):
            last = canonical({"facts": facts, "source": source, "observed_at": now})
        db.execute("UPDATE orders SET state=?,facts=?,source=?,observed_at=?,last_verified=? WHERE id=?",
                   (state, canonical(facts) if facts else None, source, now, last, order_id))
        return "CONFLICT" if state == "CONFLICT" else "APPLIED"

    def unknown(self, order_id, source):
        with self.connect() as db:
            self._update(db, order_id, None, "UNKNOWN", source)
        return self.order(order_id)

    def event(self, event, verified, fetch_order, source):
        if verified is not True:
            raise InvalidData("Webhook authenticity not verified")
        if not isinstance(event, dict):
            raise InvalidData("Webhook object required")
        if event.get("event_type") not in ("CHECKOUT.ORDER.APPROVED", "PAYMENT.CAPTURE.COMPLETED", "PAYMENT.CAPTURE.PENDING", "PAYMENT.CAPTURE.DENIED", "PAYMENT.CAPTURE.REFUNDED"):
            raise InvalidData("Unsupported webhook type")
        event_id = identifier(event.get("id"))
        resource = event.get("resource", {})
        if not isinstance(resource, dict):
            raise InvalidData("Webhook resource object required")
        if event["event_type"].startswith("CHECKOUT.ORDER."):
            order_id = resource.get("id")
        else:
            supplementary = resource.get("supplementary_data", {})
            related = supplementary.get("related_ids", {}) if isinstance(supplementary, dict) else None
            if not isinstance(related, dict):
                raise InvalidData("Webhook order relation required")
            order_id = related.get("order_id")
        identifier(order_id)
        expected = self.order(order_id)
        digest = hashlib.sha256(canonical(event).encode()).hexdigest()
        with self.connect() as db:
            existing = db.execute("SELECT digest,disposition FROM events WHERE id=?", (event_id,)).fetchone()
        if existing:
            if existing["digest"] != digest:
                raise InvalidData("Webhook ID reused with different content")
            return {"disposition": "DUPLICATE", "original_disposition": existing["disposition"], "order": self.order(order_id)}
        try:
            facts = project_order(fetch_order(order_id), expected)
            state = facts["state"]
            disposition = "NEEDS_RECONCILIATION" if state == "UNKNOWN" else "APPLIED"
        except UnknownResult:
            facts, state, disposition = None, "UNKNOWN", "NEEDS_RECONCILIATION"
        except (InvalidData, TypeError, AttributeError, KeyError):
            facts, state, disposition = None, "CONFLICT", "CONFLICT"
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT digest,disposition FROM events WHERE id=?", (event_id,)).fetchone()
            if existing:
                if existing["digest"] != digest:
                    raise InvalidData("Webhook ID reused with different content")
                return {"disposition": "DUPLICATE", "original_disposition": existing["disposition"], "order": self.order(order_id)}
            applied = self._update(db, order_id, facts, state, source)
            if applied in ("STALE_IGNORED", "CONFLICT"):
                disposition = applied
            db.execute("INSERT INTO events VALUES(?,?,?,?)", (event_id, digest, order_id, disposition))
        return {"disposition": disposition, "order": self.order(order_id)}

    def reconcile(self, order_id, fetch_order, source):
        """Explicit fresh read: never repeats an event or financial operation."""
        try:
            result = self.observe(order_id, fetch_order(order_id), source)
        except UnknownResult:
            return self.unknown(order_id, source)
        if result["state"] not in ("UNKNOWN", "CONFLICT"):
            with self.connect() as db:
                db.execute("UPDATE events SET disposition='RECONCILED' WHERE order_id=? AND disposition='NEEDS_RECONCILIATION'", (order_id,))
        return result

    def reserve_effect(self, request_id, payload):
        identifier(request_id)
        digest = hashlib.sha256(canonical(payload).encode()).hexdigest()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM effects WHERE request_id=?", (request_id,)).fetchone():
                raise InvalidData("Consumed request ID; reconcile, never retry")
            db.execute("INSERT INTO effects VALUES(?,?,'UNKNOWN',NULL)", (request_id, digest))

    def finish_effect(self, request_id, order_id):
        identifier(order_id)
        with self.connect() as db:
            db.execute("UPDATE effects SET state='APPLIED',order_id=? WHERE request_id=?", (order_id, request_id))
