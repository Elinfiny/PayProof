from datetime import datetime, timezone
from .core import InvalidData, UnknownResult

ORDER_ID = "DEMO-ORDER-001"


def order(scenario):
    if scenario == "unknown":
        raise UnknownResult("Synthetic unavailable provider")
    if scenario not in ("created", "approved", "pending", "completed", "conflict", "incomplete", "refunded"):
        raise InvalidData("Unsupported synthetic scenario")
    status = "APPROVED" if scenario == "approved" else "CREATED" if scenario == "created" else "COMPLETED"
    unit = {"amount": {"value": "99.00" if scenario == "conflict" else "120.00", "currency_code": "EUR"}}
    if scenario not in ("created", "approved", "incomplete"):
        unit["payments"] = {"captures": [{"id": "DEMO-CAPTURE-001", "status": "PENDING" if scenario == "pending" else "REFUNDED" if scenario == "refunded" else "COMPLETED",
            "amount": {"value": "120.00", "currency_code": "EUR"}}]}
    return {"id": ORDER_ID, "status": status, "update_time": datetime.now(timezone.utc).isoformat(), "purchase_units": [unit],
            "payer": {"email_address": "synthetic-private-field@example.invalid"}}


def event(scenario, event_id):
    return {"id": event_id, "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {"id": "DEMO-CAPTURE-001", "supplementary_data": {"related_ids": {"order_id": ORDER_ID}}},
            "synthetic_scenario": scenario}
