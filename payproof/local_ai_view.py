"""Opt-in local assistance on validated stored evidence; no financial authority.

The service's existing source validation remains first. This module revalidates
the bounded stored projection with project_order before enum-only text reaches
the learned model. It never sees provider free text or receives a provider tool.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import threading
from . import local_ai
from .core import canonical, project_order

_CORPUS_RAW_SHA256 = "ee21d461b563469ce7aeb4d861b6b5ef91cada2bec1e7c3f5f79afaf34ab4023"
_CORPUS_CANONICAL_SHA256 = "4a29e86e87abf252972f05e034a60f589550de95df7dc4a288369b1c0a61c283"
_MODEL_SHA256 = "0513952a8592ad96858b70d87da5cf3d8079b2c5e53e4e38b8dbed2e90d30662"
_LOCK = threading.Lock()
_ATTEMPTED = False
_FIT_CALLS = 0
_HANDLE = None
_SUMMARIES = {
    "APPROVED": ("payer approval record documents buyer consent only", ("approval_record",)),
    "PAYER_ACTION_REQUIRED": ("payer approval record documents buyer consent only", ("approval_record",)),
    "COMPLETED": ("completed capture transaction receipt documentation", ("capture_record",)),
    "PENDING": ("capture record transaction receipt pending", ("capture_record",)),
    "REVIEW_REQUIRED": ("conflicting source records discrepancy review", ("reconciliation_note",)),
    "CREATED": ("missing source documentation request evidence", ("source_log",)),
    "SAVED": ("missing source documentation request evidence", ("source_log",)),
    "VOIDED": ("missing source documentation request evidence", ("source_log",)),
}


@dataclass(frozen=True)
class LocalAssistance:
    model: object
    status: str


def enable_local_assistance():
    """Explicit startup only; bounded pinned corpus, at most one fit per process.

    Failed startup is cached as unavailable. No automatic retry and no fit on
    import. This is a local model selection, never a native PayPal/AI grant.
    """
    global _ATTEMPTED, _FIT_CALLS, _HANDLE
    with _LOCK:
        if _ATTEMPTED:
            return _HANDLE
        _ATTEMPTED = True
        try:
            with Path(__file__).with_name("local_ai_training91.json").open("rb") as stream:
                raw = stream.read(32769)
            if len(raw) > 32768 or hashlib.sha256(raw).hexdigest() != _CORPUS_RAW_SHA256:
                raise ValueError("CORPUS_IDENTITY")
            corpus = json.loads(raw)
            _FIT_CALLS += 1
            model = local_ai.fit(corpus)
            if model.corpus_sha256 != _CORPUS_CANONICAL_SHA256 or model.fingerprint != _MODEL_SHA256:
                raise ValueError("MODEL_IDENTITY")
            _HANDLE = LocalAssistance(model, "READY")
        except Exception:
            # Do not log a path, exception payload, provider data or credentials.
            _HANDLE = LocalAssistance(None, "MODEL_UNAVAILABLE")
        return _HANDLE


def _pin(value):
    return value if type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) else ""


def assistance_metadata(handle, synthetic=False):
    enabled = type(handle) is LocalAssistance
    model = handle.model if enabled and type(handle.model) is local_ai.FittedModel else None
    mode = ("LOCAL MODEL ASSISTANCE — SYNTHETIC DEMO" if synthetic else "LOCAL MODEL ASSISTANCE") if enabled else "DETERMINISTIC — NOT LIVE AI"
    if enabled and model is None:
        mode += " — UNAVAILABLE"
    return {"mode": mode, "enabled": enabled, "model_ready": model is not None,
            "model_fingerprint": _pin(model.fingerprint) if model else "",
            "corpus_sha256": _pin(model.corpus_sha256) if model else "",
            "synthetic": bool(synthetic), "financial_authority": False,
            "live_paypal_verified": False, "payment_actions": []}


def _unknown(handle, synthetic, reason):
    return dict(assistance_metadata(handle, synthetic), priority="unknown",
                text="Local advisory priority is unknown; use the validated evidence and deterministic status.",
                uncertainty=True, reason=reason, source_fields=[])


def _timestamp(value):
    if type(value) is not str or not 1 <= len(value) <= 64:
        raise ValueError("PROVENANCE")
    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None or value > datetime.now(timezone.utc):
        raise ValueError("PROVENANCE")


def _validated_state(order, synthetic):
    """Recheck the exact existing projection, not a caller's validation string.

    Authenticity still belongs to the existing Store/service/host admission.
    Reprojection checks consistency only; it creates no authenticity grant.
    Historical last_verified is never substituted for uncertain current facts.
    """
    if type(order) is not dict:
        raise ValueError("ORDER")
    allowed = {"SYNTHETIC_FIXTURE", "SYNTHETIC_VERIFICATION_STUB", "SANDBOX_CONTRACT_TEST"} if synthetic else {"PAYPAL_SANDBOX"}
    if type(order.get("source")) is not str or order["source"] not in allowed:
        raise ValueError("PROVENANCE")
    _timestamp(order.get("observed_at"))
    facts = order.get("facts")
    keys = {"id", "amount", "currency", "provider_status", "state", "captures", "provider_updated_at"}
    if type(facts) is not dict or set(facts) != keys:
        raise ValueError("CURRENT_FACTS")
    for key in keys - {"captures"}:
        if type(facts[key]) is not str or not 1 <= len(facts[key]) <= 128:
            raise ValueError("FACT_LIMIT")
    for key in ("id", "amount", "currency"):
        if type(order.get(key)) is not str or not 1 <= len(order[key]) <= 128:
            raise ValueError("EXPECTED_LIMIT")
    captures = facts["captures"]
    if type(captures) is not list or len(captures) > 10:
        raise ValueError("CAPTURE_LIMIT")
    raw_captures = []
    for capture in captures:
        if type(capture) is not dict or set(capture) != {"id", "status", "amount", "currency"}:
            raise ValueError("CAPTURE_SCHEMA")
        if any(type(v) is not str or not 1 <= len(v) <= 128 for v in capture.values()):
            raise ValueError("CAPTURE_LIMIT")
        raw_captures.append({"id": capture["id"], "status": capture["status"],
                             "amount": {"value": capture["amount"], "currency_code": capture["currency"]}})
    raw = {"id": facts["id"], "status": facts["provider_status"],
           "update_time": facts["provider_updated_at"],
           "purchase_units": [{"amount": {"value": facts["amount"], "currency_code": facts["currency"]},
                               "payments": {"captures": raw_captures}}]}
    projected = project_order(raw, order)
    if canonical(projected) != canonical(facts) or projected["state"] != order.get("state"):
        raise ValueError("PROJECTION_MISMATCH")
    return projected["state"]


def advisory_view(order, handle=None, synthetic=False):
    if type(handle) is not LocalAssistance:
        return _unknown(handle, synthetic, "DISABLED")
    if type(handle.model) is not local_ai.FittedModel:
        return _unknown(handle, synthetic, "MODEL_UNAVAILABLE")
    try:
        state = _validated_state(order, synthetic)
        if state not in _SUMMARIES:
            return _unknown(handle, synthetic, "UNCERTAIN_CURRENT_EVIDENCE")
        text, references = _SUMMARIES[state]
        # Text and reference labels come exclusively from the fixed enum map.
        # No amount, ID, timestamp, payer text, URL or provider string is sent.
        prediction = local_ai.predict_priority(handle.model, local_ai.SanitizedFacts(
            text, "VALIDATED_SANITIZED_FACTS", references))
        if prediction.abstained:
            return _unknown(handle, synthetic, prediction.reason)
        if prediction.label not in local_ai.LABELS or prediction.financial_authority or prediction.payment_actions:
            return _unknown(handle, synthetic, "INVALID_MODEL_OUTPUT")
        return dict(assistance_metadata(handle, synthetic), priority=prediction.label,
                    text=prediction.explanation, uncertainty=False,
                    reason="MODEL_ASSISTED_PRIORITY_NOT_FINANCIAL_TRUTH",
                    source_fields=["state", "provider_status", "captures"])
    except Exception:
        return _unknown(handle, synthetic, "INVALID_OR_UNVERIFIED_EVIDENCE")

