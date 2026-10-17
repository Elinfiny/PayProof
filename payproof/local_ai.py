"""Inactive local learned explanation-priority candidate; never payment truth.

Pure standard-library multinomial Naive Bayes. Import performs no fit or I/O.
Call fit with an explicit synthetic corpus, then pass that fitted model and an
explicit validated/sanitized fact projection to predict_priority. No transport,
file loader, process, network, mutable financial state, or action tool exists.
"""
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
import re

LABELS = ("approval_context", "capture_context", "conflict_review", "request_evidence")
UNKNOWN = "unknown"
MAX_ROWS = 256
MAX_CORPUS_BYTES = 32768
MAX_VOCAB = 2048
MAX_TEXT_BYTES = 512
MAX_TOKENS = 96
MIN_KNOWN_FRACTION = 0.65
MIN_POSTERIOR = 0.72
MIN_MARGIN = 0.25
ALGORITHM = "multinomial-naive-bayes-laplace1-v91"
REFERENCES = frozenset(("approval_record", "capture_record", "source_log",
                        "reconciliation_note", "missing_item_summary"))
_TOKENS = re.compile(r"[a-z]+")
_RISK = re.compile(r"https?://|www\.|@|[0-9]|secret|password|token|api[ _-]?key|client[ _-]?id|bearer|-----", re.I)
_TEXT = re.compile(r"[A-Za-z \t\r\n-]+")
_TEMPLATES = {
    "approval_context": "Prioritize reviewing the scope of the supplied approval evidence.",
    "capture_context": "Prioritize reviewing the supplied capture evidence and its source.",
    "conflict_review": "Prioritize reconciling discrepancies in the supplied evidence.",
    "request_evidence": "Prioritize requesting the missing evidence and verifying its source.",
    UNKNOWN: "Priority unknown; rely on validated evidence and deterministic status.",
}


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tokens(text):
    if type(text) is not str:
        raise ValueError("TEXT_TYPE")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        raise ValueError("TEXT_ENCODING") from None
    if not 1 <= size <= MAX_TEXT_BYTES or _RISK.search(text) or not _TEXT.fullmatch(text):
        raise ValueError("TEXT_REJECTED")
    result = tuple(_TOKENS.findall(text.lower()))
    if not 1 <= len(result) <= MAX_TOKENS or any(len(w) > 24 for w in result):
        raise ValueError("TOKEN_LIMIT")
    return result


@dataclass(frozen=True)
class SanitizedFacts:
    """Caller projection, not an authority token; no provider payload accepted."""
    text: str
    validation: str
    references: tuple = ()


@dataclass(frozen=True)
class FittedModel:
    algorithm: str
    corpus_sha256: str
    fingerprint: str
    vocabulary: tuple
    document_counts: tuple
    token_counts: tuple
    trained_rows: int


@dataclass(frozen=True)
class PriorityPrediction:
    label: str
    abstained: bool
    reason: str
    confidence: float
    known_token_fraction: float
    model_fingerprint: str
    explanation: str
    supplied_references: tuple
    financial_authority: bool = False
    payment_actions: tuple = ()


def fit(corpus):
    """Learn counts from an explicit bounded corpus. Never read a path or URL."""
    if type(corpus) is not dict or set(corpus) != {"schema", "license", "provenance", "rows"}:
        raise ValueError("CORPUS_SCHEMA")
    if corpus["schema"] != "PAYPROOF_SYNTHETIC_TEXT_TRAINING91_V1" or corpus["license"] != "CC0-1.0":
        raise ValueError("CORPUS_PROVENANCE")
    if type(corpus["provenance"]) is not str or len(corpus["provenance"]) > 512:
        raise ValueError("CORPUS_PROVENANCE")
    rows = corpus["rows"]
    if type(rows) is not list or not 4 <= len(rows) <= MAX_ROWS:
        raise ValueError("CORPUS_ROWS")
    counts = {label: Counter() for label in LABELS}
    docs = Counter()
    groups = set()
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != {"group", "label", "text"}:
            raise ValueError("ROW_SCHEMA")
        group, label = row["group"], row["label"]
        if type(group) is not str or not re.fullmatch(r"[a-z-]{1,48}[0-9]{2}", group) or group in groups:
            raise ValueError("GROUP")
        if type(label) is not str or label not in LABELS:
            raise ValueError("LABEL")
        words = _tokens(row["text"])
        if words in seen:
            raise ValueError("DUPLICATE_TEXT")
        seen.add(words)
        groups.add(group)
        counts[label].update(words)
        docs[label] += 1
    if any(docs[label] < 1 for label in LABELS):
        raise ValueError("MISSING_CLASS")
    if len(_canonical(corpus)) > MAX_CORPUS_BYTES:
        raise ValueError("CORPUS_SIZE")
    vocabulary = tuple(sorted(set().union(*(set(c) for c in counts.values()))))
    if not 2 <= len(vocabulary) <= MAX_VOCAB:
        raise ValueError("VOCABULARY")
    document_counts = tuple(docs[label] for label in LABELS)
    token_counts = tuple(tuple(counts[label][w] for w in vocabulary) for label in LABELS)
    corpus_id = _digest(corpus)
    params = {"algorithm": ALGORITHM, "corpus": corpus_id, "vocabulary": vocabulary,
              "document_counts": document_counts, "token_counts": token_counts}
    return FittedModel(ALGORITHM, corpus_id, _digest(params), vocabulary,
                       document_counts, token_counts, len(rows))


def _unknown(reason, model=None, coverage=0.0, confidence=0.0):
    pin = (model.fingerprint if type(model) is FittedModel
           and type(model.fingerprint) is str
           and re.fullmatch(r"[a-f0-9]{64}", model.fingerprint) else "")
    return PriorityPrediction(UNKNOWN, True, reason, confidence, coverage, pin,
                              _TEMPLATES[UNKNOWN], ())


def predict_priority(model, facts):
    """Nonbinding learned priority only; input facts and financial state untouched.

    The caller must verify source facts independently before making this narrow
    sanitized projection. The validation string itself grants no host authority.
    References can only be returned from the caller's fixed allowlisted labels.
    """
    if type(model) is not FittedModel:
        return _unknown("MISSING_FITTED_MODEL")
    if model.algorithm != ALGORITHM or type(facts) is not SanitizedFacts:
        return _unknown("INVALID_INPUT", model)
    if facts.validation != "VALIDATED_SANITIZED_FACTS":
        return _unknown("UNVALIDATED_FACTS", model)
    refs = facts.references
    if type(refs) is not tuple or len(refs) > 8 or any(type(r) is not str or r not in REFERENCES for r in refs):
        return _unknown("INVALID_REFERENCES", model)
    try:
        words = _tokens(facts.text)
    except ValueError as exc:
        return _unknown(str(exc), model)
    # All dimensions/counts are bounded and obtained from fit; a forged model
    # cannot grant financial authority, even when a caller constructs the class.
    v = model.vocabulary
    if (type(v) is not tuple or not 2 <= len(v) <= MAX_VOCAB
            or any(type(w) is not str or not re.fullmatch(r"[a-z]{1,24}", w) for w in v)
            or len(set(v)) != len(v)
            or type(model.document_counts) is not tuple or type(model.token_counts) is not tuple
            or len(model.document_counts) != len(LABELS) or len(model.token_counts) != len(LABELS)
            or any(type(n) is not int or not 1 <= n <= MAX_ROWS for n in model.document_counts)
            or any(type(row) is not tuple or len(row) != len(v)
                   or any(type(n) is not int or not 0 <= n <= MAX_ROWS * MAX_TOKENS for n in row)
                   for row in model.token_counts)):
        return _unknown("INVALID_MODEL", model)
    params = {"algorithm": ALGORITHM, "corpus": model.corpus_sha256, "vocabulary": v,
              "document_counts": model.document_counts, "token_counts": model.token_counts}
    if model.fingerprint != _digest(params):
        return _unknown("MODEL_IDENTITY_MISMATCH", model)
    index = {word: i for i, word in enumerate(v)}
    known = [word for word in words if word in index]
    coverage = len(known) / len(words)
    if coverage < MIN_KNOWN_FRACTION or len(set(known)) < 2:
        return _unknown("OUT_OF_DISTRIBUTION", model, coverage)
    sample = Counter(known)
    total_docs = sum(model.document_counts)
    scores = []
    for k in range(len(LABELS)):
        row = model.token_counts[k]
        denominator = sum(row) + len(v)
        score = math.log((model.document_counts[k] + 1) / (total_docs + len(LABELS)))
        score += sum(n * math.log((row[index[word]] + 1) / denominator)
                     for word, n in sample.items())
        scores.append(score)
    top = max(scores)
    weights = [math.exp(s - top) for s in scores]
    probs = [w / sum(weights) for w in weights]
    ranked = sorted(range(len(LABELS)), key=lambda k: (-probs[k], k))
    winner, runner = ranked[:2]
    confidence = probs[winner]
    if confidence < MIN_POSTERIOR or confidence - probs[runner] < MIN_MARGIN:
        return _unknown("AMBIGUOUS", model, coverage, confidence)
    label = LABELS[winner]
    return PriorityPrediction(label, False, "MODEL_ASSISTED_PRIORITY_NOT_TRUTH",
                              confidence, coverage, model.fingerprint,
                              _TEMPLATES[label], refs)

