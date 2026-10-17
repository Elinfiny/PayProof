# Local learned explanation priority — inactive candidate91

This candidate fits a standard-library multinomial Naive Bayes text model using
32 original, public synthetic sentences (eight per class, CC0-1.0). The learned
document/token counts determine predictions. No pretrained model, installation,
download, external inference, key, transport or telemetry is used.

The four nonbinding priorities are approval context, capture context,
conflicting-evidence review and requesting missing evidence. A prediction selects
a fixed safe explanatory template; the template is not the learned model.
The API emits no financial status, amount, transaction identifier or payment
action. It may echo only caller-supplied allowlisted reference labels. It does
not authenticate evidence, establish payment truth, or judge fraud/creditworthiness.
Financial proof, state transitions and native admission remain deterministic.

## Explicit use

Call `fit(corpus_dict)` explicitly, then
`predict_priority(fitted_model, SanitizedFacts(text, "VALIDATED_SANITIZED_FACTS",
("source_log",)))`. This validation label is not an authority token: the future
caller must actually validate source facts before constructing the projection.
Import does not read a file, train, register a route or modify existing behavior.
Missing model, unvalidated evidence, invalid input, low vocabulary coverage or
ambiguous posterior returns unknown. No UI/server/service/core file is changed.

Inputs are deliberately narrow English synthetic-style summaries, not raw
provider payloads: at most512 UTF-8 bytes/96 tokens, letters/whitespace/hyphens,
no URLs, digits/identifiers, email, possible-secret markers or long tokens.
This reduces exposure; it is not a universal detector of secrets or prompt attacks.
Untrusted text is counted as data and has no instructions/tools or execution path.

## Frozen qualification protocol

Exactly one new four-scenario group, at most120 seconds; no old suite or smoke.
Source and corpus hashes are frozen before that run. Sixteen held-out sentences
have distinct scenario/group IDs and normalized sentences from the training set.
They and six unrelated-domain OOD probes are not passed to fit or used to tune.
Small, manually authored English examples share vocabulary and evidence concepts:
this is a limited functional qualification, not independent real-world accuracy
or broad robustness evidence.

Fixed pre-run thresholds: Laplace1; posterior>=0.72, winner margin>=0.25,
known-token fraction>=0.65 and at least two distinct known tokens. Holdout
coverage>=0.75, selective accuracy>=0.90, overall accuracy>=0.75; all six OOD
probes must abstain. The actual run reports the confusion matrix, per-class
counts, abstentions, coverage and measured performance without substituting
future targets. No post-run tuning or repair-and-replay is admitted in91.

The remaining cases verify financial immutability/no invented facts or references;
malformed/oversized/possible-secret/OOD input and audited I/O rejection; and
determinism, model/corpus identities, actual changed-training sensitivity and
zero fit calls on import. Sensitivity alters training labels and measures changed
training-probe predictions; it is not another holdout tuning pass. An audit hook
rejects file/process/network operations during model import, fit and prediction
after the harness has loaded the fixed sources/corpus/stdlib.

## Limits and next integration

This is an inactive private review candidate, not live AI in the product.
The existing frontend and all71 canonical source leaves remain unchanged.
A later independently reviewed integration can feed a validated, sanitized
evidence summary into the explicit fitted-model API and display its priority
alongside unchanged deterministic financial status. It must preserve unknown
and conflicting evidence and clearly label uncertainty and non-authority.

The real PayPal Sandbox app allocation, authentic credential custody, admitted
once-only native invocation and working Sandbox integration remain open.
The contained browser restrictions/unknown attempts are not rearmed.
Local ML is a plausible contest approach; organizer eligibility and the contest
AI requirement are not declared fulfilled by source or this qualification alone.

