# Private integration contract — direction V28-PAYPAL-REVIEW-NEXT-20261015-01

`PaymentEvidenceService` coordinates a registered expectation, a host-qualified sandbox adapter and deterministic explanations. It is not wired into the fixture HTTP server. The existing interface remains visibly synthetic, with no live integration endpoint.

## Runtime admission boundary

The old `admitted=True` constructor was removed. Production construction accepts a sealed `SandboxContext` produced by `load_host_context()`. The loader accepts no public JSON, path or boolean arguments and checks fixed host locations for the admission, trust key and credentials. Files must be root-owned regular files with mode0600 and one hard link; final-component symlinks are rejected.

The HMAC-authenticated receipt binds project, sandbox environment, exact source fingerprint, application/client identity, webhook identity, explicit operations and expiry. It cannot authorize live AI, paid services, capture, refund or transfer. Every adapter request revalidates source and expiry; create admission is checked before reserving its effect.

No host issuer, signing key, receipt or real credentials were created. These locations are a **prepared deployment contract**, not evidence that custody is available or authorized. The host provisioning and trust-root lifecycle must be independently admitted and verified before this code can operate against a real sandbox. Python process administrators remain trusted: the sealed object is not a security boundary against a person who can rewrite server code or private host files. No signing capability is exposed through HTTP.

Tests construct explicitly synthetic signed receipts using an obvious test key in the test directory. Test-only contexts cannot use the real network transport; injected transport always labels results `SANDBOX_CONTRACT_TEST`.

## Service flow

Webhook: bounded original bytes → parse without duplicate keys → host operation checks → provider signature verification → fresh authoritative GET → identity/amount/currency/capture/freshness checks → unique event ledger update.

`verified` or `admitted` fields in the webhook body never provide authenticity. A verification timeout produces `VERIFICATION_UNKNOWN` and no ledger mutation. A GET timeout records unresolved evidence; duplicate notifications cannot generate another create. A fresh service read is the reconciliation path.

## Explanation contract

The future explanation port receives allowlisted facts, a source digest, empty tool and transaction-action lists. It receives no store, credentials or PayPal client. Candidate schema rejects extra tools/commands, a changed source digest and false certainty at UNKNOWN/CONFLICT/REVIEW_REQUIRED. Candidate text remains explicitly untrusted and is not presented as live AI or used to execute actions.

`explain_with_live_ai` currently fails closed **before invoking any provider**. There is no AI admission loader or artificial budget receipt. Current product explanations remain deterministic. Source binding and schema validation do not guarantee the factual truth of model prose; independent semantic validation belongs to the future qualified AI slice.

## Access qualification in this invocation

- PayPal: one cloud inventory read returned zero tabs for this caller. No existing PayPal Developer/Sandbox route or account metadata was exposed. No navigation, login, application/key/webhook creation, token/OAuth call or transaction was attempted. This does not prove account-wide absence.
- GitHub: the connected repository metadata call returned404 for Elinfiny/PayProof. That is not proof of absence, because access scope can also produce404. The connector exposes no repository-create operation; `gh` CLI is absent; no existing authenticated cloud GitHub tab was surfaced. No guarded create route was established, and no repository was created/adopted.
- Renderer: no browser installation or workaround was repeated. Basics owns the current shared renderer qualification.

Next eligible external step: qualify an actually exposed supported repository-create/access route and sandbox custody under the current direction; preserve the zero external spending grant and independent publication gates.

## Private HTTP read-only candidate — direction 20261015-08

This addendum describes a review candidate, not a deployed integration. Fixture mode remains the default, uses the existing synthetic UI/state/actions and still prints `SYNTHETIC ONLY`. The optional `--mode sandbox-readonly` does not grant authority: production preparation loads only the existing fixed-file host context, requires an exact `orders:read` scope and rejects synthetic test contexts before directory, SQLite, adapter network or socket effects. No fallback to fixtures is allowed. No issuer, HMAC rule, receipt schema, trust key, credential or grant is created or changed. The source fingerprint now includes `server.py`, so earlier source-bound receipts cannot admit this new HTTP path.

The two default database paths differ. A persisted SQLite application ID also prevents either HTTP mode from reusing the other's ledger even when a custom path is supplied. Only a recognizable legacy fixture-only ledger can be adopted as fixture; an untagged existing ledger cannot become sandbox custody. Sandbox startup seeds no fictional order. Registration and custody provisioning remain separate, unadmitted host operations; no HTTP registration route exists.

Sandbox exposes only `POST /api/sandbox/read` with exactly `{"order_id":"<already registered admitted ID>"}`. It preserves the loopback Host/same-Origin guard, bounded JSON and mode-specific `X-PayProof-Request: sandbox-readonly-ui`; duplicate/extra keys, caller endpoints, credential fields and booleans cannot supply authority. The shared socket-free dispatch verifies registration before calling the existing `PaymentEvidenceService.read`; the existing adapter revalidates admission before transport. UNKNOWN and historical evidence are retained without creating or replaying a financial effect. No create, capture, refund, transfer, webhook verification or live-AI action is exposed. Public metadata GET returns no order enumeration, and fixture UI/assets are not served in sandbox mode; this candidate does not implement a sandbox frontend.

The three new tests are **SYNTHETIC, in-process and test-only-network-blocked**. They use the existing typed signing fixture and fake transport data, never a socket, browser, real host context or PayPal API. They exercise missing-context pre-effect refusal; ledger isolation and rejection of JSON/boolean/test-context authority; and actual service dispatch with unregistered-ID refusal, request guards and UNKNOWN preservation. Passing these tests cannot qualify real custody, sandbox identity, injection, OAuth, hosting, AI, contest readiness or deployment. Existing historical suites and the 26 browser checks are not repeated here.
