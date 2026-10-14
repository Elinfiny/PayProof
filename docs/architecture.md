# Architecture

Browser → fixture-only loopback HTTP handler → reconciliation service → SQLite ledger.

The separate prepared server-side PayPal adapter is not reachable from the fixture HTTP handler. No secret is configured in this package. OAuth tokens stay transient in server memory once a future admitted integration exists.

Webhook handling: verify authenticity → resolve related order ID → compare event ID/payload digest → obtain fresh order data → validate registered amount/currency and capture evidence → transactional unique event insert + state update. Concurrent duplicates may perform duplicate harmless reads; only one ledger mutation wins. Same ID with different content is rejected. A notification's payment claim is never accepted as authoritative order evidence.

UNKNOWN: preserve the prior reliable evidence separately, label current uncertainty, forbid automatic write retry, perform an explicit read reconciliation. A consumed create request ID stays consumed even after a crash. There is no automatic create retry or request-ID reset.

Freshness: `update_time` is required for usable provider evidence; older reads cannot regress newer reliable facts, and equal-timestamp disagreements fail closed. Missing freshness fails closed. Multi-unit orders, unsupported currency, malformed amounts and ambiguous capture sets are outside this slice.

Isolation: a newly created project directory and private artifacts only. No shared repository branch, deployment, server, backup-controller object, global policy or peer checkpoint is modified.

Backup/rollback: initial project was absent. RECEIVED and START persist as distinct checkpoint versions. Private code is packaged with member hashes and outer hash; no live provider rollback is needed because no provider write is admitted. For a subsequent modification, retain the exact source archive/baseline and apply a scoped patch.

Production readiness remains open: hosted authentication/authorization, TLS, ingress limits, real provider tests, durable encrypted backup, runtime quotas, observability and a qualified live AI integration. The loopback fixture server must not be exposed as a public service.
