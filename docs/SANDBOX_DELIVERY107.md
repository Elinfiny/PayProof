# Portable operator-managed Sandbox read (candidate107)

This prospective profile belongs to the person operating a private process.
It is independent of our private checkpoint store, Netcup and issuer keys.
It does not claim a vendor attestation or qualify the existing sealed-host
V2/V3/native67 path. Those paths, defaults and guards remain unchanged.
This branch is source-only: no real credentials or PayPal request were used.
The five inert scenarios use public fake strings and a fake provider.

## What the product does

An operator explicitly starts a reviewed Git checkout, supplies an existing
Sandbox application credential pair privately, and reads exactly one previously
registered Sandbox order. The existing SandboxPayPal request implementation is
composed behind a two-call state machine: one fixed Sandbox OAuth POST, then one
exact order GET. Production, redirects, arbitrary routes, create/capture/refund,
webhooks and live model tools are unavailable on this profile. A late, invalid or
unknown response consumes the attempt and prevents the next call/retry.
Store.reconcile and the existing deterministic projection remain authoritative.
The optional actual local learned model sees only the validated enum projection;
it cannot authorize money movement and uncertain current evidence stays UNKNOWN.
OAuth success alone is not evidence of a working payment-evidence product.

## Concrete future judge/operator setup

After source review and publication approval, a judge clones the public MIT
source/release and uses their own free Sandbox application and order. No Owner
secret is distributed. Python >=3.11, Git and the repository's pinned dependencies
are the existing project setup; this direction installs nothing. No private
Library identity or host attestation is an input. A private terminal is required;
there is no HTTP endpoint accepting configuration/credentials. Do not put secret
values in command arguments, configuration JSON, chat, logs, screenshots or files.

From the reviewed checkout, obtain the public source fingerprint with:

```sh
python -m tools.sandbox_delivery107 fingerprint
git rev-parse HEAD
git rev-parse 'HEAD^{tree}'
```

Create a private configuration JSON containing exactly these data fields:
`profile` = `OWNER_MANAGED_SANDBOX`; `source_sha256`, `source_commit`,
`source_tree` = the independently reviewed current values; `operator_allocation`
and `credential_provenance` = bounded nonsecret operator allocation/reference IDs;
`client_id_sha256` = the independently recorded SHA256 of that app's client ID;
`order_id`, `amount` (two decimals) and `currency` (USD/EUR) = authentic expectations;
`order_lineage_sha256` = reviewed authentic acquisition/ownership evidence hash;
`once_id` = a unique trace label; `not_before` and `expires_at` = timezone-aware
ISO8601 times, a window no longer than 120 seconds; `included_allowance_usd` =
`0.00`. Missing/wrong source, window, profile, provenance or allowance refuses.
These fields are configuration under explicit operator trust, not provider proof.
The private CLI action and credential prompts are the operator boundary; merely
loading JSON, a path, a boolean or a browser request cannot create a session.

Use an existing operator-owned private SQLite Store, registered via the existing
`Store.register(order_id, amount, currency)` interface only after authentic order
lineage review. Registration records an expectation, never provider authenticity.
Do not use synthetic order IDs as authentic inputs. No registration command or
financial creation endpoint is added here. Keep the persistent journal in an
operator-owned directory without group/other write access; its file is 0600,
same-user, regular, single-link and no-follow. Preserve the journal across exits,
source updates and failures; deleting/replacing it loses the operator's replay
protection. It is an operator-owned local boundary, not global exactly-once proof.

Then explicitly run in the private terminal:

```sh
python -m tools.sandbox_delivery107 operator-managed --config /private/operator.json --database /private/orders.sqlite --journal /private/once.sqlite --local-ai
```

The source commit/tree and critical file fingerprint must match before credential
prompts; default/unconfigured calls refuse without reading ENV/network. Both
credential values use hidden terminal prompts. The journal reserves the stable
app/order/lineage/read key before the first prompt. A changed `once_id` cannot
rearm it. Reconciliation returns sanitized status, amount/currency, a hashed order
ID and nonfinancial advice; provider free text, credential values and tokens are
never output. First failure and cleanup are separate. References are dropped on
close; Python cannot guarantee forensic RAM zeroization. Run only in a private
process you control; this is not isolation against malicious code in that process.

If there is no authentic existing Sandbox order, request a separate minimal
Sandbox-only test-data acquisition review: one approved Sandbox creation and
buyer approval path with real app/account ownership, lineage and durable once
record, followed by this read-only qualification. Creating, approving or capturing
an order is outside107 and must not be improvised or represented by fixture data.

## Optional hosted path: inactive and deliberately unavailable

`workflow_candidates/payproof-sandbox-delivery107.yml.disabled` is outside the
active workflow directory, manual-only and literally `if: false`. It adds no
runner, installed dependency, environment, permission, secret or API call.
Its preflight refuses with the typed missing external-once/custody admission.
The public constants/caller checks and concurrency labels do not establish trust.
This is not a ready hosted demo. The private-terminal public-source route is the
selected portable path; it needs actual operator/Sandbox qualification next.

A separately approved hosted successor would target **Elinfiny/PayProof**, repo
1419908202, **payproof-sandbox-readonly**, exact reviewed source/release and workflow,
Owner actor273768139, main/manual/attempt1, authenticated run/job and externally
consumed durable once BEFORE protected injection. Verify the two existing secret
names/presence, never values: **PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID** and
**PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET**. Their exact pre-existing step contract
and app fingerprint must match before reuse. No old64/66 refused form is accessed
through an alternate automated caller. Future indispensable Owner entry is directly
into the reviewed provider UI after exact security approval, never chat/commands.
Scope: one bounded Sandbox OAuth + exact order GET, max120sec, zero cash/external
model calls, sanitized receipt, token references dropped and no automatic retry.
Actual custody, source/once/window and included allowance must be qualified then;
this candidate cannot certify them itself. Native per-action confirmations apply.

Official references used for design (not current execution/custody authority):
[PayPal OAuth](https://developer.paypal.com/api/rest/authentication/) and
[GitHub protected secrets](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets).

## Remaining finish route

Independent review of this exact candidate → actual operator/protected-custody
approval and secure input only if indispensable → one authentic Sandbox order
read with lineage/once proof → actual end-to-end judge build qualification →
public licensed source/setup, English 2:40 demonstration and verified Devpost
submission. The current105 ZIP and104 renderer evidence remain unchanged;
they do not qualify107. Internal submission target:9November2026; official
deadline:12November2026 20:00UTC/22:00Bucharest. No contest-ready/win claim.
