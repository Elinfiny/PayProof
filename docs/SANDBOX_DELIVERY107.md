# Portable and provider-managed Owner Sandbox workflow (candidate109)

This prospective profile belongs to the person operating a private process.
It is independent of our private checkpoint store, Netcup and issuer keys.
It does not claim a vendor attestation or qualify the existing sealed-host
V2/V3/native67 path. Those paths, defaults and guards remain unchanged.
This branch is source-only: no real credentials or PayPal request were used.
Historical107 five inert scenarios remain historical; direction108 admits one
different four-scenario group only. Synthetic records never qualify native use.

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

This terminal path is an OPTIONAL judge/operator option, never an Owner-PC
requirement or technical work transfer. The selected Owner path is the prospective
GitHub cloud entry below; Marius is not asked to assemble configs or run commands.
The source commit/tree and critical file fingerprint must match before credential
prompts; default/unconfigured calls refuse without reading ENV/network. Both
credential values use hidden terminal prompts. The journal reserves the stable
PayProof/Sandbox/orders:read/client-fingerprint/exact-order key before the first
prompt. Lineage, once labels, source and window are validated attached metadata,
never selectors that can rearm that identity. Changing them refuses against the
same consumed key. Historical107 journals are not reset or migrated: a legacy
record without108 attached metadata refuses pending separate migration review.
Native107 never ran; new tests use fresh explicitly synthetic journals only.
Reconciliation returns sanitized status, amount/currency, a hashed order
ID and nonfinancial advice; provider free text, credential values and tokens are
never output. First failure and cleanup are separate. References are dropped on
close; Python cannot guarantee forensic RAM zeroization. Run only in a private
process you control; this is not isolation against malicious code in that process.

If there is no authentic existing Sandbox order, request a separate minimal
Sandbox-only test-data acquisition review: one approved Sandbox creation and
buyer approval path with real app/account ownership, lineage and durable once
record, followed by this read-only qualification. Creating, approving or capturing
an order is outside107 and must not be improvised or represented by fixture data.

## Historical cloud profile108: preserved, inactive and unqualified

`workflow_candidates/payproof-sandbox-delivery107.yml.disabled` remains outside
the active workflow directory, manual-only and literally `if: false`. No runner,
dependency installation, environment creation, secret or API operation occurs.
The `github-owner-managed` entry, `GITHUB_OWNER_MANAGED_SANDBOX` typed profile,
two-call reader, existing reconciliation and optional local advice are implemented.
It requires no TTY/getpass/Owner command. The template now contains a public-data
preflight, expectation registration and one gated runtime step with exactly the
two existing credential names mapped ONLY to that step. Actual source/workflow
and caller comparison precedes credential reads; synthetic admission cannot enter
the operator profile. Public configuration/JSON/ENV/concurrency labels are data,
not authority. There is no public credentials endpoint or legacy host seal use.

The exact remaining native adapter fact is reported as
`MISSING_OWN_CAS_FIRST_RUN_JOB_ADAPTER108`. `load_owned_dispatch108` refuses until
the existing PayPal producer can deliver a genuinely provider-bound, process-private
OwnedDispatch108 from conditional-own INTENT→CONSUMED and the first actual run/job.
No runtime Library reader, fake signing key, invented host attestation or public
`consumed=true` can replace that binding. Matching hash/version strings are checked
for consistency only; they cannot create the native typed binding. This adapter
has NOT been implemented/qualified by a synthetic constructor. Therefore the
current template fails closed BEFORE mapping secrets. The complete orchestration
can be exercised through an explicitly synthetic binding/transport only. This is
not a ready hosted demo or native integration, and activation is not authorized.

Real future producer contract, on the existing project route: PayPal V1 reads the
current own version and source/workflow/release scope, persists exact effect INTENT,
independently reads it back, then conditionally advances the same journal to
CONSUMED BEFORE one actual supported dispatch. The stable app/order/read key is
consumed independently of labels/source. On the native dispatch response and one
canonical first-run/job readback, it binds exact numeric run/job, attempt1,
repository/Owner/actor, reviewed source/tree/fingerprint/workflow SHA, registered
app fingerprint/order/amount/currency/lineage and admission ID. Unknown dispatch
is reconciled once, never resent. Duplicates/reruns refuse. The real missing bridge
must carry this authentic already-consumed fact into the SAME protected runtime;
an independently supplied expected public projection identifies it, never grants
it. If actual delivery cannot bind that fact, retain the exact missing adapter
status; do not ask Marius to manufacture it or execute technical commands.

Dormant→active→dormant review contract: only after independent source/security/effect
admission, move this candidate to the prospective
`.github/workflows/payproof-sandbox-delivery108.yml`, replace the literalfalse job
gate with exact main/manual/Owner/repository/attempt1 guards, and independently
pin the actual resulting workflow bytes and release head OUTSIDE that future
commit. Do not embed its own future SHA in source. The externally reviewed
admission then supplies expected head/tree/source/workflow pins, and runtime
compares actual Git checkout/files/context. After the one bounded run, restore
literalfalse and verify dormant source. No such move/activation/dispatch108 occurred.
All active .github workflows remain byte-identical.

Timing/error contract: wall-clock admission window is retained, and the remaining
window (at most120sec) is anchored once to actual monotonic time before credentials.
It is never reset by a second call. The bounded original parsed provider return is
retained privately BEFORE post-return guards; OAuth/token originals and any
token-derived hashes never reach stdout, disk, artifacts or public receipts.
Only allowlisted public status/count/stage/metadata are exported. A late return
keeps the first sanitized code/stage, UNKNOWN and no next call. Primary and cleanup
remain separate. Closing drops credential and private-return references; neither
the monotonic guard nor the old socket timeout proves kernel/backend cancellation
or forensic RAM zeroization.

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

Concrete future custody decision (PREPARATION, NOT APPROVAL): qualify that exact
existing environment/source/workflow/external-once binding first, plus authentic
Sandbox app allocation and order lineage. Confirm secret NAME/presence, never
VALUE. If credential entry is genuinely indispensable, the single Owner step is
private entry into the exact already-reviewed GitHub environment secret field;
no config assembly, scripts, terminal commands, secret chat or old64/66 form reuse.
Only the already-gated runtime step receives the pair, only in process RAM, for
one OAuth+one read; zero payment actions, model APIs or cash. Safe failure emits
sanitized primary/stage and separate cleanup, drops ephemeral configuration/order
files and references, and NEVER deletes the external consumed journal. Current
108 grants no entry, secret lookup, dispatch or provider effect. If no authentic
order exists, the separate Sandbox-only acquisition proposal above remains required.

Official references used for design (not current execution/custody authority):
[PayPal OAuth](https://developer.paypal.com/api/rest/authentication/) and
[GitHub protected secrets](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets).

## Remaining finish route

### Selected109 contract: provider-managed Owner workflow

The implemented GITHUB_OWNER_WORKFLOW109 profile deliberately changes the operator
trust contract for a new path. Its owner-workflow-preflight109 and
github-owner-workflow109 CLI entries run in a source-reviewed protected GitHub
process; no TTY/getpass/Owner-run commands, heap-transfer bridge, runtime Library
reader, new issuer/key/broker, signing service, OIDC or write permission is needed.
It reuses the stable consumed identity, private session, fixed two-call reader,
Store and nonfinancial local advisory. Old native67/OwnedDispatch108/default
loaders and seals remain unchanged and unqualified; no missing exception is
caught and converted into success, and no old native seal is minted.

The prospective authority boundary is the separately admitted Owner launch,
GitHub-processed main/manual/Owner guards, reviewed checkout, protected environment
and exact step-scoped credential delivery. Public JSON, flags, references and ENV
values are consistency data, not independent provider/custody/vendor/kernel proof.
No HTTP endpoint creates authority; there is no isolation claim against the Owner
or malicious code inside the same trusted process. Process-private WorkflowLaunch109
records that explicit origin and cannot serialize; synthetic evidence cannot enter
the real profile. Source/inert results never qualify actual runtime or credentials.

Before lookup, a bounded exact-key envelope contains only configuration/admission.
Checks bind Elinfiny/PayProof/id1419908202/owner273768139/actor273768139,
main/workflow_dispatch/attempt1/job SLUG sandbox_read, actual Git HEAD/tree,
GITHUB_SHA/workflow origin/source release and critical source/workflow bytes to
independently supplied post-publication pins. The active-path proposal stays
.github/workflows/payproof-sandbox-delivery108.yml. A public asserted actual run ID
or numeric job ID is an extra forbidden field. The actual run ID comes from provider
context; numeric job ID is read canonically AFTER dispatch outside the job. Never
print whole GitHub context/token. JSON is passed as ENV/file data, never shell code.
No future commit's own SHA is embedded in itself.

Feasible external-once ordering: PayPal V1 conditionally writes and independently
verifies own INTENT→CONSUMED before one supported dispatch selection, on stable
app/order/read identity and exact source/admission/workflow/target/callbudget2/
window120/cash0. After the provider response, it binds the first real run and reads
the numeric job ID; Auditor verifies consumed admission/source/logs/receipt. Unknown
dispatch is reconciled once, never retried/relabelled. Runtime does NOT authenticate
private CAS by parsing its public hash. CAS controls the sole authorized sender,
not provider-global exactly-once or a malicious Owner/admin creating other manual
runs. Ephemeral job SQLite remains separate from the persistent consumed record.

The new template remains OUTSIDE .github, literally if:false, manual only,
ubuntu-24.04/5min/contents:read, exact pinned checkout/persistfalse, existing
payproof-sandbox-readonly environment. New-profile source/caller/preflight checks
run before the already-gated runtime step and repeat before credential lookup.
Only the two credential names are mapped to that step; three allowlisted public
workflow-context fields contain no credential. Actual environment settings and
applicable native security confirmation/custody are not assumed. Future reviewed
dormant→active→dormant changes are limited to the exact move/job-gate contract,
independent actual head/tree/workflow pins, one consumed dispatch and verified
dormant restoration. No activation, dispatch, secret lookup or API109 occurred.

Concrete next protected decision: independently review the exact existing branch
review/payproof-sandbox-delivery107-20261018 and its ONE ordinary private109 PR.
Actual immutable head/tree/PR are recorded in the project result after provider
publication, never guessed/circularly embedded here. Then qualify Elinfiny/PayProof /
payproof-sandbox-readonly and genuine Sandbox app allocation plus authentic order/
amount/currency/lineage. Verify NAME/presence only for
PAYPROOF_PAYPAL_SANDBOX_CLIENT_ID and PAYPROOF_PAYPAL_SANDBOX_CLIENT_SECRET.
If indispensable, one secure Owner entry is directly into the reviewed provider
field, never config/hash/command work or technical relay. No old64/66/89/90 refused
surface is reused through another caller. If there is no real order, separately
review one minimal Sandbox-only acquisition/create and buyer-approval path with
durable authentic lineage; creation/approval/capture remain unadmitted109.

Bound the future read to one OAuth+one exact order GET/120sec/cash0/externalmodel0,
no payment actions, first sanitized code/stage, lateUNKNOWN/no next call, privately
retained provider originals and dropped references with separate cleanup. No
token-derived secret data is exported; no kernelstop/forensic RAM-zeroization
guarantee. Never reset the external consumed record. Current109 asks no Owner action.
The optional public judge-owned Sandbox route remains independent of Owner secrets,
private checkpoints and vendor attestations. Prior104/105/model proofs remain prior
proofs; the new109 group checks existing nonfinancial advisory abstention without
model fitting/retraining/rebenchmarking or replaying old groups.

Official design references, not actual provider proof:
[contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts)
and [environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

Independent review of this exact candidate → actual operator/protected-custody
approval and secure input only if indispensable → one authentic Sandbox order
read with lineage/once proof → actual end-to-end judge build qualification →
public licensed source/setup, English 2:40 demonstration and verified Devpost
submission. The current105 ZIP and104 renderer evidence remain unchanged;
they do not qualify107. Internal submission target:9November2026; official
deadline:12November2026 20:00UTC/22:00Bucharest. No contest-ready/win claim.
