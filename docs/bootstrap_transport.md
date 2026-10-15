# Private transport16: concrete code, inactive runtime

Candidate17 corrects only the shared _FixedHTTPS inside github_oidc.py, adds the
focused4case test_bootstrap_boundary17.py and updates this contract. Candidate16
preimages and its six receipts remain immutable historical evidence. No historical
suite is rerun or relabeled under the new17 fingerprint. bridge/Gitreservation16,
focused test16, inactive workflow16 and the RSA15 prefix are byte-identical.
After4newPASS, six scoped paths16/17 may update the SAME private draftPR5; main,
permissions, credentials, workflows and runtime remain unactivated.

FixedJWKSLoader uses the implemented HTTPS request/getresponse/read/close path
with standard create_default_context certificate+hostname verification and
http/1.1 ALPN. Native HTTPSConnection is the default underlying factory, but
production entry points refuse UNBOUND before any connection. Tests inject
explicit fake HTTPS connections; these cannot mint authentic provider evidence.
The only JWKS route is GET token.actions.githubusercontent.com/.well-known/jwks;
one allowance, no redirects/discovery/alternative URLs. Body cap65536B, native
socket timeout and absolute monotonic/source deadlines are checked PRE_REQUEST,
PRE_INVOKE and POST_RETURN, including cleanup. HTTPResponse and body/exception
objects are retained privately before status/bounds/parse guards. The17 boundary
owns every TLS constructor/request/getresponse/status/read return or exception
before its own POST_RETURN guard. PRE_REQUEST/PRE_INVOKE/POST_RETURN surround each
blocking operation under the SAME initial absolute deadline. Constructor ownership
transfers to the close holder before its post guard. A late request cannot call
getresponse; a late getresponse cannot inspect status/read; a late read cannot be
parsed/used. conn.timeout and sock.settimeout (when a socket exists) receive the
remaining deadline at each subsequent operation, not a reset duration. Timeout
configuration results are privately owned and guarded too.
Close is claimed once BEFORE fallible cleanup clock/preparation. Clock throws or
invalid returns retain their original error separately from a primary operation
failure, set/preserve firstUNKNOWN and cannot skip that close attempt. Cleanup
timeout configuration, close errors, late close and clock failure after close do
not overwrite the primary/firstUNKNOWN. Clock-unavailable cleanup invents no fresh
window. No request follows UNKNOWN or a late return; raw values never enter export.
Blocking native code/backend cancellation is not guaranteed by these guards.
The installed cryptography50.0.2 bytes are reused and pinned, not installed or
inferred from latest51 documentation. RSA15 and token/subject/time policy are
unchanged; no fixture-driven relaxation or production identity claim.

GitRefReservation implements native REST-shaped requests in the same private
Elinfiny/PayProof, verifying repository1419908202/owner273768139 first. A fixture
provider can exercise the exact protocol but its results remain TEST_ONLY.
Stable key=SHA256(canonical_source_grant_id:existing_order_id_sha256), never
run/JWT/PID/token. The authenticated source grant must retain its canonical
effect lineage; a new grant ID is not permission to reset a consumed effect.
The candidate refuses a different grant_id within its sealed binding; no
cross-grant/global-lineage qualification is claimed from fixtures.

Protocol, max10 HTTP calls and at most3 immutable/create-only writes:

1. GET exact repository identity; GET exact reservation ref, require404.
2. POST one-file tree with canonical consumed record; POST commit parented to
   the authenticated final source commit. No full repo copy in reservation tree.
3. POST /git/refs once, ref=refs/tags/payproof-reservations/v1/<stablekey>.
   Require native201; no update/delete/force endpoints or retry exist.
4. GET ref/commit/tree/blob/ref. Require exact201-ref raw bytes on both ref
   readbacks, exact create-commit raw bytes on commit readback plus exact
   parent/tree/message, one-entry tree with recomputed GitSHA1, decoded full
   record bytes and recomputed blobSHA1. Record binds sources, registry receipt,
   caller run_id/attempt1, source deadline and permanently consumed OAuth1+GET1.

No OAuth may start until the same original execution has confirmed those
postconditions. Existing records/restarts refuse, even if another run succeeded.
Attempt2/run mismatch is rejected before provider access, independent of cached
needs.SUCCESS. A race loser seeing409/422 performs one read-only reconciliation;
200 proves a record exists but is NEVER adopted. 422 alone is validation/spam,
not already_exists evidence. Ambiguous create/readback, late return or cleanup
failure preserves original/firstUNKNOWN and blocks continuation/retry/refund.
Objects created before a ref collision may remain orphaned; they are neither
deleted nor permission for OAuth. Nothing is actually created by these tests.

This is not a globally append-only namespace: other sufficiently privileged
actors can modify/delete refs. Active namespace protection and authenticated
provider/caller readbacks remain separate qualifications. Synthetic create201
and full readbacks demonstrate code mechanics, not real durable CAS deployment.
The real job-token loader, reviewed source-grant adapter, actual workflow/run,
authenticated current JWKS, secure exact client_id/client_secret custody,
authentic preexisting order registry and protected namespace remain UNBOUND.
The code never issues a production SandboxContext/key/receipt from strings,
JSON flags, callbacks, signed fixtures or reservation metadata.

The workflow candidate proposes contents:write only for reservation (no PayPal
credentials) and contents:read for a separate same-run OAuth/GET job. Both jobs
have literal false guards; the CLI deliberately exits UNBOUND. No outputs or
protected keys are made available. A future consumer must independently verify
the consumed record/caller; cached needs.SUCCESS/output strings are not authority.
Workflow enablement, authentic grant/caller and permission admission are distinct
future work, not missing environment variables that the Owner must fill now.

Primary references from16 are retained as provenance: GitHub REST Git references
(create201/409/422 and ref mutability), GITHUB_TOKEN per-job permissions, Python3.12
http.client/ssl. The17 change is a targeted source correction, not a new dependency
or vendor claim. No peer outbox/authority is consumed. Exact final17 source pins
and its one new4case group are separate from16 six historical receipts. Cases cover
late request/constructor ownership, late response/read originals/no next operation,
primary+PREcleanup clockthrow/closeonce/error separation, and decreasing socket
timeout with timely TEST_ONLY body. Admission5 remains separate; candidate8 is
recalculated prospectively and never retroactively inserted into earlier receipts.
RealJWKS/OIDC/PayPal/provider calls remain0; no backend cancellation claim.
