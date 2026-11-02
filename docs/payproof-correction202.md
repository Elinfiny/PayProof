# PayProof compensation and transport diagnostic correction 202

C194 remains consumed/UNKNOWN. Its known new webhook cleanup was subsequently
verified in the provider UI; no old effect is replayed by this change.

## Demonstrated cause and unresolved observation
The receiver counted raw TCP accepts before TLS and closed at 512; 390 handler
errors had no phase metadata. No historical peer/exception evidence exists to
attribute those errors to a particular sender or cause. A fresh read-only
process inventory found no PayProof/probe process and only SSH listening.
The cleanup required reserve/result calls across that closed receiver.

## Implemented changes
Before creating an order, the worker obtains and retains a remote, fsynced
once reservation bound to the exact webhook freshly created by this run.
The native ledger rejects old, unbound or different webhook targets. Once the
reservation is acknowledged, the existing runner can perform one bounded
DELETE independently of the receiver. A strict 204/empty body plus target,
reservation and grant hashes is retained in the existing provider-owned job
log, without private IDs, URL, credentials, headers or response bytes. It also
attempts the existing private receipt route once. Lost acknowledgements or
unknown DELETE outcomes never permit repetition. A hard-killed runner remains
UNKNOWN: this is not a new daemon or a claim of guaranteed deletion.

Aggregate diagnostics distinguish TLS, framing, authenticated worker routes,
browser polling, disconnects and capacity. No peer or request content is logged.
An unhealthy receiver is stopped before PayPal credential release (16 errors
or 128 accepts during preflight); the overall 512-accept cap is unchanged.
No TLS, OIDC, pairing, provider operation, expiry or no-replay bound is relaxed.

## Verification
Ten new synthetic compensation/preflight cases passed with sockets forbidden:
closed-channel cleanup, preserved existing hook, lost DELETE, lost reservation
ACK, target drift, expiry, successful PayPal+AI synthetic chain, unsuccessful
cleanup, post-intent failure and unhealthy preflight. Five new bounded transport
cases passed: three normal loopback TLS requests give three accepts/zero errors;
one interrupted handshake is classified; Host refusal is separate; the 512 cap
is checked with a mocked accept (no traffic generation); categories are bounded.
All 19 accepted product files remain byte-identical. Previously accepted tests
were not rerun; changed cases were rerun only after relevant source changes.

## Live evidence boundary and rollback
This commit is preparation, not a native payment success. Historical 390-error
origin is UNKNOWN. The next distinct corrected operation uses a new root
/root/payproof-payment186-c202, fresh source/run/receipt and unchanged Sandbox
1 USD fictitious, zero real money/additional cost and ten-minute limits.
The workflow remains disabled. Reverting code never reactivates old grants,
orders, webhook effects or UNKNOWN operations. Previous canonical private base
64c0a5b8d409eb29db00cafe9d9162fac2878390 and public inactive base
e83472f862a0b265ea874f65bd309657f7753c34 retain exact preimages.
