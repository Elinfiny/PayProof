# Private bootstrap candidate15 — inactive

This candidate adds an actual RS256 signature and claim verifier plus a consumer
that binds an inert bootstrap plan. It does not create a host issuer, key, receipt,
production SandboxContext, credential file, workflow or network request.

## Concrete verification route

The already installed cryptography 50.0.2 provides RSAPublicNumbers.public_key and
RSAPublicKey.verify with PKCS1v15 and SHA256. CRYPTO_DEPENDENCY.json records exact
module and native binding hashes and the runtime OpenSSL version. PyJWT is absent;
no dependency was installed. JSON/compact-JWS parsing is strict and bounded, rejects
duplicate members and noncanonical base64url, then delegates all RSA cryptography
to this installed implementation. RS256 is the sole algorithm; RSA modulus must be
2048–8192 bits with exponent65537, unique matching kid, use=sig, alg=RS256. No jku,
x5u, embedded jwk, crit, token-selected issuer or token-selected endpoint is allowed.

The provider origin is fixed to https://token.actions.githubusercontent.com and
the proposed JWKS endpoint to /.well-known/jwks. The candidate accepts only an
explicitly sealed TEST_ONLY JWKS snapshot. A URL string with supplied keys is not
authenticated provenance. The future production fixed-origin HTTPS/JWKS loader is
unbound, never invoked and requires separate implementation/review. Current code
performs genuine signature mathematics on synthetic JWTs, not provider attestation.

Signature precedes use of identity. Exact configured audience and issuer, integer
iat/nbf/exp, fresh snapshot, and one absolute source-grant window <=300 seconds are
required with no positive leeway. Repository_id1419908202, owner_id273768139,
repository/name/visibility, workflow_ref, workflow_sha, ref, sha, event_name,
run_id, run_attempt1 and github-hosted runner are compared to source-bound
expectations. No job_id claim is invented; job_workflow_ref is not required for
an ordinary workflow. The only prospective route is
Elinfiny/PayProof/.github/workflows/payproof-read-pilot.yml@refs/heads/main with
workflow_dispatch; this workflow DOES NOT EXIST and no OIDC permission is added.
Prospective SHA/run IDs in tests are synthetic, not actual eligible bindings.

The documented immutable default subject includes owner/repository IDs for new
repositories after 15 July2026. This route explicitly pins
repo:Elinfiny@273768139/PayProof@1419908202:ref:refs/heads/main. It refuses a legacy
subject and any customized/environment subject, rather than guessing that they
are equivalent. A future authenticated source grant must confirm the actual
provider configuration and exact observed subject without changing OIDC settings.

## Concrete consumer and remaining binding

BootstrapBridge verifies the identity, then matches the final reviewed candidate
bundle fingerprint, unchanged admission5 fingerprint, client ID hash, exact two
credential fields (client_id/client_secret, no webhook), existing order hash,
registry receipt hash and the durable reservation contract. It exports metadata
only. Synthetic signatures, JSON flags, PIDs and local HMAC do not grant authority;
all test evidence stays TEST_ONLY. activate and verify_production always refuse.

One missing aggregate binding is AUTHENTIC_REVIEWED_RUNTIME_BOOTSTRAP_BINDING.
Its separately evidenced components remain: authenticated distinct source grant
for final reviewed sources; actual eligible provider caller with fixed-origin
authenticated JWKS; secure custody of the exact credential pair; authentic
preexisting order/registry; and implemented, independently reviewed durable CAS.
These are several real prerequisites, not one trivial missing field. None is
claimed qualified by this candidate. The source grant cannot authorize itself by
embedding an admitted boolean, signature key, or unverified public claims.

The existing V2 admission source_fingerprint covers exactly5 application modules
and stays unchanged. FINAL_SOURCE_PINS.json additionally computes candidate8 over
those5 plus the integrated driver and2 new modules. This prospective fingerprint
is not substituted into older receipts or claimed accepted retroactively.

## Finite durable reservation contract, not implemented persistence

Key = SHA256(source_grant_id + ':' + existing_order_id_sha256), independent of
run_id, attempt, process ID, jti and token refresh. A new JWT cannot reset it.
The proposed provider must atomically create-if-absent under this unique key,
storing final source hashes, authenticated caller identity, registry receipt hash,
absolute deadline and allowances OAuth1/GET1. Commit CONSUMED_BEFORE_OAUTH before
any OAuth invocation. Both allowances are permanently claimed; GET is permitted
only as continuation of the same admitted original execution after known timely
OAuth return, never by a restart. All existing records, including UNKNOWN,
in-progress, completed, expired or malformed records, refuse a restarted consumer.

Failure before durable-commit confirmation performs zero transport; ambiguous
commit is UNKNOWN and no transport or retry. After commit, any crash/late return
or UNKNOWN prohibits GET/retry. Original outcomes are privately retained before
guards, with firstUNKNOWN preserved through cleanup as implemented by driver14.
No deletion/refund/reset, alternate key, boolean in memory or new process is a
durability substitute. ReservationPlan validates this required contract only;
it does not write a ledger and claims no successful durable reservation.

## Validation and authority

One new failfast group of at most6 inert cases, final pins BEFORE invocation,
ephemeral in-memory fixture RSA keys only; explicit native/socket/HTTP/provider
guards. Existing suites7/3/26/6 are not rerun. New verifier/consumer remain private
and do not enter PR4. Only the two already accepted driver14 postimages join the
three accepted V2 paths in that existing PR, subject to fresh native guards.

Official sources read this unit (4 total): GitHub OpenID Connect reference and
concept pages, cryptography RSA documentation, RFC7519. Documentation supports
the design; authentic identity, custody, durability and production execution are
not inferred from documentation or synthetic PASS.
