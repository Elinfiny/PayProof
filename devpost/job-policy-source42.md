# Private pre-admission source candidate42

This is an unpublished, read-only source-preparation boundary. It does not issue
JobPolicyEvidence, credentials, a native identity, an order registry or permission
to call PayPal. PreparedJobPolicySource is always INCOMPLETE and TEST_ONLY. Its
public constructor, a JSON grant, a digest, a callback, a PID and a URL cannot
establish authenticated vendor origin. There is no import of a native seal and
no policy/custody/registry production factory in this module.

## Source contracts actually examined

Canonical private main f2655c296eeadbb355078b3e22906f16b39a4662 has tree
b42a90b099f4c931fdaeb3a6a95fbfddec047b6e. The eight runtime sources retain their
accepted manifest digest 24145845d8ab34a2aaadbdb9155115e33520ff583398bbe13a8e50dd18060790
and admission5 digest d02b9af407be2d945b194e9d68d11e2f27d40889d12183e809a313e3899041aa.
Those evidence-manifest digests are not silently substituted for the grant's
three-column bundle_manifest digest or source_fingerprint algorithm.

admission.runtime_manifest uses path/bytes/sha256 over V3_PATHS in its defined
order. admission.source_fingerprint hashes canonical [basename,sha256] rows over
admission/core/paypal/service/server. JobPolicyEvidence.require checks the
PAYPROOF_JOB_NATIVE_CONTEXT_V1 grant, the exact caller, registry reference,
canonical_effect_key_sha256, expiry and read-only budget. These are the contracts
implemented by the resolver, using whole immutable Git blobs and complete tree
Merkles. It never uses JobNativeProvider to authenticate its own initial policy.

ConsumerProvider._caller already uses repository metadata, immutable Git commits,
trees/blobs, main, actions/runs/{run_id}, and actions/runs/{run_id}/attempts/1/jobs.
The proposed independent pre-admission collector uses only those same GET routes
under fixed api.github.com/repos/Elinfiny/PayProof, with repository ID1419908202
and Owner ID273768139. It binds commit/tree, workflow source bytes, run attempt1,
sole read_only job, main ref, expected Environment subject, source manifests,
fingerprint, expiry and canonical grant/registry references. There is no invented
job_id JWT claim or Environment field in a GitHub jobs response. TEST_ONLY identity
claims are data to compare, not a replacement for authenticated identity.

The native backend is a prepared OFFICIAL_METHOD github_fetch request plan only.
Actual supported connector exposure supplies managed HTTPS/TLS and authentication;
the candidate has no raw HTTP client, cookie discovery, ENV/host token reader,
certificate override, shell, tunnel or alternate endpoint. Native source factory,
secure token delivery and provider-origin qualification are UNBOUND, so the plan
is never invoked by candidate42. collect_native rejects defaultNone before HTTP;
even forged non-None inputs still reject NATIVE_SOURCE_FACTORY_UNBOUND. No claim
of an installed native collector is made. The implemented mechanical collector
executes only explicit in-memory TEST_ONLY response objects.

## Input, deadline and provenance boundaries

The collector uses one absolute monotonic window <=30s, at most64 fixed GETs,
65536B whole JSON/blob bodies and a complete <=512-entry source tree. Originals
are retained before clock/status/type/bounds/parse checks; clock values are owned
before validation. PRE_REQUEST/PRE_INVOKE/POST_RETURN and firstUNKNOWN are sticky.
Late/exception/unknown replies prevent the next operation; cleanup is claimed
once, retained separately, then always checked at POST_CLEANUP against the same
original absolute deadline, even without a callback. A late, invalid or throwing
cleanup clock sets sticky UNKNOWN and forbids a result. Primary exceptions are
retained before cleanup and re-raised unchanged; cleanup faults never replace
them or overwrite the first UNKNOWN. Exports omit raw errors and secrets.

Positive closure proves only TEST_ONLY byte/reference consistency. All four real
bindings—authentic reviewed grant, protected manifest delivery, runtime identity
and authentic registry origin—remain UNBOUND. No local receipt is vendor evidence.

CredentialCustody returns UNBOUND with the existing legacy canonical locator
/run/secrets/payproof_paypal_sandbox.json, never opening it and never treating it
as a qualified native producer. OrderRegistry returns UNBOUND with the known
github/payproof-orders-registry.json locator. Existing grant references are checked
at their immutable revision/hash; no real client ID, order ID or registry is made.
The current canonical tree lacks the prospective read-pilot workflow and registry;
the fake-positive files exist only inside the explicit memory fixture.

## Future adapter: specified, not bound

The future native producer must independently authenticate the reviewed grant
and manifest, protected step-scoped token delivery, actual eligible provider run
and authentic preexisting registry before any native source result is accepted.
Only a separately admitted origin-bound adapter at admission.JobPolicyEvidence
construction may connect that source chain to policy. The consumer callsite is
bootstrap_bridge.JobNativeProvider.from_native(policy=JobPolicyEvidence,...),
which requires policy.require(production=True) before any SharedJobHTTPS.
That callsite is not a source producer. to_native_policy always refuses; it does
not replace the existing None producers or mint a seal. intake_step_scoped_credentials
still refuses AUTHENTIC_STEP_CUSTODY_UNBOUND. No existing module is changed here.

## Focused new validation and remaining gates

Historical42 qualified four methods/twelve subcases and left the post-cleanup
clock boundary unqualified (Auditor F42-CLEANUP-1). Those results remain consumed.
The new43 entrypoint selects ONLY NewCleanup43: three methods/six subcases,
python -I -B, child30s,
parent35s, two separate131072B pipes, frozen before/after pins. It covers defaults,
original receipts, source/blob/fingerprint drift, TEST_ONLY manifest closure,
late/exception/invalid-clock firstUNKNOWN/no-next, cleanup and non-convertibility.
Fake API and source files are in memory; no actual GitHub/OIDC/JWKS/PayPal HTTP,
credentials, RSA key/sign/verify, reservation, order, model or spend occurs.
The historical RSA37 and package41 suites are not imported or rerun. The new cases cover late callback and no-callback closure, invalid/throwing
cleanup clocks with preserved HTTP/parse primaries, timely TEST_ONLY closure and
forged-result non-convertibility. The historical42 class is defined but never run.
Actual new results are supplied separately in the checkpoint; this document makes no advance PASS claim.

The full repository regression, real source factory, native policy adapter,
protected manifest delivery, authentic runtime identity, secure credential custody,
preexisting registry, once controls and pilot allowance remain separate gates.
OAuth1+GET1/total2/retry0/300s is still not admitted; the three-call sandbox-order
creation alternative is a proposal. No workflow, freeze26, main, PR6, provider
settings, public publication or deployment is modified by candidate42.

Direction43 keeps these three corrected sources private pending independent review.
A START save conflict consumed one of four allowed save attempts; Git publication
is deferred to preserve the final result slot. This document claims no branch or
Git write. Native producers, factory and adapter remain UNBOUND.
