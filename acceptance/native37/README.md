# PayProof native boundary: isolated source review 38

This private review branch persists the exact accepted inactive source candidate. It is not main, an enabled workflow, a native GitHub identity proof, credential provisioning, a pilot, or a payment integration.

## Source and evidence lineage

Canonical base: `9a23b868361d0a351cd1aaa69ff598f56e05203d`, tree `ce16e29e68c9b72f3498cd0e93feafb3f54b1242`. The new commit must have that sole parent. Review branch: `review/payproof-native-boundary38-20261016`.

Private source 36 extended four modules while retaining their complete canonical V3/HMAC prefixes. Its eight synthetic test methods passed with the RSA public-key primitive explicitly mocked. That run did not qualify RSA mathematics and is not relabelled by the later result.

Private source 37 changed only JobLifetime initialization and `_now`: retain each returned clock object immediately before validation, including invalid bool/NaN/backwards outcomes; exceptions and first UNKNOWN remain separate and sticky. Other seven runtime modules, old V3/HMAC prefixes, the old two-call allowance and reservation behavior are unchanged from the accepted private candidate.

The single qualification 37 child ran 8 methods and 35 subcases, exit 0, 0.9234871660009958 seconds under a 45-second parent timeout. It generated exactly one ephemeral TEST_ONLY RSA2048/e65537 key in child RAM. RS256 signing and verification used the actual cryptography PKCS1v15/SHA256 primitives, without RSA, public_key, verify, hash or padding mocks. Claims-negative vectors were validly re-signed; signature/payload tampering and wrong-key failures were separate. Production/provider/admission/trust keys: zero. No private material was serialized, printed or stored. Only public n/e and vector hashes were retained. Python memory zeroization is not claimed.

Categories: signature/issuer/audience/environment-subject/main/time; synthetic/dict native-authority refusal; original clock identity, exceptions and late shared deadline; loser/consumed replay; missing policy/credentials/registry; primary and cleanup error separation; old V3 prefix/type gates; signed TEST_ONLY happy path with fake OAuth and existing-order GET. Fake GitHub/JWKS/PayPal exchanges were in-memory fixtures, never provider calls.

Actual complete, separate bounded output receipts:

- stdout: 5396 bytes, SHA256 `1974e84080162e101cf162f12b45c307ba7d71ee96b4540ddbd8dd5631eee993`.
- stderr: 1058 bytes, SHA256 `02bb4cfdd237cbaafaafe06c9fdf65281771e740ce192eae4c8199928d9eb19d`.

The exact child source is stored as `acceptance/native37/qualification_child.py`; only its storage path changed. Accepted child SHA256: `8782720fead7e7163f8174c742017410db783f3470d827f4a56d455b7d82b49b`.

## Runtime source pins

The accepted private runtime8 manifest digest is `24145845d8ab34a2aaadbdb9155115e33520ff583398bbe13a8e50dd18060790`; admission5 fingerprint is `d02b9af407be2d945b194e9d68d11e2f27d40889d12183e809a313e3899041aa`. These are candidate source fingerprints, not a grant or authority. Old canonical fingerprints remain historical and are not silently relabelled.

| Path | UTF-8 bytes | SHA256 | Git blob SHA1 |
| --- | ---: | --- | --- |
| payproof/admission.py | 22035 | e370738d355c791ab0443ca3e51bf1d73d1fb347f24b2bf20a6e87954b4d89c9 | 9bc9416321f35f18231b91b1024c32f45e7fc12c |
| payproof/core.py | 14204 | 429a7b26ccc6345f40c4a0800d42a33b7225c87b4901eb09544e861931364d72 | d186a28d9296408b7b108941be4a35ada112aa8b |
| payproof/paypal.py | 6428 | 289488de2d9d04878c67b99f98e7995b9d869ed0e56dc4b1e9a5d5036cd983c4 | b574fe54d52b7a34a1322306f5c9badaea2caf1c |
| payproof/service.py | 4223 | c293170e1837705e6b5def5d587ab843425ea7b74c623ce4814e346319ad8fc2 | 7ca8886bbfd1b2e07db8075476aa2565a09eb0c4 |
| payproof/server.py | 11167 | f0c2606e87396090ac2814acedb90ff90af71b30aeec96a1caf58ef7bc8ad6ac | d03aba262d8d635a09b3919b4a81cdcaf662ba61 |
| payproof/github_oidc.py | 34093 | 324553275634071576e7f87367d969806b5ed6bcab58d2defc42577ef886a59e | dd27c291990506794416745e7597144bb1bfd10d |
| payproof/bootstrap_bridge.py | 39135 | e341d8b65c3f7b85506c6a19965a00fb38d8df3824ea7782a52dbba15dc95672 | ddcfc344ca519f97e7bd8b9ea401f706cea30b78 |
| tools/read_pilot_driver.py | 12716 | bae443485ccf35ad1bc3f63e81a5cb48aae32e1a9f119e46d508102b55ad1b2f | e9466ac02890781d6d6aa4d33d84a45736851b53 |

## Reproduction notes: DOCUMENTED_NOT_RUN

No test, import, native job or workflow was run for this source publication. The actual 37 qualification used isolated private import packaging with empty `payproof/__init__.py` and `tools/__init__.py` helpers. Those helpers were not attested equivalent to canonical initializers and are not published. Normal canonical initialization and full repository regression remain separate gates. No full-repository test PASS is claimed.

The child installs a process-wide `sys.addaudithook`. It must not be imported by ordinary test collection. It is intentionally outside `tests/test_*`; do not add it to unittest/pytest discovery.

For a future separately admitted reproduction, use a disposable staging directory, keeping normal checkout initializers intact. Copy the checkout's `payproof` and `tools` package trees to `<stage>/candidate/` without emptying initializers. Copy this child byte-for-byte to `<stage>/candidate/tests/test_job_native37.py` only inside that disposable layout. Verify its published hash first. Preserve the unchanged core.py/paypal.py/service.py/server.py beforeimages under `<stage>/before/payproof/` and verify their pins above. This layout is required by the child's relative source checks; executing it directly from its published acceptance path is not a qualified reproduction.

Launch that staged child in a fresh isolated interpreter with `<stage>/candidate` as its explicit import root and `runpy.run_path(..., run_name='__main__')`. Install a parent-provided child audit guard before project imports: refuse native socket/subprocess/system activity and host `/run` or environment-secret-file reads. Use exactly one child, an enforced 45-second parent timeout, separate stdout/stderr pipes drained with 131072-byte capture caps, explicit exit and truncation checks, and pre-execution source/harness/protocol pins. Do not export the key or raw synthetic tokens. A failed or uncertain run is terminal and is not repaired/replayed under this publication scope. Canonical initializer behavior may expose differences; it has not been tested here.

## Trust boundaries and remaining gates

The distinct `PAYPROOF_JOB_NATIVE_CONTEXT_V1` path is inactive. NativePolicy, ProtectedManifest delivery, CredentialCustody and authentic OrderRegistry producers remain unbound; default entrypoints reject None before effects. The current credential intake interface explicitly refuses genuine intake until its protected producer is qualified. A dict, environment value, UID/PID, public factory, local HMAC or synthetic RSA signature cannot become native authority.

The expected future subject is the exact immutable owner/repository Environment subject for `payproof-sandbox-readonly`, together with main ref and verified issuer/audience/IDs/source/workflow/run/sole-job checks. Actual GitHub token format, native policy provenance, canonical packaging, credential custody, durable native once controls and authentic order provenance are not qualified by this branch. Signed-token validity and the shared absolute effect deadline are separate checks. The original OAuth1 + existing-order GET1, total2/retry0/300s pilot remains NOT ADMITTED. The separate sandbox create-test-order three-call alternative remains a proposal; no creation/capture/approval/payment/live endpoint is admitted.

The disabled workflow candidate has literal false, empty permissions and no Environment or secret references, outside `.github/workflows`. No active workflow, PR, dispatch, merge, source freeze, secret setting or native control was changed. Final eligible producer integration must first be reviewed and source-published; only then may exact final source pins and separately admitted freeze26/once controls be qualified. An active restrict-update rule with no bypass freezes every writer. No invented Owner/App bypass is proposed.

Independent review of these exact native source readbacks, canonical-package regression and genuine producer binding are required before any native job. Source persistence and synthetic cryptographic verification do not prove vendor identity, runtime eligibility, independent backup/escrow/restore, payment readiness or contest completion.
