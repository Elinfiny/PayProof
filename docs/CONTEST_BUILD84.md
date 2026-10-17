# PayProof reproducible source test-build

This build is a runnable **synthetic preview**, not a finished contest entry.
It does not connect to PayPal or an AI model. An UNKNOWN order does not prove
payment. The fixture webhook uses an explicitly labeled verification stub.
No Netcup server or public hosting is needed to run this preview.

## Run the supplied ZIP

Use Python 3.11 or newer with standard-library SQLite. Extract the ZIP into a
new directory; keep its files unchanged. Create an empty private data directory
outside the extracted build (0700 on Linux/macOS), then run from its root:

```sh
mkdir -m 700 /tmp/payproof-review-new
python3 -I -S -B tools/contest_launcher84.py --data-dir /tmp/payproof-review-new --port 8765
```

Open http://127.0.0.1:8765 on that same machine. The existing fixture interface
shows deterministic explanations, simulated order scenarios and JSON export.
Ctrl+C closes the local server. The data directory contains only synthetic data;
retain it for review. A subsequent run needs a different empty private directory.
Do not point this launcher at existing databases or real user data.

The launcher validates every manifest payload before importing the package,
always chooses the existing `fixture` mode and binds only to loopback. It cannot
grant sandbox authority or replace the sealed native host context. This local
source-run route is not a browser/site access workaround or a deployed service.
Windows users need a private directory/compatible permission semantics; this
specific launcher qualification uses POSIX 0700/0600 and is not Windows proof.

## Dependencies and rebuild

The fixture entry is exercised with `-I -S -B`: user/site packages are disabled.
The actual import graph of server/core/admission/paypal/service/fixtures loads
only standard-library modules in fixture mode. Native identity modules import
`cryptography`, and the unchanged `pyproject.toml` declares exactly
`cryptography==50.0.2`. This build neither drops that requirement nor supplies a
crypto stub. Native mode is not exposed by this launcher. No new dependency
download, install or compatibility claim is made for a different interpreter.
Do not run an unbounded `pip install .` as part of this source preview:
`setuptools>=65` in the original package metadata is not an offline lock.

From an exact reviewed Git checkout containing these tools, inspect the commit
and tree with `git rev-parse HEAD` and `git rev-parse HEAD^{tree}`, then run:

```sh
python3 -I -S -B tools/contest_build84.py --root . --source-commit EXACT_COMMIT --source-tree EXACT_TREE --output /tmp/PayProof_contest_new.zip
```

Replace both placeholders with the inspected full identifiers. The output must
be absent. The builder uses local `git ls-tree` only, or a separately verified
complete inventory supplied with `--inventory`; it never fetches or installs.
It checks the full inventory Merkle root and each allowlisted source Git blob.
The ZIP includes package/web assets, LICENSE, original setup metadata, these
tools/instructions, a disabled execution candidate, source identifiers and a
complete SHA-256 manifest. No secret, admission, database, cache, saved receipt,
old qualification archive or installation directory is included. `SOURCE84.json`
is integrity metadata, never authority. Keep any partial failed output; do not
retry into it or treat it as a successful build.

The bounded smoke entry is `tools/contest_launcher84.py --smoke --data-dir
ABSOLUTE_EMPTY_PRIVATE_DIR --event-id DISTINCT_SYNTHETIC_ID`, also using
`python3 -I -S -B`. It starts the packaged fixture server on an ephemeral
loopback port, reads initial UNKNOWN state, delivers one new **synthetic**
unavailable-provider event, confirms UNKNOWN/NEEDS_RECONCILIATION and closes
the server. The exact84 local case is consumed; do not rerun it to reproduce
the stored receipt. Future hosted qualification needs its distinct admission,
fresh namespace and event identifier.

## Remaining contest integrations

Real free PayPal sandbox integration must be central to the submitted product.
The existing SandboxPayPal adapter still requires authentic application/owner
association, secret custody, sealed expiring source-bound host admission,
approved operations and registered-order scope. Application identity and custody
are unproved here; default loader remains UNADOPTED and real pilot UNADMITTED.
Do not fabricate signatures, weaken expiry/allowlists, reuse a refused caller,
put credentials in source/artifacts, or infer permission from a logged-in page.
The next safe effect is an independently admitted existing sandbox route with
authentic nonsecret app/owner metadata and a supported secret-custody mechanism,
then separately scoped sandbox calls. Real money endpoints remain excluded.

The service's ExplanationPort is a future integration boundary, not an actual
AI tool/model integration. A future reviewed adapter must call an admitted real
model using sanitized source-bound facts only, without payment tools, preserve
uncertainty and enforce a numeric usage cap. Current external/model ceiling is
USD 0; sponsor credits or a USD5 proposal are not an approved budget. No model
call or key creation is performed in84.

A complete runnable test-build is an alternative to public hosting under the
rules reviewed by Auditor, but this synthetic build alone does not satisfy
PayPal/AI integration. Final entry still needs actual integrations, free working
judge access through judging, public licensed source/setup under its publication
gate, English demonstration/video and verified submission. Reconfirm the
official deadline before final submission: 12 November 2026, 20:00 UTC
(22:00 Europe/Bucharest). Official rules: https://paypalaihackathon.devpost.com/rules

## Hosted candidate and activation gate

`workflow_candidates/payproof-contest-build84.yml.disabled` is source only.
It is not under `.github/workflows`, has not run, and grants no native or custody
authority. Before activation, independently review the exact source commit,
workflow and one-run nonce; qualify GitHub included runner minutes/artifact
storage/retention and enforce zero new spend. The candidate uses no installer,
cache, provider environment, secrets or id-token. Artifact upload/transfer is
deliberately absent until a separately reviewed storage/cost route is admitted.
No real PayPal call or actual AI integration is hidden inside a build job.
