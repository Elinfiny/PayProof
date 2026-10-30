# Run and evaluate PayProof

## Requirements

- The qualified environment is Linux with a POSIX shell, private temporary
  directories, and Python 3.12.14 with the standard-library SQLite module.
  Metadata declares Python >=3.11; other Python versions and operating systems
  have not been qualified by these results.
- A modern desktop browser. The application binds only to 127.0.0.1.
- A complete checkout of this public repository.

Retrieve the source with:

```sh
git clone https://github.com/Elinfiny/PayProof.git
cd PayProof
```

The source entry needs no installer or external credentials. From the checkout
root, follow the two complete commands in [README](../README.md): default fixture,
or a fresh fixture directory with `--local-ai`. Keep that shell open and visit
http://127.0.0.1:8765. Ctrl+C stops the server and releases the port. If the port is
occupied, stop the other local instance or choose `--port 8766` and open that URL.
Do not reuse a Sandbox database as a fixture database.

Windows has not been qualified for this delivery; use an appropriate POSIX
environment. Historical browser checks covered Chromium at 390×844 and 1440×900;
this documentation change adds no new browser or platform qualification.

## What to try

1. Read the synthetic-mode banner and initial UNKNOWN evidence state.
2. Select buyer approval. Approval alone does not mean a verified paid capture.
3. Inspect the synthetic completed-capture, pending, conflicting, and unknown
   scenarios. Read evidence status separately from advisory language.
4. Open the recorded Sandbox panel and its proof details. It shows the historical
   CONFLICT result and “No payment verified”; it does not refresh PayPal.
5. In a separate opt-in local-AI run, inspect the model status and advisory
   priority. The learned assistant can return unknown. It cannot change payment
   facts or execute financial actions.

The default UI is interactive synthetic evidence software, not a payment checkout.
There are no production payments or external model calls in this walkthrough.

## Dependencies and installation boundary

The checked-in source fixture imports only Python standard-library components,
including SQLite and the local HTTP server. The local Naive Bayes implementation
also uses the standard library and fits the bundled synthetic corpus explicitly
at startup only when requested. It does not download weights or use an API key.

`pyproject.toml` declares Python >=3.11, `cryptography==50.0.2`, and the
`setuptools>=65` build backend. Cryptography supports native identity modules;
it is not a prerequisite for the source fixture entry above. The setuptools
constraint is a lower bound, not a fully pinned deployment environment.
The source checkout remains the recommended judge entry and requires no package
installation. The distribution metadata now explicitly includes the recorded
Sandbox JSON and local training corpus JSON as package data. The post-submission
review describes the separate wheel-content and isolated source-start checks;
neither grants a native Sandbox session or installs optional provider authority.

## Existing reviewer package

If reviewing the separately supplied immutable reviewer ZIP, extract it into a
new directory. From its `PayProof_contest84/` folder, run:

```sh
PAYPROOF_PACKAGE_DATA=$(mktemp -d /tmp/payproof-package.XXXXXXXX)
python3 -I -S -B tools/contest_launcher84.py --data-dir "$PAYPROOF_PACKAGE_DATA" --port 8765
```

Append `--local-ai` only for a new, explicit opt-in synthetic run. The launcher
verifies the package's own manifest before starting. It is not a general
repository launcher: the Git checkout does not carry that generated package
manifest at its root. The existing ZIP is not rebuilt by these release documents.
Its original packaging verification result and limitations remain historical.

## Actual PayPal integration and its limit

The separate read-only service uses the PayPal Orders API, authenticates through
the admitted host, validates the registered order, and passes only constrained,
validated evidence to optional local assistance. Invalid or conflicting evidence
can produce abstention. The historical real Sandbox read reached CONFLICT with a
ready local model and unknown priority; it proves neither settlement nor a
successful paid lifecycle. The precise inner conflict cause was not retained.

Your own Sandbox account and registered test order are necessary for any new
provider experiment. They are not sufficient by themselves: the native service
also requires its existing secure host identity/admission and credential custody.
No such authority, signing key, credential, order identifier, or account access
is distributed in this repository. There is no generic public toggle that turns
fixture execution into an authenticated provider session. Use the synthetic and
recorded paths for the credential-free judge walkthrough. A separate native
deployment/admission setup is required for a fresh real API run; it is not claimed
as a turnkey public hosted demo.

## Validation and availability

The public source setup, public video, and Submitted Devpost entry were verified
after submission on 30 October 2026. An independent offline review started both
the default source fixture and opt-in local model using Python 3.12.14 with
third-party site packages disabled. Its 55 checks covered all eight scenarios,
duplicate events, uncertainty/history, input and route rejection, SQLite
integrity, recorded-data integrity, model identity, and clean shutdown.

Historical recorded-panel viewport checks and actual application footage remain
separate evidence. The original media job failed at its audio stage; later
assembly and the final Kokoro narration correction used that same footage.
These distinct results do not rewrite the failed job as successful. The public
160-second video and selectable English captions were verified in YouTube.

The independent review also found historical native-admission test harness drift.
The current source addresses the uncovered cases, preserves the original
failures and separates reused results from newly executed cases. Independent
review151 accepted the reviewed corrections and their local validation scope;
it does not establish a current successful real Sandbox capture or authenticated
webhook. The response binding covers the parsed order JSON, which can include
provider personal data; its digest does not hash the separate OAuth response
and is not a guarantee that arbitrary order fields contain no sensitive values. See
[the scoped audit and known limits](POST_SUBMISSION_AUDIT141.md). No real PayPal
or external model call, capture, or financial action was repeated by the review.

The free judge access method is the complete source setup, retained through
15 December 2026, 16:00 UTC. No live hosted judge session is promised.
