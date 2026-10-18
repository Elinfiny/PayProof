# PayProof — know when to wait

PayProof helps freelancers separate an approved order from evidence of paid work.
It combines a visible evidence state with advisory assistance that can abstain.
No model can capture, refund or authorize a payment through this application.

This is a **private reviewer candidate**, not a submitted contest entry.
The exact private PR, candidate commit and complete Git tree are recorded in the
generated `SOURCE84.json` (`source_pr_url`, `source_commit`, `source_tree`). The
candidate branch is `review/payproof-reviewer-build121-20261018`; source remains
canonical in the private [Elinfiny/PayProof repository](https://github.com/Elinfiny/PayProof).
The document cannot embed the hash of the future commit containing itself.

| What you can examine | Evidence and meaning |
| --- | --- |
| Interactive offline fixture | Synthetic scenarios in the local UI; deterministic wording by default, model disabled. No current PayPal session. |
| Recorded real Sandbox result117 | Saved 18 October 2026 at 19:36:29.277776Z: CONFLICT; local model READY but priority unknown; no payment verified. The panel reads a bundled sanitized record, not PayPal. |
| Remaining proof | No successful paid/captured lifecycle, authentic webhook, hosted judge session, published video or submitted entry is established by this ZIP. |

## Start reviewing

Read [the package guide](docs/CONTEST_BUILD84.md), then the
[2:40 English walkthrough](docs/demo.md). Python3.11+ with standard-library SQLite
and POSIX private-directory semantics is required for the fixture source entry.
Extract the reviewer ZIP into a fresh directory and keep its files unchanged.
Inside `PayProof_contest84/`, create a **new** empty data directory outside the
package and run:

```sh
mkdir -m 700 /tmp/payproof-reviewer-new
python3 -I -S -B tools/contest_launcher84.py --data-dir /tmp/payproof-reviewer-new --port 8765
```

Open http://127.0.0.1:8765 on that machine. This is a reviewer run instruction;
build121 did not start HTTP or a browser. Ctrl+C stops the server. A later run
needs another fresh data directory. Do not use real customer data. No installer,
PayPal credentials or external AI account is needed for the default fixture.
The launcher checks every manifest member before starting the fixture.

The unchanged project dependency `cryptography==50.0.2` belongs to native identity
modules; the fixture entry imports only standard-library dependencies under
`-I -S -B`. It is neither installed nor replaced by a stub in this delivery.
The optional existing `--local-ai` fits the bundled synthetic local model; it is
off by default and was not run121. Included model code is not a live model API.

## Evidence you can follow

- [Recorded117](payproof/web/recorded-run117.json) and its
  [review notes](payproof/web/recorded-run117.review.json) preserve the sanitized
  original conclusion. The original [run39159527253](https://github.com/Elinfiny/PayProof/actions/runs/39159527253)
  performed one OAuth request and one registered-order GET, not a payment action.
- The explanation is “Order facts conflict with the registered expectation.”
  The precise inner validation cause was not retained. A guessed amount mismatch
  or freshness failure is not proof of that historical cause.
- [Panel QA120](https://github.com/Elinfiny/PayProof/actions/runs/39163115561)
  passed recorded-panel checks at 390×844 and 1440×900. This scoped historical
  result is not a new whole-product or contest-readiness test.
- The ZIP's `MANIFEST.csv` and `SOURCE84.json` bind all included files to the
  actual candidate and distinguish transport integrity from runtime authority.

[Contest conditions](docs/contest.md) remain open. Repository visibility is
private; no merge, deployment, video upload, terms acceptance or submission is
performed by this delivery. Licensed under [MIT](LICENSE).
