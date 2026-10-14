# PayProof

Payment evidence explained for freelancers. This is a **private synthetic development slice**: no PayPal account is connected, no live AI runs, and no real money moves. It is not a contest-ready submission.

## Run

Python 3.11+ is the only runtime dependency. From the extracted project directory:

```sh
python3 -m payproof.server
```

Open `http://127.0.0.1:8765`. On Windows, use `py -m payproof.server` if appropriate. The server binds to loopback and is intended for one local reviewer, not public hosting.

```sh
python3 -m unittest discover -s tests -v
```

Optional installation: `python3 -m pip install .` (the build tool may be downloaded by pip). No package installation is necessary for source execution. Static assets are included in the package.

## Try the complete private workflow

1. Choose **Approved** and read the synthetic order. Approval is distinguished from capture.
2. Choose **Completed capture**, deliver the synthetic webhook, then redeliver it. The duplicate has no second state effect.
3. Choose **Provider unavailable**. A fresh read reports UNKNOWN; earlier reliable evidence remains clearly historical.
4. Choose **Completed capture** and read again to reconcile. No payment operation is repeated.
5. Choose an amount conflict or missing capture. The app abstains from calling it paid.
6. Turn off simulated authenticity and deliver an event. It is rejected. Export the sanitized synthetic evidence as JSON.

The webhook lab is explicitly a **verification stub**. It does not demonstrate actual PayPal authentication. Explanations are deterministic and explicitly labeled **not live AI**.

## Architecture and safety

- Standard-library Python HTTP server, SQLite transactional event ledger, plain HTML/CSS/JavaScript.
- Immutable registered order ID/amount/currency; allowlisted facts only. Payer data and provider credentials are never exported.
- Webhooks do not directly set payment state. An authentic event triggers authoritative order reconciliation. Duplicate IDs with changed content fail closed. Older provider observations cannot overwrite newer reliable evidence.
- Completed order status alone is insufficient; matching completed captures are required. Refunds, mixed captures and unsupported statuses require review.
- The prepared `SandboxPayPal` adapter only permits OAuth, create order, read order and verify webhook paths at the fixed sandbox host. Redirects are rejected. There is no capture, refund or transfer method. A public boolean cannot activate it: the adapter requires a sealed host context from a signed, expiring admission bound to this exact source and sandbox application.
- Create order reserves its request ID durably before network access. A timeout/uncertain response retains UNKNOWN. This build has no UI to call the adapter.
- Real signature verification is prepared using original bounded event bytes and PayPal's verification endpoint; verified only with fake transport so far.
- SQLite stores sanitized facts and payload digests, not full webhook bodies. Database files are excluded from the deliverable.
- Host/origin checks, custom request header, body limits, CSP and text-only rendering protect the fixture interface.

## Remaining gates

Auditor V28 confirmed Basics/TraceHarbor isolation for the examined private scope. Sandbox access and custody are still unqualified. The real checkout lifecycle, real authenticated webhooks and actual PayPal order reads remain unexecuted. Live AI requires a qualified provider, secret custody, numeric budget and enforceable cap; no numeric grant is currently admitted. Publication, deployment and submission require independent review. Do not put credentials in this repository, frontend, exported evidence or chat.

The current authorized external API/model spending ceiling is **USD 0**. The private fixture mode has no external service calls. Subscription/runtime consumption is not measured here. Future hosting/model costs must be estimated and capped after choosing an admitted route.

Project source is held privately in Elinfiny/PayProof. Use the exact reviewed commit as the source reference; historical archives remain transfer carriers. Public publication, deployment and submission have not been performed.

See `docs/scope.md`, `docs/architecture.md`, `docs/service_contract.md`, `docs/contest.md`, `docs/demo.md`, and the verification reports for exact scope and evidence.
