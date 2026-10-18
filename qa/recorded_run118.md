# Recorded Sandbox evidence panel

The existing UI now shows the reviewed saved Sandbox run separately from its synthetic order controls. It displays CONFLICT, “No payment verified”, and the local model's READY state with advisory abstention. The original explanation is retained; the exact internal financial validation cause was not recorded.

The inert JSON embedded in the existing HTML is an exact minimal projection of the saved public receipt at 2026-10-18T19:36:29.277776Z. Its canonical bytes are also in `payproof/web/recorded-run117.json`; the separate review record contains their SHA-256 and provenance. The SHA checks consistency, not vendor attestation or authority. Missing, modified, malformed, or unavailable integrity evidence keeps the panel unverified. The fixed existing run link does not trigger execution. No import, refresh, payment button, provider/model call, or Store write is introduced.

The existing application script serves the isolated binding; no server route or CSP change is required. The CSS, earlier UI bindings, core, admission, provider, model, corpus, and every workflow remain unchanged. The record contains an order hash, not an order ID or credentials.

Run only the new bounded group: `node --test qa/recorded_run118.cjs` (3 cases). It exercises the actual appended production binding with Node WebCrypto and a minimal DOM sink harness: saved real evidence, changed/missing evidence, and hostile text. This is behavioral validation, not a browser/layout PASS.

For the next supported renderer review, use only this new panel at 390×844 and 1440×900: visible heading and CONFLICT/no-payment distinction; readable wrapped UTC date and local abstention; keyboard expansion/collapse of original evidence; fixed run link; no horizontal overflow with details open; unchanged synthetic controls above. This run has no available local Chromium executable, and no refused browser route, runner, install, or workflow was retried. Visual review of these two new targets remains pending; earlier UI104 results apply to its earlier source.

