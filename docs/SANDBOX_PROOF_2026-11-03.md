# Verified Sandbox chain — 3 November 2026

A distinct, bounded PayPal Sandbox proof completed successfully on 3 November
2026 at 13:54 UTC. It used USD 1.00 of fictitious Sandbox funds, no real money,
and no external AI service. This later proof is presented explicitly as recorded evidence in the new
[2:52 demonstration](https://youtu.be/EEMdhzDCnGE). It remains separate from the historical
CONFLICT record in the retained old film.

## Verifiable result

[GitHub run 41647346073](https://github.com/Elinfiny/PayProof/actions/runs/41647346073)
completed successfully, attempt 1, from source
`56f0716835d0ca9054b5d297102b6fea47058b88`.
The sanitized terminal result is `COMPLETED`:

- One order was created, approved by the Sandbox buyer, and captured.
- A separate final order read confirmed the completed capture.
- An authentic webhook was received; its signature was checked with PayPal,
  and the corresponding event was read and bound to the same evidence.
- The local learned model ran on the validated Sandbox evidence. Its persisted
  output was `model_ready: true`, `priority: capture_context`,
  `uncertainty: false`, and `synthetic: false`.
- The model's recommendation was to review the supplied capture evidence and
  its source. It had `financial_authority: false` and `payment_actions: []`;
  its output is advice, not an independent payment verification.

Each of the ten admitted provider operations was used exactly once: OAuth,
webhook-subscription read/create, order create, approval read, capture, final
read, signature verification, event read, and deletion of the newly created
webhook subscription. No retry or second attempt was needed for this run.

## Cleanup and evidence custody

Independent cleanup returned HTTP 204 (`DELETED_NEW`). Native closure recorded
`closed: true`, `ingress_restored: true`, and `ACCESS_CLOSED`.
A subsequent read observed only TCP 22 listening, no temporary nftables table,
and an inactive proof timer. The public workflow admission gate was closed.

All 47 retained evidence files matched their custody SHA-256 inventory.
Original provider payloads, credentials, buyer identifiers and approval material
remain private and are not included in this repository. The public workflow
contains the sanitized outcome and cleanup receipt.

The ten-minute and 512-connection ceilings were unchanged. The native result
reported 221 accepted connections and 96 errors; this is not a zero-error or
production-load qualification.

## Reading this alongside the film

The earlier [English film](https://youtu.be/eG6frmPgfKw) remains the historical
application walkthrough: synthetic scenarios plus the 18 October CONFLICT read.
It is not footage of this new successful chain. The old record remains
CONFLICT / No payment verified and has not been rewritten.

This new Sandbox result does not resolve other historical UNKNOWN attempts,
authorize replay, demonstrate real-money processing, or establish production
readiness. The local judge walkthrough remains credential-free; the temporary
proof receiver has been shut down.


## New recorded-proof presentation

The new film and dedicated C244 panel show a sanitized saved projection of this result.
Opening the panel makes no provider call; no payment was repeated for filming.
The old film and original117 CONFLICT panel remain intact.
