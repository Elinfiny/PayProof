# PayProof submission text

The English story below is saved in the existing Devpost entry 1245971,
submitted on 30 October 2026 and independently observed as Submitted (5/5):
https://devpost.com/software/payproof-8umpng.
The actual additional questions, technology and required AI answers, source/build
links, Owner-supplied participant answers, and final acceptance were saved.
This source document records delivery; it does not independently certify eligibility.

## Project name

PayProof

## Project tagline

Know when to wait: PayPal payment evidence and local AI guidance for freelancers, with uncertainty made visible.

## Project story

### Inspiration

For a freelancer, "approved" and "paid" can sound dangerously similar. Starting work on uncertain evidence can create avoidable disputes. PayProof makes the evidence state visible before offering advice, so a confident sentence cannot silently become financial authority.

### What it does

PayProof is a local application for reviewing payment evidence. Its interactive synthetic scenarios distinguish buyer approval, capture status, pending evidence, conflict, and unknown outcomes. The default fixture uses deterministic wording and makes no PayPal or external AI call.

A separate, integrity-checked recorded panel presents the successful real PayPal Sandbox proof C244 from 3 November 2026. It is saved evidence, not a new live payment. The earlier 18 October CONFLICT record remains intact in its own historical panel. The demonstrated interface cannot initiate payments, capture funds, or issue refunds.

### Verified PayPal + local AI proof

The bounded C244 test used one fictitious US dollar and no real money. Buyer approval was followed by a completed capture and a separate confirming final order read. An authentic webhook signature was verified through PayPal and the event was bound to the same payment evidence. Each of the ten admitted provider operations was used exactly once.

The local learned model analysed the validated evidence. Its saved output was model_ready: true, priority: capture_context, uncertainty: false, and synthetic: false. The recommendation was to review the supplied capture evidence and its source. The model had financial_authority: false and no payment actions; its output is advisory, not independent provider verification.

Independent cleanup removed the temporary webhook subscription with HTTP 204. The receiver and temporary access were closed. All 47 retained evidence files matched their custody hashes. Original provider payloads and buyer details remain private.

[Successful run](https://github.com/Elinfiny/PayProof/actions/runs/41647346073) · [Scoped proof](https://github.com/Elinfiny/PayProof/blob/main/docs/SANDBOX_PROOF_2026-11-03.md).

### How it works

The read-only service integrates PayPal Orders API semantics with evidence validation and a SQLite ledger. An optional local multinomial Naive Bayes assistant uses a pinned, bundled CC0 synthetic corpus. It is implemented with the Python standard library, with no external AI service. Validation precedes advice, and the assistant can abstain when evidence is invalid or unconfirmed.

Python serves the HTML, CSS, and JavaScript interface locally. The synthetic walkthrough and recorded evidence are available without credentials or a paid service. The separately admitted Sandbox proof harness is distinct from the read-only application interface; opening the recorded panel does not repeat that test.

### Challenges and lessons

A ready model is not evidence of a successful payment. We preserve conflicting facts and UNKNOWN outcomes instead of replacing them with a success claim. The successful C244 proof does not resolve earlier uncertain attempts. Recorded evidence must remain visibly separate from interactive synthetic examples and current provider state.

### Accomplishments and limits

The project combines an interactive evidence workflow, read-only PayPal integration, local learned advice, and a separately verified Sandbox chain with independent cleanup. The new 2:52 English film shows the actual application and explicitly recorded C244 evidence, with narration and English captions. The earlier 2:40 film remains available as historical material.

This is a prototype, not production readiness or a guarantee for every payment scenario. C244 recorded 221 accepted connections and 96 errors; it is not a zero-error or production-load qualification. No real-money processing, measured customer adoption, or financial advice is claimed.

### What's next

Improve explanations for conflicting evidence and broaden deployment and accessibility validation. Any future provider experiment requires its own secure admission and custody. The credential-free judge walkthrough remains the recommended way to evaluate the application.

## Built with

Python; SQLite; JavaScript; HTML; CSS; PayPal Orders API (Sandbox); local
multinomial Naive Bayes. The local model uses a CC0 synthetic corpus. No external
AI service or optional sponsor tool is claimed.

## Try it out / testing instructions

Repository: https://github.com/Elinfiny/PayProof — verified public.
Run instructions: README.md and docs/JUDGE_GUIDE.md in that repository.
No login, credential, or paid service is required for the interactive synthetic
and recorded judge walkthrough. Fresh real provider execution additionally
requires your own Sandbox and separately admitted secure host setup.

Public video: https://youtu.be/EEMdhzDCnGE (2:52, English, English captions).
The final narration is Kokoro v1.0 `af_heart`. Hosted demo URL: none claimed.

## Five judging criteria and existing evidence

| Criterion | Evidence the reviewer can assess | Limit |
| --- | --- | --- |
| Technological Implementation | PayPal read-only service, validation, SQLite ledger, local learned model, and recorded successful C244 proof plus historical abstention. | Later Sandbox proof is separately documented; no real-money lifecycle or production readiness is claimed. |
| Design | Interactive evidence states, separate recorded proof, expandable details, and two tested viewport sizes. | These checks do not certify every platform or accessibility requirement. |
| Potential Impact | Concrete freelancer decision: inspect whether available evidence supports starting work. | No measured customer adoption or financial savings. |
| Innovation/Idea | Local learned assistance constrained by validated payment evidence and visible abstention. | No claim of market uniqueness. |
| Presentation | Public 172-second English application film, English captions and independently checked source instructions. | Full platform/accessibility coverage and future uptime are not guaranteed. |

## Saved form and continuing availability

The existing entry is Submitted (5/5). No second entry or final Submit is needed.
Its saved build link identifies the submitted source revision; any later reviewed
source correction must update that link in the same entry while preserving the
actual submitted state. The repository, video and judge setup must remain freely
available throughout judging. Optional gallery or contribution fields do not
replace that requirement.

Published requirements: [hackathon rules](https://paypalaihackathon.devpost.com/rules)
and [Devpost submission steps](https://help.devpost.com/article/126-know-your-submission-steps).

