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

For a freelancer, “approved” and “paid” can sound dangerously similar. Starting
work on uncertain evidence can create avoidable disputes. PayProof makes the
evidence state visible before offering advice, so a confident sentence cannot
silently become financial authority.

### What it does

PayProof is a local application for reviewing payment evidence. Its interactive
synthetic scenarios distinguish buyer approval, capture status, pending evidence,
conflict, and unknown outcomes. A separate recorded panel shows a real historical
PayPal Sandbox order read without making a fresh provider request.

The recorded read returned CONFLICT. The local model was ready, but advisory
priority remained unknown and no payment was verified. That uncertainty is shown
in the product rather than replaced by a success claim. PayProof cannot initiate
a payment, capture, or refund from the demonstrated interface.

### How we built it

The read-only service integrates the PayPal Orders API with evidence validation
and a SQLite ledger. PayPal order and capture semantics are central to the
problem the application addresses. An optional local multinomial Naive Bayes
assistant uses a pinned, bundled synthetic corpus. It is a learned model built
with the Python standard library, not an external AI service. Source validation
precedes advice, and the assistant can abstain when evidence is invalid or
unconfirmed. The assistant has no financial tools.

The frontend uses HTML, CSS, and JavaScript. Python serves the local UI. The
default fixture uses deterministic wording; the learned assistant is an explicit
opt-in. The demonstration separates synthetic behavior from the historical real
Sandbox result so viewers can assess each on its own evidence.

### Challenges and what we learned

The hard problem was maintaining the boundary between a useful explanation and a
verified payment fact. A ready model is not evidence of a successful transaction.
Conflicting provider facts must remain visible, and the original outcome must
survive later presentation improvements. We also learned to make recorded proof
legible on narrow screens without blending it into an interactive simulation.

### Accomplishments

We built an interactive evidence workflow, a local advisory model, a read-only
PayPal integration, a sanitized recorded-result panel, and a short English film
showing the application functioning. Existing recorded-panel checks covered
390×844 and 1440×900. The film lasts 2:40. These are scoped results, not a claim
that the prototype is production ready or that every financial path has passed.

### What's next

Improve the explanation of conflicting evidence and broaden deployment and
accessibility validation. Any further real Sandbox experiment needs separate
admission and secure custody. Successful capture, authentic webhook delivery,
and a production payment lifecycle are not demonstrated by this entry material.

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

Public video: https://youtu.be/eG6frmPgfKw (2:40, English, selectable English captions).
The final narration is Kokoro v1.0 `af_heart`. Hosted demo URL: none claimed.

## Five judging criteria and existing evidence

| Criterion | Evidence the reviewer can assess | Limit |
| --- | --- | --- |
| Technological Implementation | PayPal read-only service, validation, SQLite ledger, local learned model, and real recorded abstention. | No successful paid lifecycle or new positive prediction is claimed. |
| Design | Interactive evidence states, separate recorded proof, expandable details, and two tested viewport sizes. | These checks do not certify every platform or accessibility requirement. |
| Potential Impact | Concrete freelancer decision: inspect whether available evidence supports starting work. | No measured customer adoption or financial savings. |
| Innovation/Idea | Local learned assistance constrained by validated payment evidence and visible abstention. | No claim of market uniqueness. |
| Presentation | Public 160-second English application film, English captions and independently checked source instructions. | Full platform/accessibility coverage and future uptime are not guaranteed. |

## Saved form and continuing availability

The existing entry is Submitted (5/5). No second entry or final Submit is needed.
Its saved build link identifies the submitted source revision; any later reviewed
source correction must update that link in the same entry while preserving the
actual submitted state. The repository, video and judge setup must remain freely
available throughout judging. Optional gallery or contribution fields do not
replace that requirement.

Published requirements: [hackathon rules](https://paypalaihackathon.devpost.com/rules)
and [Devpost submission steps](https://help.devpost.com/article/126-know-your-submission-steps).
