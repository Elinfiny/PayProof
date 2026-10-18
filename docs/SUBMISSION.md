# PayProof submission text

Prepared English copy; no entry has been submitted. Field names below follow
Devpost's standard submission guide and this hackathon's published requirements.
Hackathon-specific additional questions still require inspection in the actual
authenticated form. A generic guide is not evidence that those fields were seen.

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

Repository: https://github.com/Elinfiny/PayProof — public availability pending.
Run instructions: README.md and docs/JUDGE_GUIDE.md in that repository.
No login, credential, or paid service is required for the interactive synthetic
and recorded judge walkthrough. Fresh real provider execution additionally
requires your own Sandbox and separately admitted secure host setup.

Video URL: pending the actual public YouTube upload; no placeholder URL should
be pasted into the submission. Hosted demo URL: none claimed.

## Five judging criteria and existing evidence

| Criterion | Evidence the reviewer can assess | Limit |
| --- | --- | --- |
| Technological Implementation | PayPal read-only service, validation, SQLite ledger, local learned model, and real recorded abstention. | No successful paid lifecycle or new positive prediction is claimed. |
| Design | Interactive evidence states, separate recorded proof, expandable details, and two tested viewport sizes. | These checks do not certify every platform or accessibility requirement. |
| Potential Impact | Concrete freelancer decision: inspect whether available evidence supports starting work. | No measured customer adoption or financial savings. |
| Innovation/Idea | Local learned assistance constrained by validated payment evidence and visible abstention. | No claim of market uniqueness. |
| Presentation | Actual 160-second English application film and reproducible source instructions. | Public upload and final judge access still need verification. |

## Remaining actual form information

Devpost's standard flow includes team, project overview, story, technology tags,
try-it-out links, gallery, video, additional hackathon questions, and final terms.
The current browser showed “Register for this hackathon” and a login link before
the actual project form; the authenticated submission fields were not exposed.
Required custom fields, options, length limits, participant account, team or
organization representation, age/residence/conflicts, and legal confirmations
have not been filled or guessed. No team invitation, draft creation, enrollment,
terms acceptance, or submission has occurred. A thumbnail or gallery asset, if
required by the actual form, also remains to be selected; none is invented here.

Published requirements: [hackathon rules](https://paypalaihackathon.devpost.com/rules)
and [Devpost submission steps](https://help.devpost.com/article/126-know-your-submission-steps).
