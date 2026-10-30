# PayProof — know when to wait

PayProof helps freelancers distinguish buyer approval from evidence of paid work.
It combines PayPal order and capture semantics, visible evidence states, and an
optional local learned assistant that can abstain. The assistant has no authority
to authorize, capture, refund, or otherwise move money.

PayProof was submitted to the PayPal AI Hackathon on 30 October 2026.
The existing Devpost entry is Submitted (5/5), the source repository is public,
and the English demonstration is public on YouTube. Submission confirms delivery;
it is not an eligibility, prize, or production-readiness guarantee.

- [Submitted project](https://devpost.com/software/payproof-8umpng)
- [Watch the 2:40 demonstration](https://youtu.be/eG6frmPgfKw)
- [Independent post-submission review and known limits](docs/POST_SUBMISSION_AUDIT141.md)

## Run the interactive application

Use Linux or macOS with Python 3.11 or newer, its standard-library SQLite, and a
modern browser. From this repository's root, run:

```sh
umask 077
PAYPROOF_DATA=$(mktemp -d /tmp/payproof-demo.XXXXXXXX)
python3 -B -m payproof.server --mode fixture --db "$PAYPROOF_DATA/fixture.sqlite3" --port 8765
```

Open http://127.0.0.1:8765 on the same computer. The default mode is clearly
labelled synthetic, uses deterministic wording, and makes no PayPal or external
AI call. Choose scenarios in the UI to inspect approval, capture, conflict, and
uncertain evidence. Stop with Ctrl+C. Keep the data directory if you want to
inspect it; use a fresh directory for another independent demonstration.

To try the bundled learned assistant, stop the first server, create another
directory, and explicitly opt in:

```sh
PAYPROOF_AI_DATA=$(mktemp -d /tmp/payproof-ai.XXXXXXXX)
python3 -B -m payproof.server --mode fixture --local-ai --db "$PAYPROOF_AI_DATA/fixture.sqlite3" --port 8765
```

The assistant fits a small pinned synthetic corpus once per process. It is
multinomial Naive Bayes implemented with the Python standard library, rather than
an external AI service. Evidence validation precedes advice. Unknown priority is
a supported result, not a payment decision.

No package installation, credentials, paid account, or hosted service is needed
for these source-tree fixture commands. Full instructions, dependencies,
platform limits, and the separate verified-package entry are in the
[judge guide](docs/JUDGE_GUIDE.md).

## Read the evidence correctly

| View | What it demonstrates |
| --- | --- |
| Interactive fixture | Synthetic scenarios and deterministic evidence handling; optional synthetic local AI. |
| Recorded Sandbox panel | A historical real order read from 18 October 2026: CONFLICT, model READY, advisory priority unknown, and **No payment verified**. Opening it makes no current PayPal request. |
| PayPal read-only service | Source integrates authenticated Sandbox order reads with validation and optional local advice. Running it against your own Sandbox additionally requires secure host admission; the fixture cannot grant that authority. |

The [sanitized record](payproof/web/recorded-run117.json) preserves the original
conclusion. Its inner conflict cause was not retained. Successful payment,
capture, authentic webhook delivery, and a current provider session are not
demonstrated by that record. The recorded panel is an offline historical view;
its own label and proof details distinguish it from the interactive fixture.

The [public English demonstration](https://youtu.be/eG6frmPgfKw) lasts 2:40.
It shows actual application footage, synthetic scenarios, and the separate
recorded result. Its final narration uses Kokoro v1.0 `af_heart`; the former
Flite narration is historical and is not the submitted version. English captions
are published and selectable in the YouTube player. See the
[submission text](docs/SUBMISSION.md), [video metadata](docs/YOUTUBE.md), and
[contest status](docs/contest.md).

Source is [MIT licensed](LICENSE). The synthetic training corpus is CC0-1.0.
See [third-party notices](docs/THIRD_PARTY.md) for the dependency and narration
boundary. PayProof is an independent prototype; no financial success, production
readiness, eligibility decision, or competition result is promised.
