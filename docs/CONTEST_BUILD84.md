# Private reviewer delivery121 — current package contract

This new reviewer ZIP reuses the existing builder84/launcher84 and accepted105
source payload, updated to the actual candidate121. It is not a replay of the
consumed84/105 build/smoke. It is private and has not been submitted.

## Exact source and contents

`SOURCE84.json`, schema `PAYPROOF_PRIVATE_REVIEWER_SOURCE121`, records the exact
private `source_pr_url`, candidate `source_commit`, complete `source_tree` and
Git blob/size/SHA256 pins for all30 tracked product files. These identifiers are
generated after the real PR candidate exists; the historical84 base identifiers
remain explicitly historical. `MANIFEST.csv` has31 rows; the ZIP has32 members,
including provenance and the manifest, under the retained `PayProof_contest84/`
folder name. This folder name does not identify the package as the old84 build.

The allowlist contains application code/assets, the pinned synthetic model
corpus, license, setup, builder/launcher, this guide, contest/demo notes and the
two sanitized recorded117 files. Historical workflow candidates, QA history,
repository backups, databases, secrets and dependency directories are excluded.
Metadata establishes source/transport integrity, never runtime authority.

## Reviewer run (not executed121)

Python3.11+ with standard-library SQLite and compatible POSIX directory semantics
is required. Extract the ZIP into a fresh directory. From `PayProof_contest84/`:

```sh
mkdir -m 700 /tmp/payproof-reviewer-new
python3 -I -S -B tools/contest_launcher84.py --data-dir /tmp/payproof-reviewer-new --port 8765
```

The data directory must be newly created, empty, owned and0700, outside the
package. Open http://127.0.0.1:8765 on that machine; Ctrl+C closes the server.
Each later run needs a different fresh directory. Default mode is an interactive
synthetic fixture with deterministic wording, no external connection and model
disabled. Recorded117 is a separate saved panel and makes no current PayPal call.
Optional existing `--local-ai` fits the bundled synthetic model; not used121.
Native identity modules still declare cryptography==50.0.2; no installer or stub
is provided. The fixture import path needs only standard-library dependencies.
Other platforms and HTTP startup are **not tested121**.

## Current validation boundary

One new build121 and one packaging group with at most three checks:
integrity/source/dependency coverage; actual CLI help plus manifest verification
and fixture import in a fresh isolated extraction; claims/proof agreement.
The existing real argparse `--help` and `verify_build` function support the
non-network entry check. No `--check` flag is invented, no server or historical
`--smoke` is run, and no model fit, PayPal API, browser or installation occurs.
Build121 results belong to the delivered artifact receipt; this source document
defines the checks and does not pre-assert their outcome. Historical105 runtime
and120 panel qualification remain separately scoped evidence, not new121 tests.

## Controlled build contract

From the exact candidate checkout, using actual immutable identifiers and the
actual private PR URL (or a verified complete inventory via `--inventory`):

```sh
python3 -I -S -B tools/contest_build84.py --root . --source-commit EXACT_CANDIDATE_COMMIT --source-tree EXACT_CANDIDATE_TREE --source-pr-url EXACT_PRIVATE_PR_URL --output /tmp/PayProof_reviewer121.zip
```

This documents the real builder interface, not an instruction to replay the
consumed121 build. The output must be absent; source bodies must match the full
native Git Merkle inventory. Cap786432 bytes applies separately to compressed
and aggregate uncompressed bytes, each source member<=65536. Keep partial output
and original failure on error; no delete/recreate/repair-and-replay.

## Meaning and remaining work

Three levels: offline interactive fixture; historical real117 CONFLICT with
local model READY/priority unknown/no financial authority/no payment actions;
unproved payment/capture/authentic webhook/hosting/public entry. The exact inner
validation cause117 was not retained. See demo.md for the English ~2:40 narration
and proof map; contest.md lists every remaining official condition. Public source,
judge access, a qualifying integrated demonstration, eligibility/terms, actual
public YouTube video under3min and complete timely submission remain open.
No new current provider session, finished contest entry or video is claimed.
