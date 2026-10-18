# PayProof current local-model source preview105

This private ZIP is a runnable synthetic preview, not a finished contest entry.
It includes the existing local learned advisory model and pinned CC0 training
corpus. The model is disabled by default; --local-ai explicitly enables it.
It uses no external AI service or PayPal connection and cannot execute payments.
UNKNOWN evidence remains UNKNOWN; model advice is never financial authority.

## Run this package

Use Python3.11+ with standard-library SQLite and compatible POSIX private-directory
semantics. Extract PayProof_current_local_model105.zip into a new directory;
keep its files unchanged. Create a fresh empty private data directory outside
the extracted root, then run from PayProof_contest84/:

```sh
mkdir -m 700 /tmp/payproof-local-model-new
python3 -I -S -B tools/contest_launcher84.py --data-dir /tmp/payproof-local-model-new --port 8765 --local-ai
```

Open http://127.0.0.1:8765 on the same machine. Removing only --local-ai keeps
the default deterministic behavior. The UI supports synthetic scenarios and
JSON export; Ctrl+C closes the server. Each subsequent run needs a new empty
private data directory. Retain synthetic data for review; never point this
launcher at real data. Host/Origin/CSP/fixture-only guards remain unchanged.
This source preview needs no server, public hosting or installer. Windows and
other interpreter/platform combinations are not qualified by this build.

## Exact current source and rebuild

SOURCE84.json is the authoritative build provenance: schema
PAYPROOF_CURRENT_LOCAL_MODEL_SOURCE105, exact source_commit and source_tree,
and all27 included source paths with Git blob/SHA256/size pins. These actual
final-candidate identifiers are written by the builder after source publication;
they are not self-embedded in this document. MANIFEST.csv has28 rows and the
ZIP29 members, including provenance and the manifest. The historical84 base
commit3d7eb63fbfaf8c3cb9223effecac41f24c6623e3 and tree
fc3f4ce717209193eeaf2591020abd28420ae154 are labeled historical_84_base_*;
neither is claimed as this new package's current source. The accepted pre105
baseline was maina15d904bc77b742f518bc22058fee6e04fb64c62/tree
61f56ad55e3a4082f4ea90c414d7f051e46f8c4f.

From the exact reviewed Git checkout, inspect git rev-parse HEAD and
git rev-parse HEAD^{tree}, then use their full actual values:

```sh
python3 -I -S -B tools/contest_build84.py --root . --source-commit EXACT_REVIEWED_COMMIT --source-tree EXACT_REVIEWED_TREE --output /tmp/PayProof_current_local_model105.zip
```

The output must be absent. The builder uses local git ls-tree only or an
independently verified full83-leaf inventory passed with --inventory; it checks
the complete Git Merkle root and every included source body. Only the three
missing canonical model files were added to the closed payload allowlist.
Compressed and aggregate uncompressed sizes remain <=786432B, each source
<=65536B, with no symlink/duplicate/undeclared payload, installer, dependency
directory, receipt, live database, secret or admission. Partial output is
retained on failure; it must not be retried or called successful.

The current packaged-entry qualification uses one NEW synthetic unavailable
event, --smoke --local-ai, fresh private0700 data/DB, and separate40s parent
containment around20s work plus5s bounded server cleanup. It records every
original HTTP response before assertions, requires local model READY and pinned
fingerprint0513952a8592ad96858b70d87da5cf3d8079b2c5e53e4e38b8dbed2e90d30662,
UNKNOWN/advisory abstention, events1/effects0, serverclosed/no livethread,
and no external connection, secret open or cryptography import. Historical84
qualification is valid only for its historical ZIP. Do not replay the consumed
PAYPROOF-PACKAGED105-LOCALMODEL-ONCE case; source/packaged qualification results
are reported separately from future interactive preview use. Default-off84
smoke, model benchmarks and renderer104 are not rerun105.

The fixture import graph uses standard-library modules under -I -S -B.
The unchanged pyproject still declares cryptography==50.0.2 for native identity
modules; that dependency is neither removed nor stubbed. No pip/npm/download
or dependency installation is part of this package qualification.

## Remaining real integrations

Real free PayPal Sandbox integration remains central and unqualified. The
existing adapter requires authentic nonsecret app/owner association, supported
secret custody and the existing sealed source-bound host admission/registered
order scope. Retained historical handles and login do not prove custody; no
new PayPal account read/login/OAuth/API/key/payment operation is admitted105.
The smallest next provider step must come from the existing authentic access
and custody evidence under a distinct actual scope, without inventing another
broker/certificate or replaying UNKNOWN effects.

Included local inference is real local model assistance. External model API
integration is absent; no model/API cash grant or payment tools are implied.
Public licensed source/setup, judge access, English video, real Sandbox
integration and final submission remain open. This build makes no hosted,
public, human-visual or finished-contest qualification claim. The disabled
workflow candidate remains historical source only; no CI/job is started105.
