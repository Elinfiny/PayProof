# Transport diagnosis and dormant correction

The previous one-use native session remains consumed and closed. No admission,
credential, workflow dispatch, provider call, or server installation is created
by this source change. Existing workflow guards and provider effect slots stay
unchanged.

The HTTPS client now retains only a bounded category, stage, operation and
numeric HTTP status before freezing on an uncertain result. TLS certificate,
TLS EOF, TLS protocol, timeout, connection, HTTP and JSON errors remain distinct.
No retries, exception messages, headers, URLs, IDs or bodies enter the public log.

Local TLS tests exposed missing explicit closure of the wrapped socket. The
original request socket is detached during TLS wrapping; closing it is not
sufficient. The handler now closes the wrapped connection after a request and
when setup fails. This is a verified resource-lifecycle defect; it is not proof
that this defect caused the historical incident. A single synthetic refusal at
the existing connection limit also produced TLS EOF. The old session did not
retain sufficient transport telemetry to select its actual cause.

`buyer_envelope164.py` replaces transcription at the codec boundary with exact
file bytes bound to a trusted file digest, source, run, expiry and recipient.
Tests use disposable synthetic RSA ciphertext only. The codec does not provide
a native private transfer route. Do not feed screenshots, manually reconstructed
text, public uploads, or an expired session into it. Qualifying an existing
authorized private byte-transfer route remains a separate dependency. The old
approval payload and ephemeral private transport key cannot be reconstructed.

## One proposed native diagnostic, not authorized by this document

`tools/native_tls_diagnostic164.py` defaults to refusal without a separate
root-private admission recording a distinct real Owner authorization and its
source hash. A JSON file alone is not permission. One immutable intent prevents
rearming under the same path. Installation and execution remain unperformed.

The proposal uses the existing Netcup TLS certificate and system trust, binds
only `127.0.0.1:9443`, has an absolute 180-second ceiling, at most three synthetic
GETs and twelve accepted connections, and stops on the first unexpected result.
It creates no credentials, PayPal calls, workflow runs or extra cost. It neither
reopens port443 nor modifies the original receiver directory or its ledgers.
Shutdown closes the listener and joins its threads before writing a private
immutable receipt. Canonical source and receipt hash readbacks and an independent
port check are required. Any uncertain start consumes the intent and prohibits
retry. Leave diagnostics for investigation; do not delete intent to rearm.

This probe can qualify local TLS/runtime behavior on the actual host. It cannot
qualify the external GitHub-to-Netcup path, recover old provider IDs or authorize
a new payment test. Those remain explicitly outside its result and authority.

## Validation

Twelve new test methods cover ciphertext byte transfer and corrupt/expired/wrong
bindings, external-network denial, sanitized failure categories, HTTP/schema
errors, delayed buyer ACK and expiry, receiver busy handling, terminal custody,
real loopback TLS trust/refusal, the connection-budget EOF case, explicit socket
closure, separate admission limits, and the full local diagnostic lifecycle with
three synthetic GETs and refusal to rearm. Only affected new checks were rerun
after the test fixture and socket-closure corrections. Existing accepted suites
were not replayed. The test audit hook denies external DNS, connects and binds.

Rollback is a targeted inverse commit restoring the three modified existing
files and removing the three new code/test files plus this document. Preserve
all independent later changes and the dormant workflow; never reset a branch,
restore an expired session, remove a consumed intent or erase UNKNOWN effects.
