import argparse
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from .core import Store, InvalidData, canonical, identifier
from .admission import SandboxContext, load_host_context, _json
from .paypal import SandboxPayPal
from .service import PaymentEvidenceService, annotated_order
from .local_ai_view import enable_local_assistance, assistance_metadata
from . import fixtures

STATIC = Path(__file__).resolve().parent / "web"
LIMIT = 16 * 1024
NAMESPACES = {"fixture": 0x50504658, "sandbox-readonly": 0x50505342}
DEFAULT_DATABASES = {"fixture": ".data/payproof.sqlite3",
                     "sandbox-readonly": ".data/payproof-sandbox-readonly.sqlite3"}
GATES = ["Sandbox access + isolation review", "Live AI custody + enforced budget", "Independent publication review"]


def _namespace_store(db_path, mode):
    """Keep HTTP fixture and sandbox ledgers separate, including caller-supplied paths."""
    if mode not in NAMESPACES or str(db_path) == ":memory:":
        raise InvalidData("A mode-specific persistent database is required")
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(path), timeout=5)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        current = db.execute("PRAGMA application_id").fetchone()[0]
        if current not in (0, NAMESPACES[mode]):
            raise InvalidData("Fixture and sandbox databases cannot be shared")
        if current == 0:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            # Only the existing fixture-only HTTP ledger may be adopted as a legacy fixture.
            legacy_fixture = (mode == "fixture" and tables == {"orders", "events", "effects"}
                              and all(row[0] == fixtures.ORDER_ID for row in db.execute("SELECT id FROM orders"))
                              and db.execute("SELECT count(*) FROM effects").fetchone()[0] == 0)
            if tables and not legacy_fixture:
                raise InvalidData("An unqualified existing ledger cannot be adopted")
            db.execute(f"PRAGMA application_id={NAMESPACES[mode]}")
    return Store(path)


def _read_scope(context):
    if type(context) is not SandboxContext:
        raise InvalidData("Verified typed host context required")
    context.require("orders:read")
    if context.operations != frozenset({"orders:read"}):
        raise InvalidData("HTTP sandbox mode requires only orders:read admission")


@dataclass(frozen=True)
class HttpApplication:
    mode: str
    store: Store
    service: PaymentEvidenceService = None
    assistance: object = None

    def __post_init__(self):
        if self.mode not in NAMESPACES or type(self.store) is not Store:
            raise InvalidData("Invalid HTTP application")
        if self.mode == "sandbox-readonly":
            if type(self.service) is not PaymentEvidenceService or self.service.store is not self.store:
                raise InvalidData("The existing payment evidence service is required")
            _read_scope(self.service.adapter.context)
        elif self.service is not None:
            raise InvalidData("Fixture mode cannot receive sandbox service authority")
        with self.store.connect() as db:
            if db.execute("PRAGMA application_id").fetchone()[0] != NAMESPACES[self.mode]:
                raise InvalidData("HTTP database namespace mismatch")

    def state(self):
        local_model = assistance_metadata(self.assistance, self.mode == 'fixture')
        if self.mode == "fixture":
            return {"mode": "SYNTHETIC FIXTURES — NO PAYPAL CONNECTION", "ai_mode": local_model['mode'],
                    "local_model": local_model, "contest_ready": False,
                    "orders": [annotated_order(order, self.assistance, True) for order in self.store.list_orders()], "gates": list(GATES)}
        # No account/order enumeration or real order data on the public metadata GET.
        return {"mode": self.service.adapter.mode + " — READ_ONLY", "ai_mode": local_model['mode'],
                "local_model": local_model, "contest_ready": False, "orders": [], "gates": list(GATES)}

    def post(self, path, data):
        if self.mode == "sandbox-readonly":
            if path != "/api/sandbox/read":
                return 404, {"error": "Only a registered order read is available"}
            if set(data) != {"order_id"}:
                raise InvalidData("Only an order identifier is accepted")
            order_id = identifier(data["order_id"])
            self.store.order(order_id)  # Reject unregistered IDs before any adapter/OAuth call.
            return 200, self.service.read(order_id)
        if path == "/api/fixture":
            if set(data) != {"scenario"}:
                raise InvalidData("Unexpected fields")
            return 200, self.store.reconcile(fixtures.ORDER_ID, lambda _: fixtures.order(data["scenario"]), "SYNTHETIC_FIXTURE")
        if path == "/api/fixture-event":
            if set(data) != {"scenario", "event_id", "verified"}:
                raise InvalidData("Unexpected fields")
            event = fixtures.event(data["scenario"], data["event_id"])
            return 200, self.store.event(event, data["verified"], lambda _: fixtures.order(data["scenario"]), "SYNTHETIC_VERIFICATION_STUB")
        return 404, {"error": "No live integration endpoint in this staged build"}


def prepare_application(mode="fixture", db_path=None, local_ai=False):
    if mode not in NAMESPACES:
        raise InvalidData("Unknown server mode")
    adapter = None
    if mode == "sandbox-readonly":
        context = load_host_context()  # No public JSON/path/boolean supplies this authority.
        _read_scope(context)
        if context.test_only:
            raise InvalidData("Synthetic context cannot start the HTTP server")
        adapter = SandboxPayPal(context)
    # Admission must precede directory creation, SQLite, socket creation and all network effects.
    store = _namespace_store(db_path or DEFAULT_DATABASES[mode], mode)
    assistance = enable_local_assistance() if local_ai else None
    if mode == "fixture":
        store.register(fixtures.ORDER_ID, "120.00", "EUR")
        return HttpApplication(mode, store, assistance=assistance)
    return HttpApplication(mode, store, PaymentEvidenceService(store, adapter, assistance), assistance)


def _post_guard(application, headers, port):
    allowed = (f"127.0.0.1:{port}", f"localhost:{port}")
    if headers.get("Host") not in allowed or headers.get("Origin") not in tuple("http://" + host for host in allowed):
        return 403, {"error": "Origin rejected"}
    csrf = "fixture-ui" if application.mode == "fixture" else "sandbox-readonly-ui"
    if headers.get("Content-Type") != "application/json" or headers.get("X-PayProof-Request") != csrf:
        return 415, {"error": "JSON request required"}
    return None


def dispatch_post(application, path, headers, body, port):
    """The same bounded policy/dispatch path is used by HTTP and socket-free contract tests."""
    guard = _post_guard(application, headers, port)
    if guard:
        return guard
    try:
        length = int(headers.get("Content-Length", "0"))
        if not 0 < length <= LIMIT:
            return 413, {"error": "Body outside limit"}
        if not isinstance(body, bytes) or len(body) != length:
            raise InvalidData("Body length mismatch")
        data = _json(body) if application.mode == "sandbox-readonly" else json.loads(body)
        if not isinstance(data, dict):
            raise InvalidData("Object required")
        return application.post(path, data)
    except (ValueError, KeyError, TypeError):
        message = ("Invalid input or unverified/conflicting event" if application.mode == "fixture"
                   else "Invalid or unregistered read request")
        return 400, {"error": message}


def make_server(port=0, db_path=None, mode="fixture", local_ai=False):
    application = prepare_application(mode, db_path, local_ai)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Avoid sensitive request/body logging.

        def respond(self, status, data, kind="application/json"):
            body = canonical(data).encode() if kind == "application/json" else data
            self.send_response(status)
            self.send_header("Content-Type", kind + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def host_allowed(self):
            return self.headers.get("Host") in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}")

        def do_GET(self):
            if not self.host_allowed():
                return self.respond(403, {"error": "Host rejected"})
            path = urlparse(self.path).path
            if path == "/api/state":
                return self.respond(200, application.state())
            if application.mode != "fixture":
                return self.respond(404, {"error": "Sandbox read-only API; fixture UI unavailable"})
            assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
            if path not in assets:
                return self.respond(404, {"error": "Not found"})
            name, kind = assets[path]
            return self.respond(200, (STATIC / name).read_bytes(), kind)

        def do_POST(self):
            guard = _post_guard(application, self.headers, self.server.server_port)
            if guard:
                return self.respond(*guard)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= LIMIT:
                    return self.respond(413, {"error": "Body outside limit"})
            except ValueError:
                return self.respond(400, {"error": "Invalid input or unverified/conflicting event" if application.mode == "fixture" else "Invalid or unregistered read request"})
            self.respond(*dispatch_post(application, self.path, self.headers, self.rfile.read(length), self.server.server_port))

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.store = application.store
    return server


def main():
    parser = argparse.ArgumentParser(description="Private PayProof; sandbox reads require existing host admission")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=None)
    parser.add_argument("--mode", choices=tuple(NAMESPACES), default="fixture")
    parser.add_argument("--local-ai", action="store_true", help="Explicitly enable local nonbinding model assistance; no external AI")
    args = parser.parse_args()
    os.umask(0o077)
    server = make_server(args.port, args.db, args.mode, args.local_ai)
    label = "SYNTHETIC ONLY" if args.mode == "fixture" else "SANDBOX READ_ONLY"
    print(f"PayProof running at http://127.0.0.1:{server.server_port} — {label}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
