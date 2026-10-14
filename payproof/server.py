import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from .core import Store, InvalidData, canonical
from . import fixtures

STATIC = Path(__file__).resolve().parent / "web"
LIMIT = 16 * 1024


def make_server(port=0, db_path=".data/payproof.sqlite3"):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    store = Store(db_path)
    store.register(fixtures.ORDER_ID, "120.00", "EUR")

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
                return self.respond(200, {"mode": "SYNTHETIC FIXTURES — NO PAYPAL CONNECTION", "ai_mode": "DETERMINISTIC — NOT LIVE AI",
                    "contest_ready": False, "orders": store.list_orders(), "gates": ["Sandbox access + isolation review", "Live AI custody + enforced budget", "Independent publication review"]})
            assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
            if path not in assets:
                return self.respond(404, {"error": "Not found"})
            name, kind = assets[path]
            return self.respond(200, (STATIC / name).read_bytes(), kind)

        def do_POST(self):
            if not self.host_allowed() or self.headers.get("Origin") not in (f"http://127.0.0.1:{self.server.server_port}", f"http://localhost:{self.server.server_port}"):
                return self.respond(403, {"error": "Origin rejected"})
            if self.headers.get("Content-Type") != "application/json" or self.headers.get("X-PayProof-Request") != "fixture-ui":
                return self.respond(415, {"error": "JSON request required"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= LIMIT:
                    return self.respond(413, {"error": "Body outside limit"})
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise InvalidData("Object required")
                if self.path == "/api/fixture":
                    if set(data) != {"scenario"}:
                        raise InvalidData("Unexpected fields")
                    result = store.reconcile(fixtures.ORDER_ID, lambda _: fixtures.order(data["scenario"]), "SYNTHETIC_FIXTURE")
                elif self.path == "/api/fixture-event":
                    if set(data) != {"scenario", "event_id", "verified"}:
                        raise InvalidData("Unexpected fields")
                    event = fixtures.event(data["scenario"], data["event_id"])
                    result = store.event(event, data["verified"], lambda _: fixtures.order(data["scenario"]), "SYNTHETIC_VERIFICATION_STUB")
                else:
                    return self.respond(404, {"error": "No live integration endpoint in this staged build"})
                self.respond(200, result)
            except (ValueError, KeyError, TypeError):
                self.respond(400, {"error": "Invalid input or unverified/conflicting event"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.store = store
    return server


def main():
    parser = argparse.ArgumentParser(description="Private fixture-only PayProof")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=".data/payproof.sqlite3")
    args = parser.parse_args()
    os.umask(0o077)
    server = make_server(args.port, args.db)
    print(f"PayProof running at http://127.0.0.1:{server.server_port} — SYNTHETIC ONLY", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
