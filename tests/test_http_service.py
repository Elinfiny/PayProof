"""Three SYNTHETIC in-process cases; no socket, browser or PayPal transport."""
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from payproof import fixtures, server
from payproof.core import InvalidData, UnknownResult
from payproof.paypal import SandboxPayPal
from payproof.service import PaymentEvidenceService
from host_contract_fixture import context

ORDER_ID = "SYNTHETICORDER01"
PORT = 8765


def request(application, path, data, changes=None):
    body = json.dumps(data).encode() if isinstance(data, dict) else data
    headers = {"Host": f"127.0.0.1:{PORT}", "Origin": f"http://127.0.0.1:{PORT}",
               "Content-Type": "application/json", "Content-Length": str(len(body)),
               "X-PayProof-Request": "fixture-ui" if application.mode == "fixture" else "sandbox-readonly-ui"}
    headers.update(changes or {})
    return server.dispatch_post(application, path, headers, body, PORT)


class HttpServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.socket_block = patch.object(socket, "socket", side_effect=AssertionError("Sockets forbidden in contract tests"))
        self.network_block = patch.object(SandboxPayPal, "_network", side_effect=AssertionError("Real transport forbidden"))
        self.socket_mock = self.socket_block.start()
        self.network_mock = self.network_block.start()
        self.addCleanup(self.socket_block.stop)
        self.addCleanup(self.network_block.stop)
        self.receipt = {"classification": "SYNTHETIC_IN_PROCESS — NOT PAYPAL INTEGRATION"}

    def tearDown(self):
        self.socket_mock.assert_not_called()
        self.network_mock.assert_not_called()

    def sandbox_application(self, transport):
        typed = context({"operations": ["orders:read"]})
        store = server._namespace_store(self.root / "sandbox.sqlite3", "sandbox-readonly")
        adapter = SandboxPayPal(typed, transport=transport)
        return server.HttpApplication("sandbox-readonly", store, PaymentEvidenceService(store, adapter))

    def test_01_missing_context_rejected_before_any_effect(self):
        db = self.root / "must-not-exist" / "sandbox.sqlite3"
        with patch.object(server, "load_host_context", side_effect=InvalidData("Host custody absent")) as load, \
             patch.object(server, "_namespace_store") as store, \
             patch.object(server, "ThreadingHTTPServer") as bind, \
             patch.object(server, "SandboxPayPal") as adapter:
            with self.assertRaises(InvalidData):
                server.make_server(0, db, "sandbox-readonly")
            load.assert_called_once_with()
            store.assert_not_called()
            bind.assert_not_called()
            adapter.assert_not_called()
        self.assertFalse(db.parent.exists())
        self.receipt.update({"before_directory_sqlite_socket_adapter": "PASS", "effects": 0})

    def test_02_database_isolation_and_no_json_authority(self):
        fixture_path = self.root / "fixture.sqlite3"
        fixture = server.prepare_application(db_path=fixture_path)
        original = fixture.store.order(fixtures.ORDER_ID)
        self.assertEqual(fixture.state()["mode"], "SYNTHETIC FIXTURES — NO PAYPAL CONNECTION")
        self.assertFalse(fixture.state()["contest_ready"])
        with self.assertRaises(InvalidData):
            server._namespace_store(fixture_path, "sandbox-readonly")
        sandbox = self.sandbox_application(lambda *args: (_ for _ in ()).throw(AssertionError("No read expected")))
        self.assertEqual(sandbox.store.list_orders(), [])
        with self.assertRaises(InvalidData):
            server.prepare_application(db_path=sandbox.store.path)
        self.assertEqual(sandbox.store.list_orders(), [])
        self.assertEqual(fixture.store.order(fixtures.ORDER_ID), original)
        for payload in [{"scenario": "completed", "admitted": True}, {"mode": "sandbox-readonly", "context": {"verified": True}}]:
            self.assertEqual(request(fixture, "/api/fixture", payload)[0], 400)
        self.assertEqual(request(fixture, "/api/sandbox/read", {"order_id": ORDER_ID})[0], 404)
        self.assertEqual(request(sandbox, "/api/fixture", {"scenario": "completed"})[0], 404)
        self.assertEqual(request(sandbox, "/api/sandbox/read", {"order_id": ORDER_ID, "admitted": True})[0], 400)
        # Production entry accepts neither JSON/boolean authority nor test-only typed context.
        for counterfeit in [True, {"admitted": True}, context({"operations": ["orders:read"]})]:
            with patch.object(server, "load_host_context", return_value=counterfeit), \
                 patch.object(server, "_namespace_store") as store, patch.object(server, "ThreadingHTTPServer") as bind:
                with self.assertRaises(InvalidData):
                    server.make_server(0, self.root / "forbidden.sqlite3", "sandbox-readonly")
                store.assert_not_called()
                bind.assert_not_called()
        with self.assertRaises(InvalidData):
            SandboxPayPal(context({"operations": ["orders:read"]}))
        self.receipt.update({"fixture_sandbox_ledgers": "ISOLATED", "fixture_seed_in_sandbox": False,
                             "json_boolean_authority": "REFUSED", "test_context_production_network": "REFUSED"})

    def test_03_registered_service_read_guards_and_unknown(self):
        calls = []
        unavailable = False

        def transport(method, path, headers, body):
            calls.append((method, path))  # Never retain even synthetic authorization values.
            if (method, path) == ("POST", "/v1/oauth2/token"):
                return {"access_token": "synthetic-not-a-live-token"}
            self.assertEqual((method, path), ("GET", "/v2/checkout/orders/" + ORDER_ID))
            if unavailable:
                raise UnknownResult("SYNTHETIC unavailable provider")
            result = fixtures.order("completed")
            result["id"] = ORDER_ID
            return result

        app = self.sandbox_application(transport)
        app.store.register(ORDER_ID, "120.00", "EUR")
        with patch.object(app.service, "read", wraps=app.service.read) as read:
            self.assertEqual(request(app, "/api/sandbox/read", {"order_id": "UNREGISTERED01"})[0], 400)
            self.assertEqual(request(app, "/api/sandbox/read", {"order_id": ORDER_ID, "endpoint": "https://example.invalid"})[0], 400)
            self.assertEqual(request(app, "/api/sandbox/read", {"order_id": ORDER_ID}, {"Host": "example.invalid"})[0], 403)
            self.assertEqual(request(app, "/api/sandbox/read", {"order_id": ORDER_ID}, {"Origin": "https://example.invalid"})[0], 403)
            self.assertEqual(request(app, "/api/sandbox/read", {"order_id": ORDER_ID}, {"X-PayProof-Request": "fixture-ui"})[0], 415)
            self.assertEqual(request(app, "/api/sandbox/read", b"x" * (server.LIMIT + 1))[0], 413)
            self.assertEqual(request(app, "/api/sandbox/read", b'{"order_id":"A","order_id":"B"}')[0], 400)
            self.assertEqual(request(app, "/api/sandbox/create", {"order_id": ORDER_ID})[0], 404)
            read.assert_not_called()
            self.assertEqual(calls, [])
            status, completed = request(app, "/api/sandbox/read", {"order_id": ORDER_ID})
            self.assertEqual(status, 200)
            self.assertEqual(completed["mode"], "SANDBOX_CONTRACT_TEST")
            self.assertEqual(completed["order"]["state"], "COMPLETED")
            historical = completed["order"]["last_verified"]
            unavailable = True
            status, unknown = request(app, "/api/sandbox/read", {"order_id": ORDER_ID})
            self.assertEqual(status, 200)
            self.assertEqual(unknown["order"]["state"], "UNKNOWN")
            self.assertIsNone(unknown["order"]["facts"])
            self.assertEqual(unknown["order"]["last_verified"], historical)
            self.assertEqual(unknown["payment_mutation_actions"], [])
            self.assertFalse(unknown["live_ai"])
            self.assertNotIn("payer", json.dumps(unknown))
            self.assertEqual(read.call_count, 2)
            self.assertEqual(calls, [("POST", "/v1/oauth2/token"), ("GET", "/v2/checkout/orders/" + ORDER_ID)] * 2)
        self.assertEqual(app.state()["orders"], [])  # Metadata GET cannot enumerate registered orders.
        self.receipt.update({"typed_test_context": "SYNTHETIC_NETWORK_BLOCKED", "real_service_read_calls": 2,
                             "fake_transport_calls": 4, "unregistered_id_before_transport": "REFUSED",
                             "unknown_historical_evidence": "PRESERVED", "payment_replay": 0})
