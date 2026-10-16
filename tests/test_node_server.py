import threading
import hashlib
import socket
from io import BytesIO
import tempfile
import unittest
from unittest.mock import patch
import json
import time
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from public_identity import PublicKeySigner, author_id
from resilient_exchange import _canonical
from node_server import (DEMO_SIGNER, MAX_PEER_RESPONSE_BYTES, PeerResponseTooLarge, Node,
                         decode_event, event_dict, load_public_genesis, loopback_url,
                         make_server, public_genesis_domain, start_auto_sync)


class NodeServerTest(unittest.TestCase):
    def setUp(self):
        self.left = Node("left", [])
        self.right = Node("right", [])
        self.servers = [make_server(self.left, 0), make_server(self.right, 0)]
        self.threads = [threading.Thread(target=server.serve_forever, daemon=True)
                        for server in self.servers]
        for thread in self.threads:
            thread.start()
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        self.right.peers = [f"http://127.0.0.1:{self.servers[0].server_port}"]

    def tearDown(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def test_http_relay_and_partition_reconciliation(self):
        first = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                 {"recipient": "bob", "amount": 25})
        result = self.left._request(self.left.peers[0], "POST", "/events", event_dict(first))
        self.assertTrue(result["accepted"])
        self.assertEqual(result["relay"]["delivered"], [self.right.peers[0]])
        self.assertEqual(result["relay"]["failed"], [])
        self.assertEqual(self.left.peer.balances, self.right.peer.balances)

        self.left.peers = []  # Simulate a disconnected peer.
        second = DEMO_SIGNER.sign("alice", 2, first.id, "transfer",
                                  {"recipient": "chen", "amount": 10})
        self.assertTrue(self.left.accept(second)["accepted"])
        self.assertNotIn(second.id, self.right.peer.events)
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        report = self.left.sync()
        self.assertEqual(report["unreachable"], [])
        self.assertIn(second.id, self.right.peer.events)
        self.assertEqual(self.left.peer.balances, self.right.peer.balances)

    def test_peer_url_rejects_ignored_query_or_fragment(self):
        for suffix in ("?node=other", "#other", "/;other"):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ValueError, "only host and port"):
                    loopback_url("http://127.0.0.1:8766" + suffix)

    def test_duplicate_peer_urls_are_contacted_once(self):
        peer = f"http://127.0.0.1:{self.servers[1].server_port}"
        left = Node("left", [peer, peer, peer + "/"])
        self.assertEqual(left.peers, [peer])
        result = left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.assertEqual(result["relay"]["attempted"], 1)
        self.assertEqual(result["relay"]["delivered"], [peer])

    def test_node_cannot_list_its_own_port_as_peer(self):
        node = Node("left", ["http://127.0.0.1:8766"])
        with patch("node_server.ThreadingHTTPServer") as server_type:
            server_type.return_value.server_port = 8766
            with self.assertRaisesRegex(ValueError, "own listening port"):
                make_server(node, 0)
            server_type.return_value.server_close.assert_called_once()

    def test_event_id_can_be_checked_on_configured_peer(self):
        self.right.peers = []
        self.left.peers = []
        event = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                 {"recipient": "bob", "amount": 2})
        self.assertTrue(self.left.accept(event)["accepted"])
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + f"/events/id/{event.id}/peers", timeout=2) as response:
            missing = json.load(response)
        self.assertEqual(missing["peers"][self.left.peers[0]], "not_visible")
        self.assertFalse(missing["finality_proven"])
        self.assertTrue(self.right.accept(event)["accepted"])
        with urlopen(base + f"/events/id/{event.id}/peers", timeout=2) as response:
            observed = json.load(response)
        self.assertEqual(observed["peers"][self.left.peers[0]], "observed")
        self.assertFalse(observed["local_changed"])
        original_request = self.left._request

        def invalid_evidence(peer, method, path, body=None):
            reply = original_request(peer, method, path, body)
            if path == f"/events/id/{event.id}":
                return {**reply, "signature_valid": False}
            return reply

        with patch.object(self.left, "_request", side_effect=invalid_evidence):
            self.assertEqual(self.left.check_event_peers(event.id)["peers"][self.left.peers[0]],
                             "invalid")
        status_reads = 0

        def invalid_during_restart(peer, method, path, body=None):
            nonlocal status_reads
            reply = invalid_evidence(peer, method, path, body)
            if path == "/status":
                status_reads += 1
                if status_reads == 2:
                    return {**reply, "process_epoch": "0" * 32}
            return reply

        with patch.object(self.left, "_request", side_effect=invalid_during_restart):
            self.assertEqual(self.left.check_event_peers(event.id)["peers"][self.left.peers[0]],
                             "invalid")
        status_reads = 0

        def changing_peer(peer, method, path, body=None):
            nonlocal status_reads
            reply = original_request(peer, method, path, body)
            if path == "/status":
                status_reads += 1
                if status_reads == 2:
                    return {**reply, "events": reply["events"] + 1}
            return reply

        with patch.object(self.left, "_request", side_effect=changing_peer):
            self.assertEqual(self.left.check_event_peers(event.id)["peers"][self.left.peers[0]],
                             "incomplete")
        status_reads = 0

        def restarted_peer(peer, method, path, body=None):
            nonlocal status_reads
            reply = original_request(peer, method, path, body)
            if path == "/status":
                status_reads += 1
                if status_reads == 2:
                    return {**reply, "process_epoch": "0" * 32}
            return reply

        with patch.object(self.left, "_request", side_effect=restarted_peer):
            self.assertEqual(self.left.check_event_peers(event.id)["peers"][self.left.peers[0]],
                             "incomplete")
        added = False

        def local_change(peer, method, path, body=None):
            nonlocal added
            reply = original_request(peer, method, path, body)
            if path == "/status" and not added:
                added = True
                extra = DEMO_SIGNER.sign("bob", 1, "GENESIS", "transfer",
                                         {"recipient": "chen", "amount": 1})
                with self.left.lock:
                    self.left._ingest(extra)
            return reply

        with patch.object(self.left, "_request", side_effect=local_change):
            self.assertTrue(self.left.check_event_peers(event.id)["local_changed"])
        with self.assertRaises(HTTPError) as error:
            urlopen(base + f"/events/id/{'0' * 64}/peers", timeout=2)
        self.assertEqual(error.exception.code, 404)
        error.exception.close()

    def test_slow_status_response_does_not_hold_node_lock(self):
        self.left.peers = []
        ready, release, completed = threading.Event(), threading.Event(), threading.Event()
        handler = self.servers[0].RequestHandlerClass
        original_respond = handler.respond

        def delayed_respond(request, code, value):
            if request.path == "/status":
                ready.set()
                release.wait(2)
            return original_respond(request, code, value)

        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        reader = threading.Thread(target=lambda: urlopen(base + "/status", timeout=3).close())
        writer = threading.Thread(target=lambda: (self.left.action(
            "alice", "transfer", {"recipient": "bob", "amount": 1}), completed.set()))
        with patch.object(handler, "respond", delayed_respond):
            try:
                reader.start()
                self.assertTrue(ready.wait(1))
                writer.start()
                self.assertTrue(completed.wait(1), "Slow HTTP client held the event lock")
            finally:
                release.set()
                reader.join(timeout=3)
                if writer.ident is not None:
                    writer.join(timeout=3)

    def test_foreign_host_cannot_read_or_submit_actions(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with self.assertRaises(HTTPError) as read_error:
            urlopen(Request(base + "/status", headers={"Host": "other.example"}), timeout=2)
        self.assertEqual(read_error.exception.code, 403)
        body = json.dumps({"author": "alice", "kind": "transfer",
                           "payload": {"recipient": "bob", "amount": 1}}).encode("utf-8")
        request = Request(base + "/actions", data=body, method="POST",
                          headers={"Host": "other.example", "Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as write_error:
            urlopen(request, timeout=2)
        self.assertEqual(write_error.exception.code, 403)
        self.assertEqual(self.left.peer.balances["bob"], 100)

    def test_node_page_cannot_be_framed_by_another_site(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/", timeout=2) as response:
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            policy = response.headers["Content-Security-Policy"]
            self.assertIn("script-src 'self'", policy)
            self.assertIn("frame-ancestors 'none'", policy)
        with urlopen(base + "/node.js", timeout=2) as response:
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_truncated_post_body_is_not_processed(self):
        port = self.servers[0].server_port
        body = json.dumps({"author": "alice", "kind": "transfer",
                           "payload": {"recipient": "bob", "amount": 1}}).encode("utf-8")
        request = (f"POST /actions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   f"Content-Type: application/json\r\nContent-Length: {len(body) + 1}\r\n"
                   "Connection: close\r\n\r\n").encode("ascii") + body
        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response = connection.recv(4096)
        self.assertIn(b" 400 ", response)
        self.assertEqual(self.left.peer.balances["bob"], 100)

    def test_stalled_post_body_times_out_without_creating_event(self):
        port = self.servers[0].server_port
        request = (f"POST /actions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   "Content-Type: application/json\r\nContent-Length: 100\r\n"
                   "Connection: close\r\n\r\n{}").encode("ascii")
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            connection.sendall(request)
            response = connection.recv(4096)
        self.assertIn(b" 408 ", response)
        self.assertEqual(self.left.peer.events, {})

    def test_duplicate_request_lengths_cannot_create_event(self):
        port = self.servers[0].server_port
        body = json.dumps({"author": "alice", "kind": "transfer",
                           "payload": {"recipient": "bob", "amount": 1}}).encode("utf-8")
        request = (f"POST /actions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                   f"Content-Length: {len(body) + 1}\r\nConnection: close\r\n\r\n").encode("ascii") + body
        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response = connection.recv(4096)
        self.assertIn(b" 400 ", response)
        self.assertEqual(self.left.peer.events, {})

    def test_transfer_encoding_with_request_length_cannot_create_event(self):
        port = self.servers[0].server_port
        body = json.dumps({"author": "alice", "kind": "transfer",
                           "payload": {"recipient": "bob", "amount": 1}}).encode("utf-8")
        request = (f"POST /actions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii") + body
        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response = connection.recv(4096)
        self.assertIn(b" 400 ", response)
        self.assertEqual(self.left.peer.events, {})

    def test_duplicate_origins_cannot_create_event(self):
        port = self.servers[0].server_port
        body = json.dumps({"author": "alice", "kind": "transfer",
                           "payload": {"recipient": "bob", "amount": 1}}).encode("utf-8")
        request = (f"POST /actions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   f"Origin: http://127.0.0.1:{port}\r\nOrigin: http://evil.example\r\n"
                   f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                   "Connection: close\r\n\r\n").encode("ascii") + body
        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response = connection.recv(4096)
        self.assertIn(b" 403 ", response)
        self.assertEqual(self.left.peer.events, {})

    def test_duplicate_content_types_cannot_create_event(self):
        port = self.servers[0].server_port
        body = json.dumps({"author": "alice", "kind": "transfer",
                           "payload": {"recipient": "bob", "amount": 1}}).encode("utf-8")
        request = (f"POST /actions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                   "Content-Type: application/json\r\nContent-Type: text/plain\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii") + body
        with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            response = connection.recv(4096)
        self.assertIn(b" 415 ", response)
        self.assertEqual(self.left.peer.events, {})

    def test_peer_response_is_bounded_before_json_parse(self):
        oversized = BytesIO(b" " * (MAX_PEER_RESPONSE_BYTES + 1))
        with patch("node_server.urlopen", return_value=oversized):
            with self.assertRaisesRegex(ValueError, "exceeds local prototype limit"):
                self.left._request(self.left.peers[0], "GET", "/snapshot")

    def test_peer_response_rejects_duplicate_json_fields(self):
        ambiguous = BytesIO(b'{"event":{"id":"first","id":"second"}}')
        with patch("node_server.urlopen", return_value=ambiguous):
            with self.assertRaisesRegex(ValueError, "Duplicate JSON field: id"):
                self.left._request(self.left.peers[0], "GET", "/events/id/example")

    def test_peer_response_rejects_nonstandard_json_constants(self):
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(constant=constant):
                response = BytesIO(b'{"event_count":' + constant + b'}')
                with patch("node_server.urlopen", return_value=response):
                    with self.assertRaisesRegex(ValueError, "Nonstandard JSON constant"):
                        self.left._request(self.left.peers[0], "GET", "/snapshot")

    def test_peer_response_rejects_non_object_root(self):
        for body in (b"null", b"[]", b'"status"', b"0"):
            with self.subTest(body=body):
                with patch("node_server.urlopen", return_value=BytesIO(body)):
                    with self.assertRaisesRegex(ValueError, "must be a JSON object"):
                        self.left._request(self.left.peers[0], "GET", "/status")

    def test_peer_genesis_rejects_boolean_balance_even_when_equal_to_one(self):
        genesis = {"alice": True, "bob": 0}
        with self.assertRaisesRegex(ValueError, "Malformed peer status"):
            Node._check_status_shape({"events": 0, "signature_domain": "demo",
                                      "genesis": genesis})
        with self.assertRaisesRegex(ValueError, "Malformed peer snapshot"):
            Node._check_snapshot_shape({"event_count": 0, "events": [],
                                        "signature_domain": "demo", "genesis": genesis})

    def test_peer_protocol_version_rejects_boolean_equal_to_one(self):
        status = self.left._request(self.left.peers[0], "GET", "/status")
        with self.assertRaisesRegex(ValueError, "Malformed peer status"):
            Node._check_status_shape({**status, "protocol_version": True})
        snapshot = self.right.snapshot()
        with self.assertRaisesRegex(ValueError, "Malformed peer snapshot"):
            Node._check_snapshot_shape({**snapshot, "protocol_version": True})

    def test_snapshot_page_rejects_boolean_cursor_equal_to_zero(self):
        page = {**self.right.snapshot(), "relayable_count": 0, "cursor": False,
                "next_cursor": None}

        def page_response(base, method, path, body=None):
            if path == "/snapshot":
                raise PeerResponseTooLarge("oversized")
            return page

        with patch.object(self.left, "_request", side_effect=page_response):
            with self.assertRaisesRegex(ValueError, "Malformed snapshot page"):
                self.left._fetch_snapshot(self.left.peers[0])

    def test_local_acceptance_reports_failed_relay_without_claiming_delivery(self):
        with patch.object(self.left, "_request", side_effect=URLError("offline")):
            result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.assertTrue(result["accepted"])
        self.assertEqual(result["relay"]["delivered"], [])
        self.assertEqual(result["relay"]["failed"],
                         [{"peer": self.left.peers[0], "reason": "unreachable"}])
        self.assertEqual(self.left.peer.balances["bob"], 101)
        self.assertEqual(self.right.peer.balances["bob"], 100)

    def test_relay_does_not_claim_delivery_from_invalid_acknowledgement(self):
        original_request = self.left._request

        def invalid_ack(base, method, path, body=None):
            return {"accepted": False} if method == "POST" else original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=invalid_ack):
            result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.assertTrue(result["accepted"])
        self.assertEqual(result["relay"]["delivered"], [])
        self.assertEqual(result["relay"]["failed"],
                         [{"peer": self.left.peers[0], "reason": "invalid_ack"}])

    def test_relay_does_not_claim_delivery_from_ack_without_remote_record(self):
        original_request = self.left._request

        def false_ack(base, method, path, body=None):
            if method == "POST" and path == "/events":
                return {"accepted": True, "event": decode_event(body).id}
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=false_ack):
            result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.assertEqual(result["relay"]["delivered"], [])
        self.assertEqual(result["relay"]["failed"],
                         [{"peer": self.left.peers[0], "reason": "unverified_ack"}])
        self.assertNotIn(result["event"], self.right.peer.events)

    def test_missing_remote_event_record_does_not_hide_local_acceptance(self):
        original_request = self.left._request

        def missing_record(base, method, path, body=None):
            if path.startswith("/events/id/"):
                return {"id": path.rsplit("/", 1)[-1], "signature_valid": True}
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=missing_record):
            result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.assertTrue(result["accepted"])
        self.assertIn(result["event"], self.left.peer.events)
        self.assertEqual(result["relay"]["failed"],
                         [{"peer": self.left.peers[0], "reason": "invalid_ack"}])

    def test_live_relay_does_not_post_to_incompatible_peer(self):
        original_request = self.left._request
        posted = []

        def old_peer(base, method, path, body=None):
            if method == "GET" and path == "/status":
                status = original_request(base, method, path, body)
                status.pop("protocol_version")
                return status
            if method == "POST":
                posted.append(path)
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=old_peer):
            result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.assertTrue(result["accepted"])
        self.assertEqual(posted, [])
        self.assertEqual(result["relay"]["failed"],
                         [{"peer": self.left.peers[0], "reason": "incompatible"}])
        self.assertEqual(self.right.peer.events, {})

    def test_malformed_relay_ack_does_not_hide_local_acceptance(self):
        original_request = self.left._request

        def malformed_ack(base, method, path, body=None):
            if method == "POST":
                raise ValueError("bad peer JSON")
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=malformed_ack):
            result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.assertTrue(result["accepted"])
        self.assertEqual(result["relay"]["failed"],
                         [{"peer": self.left.peers[0], "reason": "invalid_ack"}])
        self.assertIn(result["event"], self.left.peer.events)

    def test_malformed_peer_status_prevents_live_post(self):
        with patch.object(self.left, "_request", return_value={"events": True}):
            result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.assertTrue(result["accepted"])
        self.assertEqual(result["relay"]["failed"],
                         [{"peer": self.left.peers[0], "reason": "invalid_peer_data"}])
        self.assertEqual(self.right.peer.events, {})

    def test_sync_reports_invalid_peer_acknowledgement_as_undelivered(self):
        self.left.peers = []
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        original_request = self.left._request

        def invalid_post(base, method, path, body=None):
            if method == "POST" and path == "/events":
                return {"accepted": False, "event": result["event"]}
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=invalid_post):
            report = self.left.sync()
        self.assertEqual(report["undelivered"][self.left.peers[0]],
                         [{"event": result["event"], "reason": "invalid_ack"}])
        self.assertNotIn(result["event"], self.right.peer.events)

    def test_sync_does_not_trust_ack_without_remote_record(self):
        self.left.peers = []
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        original_request = self.left._request

        def false_ack(base, method, path, body=None):
            if method == "POST" and path == "/events":
                return {"accepted": True, "event": decode_event(body).id}
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=false_ack):
            report = self.left.sync()
        self.assertEqual(report["undelivered"][self.left.peers[0]],
                         [{"event": result["event"], "http_status": 404}])
        self.assertNotIn(result["event"], self.right.peer.events)

    def test_sync_reports_missing_remote_event_record_as_undelivered(self):
        self.left.peers = []
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        original_request = self.left._request

        def missing_record(base, method, path, body=None):
            if path.startswith("/events/id/"):
                return {"id": path.rsplit("/", 1)[-1], "signature_valid": True}
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=missing_record):
            report = self.left.sync()
        self.assertEqual(report["undelivered"][self.left.peers[0]],
                         [{"event": result["event"], "reason": "invalid_ack"}])

    def test_sync_reports_malformed_ack_per_event_without_aborting(self):
        self.left.peers = []
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        original_request = self.left._request

        def malformed_post(base, method, path, body=None):
            if method == "POST" and path == "/events":
                raise ValueError("bad peer JSON")
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=malformed_post):
            report = self.left.sync()
        self.assertEqual(report["undelivered"][self.left.peers[0]],
                         [{"event": result["event"], "reason": "invalid_ack"}])
        self.assertEqual(report["invalid"], [])

    def test_sync_continues_after_one_event_delivery_failure(self):
        self.left.peers = []
        first = self.left.action("alice", "transfer", {"recipient": "chen", "amount": 1})
        second = self.left.action("bob", "transfer", {"recipient": "chen", "amount": 1})
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        original_request = self.left._request

        def fail_first_post(base, method, path, body=None):
            if method == "POST" and path == "/events" and body["author"] == "alice":
                raise URLError("temporary outage")
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=fail_first_post):
            report = self.left.sync()
        self.assertEqual(report["undelivered"][self.left.peers[0]],
                         [{"event": first["event"], "reason": "unreachable"}])
        self.assertEqual(report["unreachable"], [])
        self.assertIn(second["event"], self.right.peer.events)
        self.assertNotIn(first["event"], self.right.peer.events)

    def test_sync_defers_excess_posts_and_finishes_on_next_round(self):
        self.left.peers = []
        first = self.left.action("alice", "transfer", {"recipient": "chen", "amount": 1})
        second = self.left.action("bob", "transfer", {"recipient": "chen", "amount": 1})
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        with patch("node_server.MAX_SYNC_POSTS_PER_PEER", 1):
            report = self.left.sync()
            self.assertEqual(report["deferred"][self.left.peers[0]], 1)
            self.assertIn(first["event"], self.right.peer.events)
            self.assertNotIn(second["event"], self.right.peer.events)
            report = self.left.sync()
        self.assertEqual(report["deferred"][self.left.peers[0]], 0)
        self.assertIn(second["event"], self.right.peer.events)

    def test_failed_first_post_does_not_starve_later_events(self):
        self.left.peers = []
        first = self.left.action("alice", "transfer", {"recipient": "chen", "amount": 1})
        second = self.left.action("bob", "transfer", {"recipient": "chen", "amount": 1})
        third = self.left.action("chen", "transfer", {"recipient": "bob", "amount": 1})
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        original_request = self.left._request

        def reject_first(base, method, path, body=None):
            if method == "POST" and path == "/events" and body["author"] == "alice":
                raise URLError("persistent failure")
            return original_request(base, method, path, body)

        with patch("node_server.MAX_SYNC_POSTS_PER_PEER", 1):
            with patch.object(self.left, "_request", side_effect=reject_first):
                for _ in range(4):
                    self.left.sync()
        self.assertNotIn(first["event"], self.right.peer.events)
        self.assertIn(second["event"], self.right.peer.events)
        self.assertIn(third["event"], self.right.peer.events)

    def test_sync_defers_excess_remote_ingest_until_next_rounds(self):
        self.right.peers = []
        event_ids = []
        for author in ("alice", "bob", "chen"):
            result = self.right.action(author, "transfer", {
                "recipient": "alice" if author != "alice" else "bob", "amount": 1})
            event_ids.append(result["event"])
        with patch("node_server.MAX_SYNC_INGEST_PER_PEER", 1):
            for remaining in (2, 1, 0):
                report = self.left.sync()
                self.assertEqual(report["deferred_remote"][self.left.peers[0]], remaining)
                self.assertEqual(len(self.left.peer.events), 3 - remaining)
        self.assertEqual(set(self.left.peer.events), set(event_ids))

    def test_rejected_first_remote_event_does_not_starve_later_valid_event(self):
        invalid = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                   {"recipient": "bob", "amount": 200})
        valid = DEMO_SIGNER.sign("bob", 1, "GENESIS", "transfer",
                                 {"recipient": "chen", "amount": 1})
        snapshot = {"protocol_version": 1, "signature_domain": "demo", "genesis": self.left.peer.genesis,
                    "event_count": 2, "events": [event_dict(invalid), event_dict(valid)]}
        status = {"protocol_version": 1, "signature_domain": "demo",
                  "genesis": self.left.peer.genesis, "events": 2}

        def remote_data(base, method, path, body=None):
            return status if path == "/status" else snapshot

        with patch("node_server.MAX_SYNC_INGEST_PER_PEER", 1):
            with patch.object(self.left, "_request", side_effect=remote_data):
                first = self.left.sync()
                second = self.left.sync()
        self.assertEqual(first["unresolved"][self.left.peers[0]], [invalid.id])
        self.assertEqual(first["deferred_remote"][self.left.peers[0]], 1)
        self.assertIn(valid.id, self.left.peer.events)
        self.assertEqual(second["deferred_remote"][self.left.peers[0]], 1)

    def test_auto_sync_repairs_local_partition_without_button_click(self):
        self.left.peers = []
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 4})
        self.assertTrue(result["accepted"])
        stop, worker = start_auto_sync(self.right, 0.05)
        try:
            deadline = time.monotonic() + 3
            while (result["event"] not in self.right.peer.events
                   or self.right.auto_sync["last_result"] is None) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIn(result["event"], self.right.peer.events)
            self.assertTrue(self.right.auto_sync["enabled"])
            self.assertEqual(self.right.auto_sync["last_result"]["state"], "ok")
            self.assertIsNotNone(datetime.fromisoformat(
                self.right.auto_sync["last_result"]["checked_at"]).tzinfo)
        finally:
            stop.set()
            worker.join(timeout=2)

    def test_auto_sync_without_peers_does_not_claim_successful_reconciliation(self):
        self.left.peers = []
        stop, worker = start_auto_sync(self.left, 0.05)
        try:
            deadline = time.monotonic() + 2
            while self.left.auto_sync["last_result"] is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(self.left.auto_sync["last_result"]["state"], "no_peers")
        finally:
            stop.set()
            worker.join(timeout=2)

    def test_sync_does_not_repost_events_already_visible_on_peer(self):
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 4})
        self.assertTrue(result["accepted"])
        self.assertIn(result["event"], self.right.peer.events)
        original_request = self.left._request
        calls = []

        def record(base, method, path, body=None):
            calls.append((method, path))
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=record):
            report = self.left.sync()
        self.assertEqual(report["undelivered"][self.left.peers[0]], [])
        self.assertIn(("GET", "/snapshot"), calls)
        self.assertNotIn(("POST", "/events"), calls)

    def test_sync_flags_remote_event_added_during_snapshot(self):
        self.right.peers = []
        self.assertTrue(self.right.action("alice", "transfer",
                                          {"recipient": "bob", "amount": 1})["accepted"])
        original_request = self.left._request
        added = False

        def change_after_events(base, method, path, body=None):
            nonlocal added
            response = original_request(base, method, path, body)
            if method == "GET" and path == "/snapshot" and not added:
                added = True
                result = self.right.action("bob", "transfer", {"recipient": "chen", "amount": 2})
                self.assertTrue(result["accepted"])
            return response

        with patch.object(self.left, "_request", side_effect=change_after_events):
            report = self.left.sync()
        self.assertEqual(report["incomplete"], self.left.peers)
        self.assertEqual(len(self.left.peer.events), 0)
        self.assertEqual(self.left.sync()["incomplete"], [])
        self.assertEqual(len(self.left.peer.events), 2)

    def test_compare_omits_differences_if_remote_changes_after_snapshot(self):
        self.right.peers = []
        self.assertTrue(self.right.action("alice", "transfer",
                                          {"recipient": "bob", "amount": 1})["accepted"])
        original_request = self.left._request

        def change_after_snapshot(base, method, path, body=None):
            response = original_request(base, method, path, body)
            if method == "GET" and path == "/snapshot":
                self.assertTrue(self.right.action("bob", "transfer",
                                                  {"recipient": "chen", "amount": 1})["accepted"])
            return response

        with patch.object(self.left, "_request", side_effect=change_after_snapshot):
            comparison = self.left.compare_peers()
        self.assertEqual(comparison["incomplete"], self.left.peers)
        self.assertEqual(comparison["differences"], {})
        self.assertEqual(comparison["balance_mismatch"], [])

    def test_status_exposes_configured_peers_without_claiming_connectivity(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        status = self.left._request(base, "GET", "/status")
        self.assertEqual(status["peers"], self.left.peers)
        self.assertFalse(status["state_persistence_enabled"])
        self.left.peers = []
        self.assertEqual(self.left._request(base, "GET", "/status")["peers"], [])

    def test_sync_ui_warns_about_possible_partial_import_after_failure(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn("先前的部分事件可能已寫入本機", script)
        self.assertIn("try { await refresh(); } catch { pauseNodeActions(); }", script)

    def test_sync_ui_blocks_concurrent_manual_requests(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn("if (!nodeOnline || syncPending) return;", script)
        self.assertIn('syncRunning = Boolean(state.sync_running);', script)
        self.assertIn('$("sync").disabled = syncPending || syncRunning || peerCount === 0;', script)
        self.assertIn('$("sync").disabled = !nodeOnline || syncRunning ||', script)
        self.assertIn('state.sync_running ? "正在同步；請等待本輪結果"', script)
        self.assertIn("syncPending = false;", script)

    def test_compare_ui_blocks_overlapping_requests(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn("if (!nodeOnline || comparePending) return;", script)
        self.assertIn('$("compare-peers").disabled = comparePending || peerCount === 0;', script)
        self.assertIn("comparePending = false;", script)
        self.assertIn('$("compare-peers").disabled = !nodeOnline ||', script)

    def test_export_ui_blocks_overlapping_downloads(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn("if (!nodeOnline || exportPending) return;", script)
        self.assertIn('$("export-events").disabled = exportPending;', script)
        self.assertIn('$("export-events").disabled = true;', script)
        self.assertIn("exportPending = false;", script)
        self.assertIn('$("export-events").disabled = !nodeOnline;', script)

    def test_export_ui_uses_bounded_consistent_snapshot_pages(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn('request(`/snapshot/page?cursor=${cursor}&limit=128`)', script)
        self.assertIn('page.next_cursor !== cursor + page.events.length', script)
        self.assertIn('events.length !== snapshot.relayable_count', script)
        self.assertIn('const stateAfter = await request("/status");', script)
        self.assertNotIn('await request("/snapshot")', script)

    def test_start_commands_have_copy_buttons_without_auto_execution(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/", timeout=2) as response:
            page = response.read().decode("utf-8")
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn('id="copy-genesis-command"', page)
        self.assertIn('id="copy-pair-command"', page)
        self.assertIn('$("copy-pair-command").disabled = true;', script)
        self.assertIn('$("copy-genesis-command").disabled = true;', script)
        self.assertIn('await navigator.clipboard.writeText(command);', script)
        self.assertIn('if ($(buttonId).disabled || !command.startsWith("python ")) return;', script)

    def test_vote_selection_survives_unchanged_status_poll(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn("if (proposalsKey !== renderedProposalsKey) {", script)
        self.assertIn("card.dataset.proposalId = id;", script)
        self.assertIn("voter.value = priorVoters.get(id);", script)
        self.assertIn("renderedProposalsKey = null;", script)

    def test_conflict_events_have_direct_lookup_controls(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn('if (conflictsKey !== renderedConflictsKey) {', script)
        self.assertIn('button.addEventListener("click", () => {', script)
        self.assertIn('$("lookup-form").elements.event_id.value = id;', script)
        self.assertIn('lookupById(id);', script)
        self.assertIn('await navigator.clipboard.writeText(id);', script)
        self.assertIn('notice("無法複製；請用查詢欄中的完整 ID 手動選取。");', script)
        self.assertIn('renderedConflictsKey = conflictsKey;', script)

    def test_lookup_warns_when_valid_signed_event_is_conflicted(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn('const conflictSlots = Object.entries(state.conflicts || {})', script)
        self.assertIn('Array.isArray(ids) && ids.includes(eventId)', script)
        self.assertIn('有效簽章與相鄰節點可見都不能裁決哪筆應生效', script)

    def test_lost_connection_invalidates_inflight_event_lookup(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        pause = script.split('function pauseNodeActions(', 1)[1].split('function identityOption(', 1)[0]
        self.assertIn('lookupSequence++;', pause)
        self.assertIn('先前的單筆事件核對不可沿用', pause)
        self.assertIn('if (sequence !== lookupSequence) return;', script)

    def test_lookup_rejects_changed_test_network(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn('`${state.identity_mode}:${state.signature_domain}` !== observedNetwork', script)
        self.assertIn('先前與目前的事件核對不可混用', script)

    def test_peer_difference_ids_are_inspectable_in_browser(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/", timeout=2) as response:
            page = response.read().decode("utf-8")
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn('id="compare-details"', page)
        self.assertIn('function renderPeerDifferences(differences)', script)
        self.assertIn('for (const id of ids.slice(0, 20))', script)
        self.assertIn('renderPeerDifferences(report.differences);', script)
        self.assertIn('$("compare-details").hidden = true;', script)

    def test_identity_selects_keep_focus_when_poll_values_are_unchanged(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn("select.options.length === values.length", script)
        self.assertIn("values.every((value, index) => select.options[index].value === value)", script)
        self.assertIn("if (values.includes(selected)) select.value = selected;", script)

    def test_uncertain_result_survives_failed_manual_clear(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        handler = script.split('$("clear-uncertain").addEventListener("click", async () => {', 1)[1]
        handler = handler.split('refreshBrowserIdentities().catch', 1)[0]
        self.assertLess(handler.index('const beforeReady = await refresh();'),
                        handler.index('forgetPendingAttempt();'))
        self.assertIn('if (!nodeOnline || !beforeReady)', handler)
        self.assertIn('if (!nodeOnline || !afterReady)', handler)
        self.assertIn('return !configError;', script)
        self.assertIn('rememberPendingAttempt(attemptedId);', handler)
        self.assertIn('submissionUncertain = true;', handler)
        self.assertIn('button.hidden = false;', handler)
        self.assertIn('pauseNodeActions();', handler)

    def test_ui_blocks_retry_when_event_post_outcome_is_unknown(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn('let submissionUncertain = Boolean(pendingAttempt);', script)
        self.assertIn('state.finality === "insufficient" || submissionUncertain', script)
        self.assertIn('if (sendStarted && (responseAccepted || !error.definitiveRejection))', script)
        self.assertIn('submissionUncertain = true;', script)
        self.assertIn('不要直接重送', script)
        self.assertIn('attemptedId = await DirectionIdentity.eventId(signed);', script)
        self.assertIn('$("lookup-form").elements.event_id.value = attemptedId;', script)
        self.assertIn('if (nodeOnline) lookupById(attemptedId);', script)
        self.assertIn('if (attemptedId && result.event !== attemptedId)', script)
        self.assertIn('節點回覆的事件 ID 與本機簽章事件不符', script)
        self.assertIn('setTimeout(() => controller.abort(), timeoutMs)', script)
        self.assertIn('timeoutMs = body === undefined ? 10000 : 0', script)
        self.assertIn('if (error?.name === "AbortError")', script)
        self.assertIn('節點請求逾時；若剛送出事件，結果可能已寫入，請先核對', script)
        self.assertIn('Date.now() - lastSuccessfulRefreshMs > 10000', script)
        self.assertIn('pauseNodeActions("節點超過十秒沒有成功更新")', script)
        self.assertIn('if (pollInProgress || submissionPending || syncPending) return;', script)
        self.assertIn('refresh().catch(() => {}).finally(() => { pollInProgress = false; });', script)
        self.assertIn('result = await request("/events", signed, 30000);', script)
        self.assertIn('result = await request("/actions", action, 30000);', script)
        self.assertIn('typeof result.accepted !== "boolean"', script)
        self.assertIn('!/^[0-9a-f]{64}$/.test(result.event)', script)
        self.assertIn('節點回覆缺少可核對的事件結果', script)
        self.assertIn('sessionStorage.getItem(pendingKey)', script)
        self.assertIn('let pendingStorageAvailable = true;', script)
        self.assertIn('catch { pendingStorageAvailable = false; }', script)
        self.assertIn('瀏覽器無法保存待確認標記；請勿重新載入本頁', script)
        self.assertIn('rememberPendingAttempt(attemptedId);', script)
        self.assertIn('rememberPendingAttempt(null);', script)
        self.assertIn('if (error.definitiveRejection) forgetPendingAttempt();', script)
        self.assertIn('$("clear-uncertain").hidden = false;', script)
        with urlopen(base + "/", timeout=2) as response:
            page = response.read().decode("utf-8")
        self.assertIn('id="clear-uncertain"', page)
        self.assertIn('DirectionIdentity.eventId(record.event)', script)
        self.assertEqual(script.count('Object.hasOwn(state.genesis, record.event?.author)'), 2)
        self.assertEqual(script.count('DirectionIdentity.verifyBrowserEvent(record.event, state.signature_domain)'), 2)
        self.assertIn('DirectionIdentity.genesisDomain(state.network_id, state.genesis)', script)
        self.assertIn('節點宣稱的網路簽章域與初始配置不符', script)
        self.assertIn('測試網路配置無法核對：${configError.message}；交易與投票已停用', script)
        self.assertIn('observedNetwork !== null && observedNetwork !== network', script)
        self.assertIn('observedNetwork !== `${state.identity_mode}:${state.signature_domain}`', script)
        self.assertIn('|| Boolean(configError)', script)
        self.assertIn('calculatedId !== eventId', script)
        self.assertNotIn('record.event?.id !== eventId', script)
        self.assertIn('const record = await request(`/events/id/${result.event}`, undefined, 10000);', script)
        self.assertIn('const browserValid = state.identity_mode !== "public-key" ||', script)
        self.assertIn('record.signature_valid !== true || !browserValid', script)
        self.assertIn('if (sendStarted && (responseAccepted || !error.definitiveRejection))', script)
        self.assertIn('無法在本節點核對剛送出的簽章事件', script)
        self.assertIn('|| submissionUncertain || submissionPending', script)
        self.assertIn('disableSubmissionControls();', script)
        self.assertIn('if (!submissionUncertain && nodeOnline) refresh().catch(() => pauseNodeActions());', script)

    def test_identity_storage_failure_is_visible_in_public_key_ui(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
        self.assertIn("identityError = error;", script)
        self.assertIn("無法讀取此瀏覽器的測試身分", script)
        self.assertIn('$("identity-mode").className = identityError || configError ? "danger" : "";', script)
        self.assertIn('else renderBrowserIdentities(localKeys);', script)
        self.assertIn('無法讀取本機身分；請檢查瀏覽器儲存。', script)
        self.assertIn('if (identityKey === renderedIdentityKey) return;', script)
        self.assertIn('renderedIdentityKey = null;', script)

    def test_auto_and_manual_sync_do_not_overlap_on_same_node(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def slow_sync():
            calls.append("entered")
            entered.set()
            release.wait(5)
            return {"unreachable": []}

        results = []
        with patch.object(self.left, "_sync_once", side_effect=slow_sync):
            workers = [threading.Thread(target=lambda: results.append(self.left.sync()))
                       for _ in range(2)]
            try:
                workers[0].start()
                self.assertTrue(entered.wait(1))
                workers[1].start()
                workers[1].join(timeout=0.05)
                self.assertTrue(workers[1].is_alive())
                self.assertEqual(calls, ["entered"])
            finally:
                release.set()
                for worker in workers:
                    if worker.ident is not None:
                        worker.join(timeout=2)
        self.assertEqual(len(results), 2)

    def test_status_reports_sync_in_progress(self):
        entered = threading.Event()
        release = threading.Event()

        def slow_sync():
            entered.set()
            release.wait(5)
            return {"unreachable": []}

        with patch.object(self.left, "_sync_once", side_effect=slow_sync):
            worker = threading.Thread(target=self.left.sync)
            try:
                worker.start()
                self.assertTrue(entered.wait(1))
                status = self.left._request(f"http://127.0.0.1:{self.servers[0].server_port}",
                                            "GET", "/status")
                self.assertTrue(status["sync_running"])
            finally:
                release.set()
                worker.join(timeout=2)
        status = self.left._request(f"http://127.0.0.1:{self.servers[0].server_port}",
                                    "GET", "/status")
        self.assertFalse(status["sync_running"])

    def test_snapshot_captures_event_count_and_events_together(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        self.left.action("alice", "transfer", {"recipient": "bob", "amount": 2})
        snapshot = self.left._request(base, "GET", "/snapshot")
        self.assertEqual(snapshot["signature_domain"], "demo")
        self.assertEqual(snapshot["genesis"], self.left.peer.genesis)
        self.assertEqual(snapshot["event_count"], len(snapshot["events"]))
        self.assertEqual(snapshot["event_count"], 1)

    def test_snapshot_pages_bound_event_lists_and_expose_cursor(self):
        self.left.peers = []
        for author in ("alice", "bob", "chen"):
            self.left.action(author, "transfer", {"recipient": "alice" if author != "alice" else "bob",
                                                  "amount": 1})
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        first = self.left._request(base, "GET", "/snapshot/page?cursor=0&limit=2")
        second = self.left._request(base, "GET", "/snapshot/page?cursor=2&limit=2")
        self.assertEqual((first["event_count"], first["relayable_count"]), (3, 3))
        self.assertEqual((len(first["events"]), first["next_cursor"]), (2, 2))
        self.assertEqual((len(second["events"]), second["next_cursor"]), (1, None))
        self.assertEqual({item["signature"] for item in first["events"] + second["events"]},
                         {event.signature for event in self.left.peer.events.values()})
        with self.assertRaises(HTTPError) as error:
            self.left._request(base, "GET", "/snapshot/page?cursor=-1&limit=2")
        self.assertEqual(error.exception.code, 400)
        error.exception.close()

    def test_sync_and_compare_fall_back_to_pages_after_large_snapshot(self):
        self.right.peers = []
        for author in ("alice", "bob", "chen"):
            self.right.action(author, "transfer", {"recipient": "alice" if author != "alice" else "bob",
                                                   "amount": 1})
        original_request = self.left._request
        paths = []

        def oversized_snapshot(base, method, path, body=None):
            paths.append(path)
            if path == "/snapshot":
                raise PeerResponseTooLarge("too large")
            return original_request(base, method, path, body)

        with patch("node_server.SNAPSHOT_PAGE_LIMIT", 2):
            with patch.object(self.left, "_request", side_effect=oversized_snapshot):
                report = self.left.sync()
                comparison = self.left.compare_peers()
        self.assertEqual(report["incomplete"], [])
        self.assertEqual(report["invalid"], [])
        self.assertEqual(len(self.left.peer.events), 3)
        self.assertEqual(comparison["differences"][self.left.peers[0]],
                         {"only_local": [], "only_remote": []})
        self.assertIn("/snapshot/page?cursor=2&limit=2", paths)

    def test_changed_metadata_across_snapshot_pages_is_incomplete(self):
        self.right.peers = []
        for author in ("alice", "bob", "chen"):
            self.right.action(author, "transfer", {"recipient": "alice" if author != "alice" else "bob",
                                                   "amount": 1})
        original_request = self.left._request

        def changing_page(base, method, path, body=None):
            if path == "/snapshot":
                raise PeerResponseTooLarge("too large")
            response = original_request(base, method, path, body)
            if path.startswith("/snapshot/page?cursor=2"):
                response["event_count"] += 1
            return response

        with patch("node_server.SNAPSHOT_PAGE_LIMIT", 2):
            with patch.object(self.left, "_request", side_effect=changing_page):
                report = self.left.sync()
                comparison = self.left.compare_peers()
        self.assertEqual(report["incomplete"], self.left.peers)
        self.assertEqual(self.left.peer.events, {})
        self.assertEqual(len(self.right.peer.events), 3)
        self.assertEqual(comparison["incomplete"], self.left.peers)
        self.assertEqual(comparison["differences"], {})
        self.assertEqual(comparison["balance_mismatch"], [])

    def test_read_only_peer_comparison_exposes_missing_events(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        remote = self.left.peers[0]
        self.left.peers = []
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 3})
        self.assertTrue(result["accepted"])
        self.left.peers = [remote]
        before = self.left._request(base, "GET", "/compare")
        self.assertEqual(before["differences"][remote]["only_local"], [result["event"]])
        self.assertEqual(before["differences"][remote]["only_remote"], [])
        self.assertEqual(self.right.peer.events, {})
        self.left.sync()
        after = self.left._request(base, "GET", "/compare")
        self.assertEqual(after["differences"][remote], {"only_local": [], "only_remote": []})

    def test_old_peer_without_snapshot_is_incompatible_not_offline(self):
        old_response = HTTPError(self.left.peers[0] + "/snapshot", 404,
                                 "not found", None, None)
        with patch.object(self.left, "_request", side_effect=old_response):
            sync = self.left.sync()
        self.assertEqual(sync["incompatible"], self.left.peers)
        self.assertEqual(sync["unreachable"], [])

        old_response = HTTPError(self.left.peers[0] + "/snapshot", 404,
                                 "not found", None, None)
        with patch.object(self.left, "_request", side_effect=old_response):
            comparison = self.left.compare_peers()
        self.assertEqual(comparison["incompatible"], self.left.peers)
        self.assertEqual(comparison["unreachable"], [])

    def test_missing_or_different_protocol_version_is_incompatible(self):
        original_request = self.left._request
        for version in (None, 2):
            with self.subTest(version=version):
                def old_version(base, method, path, body=None):
                    response = original_request(base, method, path, body)
                    if path in {"/snapshot", "/status"}:
                        if version is None:
                            response.pop("protocol_version", None)
                        else:
                            response["protocol_version"] = version
                    return response

                with patch.object(self.left, "_request", side_effect=old_version):
                    sync = self.left.sync()
                    comparison = self.left.compare_peers()
                self.assertEqual(sync["incompatible"], self.left.peers)
                self.assertEqual(sync["invalid"], [])
                self.assertEqual(comparison["incompatible"], self.left.peers)
                self.assertEqual(comparison["invalid"], [])

    def test_protocol_change_after_snapshot_is_incompatible(self):
        original_request = self.left._request

        def change_after_snapshot(base, method, path, body=None):
            response = original_request(base, method, path, body)
            if path == "/status":
                response["protocol_version"] = 2
            return response

        with patch.object(self.left, "_request", side_effect=change_after_snapshot):
            self.assertEqual(self.left.sync()["incompatible"], self.left.peers)
            self.assertEqual(self.left.compare_peers()["incompatible"], self.left.peers)

    def test_malformed_snapshot_header_is_invalid_not_incompatible(self):
        for snapshot in ({"events": []},
                         {"signature_domain": "demo", "genesis": self.left.peer.genesis,
                          "event_count": True, "events": []},
                         {"signature_domain": "demo", "genesis": self.left.peer.genesis,
                          "event_count": 0, "events": [], "process_epoch": 3}):
            with self.subTest(snapshot=snapshot):
                with patch.object(self.left, "_request", return_value=snapshot):
                    sync = self.left.sync()
                    comparison = self.left.compare_peers()
                self.assertEqual(sync["invalid"], self.left.peers)
                self.assertEqual(sync["incompatible"], [])
                self.assertEqual(comparison["invalid"], self.left.peers)
                self.assertEqual(comparison["incompatible"], [])

    def test_malformed_or_changed_status_after_snapshot_is_reported(self):
        original_request = self.left._request

        def changed_status(base, method, path, body=None):
            response = original_request(base, method, path, body)
            if method == "GET" and path == "/status":
                response["genesis"] = {"different": 1}
            return response

        with patch.object(self.left, "_request", side_effect=changed_status):
            self.assertEqual(self.left.sync()["incomplete"], self.left.peers)
            self.assertEqual(self.left.compare_peers()["incomplete"], self.left.peers)

        def restarted_status(base, method, path, body=None):
            response = original_request(base, method, path, body)
            if method == "GET" and path == "/status":
                response["process_epoch"] = "0" * 32
            return response

        with patch.object(self.left, "_request", side_effect=restarted_status):
            self.assertEqual(self.left.sync()["incomplete"], self.left.peers)
            self.assertEqual(self.left.compare_peers()["incomplete"], self.left.peers)

        def malformed_status(base, method, path, body=None):
            if method == "GET" and path == "/status":
                return {"events": True}
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=malformed_status):
            self.assertEqual(self.left.sync()["invalid"], self.left.peers)
            self.assertEqual(self.left.compare_peers()["invalid"], self.left.peers)

        def malformed_epoch(base, method, path, body=None):
            response = original_request(base, method, path, body)
            if method == "GET" and path == "/status":
                response["process_epoch"] = 3
            return response

        with patch.object(self.left, "_request", side_effect=malformed_epoch):
            self.assertEqual(self.left.sync()["invalid"], self.left.peers)
            self.assertEqual(self.left.compare_peers()["invalid"], self.left.peers)

    def test_compare_marks_local_changes_during_remote_read(self):
        original_request = self.left._request

        def change_local(base, method, path, body=None):
            response = original_request(base, method, path, body)
            if method == "GET" and path == "/snapshot":
                self.left.peers = []
                self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
            return response

        with patch.object(self.left, "_request", side_effect=change_local):
            comparison = self.left.compare_peers()
        self.assertTrue(comparison["local_changed"])
        self.assertEqual(comparison["unreachable"], [])

    def test_sync_marks_malformed_remote_event_invalid_not_offline(self):
        original_request = self.left._request

        def malformed_snapshot(base, method, path, body=None):
            if method == "GET" and path == "/snapshot":
                return {"protocol_version": 1, "signature_domain": "demo", "genesis": self.left.peer.genesis,
                        "event_count": 1, "events": [{"not": "an event"}]}
            return original_request(base, method, path, body)

        with patch.object(self.left, "_request", side_effect=malformed_snapshot):
            report = self.left.sync()
        self.assertEqual(report["invalid"], self.left.peers)
        self.assertEqual(report["unreachable"], [])

    def test_duplicate_remote_event_cannot_mask_missing_snapshot_item(self):
        self.right.peers = []
        self.right.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.right.action("bob", "transfer", {"recipient": "chen", "amount": 1})
        self.left.peers = []
        local = self.left.action("chen", "transfer", {"recipient": "alice", "amount": 1})
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        original_request = self.left._request

        def duplicated_snapshot(base, method, path, body=None):
            response = original_request(base, method, path, body)
            if method == "GET" and path == "/snapshot":
                response["events"][1] = response["events"][0]
            return response

        with patch.object(self.left, "_request", side_effect=duplicated_snapshot):
            sync = self.left.sync()
            comparison = self.left.compare_peers()
        self.assertEqual(sync["incomplete"], self.left.peers)
        self.assertEqual(comparison["incomplete"], self.left.peers)
        self.assertEqual(set(self.left.peer.events), {local["event"]})
        self.assertNotIn(local["event"], self.right.peer.events)
        self.assertEqual(comparison["differences"], {})

    def test_sync_accepts_valid_event_but_flags_invalid_signature_in_snapshot(self):
        self.right.peers = []
        first = self.right.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        self.right.action("bob", "transfer", {"recipient": "chen", "amount": 1})
        original_request = self.left._request

        def partly_invalid_snapshot(base, method, path, body=None):
            response = original_request(base, method, path, body)
            if method == "GET" and path == "/snapshot":
                response["events"][1]["signature"] = "0" * 64
            return response

        with patch.object(self.left, "_request", side_effect=partly_invalid_snapshot):
            report = self.left.sync()
        self.assertEqual(report["invalid"], self.left.peers)
        self.assertEqual(report["unresolved"][self.left.peers[0]], [])
        self.assertIn(first["event"], self.left.peer.events)
        self.assertEqual(len(self.left.peer.events), 1)

    def test_recent_events_limits_ui_poll_without_truncating_full_log(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        for number in range(9):
            result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
            self.assertTrue(result["accepted"], number)
        full = self.left._request(base, "GET", "/events")["events"]
        recent_reply = self.left._request(base, "GET", "/events/recent")
        recent = recent_reply["events"]
        self.assertEqual(len(full), 9)
        self.assertEqual(recent_reply["event_count"], 9)
        self.assertEqual(recent_reply["process_epoch"], self.left.process_epoch)
        self.assertEqual(recent, [{**event_dict(event), "id": event.id}
                                  for event in list(self.left.peer.events.values())[-8:]])
        self.assertNotIn("id", full[0])

    def test_event_id_lookup_is_read_only_and_distinguishes_missing(self):
        self.left.peers = []
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 1})
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        record = self.left._request(base, "GET", "/events/id/" + result["event"])
        self.assertEqual(record["id"], result["event"])
        self.assertTrue(record["signature_valid"])
        self.assertEqual(record["event"]["kind"], "transfer")
        self.assertNotIn("id", record["event"])
        self.assertEqual(self.left.peer.status()["events"], 1)
        with self.assertRaises(HTTPError) as missing:
            self.left._request(base, "GET", "/events/id/" + "0" * 64)
        self.assertEqual(missing.exception.code, 404)
        missing.exception.close()
        with self.assertRaises(HTTPError) as malformed:
            self.left._request(base, "GET", "/events/id/not-an-id")
        self.assertEqual(malformed.exception.code, 400)
        malformed.exception.close()

    def test_author_head_exposes_only_current_sequence_and_predecessor(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        head = self.left._request(base, "GET", "/authors/alice/head")
        self.assertEqual(head, {"author": "alice", "next_sequence": 1,
                                "previous": "GENESIS", "halted": False})
        result = self.left.action("alice", "transfer", {"recipient": "bob", "amount": 2})
        self.assertTrue(result["accepted"])
        head = self.left._request(base, "GET", "/authors/alice/head")
        self.assertEqual(head["next_sequence"], 2)
        self.assertEqual(head["previous"], result["event"])
        with self.assertRaises(HTTPError) as unknown:
            self.left._request(base, "GET", "/authors/unknown/head")
        self.assertEqual(unknown.exception.code, 404)
        unknown.exception.close()

    def test_conflict_is_visible_after_reconnection(self):
        self.left.peers = []
        self.right.peers = []
        first = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                 {"recipient": "bob", "amount": 70})
        fork = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                {"recipient": "chen", "amount": 70})
        self.left.accept(first)
        self.right.accept(fork)
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        report = self.left.sync()
        self.assertEqual(report["status"]["finality"], "insufficient")
        self.assertEqual(self.right.peer.status()["finality"], "insufficient")
        self.assertEqual(len(self.left.peer.conflicts[("alice", 1)]), 2)
        comparison = self.left.compare_peers()
        self.assertEqual(comparison["differences"][self.left.peers[0]],
                         {"only_local": [], "only_remote": []})
        self.assertEqual(comparison["balance_mismatch"], self.left.peers)
        settled_report = self.left.sync()
        self.assertTrue(settled_report["status"]["balances_disputed"])
        stop, worker = start_auto_sync(self.left, 0.05)
        try:
            deadline = time.monotonic() + 2
            while self.left.auto_sync["last_result"] is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(self.left.auto_sync["last_result"]["state"], "issue")
            self.assertEqual(self.left.auto_sync["last_result"]["conflicts"], 1)
        finally:
            stop.set()
            worker.join(timeout=2)

    def test_compare_exposes_divergent_proposals_with_same_event_ids(self):
        self.left.peers = []
        self.right.peers = []
        first = DEMO_SIGNER.sign("alice", 1, "GENESIS", "proposal",
                                 {"id": "garden", "title": "Garden"})
        fork = DEMO_SIGNER.sign("alice", 1, "GENESIS", "proposal",
                                {"id": "library", "title": "Library"})
        self.assertTrue(self.left.accept(first)["accepted"])
        self.assertTrue(self.right.accept(fork)["accepted"])
        self.left.peers = [f"http://127.0.0.1:{self.servers[1].server_port}"]
        self.left.sync()
        comparison = self.left.compare_peers()
        self.assertEqual(comparison["differences"][self.left.peers[0]],
                         {"only_local": [], "only_remote": []})
        self.assertEqual(comparison["balance_mismatch"], [])
        self.assertEqual(comparison["proposal_mismatch"], self.left.peers)

    def test_invalid_input_and_nonlocal_peer_rejected(self):
        with self.assertRaises(ValueError):
            loopback_url("http://example.com:8766")
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        with self.assertRaises(HTTPError) as error:
            self.left._request(base, "POST", "/events", {"payload": []})
        self.assertEqual(error.exception.code, 400)
        error.exception.close()
        malformed = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                      {"recipient": ["bob"], "amount": 1})
        with self.assertRaises(HTTPError) as error:
            self.left._request(base, "POST", "/events", event_dict(malformed))
        self.assertEqual(error.exception.code, 422)
        error.exception.close()

    def test_mutations_require_json_and_reject_foreign_browser_origin(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        cases = [({"Content-Type": "text/plain"}, 415),
                 ({"Content-Type": "application/json", "Origin": "http://other.example"}, 403),
                 ({"Content-Type": "application/json", "Origin": "null"}, 403),
                 ({"Content-Type": "application/json", "Origin": "http://127.0.0.1:not-a-port"}, 403)]
        for headers, code in cases:
            with self.subTest(headers=headers), self.assertRaises(HTTPError) as error:
                urlopen(Request(base + "/sync", data=b"{}", headers=headers, method="POST"), timeout=2)
            self.assertEqual(error.exception.code, code)
            error.exception.close()
        local_headers = {"Content-Type": "application/json", "Origin": base}
        with urlopen(Request(base + "/sync", data=b"{}", headers=local_headers, method="POST"), timeout=2) as response:
            self.assertEqual(response.status, 200)
        for body in [b"not-json", b"[]", b'{"unexpected": true}']:
            with self.subTest(body=body), self.assertRaises(HTTPError) as error:
                urlopen(Request(base + "/sync", data=body, headers=local_headers, method="POST"), timeout=2)
            self.assertEqual(error.exception.code, 400)
            error.exception.close()

    def test_post_rejects_duplicate_json_fields_before_accepting_action(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        body = (b'{"author":"alice","kind":"transfer","payload":'
                b'{"recipient":"chen","recipient":"bob","amount":1}}')
        request = Request(base + "/actions", data=body,
                          headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=2)
        self.assertEqual(error.exception.code, 400)
        error.exception.close()
        self.assertEqual(self.left.peer.status()["events"], 0)

    def test_post_rejects_nonstandard_json_numbers_before_accepting_action(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        headers = {"Content-Type": "application/json"}
        for amount in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(amount=amount):
                body = (b'{"author":"alice","kind":"transfer","payload":'
                        b'{"recipient":"bob","amount":' + amount + b'}}')
                request = Request(base + "/actions", data=body, headers=headers, method="POST")
                with self.assertRaises(HTTPError) as error:
                    urlopen(request, timeout=2)
                self.assertEqual(error.exception.code, 400)
                error.exception.close()
        self.assertEqual(self.left.peer.status()["events"], 0)

    def test_restarted_peer_replays_local_events_and_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            first = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                     {"recipient": "bob", "amount": 30})
            fork = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                    {"recipient": "chen", "amount": 30})
            node.accept(first)
            node.accept(fork)
            restored = Node("left", [], path)
            self.assertEqual(restored.peer.balances, node.peer.balances)
            self.assertEqual(restored.peer.status()["finality"], "insufficient")
            self.assertEqual(len(restored.peer.conflicts[("alice", 1)]), 2)
            with self.assertRaises(ValueError):
                Node("wrong-name", [], path)

    def test_restart_detects_truncated_new_state_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            self.assertEqual(node.state_integrity, "new")
            node.action("alice", "transfer", {"recipient": "bob", "amount": 1})
            self.assertEqual(node.state_integrity, "verified")
            node.action("bob", "transfer", {"recipient": "chen", "amount": 1})
            with open(path, encoding="utf-8") as stream:
                saved = json.load(stream)
            self.assertIn("state_digest", saved)
            saved["events"].pop()
            with open(path, "w", encoding="utf-8") as stream:
                json.dump(saved, stream)
            with self.assertRaisesRegex(ValueError, "digest"):
                Node("left", [], path)

    def test_restart_rejects_duplicate_state_fields_even_with_valid_last_value(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            node.action("alice", "transfer", {"recipient": "bob", "amount": 1})
            with open(path, encoding="utf-8") as stream:
                original = stream.read()
            for source in (original.replace('"events":', '"events": [], "events":', 1),
                           original.replace('"amount": 1', '"amount": 2, "amount": 1', 1)):
                with self.subTest(source=source):
                    with open(path, "w", encoding="utf-8") as stream:
                        stream.write(source)
                    with self.assertRaisesRegex(ValueError, "Duplicate JSON field"):
                        Node("left", [], path)

    def test_restart_rejects_non_object_state_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("[]")
            with self.assertRaisesRegex(ValueError, "State file belongs"):
                Node("left", [], path)

    def test_restart_rejects_nonstandard_json_in_state_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            for constant in ("NaN", "Infinity", "-Infinity"):
                with self.subTest(constant=constant):
                    with open(path, "w", encoding="utf-8") as stream:
                        stream.write('{"name":"left","events":[],"unexpected":' + constant + '}')
                    with self.assertRaisesRegex(ValueError, "Nonstandard JSON constant"):
                        Node("left", [], path)

    def test_restart_rejects_unknown_state_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            node.action("alice", "transfer", {"recipient": "bob", "amount": 1})
            with open(path, encoding="utf-8") as stream:
                saved = json.load(stream)
            saved["finality_proven"] = True
            with open(path, "w", encoding="utf-8") as stream:
                json.dump(saved, stream)
            with self.assertRaisesRegex(ValueError, "invalid"):
                Node("left", [], path)

    def test_restart_rejects_conflicting_demo_network_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            node.action("alice", "transfer", {"recipient": "bob", "amount": 1})
            with open(path, encoding="utf-8") as stream:
                saved = json.load(stream)
            for field, value in (("genesis", {"alice": 999}),
                                 ("signature_domain", "another-network")):
                with self.subTest(field=field):
                    changed = {**saved, field: value}
                    with open(path, "w", encoding="utf-8") as stream:
                        json.dump(changed, stream)
                    with self.assertRaisesRegex(ValueError, "invalid"):
                        Node("left", [], path)

    def test_restart_rejects_duplicate_event_even_with_matching_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            node.action("alice", "transfer", {"recipient": "bob", "amount": 1})
            with open(path, encoding="utf-8") as stream:
                saved = json.load(stream)
            saved["events"].append(saved["events"][0])
            saved["state_digest"] = hashlib.sha256(_canonical({"events": saved["events"]})).hexdigest()
            with open(path, "w", encoding="utf-8") as stream:
                json.dump(saved, stream)
            with self.assertRaisesRegex(ValueError, "duplicate event"):
                Node("left", [], path)

    def test_restart_preserves_legacy_vote_after_conflict_but_freezes_new_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            proposal = DEMO_SIGNER.sign("bob", 1, "GENESIS", "proposal",
                                        {"id": "garden", "title": "Garden"})
            first = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                     {"recipient": "bob", "amount": 1})
            fork = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                    {"recipient": "chen", "amount": 1})
            old_vote = DEMO_SIGNER.sign("chen", 1, "GENESIS", "vote",
                                        {"proposal": "garden", "approve": True})
            with open(path, "w", encoding="utf-8") as stream:
                json.dump({"name": "left", "network_id": "demo",
                           "events": [event_dict(item) for item in (proposal, first, fork, old_vote)]}, stream)
            restored = Node("left", [], path)
            self.assertEqual(restored.state_integrity, "legacy_unchecked")
            self.assertEqual(restored.peer.status()["proposals"]["garden"]["yes"], 1)
            result = restored.action("chen", "proposal", {"id": "library", "title": "Library"})
            self.assertFalse(result["accepted"])
            self.assertEqual(result["reason"], "network_conflict_unresolved")

    def test_sync_imports_signed_events_after_conflict_discovery(self):
        self.left.peers = []
        self.right.peers = []
        proposal = DEMO_SIGNER.sign("bob", 1, "GENESIS", "proposal",
                                    {"id": "garden", "title": "Garden"})
        vote = DEMO_SIGNER.sign("chen", 1, "GENESIS", "vote",
                                {"proposal": "garden", "approve": True})
        first = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                 {"recipient": "bob", "amount": 1})
        fork = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                {"recipient": "chen", "amount": 1})
        for event in (proposal, vote, first):
            self.assertTrue(self.left.accept(event)["accepted"])
        self.assertTrue(self.right.accept(first)["accepted"])
        self.assertTrue(self.right.accept(fork)["accepted"])
        self.assertEqual(self.right.peer.status()["finality"], "insufficient")

        self.right.peers = [f"http://127.0.0.1:{self.servers[0].server_port}"]
        report = self.right.sync()
        self.assertEqual(report["unresolved"][self.right.peers[0]], [])
        self.assertIn(proposal.id, self.right.peer.events)
        self.assertIn(vote.id, self.right.peer.events)
        self.assertEqual(self.right.peer.status()["proposals"]["garden"]["yes"], 1)
        self.assertEqual(self.right.peer.status()["finality"], "insufficient")
        rejected = self.right.accept(DEMO_SIGNER.sign("bob", 2, proposal.id, "proposal",
                                                  {"id": "library", "title": "Library"}))
        self.assertFalse(rejected["accepted"])
        self.assertEqual(rejected["reason"], "network_conflict_unresolved")

    def test_failed_state_write_does_not_accept_or_relay_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            event = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                     {"recipient": "bob", "amount": 30})
            with patch("node_server.os.replace", side_effect=OSError("disk unavailable")):
                with self.assertRaises(OSError):
                    node.accept(event)
            self.assertEqual(node.peer.balances["alice"], 100)
            self.assertNotIn(event.id, node.peer.events)
            self.assertFalse(node.state_path.with_name("left.json.tmp").exists())
            self.assertTrue(node.accept(event)["accepted"])
            self.assertEqual(Node("left", [], path).peer.balances["alice"], 70)

    def test_restart_refuses_interrupted_state_write_without_deleting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            self.assertTrue(node.action("alice", "transfer",
                                        {"recipient": "bob", "amount": 1})["accepted"])
            temporary = node.state_path.with_name("left.json.tmp")
            temporary.write_text('{"events":', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Interrupted state write"):
                Node("left", [], path)
            self.assertTrue(temporary.exists())
            self.assertEqual(node.peer.balances["alice"], 99)

    def test_failed_state_flush_does_not_accept_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/left.json"
            node = Node("left", [], path)
            event = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                     {"recipient": "bob", "amount": 30})
            with patch("node_server.os.fsync", side_effect=OSError("flush unavailable")):
                with self.assertRaises(OSError):
                    node.accept(event)
            self.assertEqual(node.peer.balances["alice"], 100)
            self.assertNotIn(event.id, node.peer.events)
            self.assertFalse(node.state_path.exists())
            self.assertFalse(node.state_path.with_name("left.json.tmp").exists())
            self.assertTrue(node.accept(event)["accepted"])

    def test_http_reports_storage_failure_without_accepting_event(self):
        with tempfile.TemporaryDirectory() as directory:
            node = Node("storage-test", [], f"{directory}/state.json")
            server = make_server(node, 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                initial = Node._request(base, "GET", "/status")
                self.assertTrue(initial["state_persistence_enabled"])
                self.assertEqual(initial["state_integrity"], "new")
                event = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                         {"recipient": "bob", "amount": 10})
                with patch("node_server.os.fsync", side_effect=OSError("disk unavailable")):
                    with self.assertRaises(HTTPError) as error:
                        Node._request(base, "POST", "/events", event_dict(event))
                self.assertEqual(error.exception.code, 503)
                self.assertEqual(json.load(error.exception), {"error": "state_unavailable"})
                error.exception.close()
                self.assertNotIn(event.id, node.peer.events)
                self.assertTrue(Node._request(base, "POST", "/events", event_dict(event))["accepted"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_public_key_node_accepts_signed_events_without_demo_action(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Ed25519PrivateKey.generate()
            author = author_id(key)
            other = author_id(Ed25519PrivateKey.generate())
            config_path = f"{directory}/genesis.json"
            with open(config_path, "w", encoding="utf-8") as stream:
                json.dump({"network_id": "sandbox-1", "balances": {author: 50, other: 0}}, stream)
            config = load_public_genesis(config_path)
            node = Node("signed", [], f"{directory}/state.json", public_genesis=config)
            signed = PublicKeySigner(public_genesis_domain(config), {author: key}).sign(
                author, 1, "GENESIS", "transfer", {"recipient": other, "amount": 7})
            self.assertTrue(node.accept(signed)["accepted"])
            self.assertEqual(Node("signed", [], f"{directory}/state.json", public_genesis=config).peer.balances[other], 7)
            different_genesis = Node("different", [], public_genesis=("sandbox-1", {author: 500, other: 0}))
            self.assertEqual(different_genesis.accept(signed)["reason"], "invalid_signature")
            with self.assertRaises(ValueError):
                node.action(author, "transfer", {"recipient": other, "amount": 1})
            self.assertFalse(node.accept(PublicKeySigner("wrong-network", {author: key}).sign(
                author, 2, signed.id, "transfer", {"recipient": other, "amount": 1}))["accepted"])
            with self.assertRaises(ValueError):
                Node("signed", [], f"{directory}/state.json")
            with self.assertRaises(ValueError):
                Node("signed", [], f"{directory}/state.json",
                     public_genesis=("sandbox-1", {author: 500, other: 0}))
            server = make_server(node, 0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                status = Node._request(base, "GET", "/status")
                self.assertEqual(status["identity_mode"], "public-key")
                self.assertEqual(status["network_id"], "sandbox-1")
                self.assertEqual(status["signature_domain"], public_genesis_domain(config))
                with self.assertRaises(HTTPError) as error:
                    Node._request(base, "POST", "/actions", {"author": author, "kind": "transfer",
                                                                "payload": {"recipient": other, "amount": 1}})
                self.assertEqual(error.exception.code, 400)
                error.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)

    def test_public_key_transfer_and_vote_sync_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            alice_key = Ed25519PrivateKey.generate()
            bob_key = Ed25519PrivateKey.generate()
            alice, bob = author_id(alice_key), author_id(bob_key)
            config = ("signed-test", {alice: 50, bob: 10})
            signer = PublicKeySigner(public_genesis_domain(config),
                                     {alice: alice_key, bob: bob_key})
            left_path = f"{directory}/left.json"
            right_path = f"{directory}/right.json"
            left = Node("signed-left", [], left_path, public_genesis=config)
            right = Node("signed-right", [], right_path, public_genesis=config)
            server = make_server(right, 0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                transfer = signer.sign(alice, 1, "GENESIS", "transfer",
                                       {"recipient": bob, "amount": 7})
                proposal = signer.sign(alice, 2, transfer.id, "proposal",
                                       {"id": "garden", "title": "共同菜園"})
                vote = signer.sign(bob, 1, "GENESIS", "vote",
                                   {"proposal": "garden", "approve": True})
                for event in (transfer, proposal, vote):
                    self.assertTrue(left.accept(event)["accepted"])
                self.assertEqual(len(right.peer.events), 0)
                left.peers = [f"http://127.0.0.1:{server.server_port}"]
                self.assertEqual(left.sync()["unresolved"][left.peers[0]], [])
                self.assertEqual(right.peer.balances[bob], 17)
                self.assertEqual(right.peer.status()["proposals"]["garden"]["yes"], 1)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)
            for name, path in (("signed-left", left_path), ("signed-right", right_path)):
                restored = Node(name, [], path, public_genesis=config)
                self.assertEqual(restored.peer.balances[bob], 17)
                self.assertEqual(restored.peer.status()["proposals"]["garden"]["yes"], 1)
                self.assertEqual(len(restored.peer.events), 3)

    def test_signed_partition_conflict_remains_visible_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            alice_key = Ed25519PrivateKey.generate()
            bob_key = Ed25519PrivateKey.generate()
            alice, bob = author_id(alice_key), author_id(bob_key)
            config = ("conflict-test", {alice: 30, bob: 0})
            signer = PublicKeySigner(public_genesis_domain(config), {alice: alice_key})
            left_path = f"{directory}/left.json"
            right_path = f"{directory}/right.json"
            left = Node("signed-left", [], left_path, public_genesis=config)
            right = Node("signed-right", [], right_path, public_genesis=config)
            first = signer.sign(alice, 1, "GENESIS", "transfer", {"recipient": bob, "amount": 5})
            fork = signer.sign(alice, 1, "GENESIS", "transfer", {"recipient": bob, "amount": 9})
            self.assertTrue(left.accept(first)["accepted"])
            self.assertTrue(right.accept(fork)["accepted"])
            server = make_server(right, 0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                left.peers = [f"http://127.0.0.1:{server.server_port}"]
                self.assertTrue(left.sync()["status"]["balances_disputed"])
                self.assertTrue(right.peer.status()["balances_disputed"])
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)
            for name, path in (("signed-left", left_path), ("signed-right", right_path)):
                restored = Node(name, [], path, public_genesis=config)
                self.assertTrue(restored.peer.status()["balances_disputed"])
                self.assertIn(alice, restored.peer.status()["halted_authors"])
                self.assertEqual(len(restored.peer.conflicts[(alice, 1)]), 2)
                next_transfer = signer.sign(alice, 2, first.id, "transfer",
                                            {"recipient": bob, "amount": 1})
                self.assertEqual(restored.accept(next_transfer)["reason"],
                                 "author_halted_after_conflict")

    def test_public_genesis_rejects_duplicate_json_fields(self):
        author = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/genesis.json"
            for source in (
                f'{{"network_id":"one","network_id":"two","balances":{{"{author}":1}}}}',
                f'{{"network_id":"one","balances":{{"{author}":1,"{author}":2}}}}',
            ):
                with self.subTest(source=source):
                    with open(path, "w", encoding="utf-8") as stream:
                        stream.write(source)
                    with self.assertRaisesRegex(ValueError, "Duplicate JSON field"):
                        load_public_genesis(path)

    def test_public_genesis_rejects_supply_beyond_browser_safe_integer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/genesis.json"
            balances = {"a" * 64: (1 << 53) - 1, "b" * 64: 1}
            with open(path, "w", encoding="utf-8") as stream:
                json.dump({"network_id": "sandbox-1", "balances": balances}, stream)
            with self.assertRaisesRegex(ValueError, "browser-safe integer"):
                load_public_genesis(path)
            with self.assertRaisesRegex(ValueError, "browser-safe integer"):
                Node("left", [], public_genesis=("sandbox-1", balances))
            balances["b" * 64] = 0
            with open(path, "w", encoding="utf-8") as stream:
                json.dump({"network_id": "sandbox-1", "balances": balances}, stream)
            self.assertEqual(load_public_genesis(path)[1], balances)

    def test_direct_public_genesis_cannot_bypass_file_validation(self):
        valid = "a" * 64
        for config in (("demo", {valid: 1}), ("bad network", {valid: 1}),
                       ("sandbox-1", {valid: True}),
                       ("sandbox-1", {"alice": 1}), ("sandbox-1", {valid: -1})):
            with self.subTest(config=config):
                with self.assertRaises(ValueError):
                    Node("left", [], public_genesis=config)

    def test_public_genesis_file_rejects_network_id_outside_browser_format(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/genesis.json"
            with open(path, "w", encoding="utf-8") as stream:
                json.dump({"network_id": "bad network", "balances": {"a" * 64: 1}}, stream)
            with self.assertRaisesRegex(ValueError, "browser test format"):
                load_public_genesis(path)

    def test_sync_reports_same_named_public_network_with_different_genesis(self):
        key = Ed25519PrivateKey.generate()
        author = author_id(key)
        other = author_id(Ed25519PrivateKey.generate())
        left = Node("left", [], public_genesis=("sandbox-1", {author: 50, other: 0}))
        right = Node("right", [], public_genesis=("sandbox-1", {author: 500, other: 0}))
        server = make_server(right, 0)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            left.peers = [base]
            report = left.sync()
            self.assertEqual(report["incompatible"], [base])
            self.assertEqual(left.compare_peers()["incompatible"], [base])
            self.assertEqual(report["unreachable"], [])
            self.assertEqual(left.peer.events, {})
            self.assertEqual(right.peer.events, {})
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_browser_actions_relay_proposal_and_vote(self):
        base = f"http://127.0.0.1:{self.servers[0].server_port}"
        proposal = {"author": "alice", "kind": "proposal",
                    "payload": {"id": "garden", "title": "共同菜園"}}
        self.assertTrue(self.left._request(base, "POST", "/actions", proposal)["accepted"])
        vote = {"author": "bob", "kind": "vote",
                "payload": {"proposal": "garden", "approve": True}}
        self.assertTrue(self.left._request(base, "POST", "/actions", vote)["accepted"])
        with self.assertRaises(HTTPError) as repeated:
            self.left._request(base, "POST", "/actions",
                               {"author": "bob", "kind": "vote",
                                "payload": {"proposal": "garden", "approve": False}})
        self.assertEqual(repeated.exception.code, 422)
        self.assertEqual(json.load(repeated.exception)["reason"], "duplicate_vote")
        repeated.exception.close()
        for server in self.servers:
            state = self.left._request(f"http://127.0.0.1:{server.server_port}", "GET", "/status")
            self.assertEqual(state["proposals"]["garden"]["yes"], 1)
            self.assertEqual(state["proposals"]["garden"]["votes"], {"bob": True})
            self.assertEqual(state["genesis"], {"alice": 100, "bob": 100, "chen": 100})
        from urllib.request import urlopen
        with urlopen(base + "/status", timeout=2) as response:
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        with urlopen(base + "/events", timeout=2) as response:
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        with urlopen(base + "/", timeout=2) as response:
            page = response.read().decode("utf-8")
            self.assertIn("交易與投票測試網", page)
            self.assertIn('id="pair-command"', page)
            self.assertIn('id="connection-state"', page)
            self.assertIn('id="export-events"', page)
            self.assertIn('id="compare-peers"', page)
            self.assertIn('id="auto-sync"', page)
            self.assertIn('id="peer-links"', page)
            self.assertIn('id="history"', page)
            self.assertIn('id="lookup-form"', page)
        with urlopen(base + "/identity.js", timeout=2) as response:
            self.assertIn("createBrowserIdentity", response.read().decode("utf-8"))
        with urlopen(base + "/node.js", timeout=2) as response:
            script = response.read().decode("utf-8")
            self.assertIn("run_local_pair.py --left-port", script)
            self.assertIn("pauseNodeActions();", script)
            self.assertIn("sequence !== refreshSequence", script)
            self.assertIn("direction-lab-local-events-v2", script)
            self.assertIn("direction-lab-${peerFileName}-local-events.json", script)
            self.assertIn("navigator.clipboard.writeText(event.id)", script)
            self.assertIn("noopener noreferrer", script)
            self.assertIn("lookupById(event.id)", script)

    def test_alternate_http_path_delivers_past_censoring_relay(self):
        middle = Node("middle", [], censored_authors={"alice"})
        alternate = Node("alternate", [])
        servers = [make_server(middle, 0), make_server(alternate, 0)]
        threads = [threading.Thread(target=server.serve_forever, daemon=True)
                   for server in servers]
        for thread in threads:
            thread.start()
        try:
            destination = f"http://127.0.0.1:{self.servers[1].server_port}"
            middle.peers = [destination]
            alternate.peers = [destination]
            self.left.peers = [f"http://127.0.0.1:{server.server_port}" for server in servers]
            self.right.peers = []
            event = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                     {"recipient": "bob", "amount": 15})
            self.assertTrue(self.left.accept(event)["accepted"])
            self.assertIn(event.id, middle.peer.events)
            self.assertIn(event.id, self.right.peer.events)
            self.assertEqual(self.right.peer.balances["bob"], 115)
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=2)

    def test_censoring_relay_does_not_leak_event_during_manual_sync(self):
        self.left.peer.censored_authors.add("alice")
        self.left.peers = []
        self.right.peers = [f"http://127.0.0.1:{self.servers[0].server_port}"]
        event = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                 {"recipient": "bob", "amount": 10})
        self.assertTrue(self.left.accept(event)["accepted"])
        self.assertEqual(self.left._request(self.right.peers[0], "GET", "/events"),
                         {"events": []})
        self.right.peers = []
        local = self.right.action("bob", "transfer", {"recipient": "chen", "amount": 1})
        self.right.peers = [f"http://127.0.0.1:{self.servers[0].server_port}"]
        comparison = self.right.compare_peers()
        self.assertEqual(comparison["incomplete"], [self.right.peers[0]])
        self.assertEqual(comparison["differences"], {})
        report = self.right.sync()
        self.assertEqual(report["unreachable"], [])
        self.assertEqual(report["incomplete"], [self.right.peers[0]])
        self.assertNotIn(event.id, self.right.peer.events)
        self.assertNotIn(local["event"], self.left.peer.events)


if __name__ == "__main__":
    unittest.main()
