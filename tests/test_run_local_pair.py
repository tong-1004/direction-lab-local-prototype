import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from node_server import DEMO_SIGNER, Node, event_dict, public_genesis_domain
from public_identity import PublicKeySigner, author_id
from run_local_pair import main, start_pair, stop_pair


class LocalPairTest(unittest.TestCase):
    def test_public_click_launcher_requires_explicit_genesis(self):
        script = (Path(__file__).resolve().parents[1] / "啟動公鑰雙節點.cmd").read_text(encoding="utf-8")
        self.assertIn('if not exist "data\\peers\\direction-lab-genesis.json"', script)
        self.assertEqual(script.count('--public-genesis "data\\peers\\direction-lab-genesis.json"'), 2)
        self.assertIn('exit /b 1', script)

    def test_launcher_opens_each_local_node_page(self):
        processes = [Mock(), Mock()]
        for process in processes:
            process.poll.return_value = None
        urls = ("http://127.0.0.1:8766", "http://127.0.0.1:8767")
        with patch("sys.argv", ["run_local_pair.py"]), \
                patch("run_local_pair.start_pair", return_value=(processes, urls)), \
                patch("run_local_pair.stop_pair") as cleanup, \
                patch("run_local_pair.webbrowser.open") as open_page, \
                patch("run_local_pair.time.sleep", side_effect=KeyboardInterrupt), \
                patch("builtins.print"):
            main()
        self.assertEqual([call.args[0] for call in open_page.call_args_list], list(urls))
        cleanup.assert_called_once_with(processes)

    def test_launcher_keeps_surviving_nodes_after_one_exits(self):
        stopped = Mock()
        alive = Mock()
        stopped.poll.return_value = 1
        alive.poll.return_value = None
        processes = [stopped, alive]

        def inspect_before_next_check(_delay):
            cleanup.assert_not_called()
            self.assertIsNone(alive.poll())
            raise KeyboardInterrupt

        with patch("sys.argv", ["run_local_pair.py", "--no-browser"]), \
                patch("run_local_pair.start_pair", return_value=(processes, ("left", "right"))), \
                patch("run_local_pair.stop_pair") as cleanup, \
                patch("run_local_pair.time.sleep", side_effect=inspect_before_next_check), \
                patch("builtins.print"):
            main()
        cleanup.assert_called_once_with(processes)

    def test_three_processes_relay_across_full_mesh(self):
        listeners = [socket.socket() for _ in range(3)]
        try:
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            ports = [listener.getsockname()[1] for listener in listeners]
        finally:
            for listener in listeners:
                listener.close()
        with tempfile.TemporaryDirectory() as directory:
            processes, urls = start_pair(ports[0], ports[1], Path(directory),
                                         third_port=ports[2])
            replacement = None
            try:
                self.assertEqual(len(processes), 3)
                self.assertEqual(len(urls), 3)
                for index, url in enumerate(urls):
                    status = Node._request(url, "GET", "/status")
                    self.assertEqual(status["peers"], [peer for offset, peer in enumerate(urls)
                                                       if offset != index])
                action = Node._request(urls[2], "POST", "/actions",
                                       {"author": "alice", "kind": "transfer",
                                        "payload": {"recipient": "bob", "amount": 7}})
                self.assertTrue(action["accepted"])
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if all(Node._request(url, "GET", "/status")["balances"]["bob"] == 107
                           for url in urls):
                        break
                    time.sleep(0.1)
                else:
                    self.fail("Three test nodes did not receive the same transfer")
                self.assertTrue(all(Node._request(url, "GET", "/status")["events"] == 1
                                    for url in urls))
                processes[0].terminate()
                processes[0].wait(timeout=5)
                request = Request(urls[2] + "/actions", data=json.dumps({
                    "author": "bob", "kind": "transfer", "payload": {"recipient": "chen", "amount": 2}
                }).encode("utf-8"), method="POST", headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=8) as response:
                    self.assertTrue(json.load(response)["accepted"])
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if Node._request(urls[1], "GET", "/status")["balances"]["chen"] == 102:
                        break
                    time.sleep(0.1)
                else:
                    self.fail("Surviving test nodes stopped exchanging events")
                node_script = Path(__file__).resolve().parents[1] / "node_server.py"
                replacement = subprocess.Popen(
                    [sys.executable, str(node_script), "--name", "left", "--port", str(ports[0]),
                     "--state", str(Path(directory) / "left.json"), "--sync-interval", "1",
                     "--peer", urls[1], "--peer", urls[2]],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    try:
                        recovered = Node._request(urls[0], "GET", "/status")
                        if recovered["events"] == 2 and recovered["balances"]["chen"] == 102:
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
                else:
                    self.fail("Restarted third-network node did not recover the missed event")
                for url in urls:
                    status = Node._request(url, "GET", "/status")
                    self.assertEqual(status["events"], 2)
                    self.assertEqual(status["balances"]["chen"], 102)
            finally:
                stop_pair(processes + ([replacement] if replacement is not None else []))

    def test_three_public_key_processes_verify_signed_transfer(self):
        listeners = [socket.socket() for _ in range(3)]
        try:
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            ports = [listener.getsockname()[1] for listener in listeners]
        finally:
            for listener in listeners:
                listener.close()
        sender_key, recipient_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        sender, recipient = author_id(sender_key), author_id(recipient_key)
        config = ("trio-signed-test", {sender: 20, recipient: 0})
        with tempfile.TemporaryDirectory() as directory:
            genesis = Path(directory) / "genesis.json"
            genesis.write_text(json.dumps({"network_id": config[0], "balances": config[1]}), encoding="utf-8")
            processes, urls = start_pair(ports[0], ports[1], Path(directory) / "state",
                                         genesis, third_port=ports[2])
            try:
                signer = PublicKeySigner(public_genesis_domain(config), {sender: sender_key})
                event = signer.sign(sender, 1, "GENESIS", "transfer",
                                    {"recipient": recipient, "amount": 7})
                result = Node._request(urls[2], "POST", "/events", event_dict(event))
                self.assertTrue(result["accepted"])
                self.assertEqual(set(result["relay"]["delivered"]), set(urls[:2]))
                for url in urls:
                    status = Node._request(url, "GET", "/status")
                    self.assertEqual(status["identity_mode"], "public-key")
                    self.assertEqual(status["balances"][recipient], 7)
                    self.assertEqual(status["events"], 1)
            finally:
                stop_pair(processes)

    def test_occupied_port_fails_before_launch(self):
        with socket.socket() as listener, tempfile.TemporaryDirectory() as directory:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            occupied = listener.getsockname()[1]
            other = 8766 if occupied != 8766 else 8767
            with self.assertRaisesRegex(ValueError, f"Local port {occupied} is already in use"):
                start_pair(occupied, other, Path(directory))

    def test_invalid_public_genesis_fails_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            genesis = Path(directory) / "genesis.json"
            genesis.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Public genesis requires"):
                start_pair(8766, 8767, Path(directory) / "state", genesis)

    def test_mismatched_saved_state_fails_before_launch(self):
        listeners = [socket.socket(), socket.socket()]
        try:
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            ports = [listener.getsockname()[1] for listener in listeners]
        finally:
            for listener in listeners:
                listener.close()
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            (state_dir / "left.json").write_text(
                json.dumps({"name": "other", "network_id": "demo", "events": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "State file belongs to another node"):
                start_pair(*ports, state_dir)

    def test_two_processes_relay_and_stop_together(self):
        listeners = [socket.socket(), socket.socket()]
        try:
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            ports = [listener.getsockname()[1] for listener in listeners]
        finally:
            for listener in listeners:
                listener.close()

        with tempfile.TemporaryDirectory() as directory:
            processes, urls = start_pair(*ports, Path(directory))
            try:
                left = Node._request(urls[0], "GET", "/status")
                right = Node._request(urls[1], "GET", "/status")
                self.assertEqual(left["peer"], "left")
                self.assertEqual(right["peer"], "right")
                self.assertEqual(left["peers"], [urls[1]])
                self.assertEqual(right["peers"], [urls[0]])
                self.assertTrue(left["auto_sync"]["enabled"])
                self.assertTrue(right["auto_sync"]["enabled"])
                action = {"author": "alice", "kind": "transfer", "payload": {"recipient": "bob", "amount": 7}}
                request = Request(urls[0] + "/actions", data=json.dumps(action).encode("utf-8"), method="POST",
                                  headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=8) as response:
                    self.assertTrue(json.load(response)["accepted"])
                deadline = time.monotonic() + 5
                while Node._request(urls[1], "GET", "/status")["balances"]["bob"] != 107 and time.monotonic() < deadline:
                    time.sleep(0.1)
                self.assertEqual(Node._request(urls[1], "GET", "/status")["balances"]["bob"], 107)
            finally:
                stop_pair(processes)
            self.assertTrue(all(process.poll() is not None for process in processes))

    def test_pair_restart_replays_persisted_transfer(self):
        listeners = [socket.socket(), socket.socket()]
        try:
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            ports = [listener.getsockname()[1] for listener in listeners]
        finally:
            for listener in listeners:
                listener.close()
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            processes, urls = start_pair(*ports, state_dir)
            try:
                result = Node._request(urls[0], "POST", "/actions",
                                       {"author": "alice", "kind": "transfer",
                                        "payload": {"recipient": "bob", "amount": 7}})
                self.assertTrue(result["accepted"])
                deadline = time.monotonic() + 5
                while Node._request(urls[1], "GET", "/status")["balances"]["bob"] != 107:
                    if time.monotonic() >= deadline:
                        self.fail("Right node did not receive the transfer")
                    time.sleep(0.1)
            finally:
                stop_pair(processes)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                released = []
                for port in ports:
                    with socket.socket() as probe:
                        probe.settimeout(0.2)
                        released.append(probe.connect_ex(("127.0.0.1", port)) != 0)
                if all(released):
                    break
                time.sleep(0.05)
            else:
                self.fail("Old listener did not release its port")
            restarted, urls = start_pair(*ports, state_dir)
            try:
                for url in urls:
                    status = Node._request(url, "GET", "/status")
                    self.assertEqual(status["balances"]["bob"], 107)
                    self.assertEqual(status["events"], 1)
            finally:
                stop_pair(restarted)

    def test_restarted_process_recovers_event_by_automatic_sync(self):
        listeners = [socket.socket(), socket.socket()]
        try:
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            ports = [listener.getsockname()[1] for listener in listeners]
        finally:
            for listener in listeners:
                listener.close()
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            processes, urls = start_pair(*ports, state_dir)
            replacement = None
            try:
                processes[1].terminate()
                processes[1].wait(timeout=5)
                action = {"author": "alice", "kind": "transfer",
                          "payload": {"recipient": "bob", "amount": 5}}
                request = Request(urls[0] + "/actions", data=json.dumps(action).encode("utf-8"),
                                  method="POST", headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=8) as response:
                    result = json.load(response)
                self.assertTrue(result["accepted"])
                self.assertEqual(result["relay"]["delivered"], [])
                self.assertEqual(Node._request(urls[0], "GET", "/status")["events"], 1)
                node_script = Path(__file__).resolve().parents[1] / "node_server.py"
                replacement = subprocess.Popen(
                    [sys.executable, str(node_script), "--name", "right", "--port", str(ports[1]),
                     "--peer", urls[0], "--state", str(state_dir / "right.json"), "--sync-interval", "1"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    try:
                        if Node._request(urls[1], "GET", "/status")["balances"]["bob"] == 105:
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
                else:
                    self.fail("Restarted node did not recover the missed event")
                self.assertEqual(Node._request(urls[0], "GET", "/compare")["differences"][urls[1]],
                                 {"only_local": [], "only_remote": []})
            finally:
                stop_pair(processes + ([replacement] if replacement is not None else []))

    def test_public_pair_accepts_external_signature_only(self):
        listeners = [socket.socket(), socket.socket()]
        try:
            for listener in listeners:
                listener.bind(("127.0.0.1", 0))
            ports = [listener.getsockname()[1] for listener in listeners]
        finally:
            for listener in listeners:
                listener.close()
        key = Ed25519PrivateKey.generate()
        author = author_id(key)
        recipient_key = Ed25519PrivateKey.generate()
        recipient = author_id(recipient_key)
        config = ("launcher-test", {author: 20, recipient: 0})
        with tempfile.TemporaryDirectory() as directory:
            genesis = Path(directory) / "genesis.json"
            genesis.write_text(json.dumps({"network_id": config[0], "balances": config[1]}), encoding="utf-8")
            state_dir = Path(directory) / "state"
            demo_node = Node("left", [], str(state_dir / "left.json"))
            demo_event = DEMO_SIGNER.sign("alice", 1, "GENESIS", "transfer",
                                          {"recipient": "bob", "amount": 1})
            self.assertTrue(demo_node.accept(demo_event)["accepted"])
            processes, urls = start_pair(*ports, state_dir, genesis)
            try:
                self.assertEqual(Node._request(urls[0], "GET", "/status")["identity_mode"], "public-key")
                self.assertEqual(Node._request(urls[0], "GET", "/status")["balances"][author], 20)
                with self.assertRaises(HTTPError) as error:
                    Node._request(urls[0], "POST", "/actions", {"author": author, "kind": "transfer",
                                                                    "payload": {"recipient": recipient, "amount": 3}})
                self.assertEqual(error.exception.code, 400)
                error.exception.close()
                signer = PublicKeySigner(public_genesis_domain(config),
                                         {author: key, recipient: recipient_key})
                event = signer.sign(author, 1, "GENESIS", "transfer", {"recipient": recipient, "amount": 3})
                request = Request(urls[0] + "/events", data=json.dumps(event_dict(event)).encode("utf-8"),
                                  method="POST", headers={"Content-Type": "application/json"})
                with urlopen(request, timeout=8) as response:
                    self.assertTrue(json.load(response)["accepted"])
                deadline = time.monotonic() + 5
                while Node._request(urls[1], "GET", "/status")["balances"][recipient] != 3 and time.monotonic() < deadline:
                    time.sleep(0.1)
                self.assertEqual(Node._request(urls[1], "GET", "/status")["balances"][recipient], 3)
                proposal = signer.sign(author, 2, event.id, "proposal",
                                       {"id": "signed-check", "title": "Local signed vote test"})
                self.assertTrue(Node._request(urls[0], "POST", "/events", event_dict(proposal))["accepted"])
                vote = signer.sign(recipient, 1, "GENESIS", "vote",
                                   {"proposal": "signed-check", "approve": True})
                self.assertTrue(Node._request(urls[1], "POST", "/events", event_dict(vote))["accepted"])
                for url in urls:
                    status = Node._request(url, "GET", "/status")
                    self.assertEqual(status["proposals"]["signed-check"]["yes"], 1)
            finally:
                stop_pair(processes)
            self.assertTrue((state_dir / "left.json").exists())
            self.assertTrue((state_dir / "public-left.json").exists())
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                released = []
                for port in ports:
                    with socket.socket() as probe:
                        probe.settimeout(0.2)
                        released.append(probe.connect_ex(("127.0.0.1", port)) != 0)
                if all(released):
                    break
                time.sleep(0.05)
            else:
                self.fail("Public node listeners did not release their ports")
            restarted, urls = start_pair(*ports, state_dir, genesis)
            try:
                for url in urls:
                    status = Node._request(url, "GET", "/status")
                    self.assertEqual(status["identity_mode"], "public-key")
                    self.assertEqual(status["events"], 3)
                    self.assertEqual(status["balances"][recipient], 3)
                    self.assertEqual(status["proposals"]["signed-check"]["yes"], 1)
            finally:
                stop_pair(restarted)


if __name__ == "__main__":
    unittest.main()
