import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from node_server import load_public_genesis, public_genesis_domain
from public_identity import PublicKeySigner
from resilient_exchange import Event


@unittest.skipUnless(shutil.which("node"), "Node.js is unavailable")
class BrowserSignatureTest(unittest.TestCase):
    def test_browser_identity_storage_failures_finish(self):
        root = Path(__file__).resolve().parents[1]
        subprocess.run(["node", "tests/browser_identity_store.cjs"], cwd=root,
                       check=True, capture_output=True, text=True, encoding="utf-8", timeout=10)

    def test_webcrypto_event_matches_python_verifier(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(["node", "tests/browser_sign_event.cjs"], cwd=root,
                                check=True, capture_output=True, text=True, encoding="utf-8", timeout=10)
        value = json.loads(result.stdout)
        event = Event(**value["event"])
        self.assertTrue(PublicKeySigner(value["domain"]).verify(event))
        self.assertEqual(value["eventId"], event.id)
        self.assertEqual(event.payload["title"], "共同菜園")
        vote = Event(**value["vote"])
        self.assertTrue(PublicKeySigner(value["domain"]).verify(vote))
        self.assertEqual(vote.previous, event.id)
        head_vote = Event(**value["headVote"])
        self.assertTrue(PublicKeySigner(value["domain"]).verify(head_vote))
        self.assertEqual(head_vote.previous, event.id)
        self.assertEqual(head_vote.sequence, 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "genesis.json"
            path.write_text(json.dumps(value["genesis"]), encoding="utf-8")
            network_id, balances = load_public_genesis(str(path))
            self.assertEqual(network_id, "test-net")
            self.assertEqual(balances[event.author], 100)
            self.assertEqual(value["genesisDomain"], public_genesis_domain((network_id, balances)))
