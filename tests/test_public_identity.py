import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from public_identity import PublicKeySigner, author_id
from resilient_exchange import Event, Peer


class PublicIdentityTest(unittest.TestCase):
    def setUp(self):
        self.alice_key = Ed25519PrivateKey.generate()
        self.bob_key = Ed25519PrivateKey.generate()
        self.alice = author_id(self.alice_key)
        self.bob = author_id(self.bob_key)
        self.genesis = {self.alice: 100, self.bob: 0}
        self.writer = PublicKeySigner("test-network", {self.alice: self.alice_key})
        self.reader = PublicKeySigner("test-network")

    def test_peers_verify_without_sharing_private_key(self):
        event = self.writer.sign(self.alice, 1, "GENESIS", "transfer",
                                 {"recipient": self.bob, "amount": 10})
        peer = Peer("independent", self.genesis, self.reader)
        self.assertTrue(peer.ingest(event))
        self.assertEqual(peer.balances[self.bob], 10)

    def test_wrong_network_impersonation_and_mutation_are_rejected(self):
        event = self.writer.sign(self.alice, 1, "GENESIS", "transfer",
                                 {"recipient": self.bob, "amount": 10})
        self.assertFalse(PublicKeySigner("other-network").verify(event))
        forged = Event(self.bob, event.sequence, event.previous, event.kind,
                       event.payload, event.signature)
        self.assertFalse(self.reader.verify(forged))
        changed = Event(event.author, event.sequence, event.previous, event.kind,
                        {"recipient": self.bob, "amount": 90}, event.signature)
        self.assertFalse(self.reader.verify(changed))

    def test_key_registry_cannot_claim_someone_elses_identity(self):
        with self.assertRaises(ValueError):
            PublicKeySigner("test-network", {self.bob: self.alice_key})

    def test_mutating_callers_event_does_not_change_peer_history(self):
        event = self.writer.sign(self.alice, 1, "GENESIS", "transfer",
                                 {"recipient": self.bob, "amount": 10})
        original_id = event.id
        peer = Peer("independent", self.genesis, self.reader)
        self.assertTrue(peer.ingest(event))
        event.payload["amount"] = 90
        self.assertEqual(peer.events[original_id].payload["amount"], 10)
        self.assertEqual(peer.events[original_id].id, original_id)


if __name__ == "__main__":
    unittest.main()
