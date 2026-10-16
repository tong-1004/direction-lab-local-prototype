"""Ed25519 event identities for a future non-demo peer configuration.

An author's ID is its raw public key in hex. The private key never appears in
an event or peer state file. This module supplies Peer.signer's sign/verify API.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from resilient_exchange import Event, _canonical


def author_id(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes_raw().hex()


class PublicKeySigner:
    def __init__(self, network_id: str, private_keys: dict[str, Ed25519PrivateKey] | None = None):
        if not network_id or not network_id.isascii() or len(network_id) > 64:
            raise ValueError("A short ASCII network ID is required")
        self.domain = b"direction-lab:event:v1\0" + network_id.encode("ascii") + b"\0"
        self.private_keys = dict(private_keys or {})
        if any(author_id(key) != name for name, key in self.private_keys.items()):
            raise ValueError("Private key does not match its author ID")

    def sign(self, author: str, sequence: int, previous: str, kind: str, payload: dict) -> Event:
        private_key = self.private_keys[author]
        unsigned = {"author": author, "sequence": sequence, "previous": previous,
                    "kind": kind, "payload": payload}
        signature = private_key.sign(self.domain + _canonical(unsigned)).hex()
        return Event(**unsigned, signature=signature)

    def verify(self, event: Event) -> bool:
        try:
            key = bytes.fromhex(event.author)
            signature = bytes.fromhex(event.signature)
            if len(key) != 32 or len(signature) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(key).verify(
                signature, self.domain + _canonical(event.unsigned))
            return True
        except (ValueError, InvalidSignature, TypeError):
            return False
