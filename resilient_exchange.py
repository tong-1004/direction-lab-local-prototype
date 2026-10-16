"""Multi-node censorship and partition simulator using valueless test credits.

The HMAC verifier is deliberately a deterministic test provider.  Shared
secrets are not a production decentralized identity system; real deployment
must use an audited public-key signature implementation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from copy import deepcopy
import hashlib
import hmac
import json
from collections import deque
from typing import Protocol


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Event:
    author: str
    sequence: int
    previous: str
    kind: str
    payload: dict
    signature: str

    @property
    def unsigned(self) -> dict:
        return {"author": self.author, "sequence": self.sequence, "previous": self.previous,
                "kind": self.kind, "payload": self.payload}

    @property
    def id(self) -> str:
        return hashlib.sha256(_canonical({**self.unsigned, "signature": self.signature})).hexdigest()


class TestSigner:
    """Fake provider for reproducible tests; never suitable for real assets."""

    def __init__(self, secrets: dict[str, str]):
        self.secrets = {k: v.encode() for k, v in secrets.items()}

    def sign(self, author: str, sequence: int, previous: str, kind: str, payload: dict) -> Event:
        unsigned = {"author": author, "sequence": sequence, "previous": previous,
                    "kind": kind, "payload": payload}
        signature = hmac.new(self.secrets[author], _canonical(unsigned), hashlib.sha256).hexdigest()
        return Event(**unsigned, signature=signature)

    def verify(self, event: Event) -> bool:
        secret = self.secrets.get(event.author)
        if secret is None:
            return False
        expected = hmac.new(secret, _canonical(event.unsigned), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, event.signature)


class EventVerifier(Protocol):
    def verify(self, event: Event) -> bool: ...


@dataclass
class Peer:
    name: str
    genesis: dict[str, int]
    signer: EventVerifier
    censored_authors: set[str] = field(default_factory=set)

    def __post_init__(self):
        self.events: dict[str, Event] = {}
        self.author_slots: dict[tuple[str, int], str] = {}
        self.author_head: dict[str, str] = {name: "GENESIS" for name in self.genesis}
        self.next_sequence: dict[str, int] = {name: 1 for name in self.genesis}
        self.balances = dict(self.genesis)
        self.proposals: dict[str, dict] = {}
        self.conflicts: dict[tuple[str, int], set[str]] = {}
        self.halted_authors: set[str] = set()
        self.rejections: list[dict] = []

    def _reject(self, event: Event, reason: str) -> bool:
        self.rejections.append({"event": event.id, "reason": reason})
        if len(self.rejections) > 256:
            del self.rejections[:-256]
        return False

    def ingest(self, event: Event, *, allow_disputed_import: bool = False) -> bool:
        """Validate independently; disputed import is only for signed replay/catch-up."""
        if event.id in self.events:
            return True
        if not self.signer.verify(event):
            return self._reject(event, "invalid_signature")
        if event.author not in self.genesis or type(event.sequence) is not int or event.sequence < 1:
            return self._reject(event, "unknown_author_or_sequence")
        if event.kind not in {"transfer", "proposal", "vote"}:
            # No administrator, ruler, or node has a protocol-level freeze power.
            return self._reject(event, "unsupported_privileged_operation")
        if type(event.payload) is not dict:
            return self._reject(event, "invalid_payload")
        if event.kind == "transfer":
            if set(event.payload) != {"recipient", "amount"}:
                return self._reject(event, "invalid_payload")
            recipient, amount = event.payload["recipient"], event.payload["amount"]
            if type(recipient) is not str or recipient not in self.genesis or type(amount) is not int or amount <= 0 or recipient == event.author:
                return self._reject(event, "invalid_transfer")
        elif event.kind == "proposal":
            if set(event.payload) != {"id", "title"}:
                return self._reject(event, "invalid_payload")
            proposal_id, title = event.payload["id"], event.payload["title"]
            if (type(proposal_id) is not str or not 1 <= len(proposal_id) <= 64
                    or type(title) is not str or not 1 <= len(title.strip()) <= 200):
                return self._reject(event, "invalid_proposal")
        else:
            if set(event.payload) != {"proposal", "approve"}:
                return self._reject(event, "invalid_payload")
            proposal_id, approve = event.payload["proposal"], event.payload["approve"]
            if type(proposal_id) is not str or type(approve) is not bool:
                return self._reject(event, "invalid_vote")

        slot = (event.author, event.sequence)
        prior_id = self.author_slots.get(slot)
        if prior_id and prior_id != event.id:
            self.events[event.id] = deepcopy(event)
            self.conflicts.setdefault(slot, {prior_id}).add(event.id)
            self.halted_authors.add(event.author)
            return True
        if event.author in self.halted_authors:
            return self._reject(event, "author_halted_after_conflict")
        if self.conflicts and not allow_disputed_import:
            return self._reject(event, "network_conflict_unresolved")
        if event.kind == "proposal" and proposal_id in self.proposals:
            return self._reject(event, "duplicate_proposal")
        if event.sequence != self.next_sequence[event.author] or event.previous != self.author_head[event.author]:
            return self._reject(event, "missing_or_wrong_predecessor")
        if event.kind == "transfer" and self.balances[event.author] < amount:
            return self._reject(event, "insufficient_test_credit")
        if event.kind == "vote" and proposal_id not in self.proposals:
            return self._reject(event, "missing_proposal")
        if event.kind == "vote" and event.author in self.proposals[proposal_id]["votes"]:
            return self._reject(event, "duplicate_vote")

        self.events[event.id] = deepcopy(event)
        self.author_slots[slot] = event.id
        self.author_head[event.author] = event.id
        self.next_sequence[event.author] += 1
        if event.kind == "transfer":
            self.balances[event.author] -= amount
            self.balances[recipient] += amount
        elif event.kind == "proposal":
            self.proposals[proposal_id] = {"title": title.strip(), "author": event.author, "votes": {}}
        else:
            self.proposals[proposal_id]["votes"][event.author] = approve
        return True

    def will_relay(self, event: Event) -> bool:
        return event.author not in self.censored_authors

    def status(self) -> dict:
        proposals = {key: {"title": value["title"], "author": value["author"],
                           "yes": sum(value["votes"].values()),
                           "no": len(value["votes"]) - sum(value["votes"].values()),
                           "votes": dict(value["votes"])}
                     for key, value in self.proposals.items()}
        return {"peer": self.name, "events": len(self.events), "balances": dict(self.balances),
                "balances_disputed": bool(self.conflicts),
                "proposals": proposals,
                "halted_authors": sorted(self.halted_authors),
                "conflicts": {f"{a}:{s}": sorted(ids) for (a, s), ids in self.conflicts.items()},
                "finality": "insufficient" if self.conflicts else "provisional"}


class GossipNetwork:
    def __init__(self, peers: dict[str, Peer], links: list[tuple[str, str]]):
        self.peers = peers
        self.links = {name: set() for name in peers}
        for left, right in links:
            if left not in peers or right not in peers or left == right:
                raise ValueError("Invalid network link")
            self.links[left].add(right)
            self.links[right].add(left)

    def broadcast(self, origin: str, event: Event) -> set[str]:
        if origin not in self.peers:
            raise ValueError("Unknown origin")
        reached: set[str] = set()
        queue = deque([origin])
        while queue:
            name = queue.popleft()
            if name in reached:
                continue
            peer = self.peers[name]
            if not peer.ingest(event):
                continue
            reached.add(name)
            if peer.will_relay(event):
                queue.extend(sorted(self.links[name] - reached))
        return reached

    def reconcile(self, left: str, right: str) -> dict:
        """Retry causal dependencies until no progress; never claim consensus.

        Author-name ordering is not transaction ordering: a transfer by Z can
        fund an earlier-sorted author A. Only newly accepted events justify a
        retry, so malformed or permanently rejected events cannot loop forever.
        """
        events = {**self.peers[left].events, **self.peers[right].events}
        ordered = sorted(events.values(), key=lambda e: (e.author, e.sequence, e.id))
        unresolved = {}
        for name in dict.fromkeys((left, right)):
            peer = self.peers[name]
            pending = [event for event in ordered if event.id not in peer.events]
            while pending:
                remaining = [event for event in pending if not peer.ingest(event)]
                if len(remaining) == len(pending):
                    pending = remaining
                    break
                pending = remaining
            unresolved[name] = [event.id for event in pending]
        return {'unresolved': unresolved,
                'finality': {name: self.peers[name].status()['finality'] for name in unresolved}}
