"""Loopback HTTP transport for separate test-credit peer processes.

This is an experimental transport for resilient_exchange.Peer. It binds only
to 127.0.0.1, uses synthetic identities, and provides no asset finality.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import islice
import json
import os
from pathlib import Path
import re
from threading import Event as StopEvent, Lock, RLock, Thread
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from uuid import uuid4

from resilient_exchange import Event, Peer, TestSigner, _canonical
from public_identity import PublicKeySigner


DEMO_GENESIS = {"alice": 100, "bob": 100, "chen": 100}
DEMO_SIGNER = TestSigner({name: f"demo-only-{name}" for name in DEMO_GENESIS})
PROTOCOL_VERSION = 1
MAX_PEER_RESPONSE_BYTES = 8 * 1024 * 1024
SNAPSHOT_PAGE_LIMIT = 128
MAX_PAGED_SNAPSHOT_EVENTS = 10000
MAX_SYNC_POSTS_PER_PEER = 64
MAX_SYNC_INGEST_PER_PEER = 64
MAX_BROWSER_SAFE_SUPPLY = (1 << 53) - 1


class PeerResponseTooLarge(ValueError):
    pass


def loopback_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("Peers must use loopback HTTP URLs")
    if (not parsed.port or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment or parsed.params):
        raise ValueError("Peer URL must contain only host and port")
    return f"http://127.0.0.1:{parsed.port}"


def decode_event(value: object) -> Event:
    if not isinstance(value, dict) or set(value) != {"author", "sequence", "previous", "kind", "payload", "signature"}:
        raise ValueError("Invalid event fields")
    if not isinstance(value["author"], str) or type(value["sequence"]) is not int:
        raise ValueError("Invalid event identity")
    if not all(isinstance(value[key], str) for key in ("previous", "kind", "signature")):
        raise ValueError("Invalid event text")
    if not isinstance(value["payload"], dict):
        raise ValueError("Invalid event payload")
    return Event(**value)


def event_dict(event: Event) -> dict:
    return {**event.unsigned, "signature": event.signature}


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Nonstandard JSON constant: {value}")


def load_public_genesis(path: str) -> tuple[str, dict[str, int]]:
    """Load only public identities and valueless starting balances."""
    value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
    if not isinstance(value, dict) or set(value) != {"network_id", "balances"}:
        raise ValueError("Public genesis requires network_id and balances")
    network_id, balances = value["network_id"], value["balances"]
    if not isinstance(network_id, str) or not isinstance(balances, dict) or not balances:
        raise ValueError("Invalid public genesis")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", network_id):
        raise ValueError("Public network ID must match the browser test format")
    PublicKeySigner(network_id)
    if network_id == "demo":
        raise ValueError("Public network ID cannot use the demo mode identifier")
    for author, amount in balances.items():
        if (not isinstance(author, str) or len(author) != 64
                or any(char not in "0123456789abcdef" for char in author)
                or type(amount) is not int or amount < 0):
            raise ValueError("Genesis identities must be public keys with nonnegative test balances")
    if sum(balances.values()) > MAX_BROWSER_SAFE_SUPPLY:
        raise ValueError("Public genesis supply exceeds browser-safe integer range")
    return network_id, balances


def public_genesis_domain(config: tuple[str, dict[str, int]]) -> str:
    """Bind signatures to the exact starting balances as well as network name."""
    network_id, balances = config
    return hashlib.sha256(_canonical({"network_id": network_id, "balances": balances})).hexdigest()


class Node:
    def __init__(self, name: str, peers: list[str], state_path: str | None = None,
                 censored_authors: set[str] | None = None,
                 public_genesis: tuple[str, dict[str, int]] | None = None):
        if public_genesis:
            network_id, balances = public_genesis
            if (type(network_id) is not str
                    or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", network_id)
                    or network_id == "demo" or not isinstance(balances, dict) or not balances):
                raise ValueError("Invalid public genesis")
            PublicKeySigner(network_id)
            if any(not isinstance(author, str) or len(author) != 64
                   or any(char not in "0123456789abcdef" for char in author)
                   or type(amount) is not int or amount < 0
                   for author, amount in balances.items()):
                raise ValueError("Invalid public genesis balances")
            if sum(balances.values()) > MAX_BROWSER_SAFE_SUPPLY:
                raise ValueError("Public genesis supply exceeds browser-safe integer range")
        self.public_genesis = public_genesis
        genesis = public_genesis[1] if public_genesis else DEMO_GENESIS
        verifier = PublicKeySigner(public_genesis_domain(public_genesis)) if public_genesis else DEMO_SIGNER
        self.peer = Peer(name, genesis, verifier, censored_authors or set())
        self.process_epoch = uuid4().hex
        self.peers = list(dict.fromkeys(loopback_url(url) for url in peers))
        self.lock = RLock()
        self.sync_lock = Lock()
        self.sync_cursors: dict[str, int] = {}
        self.post_cursors: dict[str, int] = {}
        self.auto_sync = {"enabled": False, "last_result": None}
        self.state_path = Path(state_path) if state_path else None
        self.state_integrity = "new"
        if self.state_path and self.state_path.with_name(self.state_path.name + ".tmp").exists():
            raise ValueError("Interrupted state write requires manual review of the .tmp file")
        if self.state_path and self.state_path.exists():
            saved = json.loads(self.state_path.read_text(encoding="utf-8"),
                               object_pairs_hook=_unique_json_object,
                               parse_constant=_reject_json_constant)
            mode = public_genesis[0] if public_genesis else "demo"
            if (not isinstance(saved, dict)
                    or not set(saved) <= {"name", "network_id", "signature_domain", "genesis",
                                           "events", "state_digest"}
                    or saved.get("name") != name or saved.get("network_id", "demo") != mode
                    or ("genesis" in saved and saved["genesis"] != genesis)
                    or ("signature_domain" in saved and saved["signature_domain"] !=
                        (public_genesis_domain(public_genesis) if public_genesis else "demo"))
                    or not isinstance(saved.get("events"), list)):
                raise ValueError("State file belongs to another node or is invalid")
            if "state_digest" in saved:
                expected = hashlib.sha256(_canonical({"events": saved["events"]})).hexdigest()
                if saved["state_digest"] != expected:
                    raise ValueError("State file event digest does not match")
            for item in saved["events"]:
                event = decode_event(item)
                if event.id in self.peer.events:
                    raise ValueError("State file contains a duplicate event")
                if not self.peer.ingest(event, allow_disputed_import=True):
                    raise ValueError("State file contains an invalid event")
            self.state_integrity = "verified" if "state_digest" in saved else "legacy_unchecked"

    def _ingest(self, event: Event, *, allow_disputed_import: bool = False) -> bool:
        already_seen = event.id in self.peer.events
        if not self.state_path or already_seen:
            return self.peer.ingest(event, allow_disputed_import=allow_disputed_import)
        candidate = deepcopy(self.peer)
        accepted = candidate.ingest(event, allow_disputed_import=allow_disputed_import)
        if not accepted:
            self.peer.rejections = candidate.rejections
            return False
        if accepted:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_name(self.state_path.name + ".tmp")
            events = [event_dict(item) for item in candidate.events.values()]
            saved = {"name": candidate.name,
                     "network_id": self.public_genesis[0] if self.public_genesis else "demo",
                     "signature_domain": public_genesis_domain(self.public_genesis) if self.public_genesis else "demo",
                     "genesis": candidate.genesis,
                     "events": events,
                     "state_digest": hashlib.sha256(_canonical({"events": events})).hexdigest()}
            try:
                with temporary.open("w", encoding="utf-8") as stream:
                    json.dump(saved, stream, ensure_ascii=False)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.state_path)
            except OSError:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
                raise
            self.peer = candidate
            self.state_integrity = "verified"
        return accepted

    def accept(self, event: Event) -> dict:
        with self.lock:
            already_seen = event.id in self.peer.events
            accepted = self._ingest(event)
            reason = None if accepted else self.peer.rejections[-1]["reason"]
        relay = self._relay(event) if accepted and not already_seen else None
        return {"accepted": accepted, "reason": reason, "event": event.id, "relay": relay}

    def _relay(self, event: Event) -> dict:
        report = {"attempted": 0, "delivered": [], "failed": [], "suppressed": False}
        if not self.peer.will_relay(event):
            report["suppressed"] = True
            return report
        for base in self.peers:
            report["attempted"] += 1
            try:
                try:
                    peer_status = self._request(base, "GET", "/status")
                    self._check_status_shape(peer_status)
                except (ValueError, TypeError, KeyError):
                    report["failed"].append({"peer": base, "reason": "invalid_peer_data"})
                    continue
                local_domain = public_genesis_domain(self.public_genesis) if self.public_genesis else "demo"
                if (peer_status.get("protocol_version") != PROTOCOL_VERSION
                        or peer_status.get("signature_domain") != local_domain
                        or peer_status.get("genesis") != self.peer.genesis):
                    report["failed"].append({"peer": base, "reason": "incompatible"})
                    continue
                acknowledgement = self._request(base, "POST", "/events", event_dict(event))
                if (isinstance(acknowledgement, dict) and acknowledgement.get("accepted") is True
                        and acknowledgement.get("event") == event.id):
                    try:
                        observed = self._remote_has_event(base, event, peer_status.get("process_epoch"))
                    except HTTPError as error:
                        if error.code != 404:
                            raise
                        error.close()
                        observed = False
                    if observed:
                        report["delivered"].append(base)
                    else:
                        report["failed"].append({"peer": base, "reason": "unverified_ack"})
                else:
                    report["failed"].append({"peer": base, "reason": "invalid_ack"})
            except HTTPError as error:
                report["failed"].append({"peer": base, "reason": "incompatible" if error.code == 404
                                         else "rejected", "http_status": error.code})
                error.close()
            except (ValueError, KeyError, TypeError):
                report["failed"].append({"peer": base, "reason": "invalid_ack"})
            except (URLError, TimeoutError, OSError):
                report["failed"].append({"peer": base, "reason": "unreachable"})
                # A later /sync can repair a disconnected link.
        return report

    def action(self, author: str, kind: str, payload: dict) -> dict:
        """Demo-only signer: chosen author is unauthenticated, never use for assets."""
        if self.public_genesis:
            raise ValueError("Public-key nodes accept only externally signed events")
        if author not in DEMO_GENESIS or kind not in {"transfer", "proposal", "vote"} or type(payload) is not dict:
            raise ValueError("Invalid demo action")
        with self.lock:
            sequence = self.peer.next_sequence[author]
            previous = self.peer.author_head[author]
            event = DEMO_SIGNER.sign(author, sequence, previous, kind, payload)
            accepted = self._ingest(event)
            reason = None if accepted else self.peer.rejections[-1]["reason"]
        relay = self._relay(event) if accepted else None
        return {"accepted": accepted, "reason": reason, "event": event.id, "relay": relay}

    @staticmethod
    def _request(base: str, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(base + path, data=data, method=method,
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=2) as response:
            payload = response.read(MAX_PEER_RESPONSE_BYTES + 1)
            if len(payload) > MAX_PEER_RESPONSE_BYTES:
                raise PeerResponseTooLarge("Peer response exceeds local prototype limit")
            result = json.loads(payload, object_pairs_hook=_unique_json_object,
                                parse_constant=_reject_json_constant)
            if not isinstance(result, dict):
                raise ValueError("Peer response must be a JSON object")
            return result

    def _remote_has_event(self, base: str, event: Event, expected_epoch: str | None = None) -> bool:
        """Check a peer's signed event record after its acknowledgement."""
        record = self._request(base, "GET", f"/events/id/{event.id}")
        remote = decode_event(record["event"])
        return (record.get("id") == event.id and record.get("signature_valid") is True
                and (expected_epoch is None or record.get("process_epoch") == expected_epoch)
                and remote.id == event.id and self.peer.signer.verify(remote))

    def snapshot(self) -> dict:
        """Capture metadata and relayable events at one local lock boundary."""
        with self.lock:
            return {"protocol_version": PROTOCOL_VERSION,
                    "process_epoch": self.process_epoch,
                    "signature_domain": public_genesis_domain(self.public_genesis)
                    if self.public_genesis else "demo",
                    "genesis": dict(self.peer.genesis),
                    "event_count": len(self.peer.events),
                    "events": [event_dict(event) for event in self.peer.events.values()
                               if self.peer.will_relay(event)]}

    def snapshot_page(self, cursor: int, limit: int) -> dict:
        """Bound one response while retaining a count to detect changing snapshots."""
        if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 128:
            raise ValueError("Invalid snapshot page request")
        with self.lock:
            relayable_count = sum(self.peer.will_relay(event) for event in self.peer.events.values())
            events = [event_dict(event) for event in islice(
                (event for event in self.peer.events.values() if self.peer.will_relay(event)),
                cursor, cursor + limit)]
            next_cursor = cursor + len(events) if cursor + len(events) < relayable_count else None
            return {"protocol_version": PROTOCOL_VERSION,
                    "process_epoch": self.process_epoch,
                    "signature_domain": public_genesis_domain(self.public_genesis)
                    if self.public_genesis else "demo",
                    "genesis": dict(self.peer.genesis), "event_count": len(self.peer.events),
                    "relayable_count": relayable_count, "cursor": cursor,
                    "next_cursor": next_cursor, "events": events}

    @staticmethod
    def _check_snapshot_shape(remote: dict) -> None:
        """Distinguish malformed peer data from a valid but different network."""
        if (not isinstance(remote, dict)
                or (remote.get("protocol_version") is not None
                    and type(remote["protocol_version"]) is not int)
                or (remote.get("process_epoch") is not None
                    and (not isinstance(remote["process_epoch"], str)
                         or not re.fullmatch(r"[0-9a-f]{32}", remote["process_epoch"])))
                or not isinstance(remote.get("signature_domain"), str)
                or not Node._valid_genesis_shape(remote.get("genesis"))
                or type(remote.get("event_count")) is not int
                or remote["event_count"] < 0
                or not isinstance(remote.get("events"), list)):
            raise ValueError("Malformed peer snapshot")

    @staticmethod
    def _check_status_shape(status: dict) -> None:
        if (not isinstance(status, dict)
                or (status.get("protocol_version") is not None
                    and type(status["protocol_version"]) is not int)
                or (status.get("process_epoch") is not None
                    and (not isinstance(status["process_epoch"], str)
                         or not re.fullmatch(r"[0-9a-f]{32}", status["process_epoch"])))
                or type(status.get("events")) is not int
                or status["events"] < 0
                or not isinstance(status.get("signature_domain"), str)
                or not Node._valid_genesis_shape(status.get("genesis"))):
            raise ValueError("Malformed peer status")

    @staticmethod
    def _valid_genesis_shape(genesis: object) -> bool:
        return (isinstance(genesis, dict) and bool(genesis)
                and all(isinstance(author, str) and type(amount) is int and amount >= 0
                        for author, amount in genesis.items()))

    def _fetch_snapshot(self, base: str) -> tuple[dict, bool]:
        """Use bounded pages when a whole snapshot exceeds the response limit."""
        try:
            return self._request(base, "GET", "/snapshot"), False
        except PeerResponseTooLarge:
            pass
        cursor, events, first, incomplete = 0, [], None, False
        while True:
            page = self._request(base, "GET", f"/snapshot/page?cursor={cursor}&limit={SNAPSHOT_PAGE_LIMIT}")
            self._check_snapshot_shape(page)
            if (type(page.get("relayable_count")) is not int or page["relayable_count"] < 0
                    or page["relayable_count"] > MAX_PAGED_SNAPSHOT_EVENTS
                    or type(page.get("cursor")) is not int or page["cursor"] != cursor
                    or len(page["events"]) > SNAPSHOT_PAGE_LIMIT):
                raise ValueError("Malformed snapshot page")
            if first is None:
                first = page
            elif any(page.get(key) != first.get(key) for key in
                     ("protocol_version", "process_epoch", "signature_domain", "genesis",
                      "event_count", "relayable_count")):
                incomplete = True
            events.extend(page["events"])
            next_cursor = page.get("next_cursor")
            if next_cursor is None:
                break
            if type(next_cursor) is not int or next_cursor != cursor + len(page["events"]):
                raise ValueError("Malformed snapshot page cursor")
            if not page["events"] or next_cursor > page["relayable_count"]:
                raise ValueError("Malformed snapshot page continuation")
            cursor = next_cursor
        if len(events) != first["relayable_count"]:
            incomplete = True
        return {"protocol_version": first.get("protocol_version"),
                "process_epoch": first.get("process_epoch"),
                "signature_domain": first["signature_domain"], "genesis": first["genesis"],
                "event_count": first["event_count"], "events": events}, incomplete

    def sync(self) -> dict:
        with self.sync_lock:
            return self._sync_once()

    def _sync_once(self) -> dict:
        report = {"unreachable": [], "incompatible": [], "invalid": [], "incomplete": [],
                  "unresolved": {}, "undelivered": {}, "deferred": {}, "deferred_remote": {}}
        for base in self.peers:
            try:
                remote, page_incomplete = self._fetch_snapshot(base)
                self._check_snapshot_shape(remote)
                local_domain = public_genesis_domain(self.public_genesis) if self.public_genesis else "demo"
                if (remote.get("protocol_version") != PROTOCOL_VERSION
                        or remote.get("signature_domain") != local_domain
                        or remote.get("genesis") != self.peer.genesis):
                    report["incompatible"].append(base)
                    continue
                if page_incomplete:
                    # A torn multi-page view is not a safe basis for importing or posting.
                    report["incomplete"].append(base)
                    continue
                pending = [decode_event(item) for item in remote["events"]]
                remote_status_after = self._request(base, "GET", "/status")
                self._check_status_shape(remote_status_after)
                if remote_status_after.get("protocol_version") != PROTOCOL_VERSION:
                    report["incompatible"].append(base)
                    continue
                if (remote_status_after["events"] != remote["event_count"]
                        or remote_status_after["signature_domain"] != local_domain
                        or remote_status_after["genesis"] != remote["genesis"]
                        or (remote.get("process_epoch") is not None
                            and remote_status_after.get("process_epoch") != remote["process_epoch"])):
                    report["incomplete"].append(base)
                    continue
                if remote["event_count"] != len(remote["events"]):
                    report["incomplete"].append(base)
                    continue
                remote_ids = {event.id for event in pending}
                if len(remote_ids) != len(pending):
                    report["incomplete"].append(base)
                    continue
                verified = [event for event in pending if self.peer.signer.verify(event)]
                if len(verified) != len(pending):
                    report["invalid"].append(base)
                with self.lock:
                    missing = [event for event in verified if event.id not in self.peer.events]
                    start = self.sync_cursors.get(base, 0) % len(missing) if missing else 0
                    pending = (missing[start:] + missing[:start])[:MAX_SYNC_INGEST_PER_PEER]
                    self.sync_cursors[base] = (start + len(pending)) % len(missing) if missing else 0
                report["deferred_remote"][base] = len(missing) - len(pending)
                remaining = []
                while pending:
                    remaining = []
                    for event in pending:
                        with self.lock:
                            accepted = self._ingest(event, allow_disputed_import=True)
                        if not accepted:
                            remaining.append(event)
                    if len(remaining) == len(pending):
                        break
                    pending = remaining
                report["unresolved"][base] = [event.id for event in pending]
                with self.lock:
                    local_events = [event_dict(event) for event in self.peer.events.values()
                                    if self.peer.will_relay(event) and event.id not in remote_ids]
                    start = self.post_cursors.get(base, 0) % len(local_events) if local_events else 0
                    posts = (local_events[start:] + local_events[:start])[:MAX_SYNC_POSTS_PER_PEER]
                    self.post_cursors[base] = (start + len(posts)) % len(local_events) if local_events else 0
                report["deferred"][base] = max(0, len(local_events) - MAX_SYNC_POSTS_PER_PEER)
                undelivered = []
                for event in posts:
                    try:
                        acknowledgement = self._request(base, "POST", "/events", event)
                        expected_id = decode_event(event).id
                        if (not isinstance(acknowledgement, dict) or acknowledgement.get("accepted") is not True
                                or acknowledgement.get("event") != expected_id):
                            undelivered.append({"event": expected_id, "reason": "invalid_ack"})
                        elif not self._remote_has_event(base, decode_event(event), remote.get("process_epoch")):
                            undelivered.append({"event": expected_id, "reason": "unverified_ack"})
                    except HTTPError as error:
                        undelivered.append({"event": decode_event(event).id, "http_status": error.code})
                        error.close()
                    except (ValueError, KeyError, TypeError):
                        undelivered.append({"event": decode_event(event).id, "reason": "invalid_ack"})
                    except (URLError, TimeoutError, OSError):
                        undelivered.append({"event": decode_event(event).id, "reason": "unreachable"})
                report["undelivered"][base] = undelivered
            except HTTPError as error:
                (report["incompatible"] if error.code == 404 else report["unreachable"]).append(base)
                error.close()
            except (ValueError, KeyError, TypeError):
                report["invalid"].append(base)
            except (URLError, TimeoutError, OSError):
                report["unreachable"].append(base)
        with self.lock:
            report["status"] = self.peer.status()
        return report

    def compare_peers(self) -> dict:
        """Read-only comparison of currently relayable event IDs on loopback peers."""
        report = {"unreachable": [], "incompatible": [], "invalid": [], "incomplete": [],
                  "local_changed": False, "balance_mismatch": [], "proposal_mismatch": [],
                  "differences": {}}
        with self.lock:
            domain = public_genesis_domain(self.public_genesis) if self.public_genesis else "demo"
            local_ids = set(self.peer.events)
            report["local_event_count"] = len(local_ids)
            report["process_epoch"] = self.process_epoch
            local_balances = dict(self.peer.balances)
            local_proposals = self.peer.status()["proposals"]
            genesis = dict(self.peer.genesis)
            verifier = self.peer.signer
        for base in self.peers:
            try:
                remote, page_incomplete = self._fetch_snapshot(base)
                self._check_snapshot_shape(remote)
                if (remote.get("protocol_version") != PROTOCOL_VERSION
                        or remote.get("signature_domain") != domain or remote.get("genesis") != genesis):
                    report["incompatible"].append(base)
                    continue
                if page_incomplete:
                    # Do not present balances or event differences from a torn view.
                    report["incomplete"].append(base)
                    continue
                remote_status_after = self._request(base, "GET", "/status")
                self._check_status_shape(remote_status_after)
                if remote_status_after.get("protocol_version") != PROTOCOL_VERSION:
                    report["incompatible"].append(base)
                    continue
                if (remote_status_after["events"] != remote["event_count"]
                        or remote_status_after["signature_domain"] != domain
                        or remote_status_after["genesis"] != remote["genesis"]
                        or (remote.get("process_epoch") is not None
                            and remote_status_after.get("process_epoch") != remote["process_epoch"])):
                    report["incomplete"].append(base)
                    continue
                if remote["event_count"] != len(remote["events"]):
                    report["incomplete"].append(base)
                    continue
                check = Peer("comparison", genesis, verifier)
                for item in remote["events"]:
                    if not check.ingest(decode_event(item), allow_disputed_import=True):
                        raise ValueError("Remote event replay failed")
                remote_ids = set(check.events)
                if len(remote_ids) != len(remote["events"]):
                    report["incomplete"].append(base)
                    continue
                if check.balances != local_balances:
                    report["balance_mismatch"].append(base)
                if check.status()["proposals"] != local_proposals:
                    report["proposal_mismatch"].append(base)
                report["differences"][base] = {"only_local": sorted(local_ids - remote_ids),
                                               "only_remote": sorted(remote_ids - local_ids)}
            except HTTPError as error:
                (report["incompatible"] if error.code == 404 else report["unreachable"]).append(base)
                error.close()
            except (ValueError, KeyError, TypeError):
                report["invalid"].append(base)
            except (URLError, TimeoutError, OSError):
                report["unreachable"].append(base)
        with self.lock:
            report["local_changed"] = set(self.peer.events) != local_ids
        return report

    def check_event_peers(self, event_id: str) -> dict:
        """Observe one local event on configured peers without implying finality."""
        with self.lock:
            event = self.peer.events.get(event_id)
            if event is None or not self.peer.will_relay(event):
                raise ValueError("Event is not locally visible")
            domain = public_genesis_domain(self.public_genesis) if self.public_genesis else "demo"
            genesis = dict(self.peer.genesis)
            signer = self.peer.signer
            local_ids = set(self.peer.events)
        results = {}
        for base in self.peers:
            try:
                status = self._request(base, "GET", "/status")
                self._check_status_shape(status)
                if (status.get("protocol_version") != PROTOCOL_VERSION
                        or status.get("signature_domain") != domain
                        or status.get("genesis") != genesis):
                    results[base] = "incompatible"
                    continue
                try:
                    record = self._request(base, "GET", f"/events/id/{event_id}")
                except HTTPError as error:
                    if error.code != 404:
                        raise
                    error.close()
                    results[base] = "not_visible"
                else:
                    remote = decode_event(record["event"])
                    results[base] = ("observed" if record.get("id") == event_id
                                     and record.get("signature_valid") is True
                                     and remote.id == event_id and signer.verify(remote)
                                     else "invalid")
                    record_epoch = record.get("process_epoch")
                    if record_epoch is not None:
                        if not isinstance(record_epoch, str) or not re.fullmatch(r"[0-9a-f]{32}", record_epoch):
                            results[base] = "invalid"
                        elif results[base] == "observed" and record_epoch != status.get("process_epoch"):
                            results[base] = "incomplete"
                status_after = self._request(base, "GET", "/status")
                self._check_status_shape(status_after)
                if (results[base] != "invalid" and
                        (status_after.get("protocol_version") != PROTOCOL_VERSION
                        or status_after.get("signature_domain") != domain
                        or status_after.get("genesis") != genesis
                        or status_after["events"] != status["events"]
                        or (status.get("process_epoch") is not None
                            and status_after.get("process_epoch") != status["process_epoch"]))):
                    results[base] = "incomplete"
            except HTTPError as error:
                results[base] = "unreachable" if error.code != 404 else "incompatible"
                error.close()
            except (ValueError, KeyError, TypeError):
                results[base] = "invalid"
            except (URLError, TimeoutError, OSError):
                results[base] = "unreachable"
        with self.lock:
            local_changed = set(self.peer.events) != local_ids
        return {"event": event_id, "peers": results, "local_changed": local_changed,
                "local_event_count": len(local_ids),
                "process_epoch": self.process_epoch,
                "finality_proven": False}


def start_auto_sync(node: Node, interval: float) -> tuple[StopEvent, Thread]:
    """Retry loopback synchronization in the background for a local test node."""
    if interval <= 0:
        raise ValueError("Automatic sync interval must be positive")
    stop = StopEvent()
    with node.lock:
        node.auto_sync = {"enabled": True, "last_result": None}

    def work() -> None:
        while not stop.wait(interval):
            try:
                report = node.sync()
                unresolved = sum(len(items) for items in report["unresolved"].values())
                undelivered = sum(len(items) for items in report["undelivered"].values())
                deferred = sum(report["deferred"].values())
                deferred_remote = sum(report["deferred_remote"].values())
                conflicts = len(report["status"]["conflicts"])
                problems = (len(report["unreachable"]) + len(report["incompatible"])
                            + len(report["invalid"])
                            + len(report["incomplete"]) + unresolved + undelivered
                            + deferred + deferred_remote + conflicts)
                result = {"state": "no_peers" if not node.peers else "ok" if not problems else "issue",
                          "unreachable": len(report["unreachable"]),
                          "incompatible": len(report["incompatible"]),
                          "invalid": len(report["invalid"]),
                          "incomplete": len(report["incomplete"]),
                          "unresolved": unresolved, "undelivered": undelivered,
                          "deferred": deferred, "deferred_remote": deferred_remote,
                          "conflicts": conflicts}
            except Exception:
                result = {"state": "error"}
            result["checked_at"] = datetime.now(timezone.utc).isoformat()
            with node.lock:
                node.auto_sync["last_result"] = result

    worker = Thread(target=work, name=f"{node.peer.name}-auto-sync", daemon=True)
    worker.start()
    return stop, worker


def make_server(node: Node, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, format, *args):
            pass

        def end_headers(self):
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                             "frame-ancestors 'none'")
            super().end_headers()

        def local_host(self) -> bool:
            """Reject browser DNS rebinding to this loopback-only test server."""
            hosts = self.headers.get_all("Host", [])
            if len(hosts) != 1:
                return False
            host = hosts[0]
            try:
                parsed = urlparse("//" + host)
                return (parsed.hostname in {"127.0.0.1", "localhost"}
                        and parsed.port == self.server.server_port
                        and not parsed.username and not parsed.password
                        and not parsed.path and not parsed.query and not parsed.fragment)
            except ValueError:
                return False

        def respond(self, code: int, value: dict):
            body = json.dumps(value, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self.local_host():
                return self.respond(403, {"error": "forbidden_host"})
            if self.path.startswith("/snapshot/page?"):
                try:
                    query = parse_qs(urlparse(self.path).query, strict_parsing=True)
                    if set(query) != {"cursor", "limit"} or any(len(values) != 1 for values in query.values()):
                        raise ValueError("Invalid snapshot page query")
                    cursor, limit = int(query["cursor"][0]), int(query["limit"][0])
                    return self.respond(200, node.snapshot_page(cursor, limit))
                except ValueError:
                    return self.respond(400, {"error": "invalid_snapshot_page"})
            assets = {"/": ("web/node.html", "text/html; charset=utf-8"),
                      "/node.css": ("web/node.css", "text/css; charset=utf-8"),
                      "/node.js": ("web/node.js", "application/javascript; charset=utf-8"),
                      "/identity.js": ("web/identity.js", "application/javascript; charset=utf-8")}
            if self.path in assets:
                path, mime = assets[self.path]
                body = (Path(__file__).parent / path).read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/status":
                with node.lock:
                    status = {**node.peer.status(),
                              "protocol_version": PROTOCOL_VERSION,
                              "process_epoch": node.process_epoch,
                              "genesis": dict(node.peer.genesis),
                              "state_integrity": node.state_integrity,
                              "state_persistence_enabled": node.state_path is not None,
                              "sync_running": node.sync_lock.locked(),
                              "auto_sync": dict(node.auto_sync),
                              "peers": list(node.peers),
                              "identity_mode": "public-key" if node.public_genesis else "demo",
                              "network_id": node.public_genesis[0] if node.public_genesis else "demo",
                              "signature_domain": public_genesis_domain(node.public_genesis)
                              if node.public_genesis else "demo"}
                return self.respond(200, status)
            if self.path == "/snapshot":
                return self.respond(200, node.snapshot())
            if self.path == "/compare":
                return self.respond(200, node.compare_peers())
            parts = self.path.split("/")
            if len(parts) == 4 and parts[1:3] == ["events", "id"]:
                event_id = parts[3]
                if len(event_id) != 64 or any(char not in "0123456789abcdef" for char in event_id):
                    return self.respond(400, {"error": "invalid_event_id"})
                with node.lock:
                    event = node.peer.events.get(event_id)
                    if event is None or not node.peer.will_relay(event):
                        response = (404, {"error": "event_not_found"})
                    else:
                        response = (200, {"id": event.id, "event": event_dict(event),
                                          "process_epoch": node.process_epoch,
                                          "signature_valid": node.peer.signer.verify(event)})
                return self.respond(*response)
            if len(parts) == 5 and parts[1:3] == ["events", "id"] and parts[4] == "peers":
                event_id = parts[3]
                if len(event_id) != 64 or any(char not in "0123456789abcdef" for char in event_id):
                    return self.respond(400, {"error": "invalid_event_id"})
                try:
                    return self.respond(200, node.check_event_peers(event_id))
                except ValueError:
                    return self.respond(404, {"error": "event_not_found"})
            if len(parts) == 4 and parts[1] == "authors" and parts[3] == "head":
                author = parts[2]
                with node.lock:
                    if author not in node.peer.genesis:
                        response = (404, {"error": "unknown_author"})
                    else:
                        response = (200, {"author": author,
                                          "next_sequence": node.peer.next_sequence[author],
                                          "previous": node.peer.author_head[author],
                                          "halted": author in node.peer.halted_authors})
                return self.respond(*response)
            if self.path in {"/events", "/events/recent"}:
                with node.lock:
                    relayable = [event for event in node.peer.events.values()
                                 if node.peer.will_relay(event)]
                    recent = self.path == "/events/recent"
                    events = [{**event_dict(event), **({"id": event.id} if recent else {})}
                              for event in (relayable[-8:] if recent else relayable)]
                    reply = {"events": events}
                    if recent:
                        reply.update({"event_count": len(node.peer.events),
                                      "process_epoch": node.process_epoch})
                return self.respond(200, reply)
            self.respond(404, {"error": "not_found"})

        def do_POST(self):
            if not self.local_host():
                return self.respond(403, {"error": "forbidden_host"})
            origins = self.headers.get_all("Origin", [])
            if len(origins) > 1:
                return self.respond(403, {"error": "forbidden_origin"})
            origin = origins[0] if origins else None
            if origin:
                try:
                    parsed_origin = urlparse(origin)
                    allowed_origin = (parsed_origin.scheme == "http"
                                      and parsed_origin.hostname in {"127.0.0.1", "localhost"}
                                      and parsed_origin.port == self.server.server_port
                                      and not parsed_origin.username and not parsed_origin.password
                                      and not parsed_origin.path and not parsed_origin.query and not parsed_origin.fragment)
                except ValueError:
                    allowed_origin = False
                if not allowed_origin:
                    return self.respond(403, {"error": "forbidden_origin"})
            content_params = self.headers.get_params(header="content-type") or []
            if (len(self.headers.get_all("Content-Type", [])) != 1
                    or self.headers.get_content_type() != "application/json"
                    or len(content_params) not in {1, 2}
                    or (len(content_params) == 2 and
                        (content_params[1][0].lower() != "charset"
                         or str(content_params[1][1]).lower() != "utf-8"))):
                return self.respond(415, {"error": "json_required"})
            if self.path not in {"/sync", "/events", "/actions"}:
                return self.respond(404, {"error": "not_found"})
            try:
                if self.headers.get_all("Transfer-Encoding", []):
                    raise ValueError("Chunked request bodies are unsupported")
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1:
                    raise ValueError("Expected one request length")
                length = int(lengths[0])
                if not 0 < length <= 65536:
                    raise ValueError("Invalid request size")
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("Incomplete request body")
                request = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_json_object,
                                     parse_constant=_reject_json_constant)
                if self.path == "/sync":
                    if type(request) is not dict or request:
                        raise ValueError("Sync accepts only an empty JSON object")
                    return self.respond(200, node.sync())
                if self.path == "/actions":
                    if not isinstance(request, dict) or set(request) != {"author", "kind", "payload"}:
                        raise ValueError("Invalid action fields")
                    result = node.action(request["author"], request["kind"], request["payload"])
                else:
                    result = node.accept(decode_event(request))
            except TimeoutError:
                return self.respond(408, {"error": "request_timeout"})
            except (ValueError, TypeError, KeyError, OverflowError):
                return self.respond(400, {"error": "invalid_event"})
            except OSError:
                return self.respond(503, {"error": "state_unavailable"})
            self.respond(200 if result["accepted"] else 422, result)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if f"http://127.0.0.1:{server.server_port}" in node.peers:
        server.server_close()
        raise ValueError("A node cannot list its own listening port as a peer")
    return server


def main():
    parser = argparse.ArgumentParser(description="Local test-credit peer; no real assets")
    parser.add_argument("--name", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--peer", action="append", default=[])
    parser.add_argument("--state", help="Local JSON state file, for example data/peers/left.json")
    parser.add_argument("--public-genesis", help="JSON with network_id and public-key test balances; disables demo actions")
    parser.add_argument("--censor-author", action="append", default=[],
                        help="Test a relay that refuses to forward this author's events")
    parser.add_argument("--sync-interval", type=float, default=0,
                        help="Retry peer sync every N seconds (1-300); 0 disables it")
    args = parser.parse_args()
    if args.sync_interval != 0 and not 1 <= args.sync_interval <= 300:
        parser.error("--sync-interval must be 0 or between 1 and 300 seconds")
    public_genesis = load_public_genesis(args.public_genesis) if args.public_genesis else None
    node = Node(args.name, args.peer, args.state, set(args.censor_author), public_genesis)
    server = make_server(node, args.port)
    auto_sync = start_auto_sync(node, args.sync_interval) if args.sync_interval else None
    print(f"{args.name}: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if auto_sync:
            auto_sync[0].set()
            auto_sync[1].join(timeout=3)
        server.server_close()


if __name__ == "__main__":
    main()
