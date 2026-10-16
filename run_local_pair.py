"""Launch two or three independent loopback test-credit nodes and open their UI.

No real assets, remote listeners, or unattended deployment are involved.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser

from node_server import Node, PROTOCOL_VERSION, load_public_genesis, public_genesis_domain


ROOT = Path(__file__).resolve().parent


def stop_pair(processes: list[subprocess.Popen]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start_pair(left_port: int, right_port: int, state_dir: Path,
               genesis: Path | None = None,
               third_port: int | None = None) -> tuple[list[subprocess.Popen], tuple[str, ...]]:
    ports = (left_port, right_port) + ((third_port,) if third_port is not None else ())
    if len(set(ports)) != len(ports) or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Choose distinct valid local ports")
    state_dir = state_dir.resolve()
    genesis = genesis.resolve() if genesis is not None else None
    if genesis is not None and not genesis.is_file():
        raise ValueError("Public genesis file does not exist")
    public_config = load_public_genesis(genesis) if genesis is not None else None
    expected_domain = public_genesis_domain(public_config) if public_config is not None else "demo"
    for port in ports:
        with socket.socket() as probe:
            probe.settimeout(0.2)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise ValueError(f"Local port {port} is already in use")
    state_dir.mkdir(parents=True, exist_ok=True)
    urls = tuple(f"http://127.0.0.1:{port}" for port in ports)
    names = ("left", "right") + (("third",) if third_port is not None else ())
    nodes = [(name, port, [url for index, url in enumerate(urls) if index != position])
             for position, (name, port) in enumerate(zip(names, ports))]
    for name, _, peers in nodes:
        state_name = f"public-{name}.json" if genesis is not None else f"{name}.json"
        Node(name, peers, str(state_dir / state_name), public_genesis=public_config)
    processes = []
    try:
        for name, port, peers in nodes:
            state_name = f"public-{name}.json" if genesis is not None else f"{name}.json"
            command = [sys.executable, str(ROOT / "node_server.py"), "--name", name,
                       "--port", str(port), "--state", str(state_dir / state_name), "--sync-interval", "5"]
            for peer in peers:
                command.extend(["--peer", peer])
            if genesis is not None:
                command.extend(["--public-genesis", str(genesis)])
            processes.append(subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if any(process.poll() is not None for process in processes):
                raise RuntimeError("A node exited during startup; check ports, state and genesis")
            try:
                for (name, _, peers), url in zip(nodes, urls):
                    with urlopen(url + "/status", timeout=0.3) as response:
                        status = json.load(response)
                        if (response.status != 200 or status.get("peer") != name
                                or status.get("peers") != peers
                                or status.get("protocol_version") != PROTOCOL_VERSION
                                or status.get("signature_domain") != expected_domain):
                            raise RuntimeError("Unexpected process answered on a selected port")
                return processes, urls
            except (URLError, TimeoutError, OSError):
                time.sleep(0.1)
        raise RuntimeError("Nodes did not become ready; check whether the ports are already in use")
    except BaseException:
        stop_pair(processes)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Start two or three local valueless Direction Lab nodes")
    parser.add_argument("--left-port", type=int, default=8766)
    parser.add_argument("--right-port", type=int, default=8767)
    parser.add_argument("--third-port", type=int, help="Optional third full-mesh local test node")
    parser.add_argument("--state-dir", type=Path, default=ROOT / "data" / "peers")
    parser.add_argument("--public-genesis", type=Path)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    processes, urls = start_pair(args.left_port, args.right_port, args.state_dir,
                                 args.public_genesis, args.third_port)
    print("  ".join(f"{name.capitalize()}: {url}" for name, url in
                    zip(("left", "right", "third"), urls)), flush=True)
    print("Synthetic test credits only. Press Ctrl+C to stop local nodes.", flush=True)
    if not args.no_browser:
        for url in urls:
            webbrowser.open(url)
    stopped = set()
    try:
        while True:
            for index, process in enumerate(processes):
                if process.poll() is not None and index not in stopped:
                    stopped.add(index)
                    print(f"{('left', 'right', 'third')[index]} node stopped; other local nodes remain available.",
                          flush=True)
            if len(stopped) == len(processes):
                raise RuntimeError("All local test nodes have stopped")
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        stop_pair(processes)


if __name__ == "__main__":
    main()
