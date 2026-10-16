# Direction Lab local prototype

An experimental, loopback-only two-node network for valueless test credits, signed events, transfers, proposals, and votes. This is a curated source snapshot with a fresh public history; it does not include the private research corpus or runtime data.

It does **not** provide real-asset settlement, cross-network decentralization, production identity security, or a basis for assigning real-world rights.

## Run locally

Install Python 3.11 or newer, then install dependencies:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

On Windows, double-click `啟動示範雙節點.cmd`, or run:

```powershell
.venv\Scripts\python.exe run_local_pair.py
```

Two independent loopback processes open at `http://127.0.0.1:8766/` and `http://127.0.0.1:8767/`. They persist local state under `data/peers/`, which is ignored by Git. The default Alice/Bob/Chen identities are public demo identities, not secure accounts.

To test browser-held Ed25519 identities, first create identities on the local page, download the public-only genesis JSON to `data/peers/direction-lab-genesis.json`, stop the demo pair, then double-click `啟動公鑰雙節點.cmd`. Private keys stay in each browser origin's local storage and have no backup or recovery workflow. Never use them for value or rights.

## Verify

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
```

Node.js is optional; browser signature tests run when it is installed. All networking is restricted to loopback. An event visible on one or two nodes is still provisional, and a conflict can freeze further actions. This repository is a research prototype, not a production payment or governance system.
