<!-- mcp-name: io.github.csolomon0704-prog/verify-proof -->
# verify-proof

Check a blockchain timestamp proof on your own machine, and make one through an API.

`verify-proof` recomputes a file's SHA-256 hash and checks it against a proof bundle, so you can confirm that this exact file existed by the time it was anchored and has not changed by a single byte since. Verification is pure computation: it needs the file and the bundle, no account and no network call. Creating a proof is the one command that goes online, through [ProofLedger](https://proofledger.io)'s API with a free key. Free, MIT licensed, Python standard library only.

> Also available for Node.js: `npm install verify-proof`, a zero-dependency port sharing the same proof format and semantics, tested against the same fixtures. See [`js/`](js/).

The sections below are the questions people ask, each answered with the shortest code that does it.

- [Install](#install)
- [How do I prove a file existed at a certain time, in code?](#how-do-i-prove-a-file-existed-at-a-certain-time-in-code)
- [How do I verify a timestamp proof offline, without trusting the service?](#how-do-i-verify-a-timestamp-proof-offline-without-trusting-the-service)
- [How do I validate a Merkle proof in code?](#how-do-i-validate-a-merkle-proof-in-code)
- [How do I anchor many files at once, with my own record IDs?](#how-do-i-anchor-many-files-at-once-with-my-own-record-ids)
- [How do I get a webhook when the anchor is confirmed?](#how-do-i-get-a-webhook-when-the-anchor-is-confirmed)
- [Can I run this against a server I host myself?](#can-i-run-this-against-a-server-i-host-myself)
- [How do I add a timestamp step to a Zapier, Make or n8n workflow?](#how-do-i-add-a-timestamp-step-to-a-zapier-make-or-n8n-workflow)
- [How do I prove what an AI agent did without storing what it saw?](#how-do-i-prove-what-an-ai-agent-did-without-storing-what-it-saw)
- [Is there a GitHub Action or GitHub App that timestamps release artifacts?](#is-there-a-github-action-or-github-app-that-timestamps-release-artifacts)
- [Use it from an AI assistant (MCP server, Claude Code, Cursor)](#use-it-from-an-ai-assistant-mcp-server-claude-code-cursor)
- [Proof file format](#proof-file-format)
- [What a proof shows, and what it does not](#what-a-proof-shows-and-what-it-does-not)

## Install

```bash
pip install verify-proof
```

The base install pulls **no dependencies** (it uses only the Python standard library) and gives you a `verify-proof` command:

```bash
verify-proof --help
```

To use it as an MCP server for Claude Desktop or Cursor, install the optional extra instead ([details below](#use-it-from-an-ai-assistant-mcp-server-claude-code-cursor)):

```bash
pip install "verify-proof[mcp]"
```

Prefer to run from source? Clone it; the CLI works the same:

```bash
git clone https://github.com/Fulcrum-Enterprises/verify-proof.git
cd verify-proof
python verify_proof.py --help
```

## How do I prove a file existed at a certain time, in code?

Hash the file locally, anchor the hash in a public blockchain transaction, and keep the record of that transaction next to the file. The transaction's block time is the "no later than" date; the hash ties it to these exact bytes. The file itself never leaves your machine.

This package does the hashing and the verifying; ProofLedger does the anchoring, on Polygon, usually within a minute, with a free API key (100 API proofs a month on the Free plan):

[Get a free key at proofledger.io](https://proofledger.io/login.html?next=%2Faccount.html&utm_source=verify-proof&utm_medium=readme&utm_campaign=create)

From the command line:

```bash
export PROOFLEDGER_API_KEY=sk_...      # Account > API Keys
verify-proof create contract.pdf
verify-proof create contract.pdf --no-filename   # send only the hash
```

Only the 64-character SHA-256 digest leaves your machine, plus the filename unless you pass `--no-filename`. Then save the proof's bundle next to the file; the offline `verify` command below works on it from then on, without ProofLedger:

```bash
curl -H "Authorization: Bearer $PROOFLEDGER_API_KEY" \
  "https://proofledger.io/api/v1/proof/42/bundle?download=1" -o contract.pdf.proof.json
```

From Python, with the small API client the package carries (standard library only):

```python
from proofledger_api import submit_proof, get_bundle
from verify_proof import hash_file
import json

proof = submit_proof(hash_file("contract.pdf"), filename="contract.pdf",
                     external_id="contract-2026-10")   # key from PROOFLEDGER_API_KEY
print(proof["id"], proof["certificate_url"])

bundle = get_bundle(proof["id"])                        # once the anchor has landed
json.dump(bundle, open("contract.pdf.proof.json", "w"), indent=2)
```

From Node.js:

```js
import { hashFile, ProofLedger } from "verify-proof";

const pl = new ProofLedger({ apiKey: process.env.PROOFLEDGER_API_KEY });
const proof = await pl.createProof({ sha256: hashFile("contract.pdf"), externalId: "contract-2026-10" });
const bundle = await pl.getBundle(proof.id);           // once the anchor has landed
```

Or straight at the API: `POST https://proofledger.io/api/v1/proof` with `{"sha256": "<64 hex>"}` and a `Bearer sk_...` header. The API is documented at [proofledger.io/api](https://proofledger.io/api.html), with an OpenAPI spec at `/openapi.json`.

`external_id` is your own record id: sending the same one again returns the existing proof instead of making a new one, so a retried job never double-anchors.

## How do I verify a timestamp proof offline, without trusting the service?

```bash
verify-proof verify contract.pdf --proof bundle.json
# VERIFIED: File matches the proof bundle. The bundle says it was anchored on polygon at 2026-10-15T02:11:09.512Z in transaction 0xabc123.... Look that transaction up on a block explorer to confirm it: https://polygonscan.com/tx/0xabc123...
```

The check runs locally: it hashes the file, compares the result with the hash in the bundle, computes the Merkle root if the bundle has a path, and reports the transaction to look up on a block explorer. It does not read the chain, so until you look that transaction up, the anchor is what the bundle says. Nothing is sent anywhere, so it works the same whether or not the service that issued the proof still exists.

The same check from Python:

```python
from verify_proof import hash_file, load_proof, verify_proof

result = verify_proof(hash_file("contract.pdf"), load_proof("bundle.json"))
print(result["verified"], result["tx_id"], result.get("explorer_url"))
```

And from Node.js: `verifyProof(hashFile("contract.pdf"), loadProof("bundle.json"))`.

A test you can run on any vendor's proof: block the vendor's domain, then verify. If the check still passes, the proof is yours; if it needs the vendor's server to say "valid", you are relying on them staying in business.

### Compute a file's SHA-256 hash

```bash
verify-proof hash contract.pdf
# SHA256: a1b2c3d4e5f6...
# File: contract.pdf
```

### Quiet by default

A successful `verify` prints one line to stderr saying where to make proofs like it. It is suppressed whenever the output is piped or redirected, so scripts never see it, and stdout is unchanged either way. To silence it everywhere:

```bash
export VERIFY_PROOF_NO_HINT=1
```

## How do I validate a Merkle proof in code?

A Merkle path is the list of sibling hashes between your leaf (the file's hash) and the root that was recorded on chain. Validating it means folding your hash up through the siblings and comparing the result with the root in the transaction. The rule this package uses, in full:

```python
import hashlib

def merkle_root(leaf_hex: str, path: list[dict]) -> str:
    current = leaf_hex
    for step in path:                      # [{"hash": "<hex>", "position": "left" | "right"}, ...]
        sibling = step["hash"]
        combined = sibling + current if step.get("position") == "left" else current + sibling
        current = hashlib.sha256(bytes.fromhex(combined)).hexdigest()
    return current
```

Each level concatenates the two hashes as raw bytes, in the order the `position` says, and hashes the result with SHA-256. `verify_proof()` runs exactly this when a bundle carries a `merkle_path`, returns the root as `merkle_root`, and prints it so you can compare it with the root recorded in the transaction. The comparison with the chain is yours to make: this package never reads the chain.

On Polygon, ProofLedger anchors each proof in its own transaction, so `merkle_path` is empty and the hash in the transaction is your file's hash directly. Bitcoin-anchored proofs from other services, and the few ProofLedger proofs anchored on Bitcoin before 2026-10-15, carry a path.

## How do I anchor many files at once, with my own record IDs?

Up to 100 hashes in one call, each with your own `external_id`, so a re-run returns the proofs that already exist instead of anchoring twice:

```python
from proofledger_api import submit_batch, get_proof_by_external_id
from verify_proof import hash_file

result = submit_batch([
    {"sha256": hash_file("invoice-1001.pdf"), "external_id": "invoice-1001", "filename": "invoice-1001.pdf"},
    {"sha256": hash_file("invoice-1002.pdf"), "external_id": "invoice-1002"},
])
print(result["summary"])                         # created / exists / invalid counts
for item in result["items"]:
    print(item["result"], (item.get("proof") or {}).get("id"))

later = get_proof_by_external_id("invoice-1001")  # None if you never anchored it
```

Node.js: `await pl.createProofs(items)` takes the same list, and `pl.getProofByExternalId(id)` looks one up. From an AI assistant, the `create_proofs_batch` MCP tool does this for a list of files, using each file's name as its record id.

Items are checked first and written together; a batch is Polygon only. For plain request retries there is also an optional `Idempotency-Key` header on the creating endpoints (the same key and body within 24 hours replays the stored response), but `external_id` is the simpler way to make submissions safe to retry.

## How do I get a webhook when the anchor is confirmed?

Register a public `https` URL once; ProofLedger then POSTs a signed JSON event, `proof.polygon.anchored`, when a proof's Polygon anchor lands. The event carries the proof's bundle, so your handler can save it next to the file with nothing further to fetch.

```js
import { ProofLedger, verifyWebhookSignature } from "verify-proof";

const pl = new ProofLedger({ apiKey: process.env.PROOFLEDGER_API_KEY });
const hook = await pl.registerWebhook("https://example.com/proofledger", ["proof.polygon.anchored"]);
// hook.secret is shown once; keep it for the check below
```

Check every delivery before trusting it. The header is `ProofLedger-Signature: t=<unix>,v1=<hex HMAC-SHA256>` over `t + "." + raw body`; pass the body exactly as received:

```python
from proofledger_api import verify_webhook_signature

ok = verify_webhook_signature(secret, request.headers["ProofLedger-Signature"], request.get_data())
```

Node.js: `verifyWebhookSignature(secret, header, rawBody)`. Both are pure computation, no network. Failed deliveries are retried seven times over almost two days, then the endpoint is switched off and the account emailed. Webhooks fire only for proofs created after the endpoint was registered. Management endpoints: `POST /api/v1/webhooks`, `GET` to list, `DELETE /api/v1/webhooks/:id`, `POST /api/v1/webhooks/:id/test`.

## Can I run this against a server I host myself?

Yes. [ProofLedger Community](https://github.com/Fulcrum-Enterprises/proofledger-community) is the same proof core as an open-source (AGPL-3.0) Node + SQLite server you run with your own Polygon key: the same v1 API shapes (single and batch proofs with `external_id`, bundles, lists, public verify, certificates, signed webhooks, `Idempotency-Key`, per-key rate limits), writing the same transaction shape as proofledger.io, so this tool checks its bundles the same way.

```bash
git clone https://github.com/Fulcrum-Enterprises/proofledger-community.git
cd proofledger-community
cp .env.example .env        # set PUBLIC_BASE_URL, POLYGON_RPC_URL and POLYGON_PRIVATE_KEY
docker compose up -d        # pulls ghcr.io/fulcrum-enterprises/proofledger-community
docker compose exec proofledger node src/cli.js user add you@example.com
docker compose exec proofledger node src/cli.js key create you@example.com "laptop"
```

Then point this package at it: `--base-url https://proofs.example.com` on the CLI, `base_url=` in Python, `baseUrl` in Node. The hosted service at proofledger.io is a separate product (managed signer, backups, branding, the integrations and support) and is not open source.

## How do I add a timestamp step to a Zapier, Make or n8n workflow?

All three produce ordinary ProofLedger proofs, so the bundles verify with this tool like any other.

- **n8n:** the community node `n8n-nodes-proofledger` (installed from Settings > Community Nodes). The ProofLedger node hashes a binary field inside n8n and sends only the hash, or takes a hash you already have, one at a time or 100 per call; it reads proofs back, fetches bundles, verifies and manages webhooks. The ProofLedger Trigger registers the webhook itself and checks every delivery's signature. Source: [github.com/Fulcrum-Enterprises/n8n-nodes-proofledger](https://github.com/Fulcrum-Enterprises/n8n-nodes-proofledger). It is a community node, not an n8n-verified one.
- **Zapier:** a private integration, by invite link only until Zapier lists it: [join here](https://zapier.com/developer/public-invite/247926/a4847d5e1592b24e2307a89d1956a28e/). Trigger Proof Anchored (signature-checked), creates Create Proof From Hash and Create Proof From File (hashed inside the Zap run; only the hash reaches ProofLedger), searches Find Proof by External ID and Verify Hash.
- **Make:** a custom app, by invite link only: [install here](https://www.make.com/en/hq/app-invitation/22d9de19e3d3ef7873f3619fcf17129e). Modules for creating a proof from a SHA-256 hash, getting one by id or external id, fetching a bundle, verifying a hash, listing proofs, and an instant trigger, Watch anchored proofs. There is no file module on Make; hash the file first.

## How do I prove what an AI agent did without storing what it saw?

With an agent run receipt: a hash chain over the steps of one run. Each step keeps only a SHA-256 fingerprint of its content (salted with a per-run secret), its type, its time and an optional short label. The chain head is anchored on ProofLedger as one ordinary proof, and the bundle is saved into the receipt. Anyone holding the receipt can recompute the chain and check the head against the bundle offline; nobody can read the prompts, tool calls or outputs from it.

```python
from agent_receipt import RunReceipt

r = RunReceipt("support-ticket-48213", agent={"name": "support-bot", "model": "claude-sonnet-5-5"})
r.prompt(customer_message, label="customer message")
r.tool_call(json.dumps(call), label="lookup_order")
r.tool_result(result_text)
r.output(reply, label="reply sent")
r.anchor()                              # one API proof; waits for the Polygon anchor (key from PROOFLEDGER_API_KEY)
r.save("ticket-48213.receipt.json")
```

```bash
verify-proof receipt verify ticket-48213.receipt.json                       # offline: chain + bundle
verify-proof receipt verify ticket-48213.receipt.json --step 0 --content customer-message.txt
verify-proof receipt show ticket-48213.receipt.json                         # labels and fingerprints, never content
verify-proof receipt anchor ticket-48213.receipt.json                       # anchor a saved, unanchored receipt
```

Remove the `secret` field before handing a receipt to a third party: the chain still verifies, and nothing in the file can be guessed; checking a step against its content then needs your secret (`--secret`). The format is `proofledger-agent-run-receipt/1`; [`examples/receipt.json`](examples/receipt.json) is a sample the Python and Node ports both verify, and [`examples/langchain_receipt_callback.py`](examples/langchain_receipt_callback.py) is a LangChain callback handler that builds a receipt from a run. The chain rule is in the module docstring of [`agent_receipt.py`](agent_receipt.py), so it can be recomputed in any language. Node.js has the same `RunReceipt`, `verifyReceipt` and `verifyStep`.

A receipt shows that this exact sequence of steps existed by the anchor time and has not changed since, and, given a step's content and the secret, that the step was made from that content. It does not show that the agent was right, or who ran it.

## Is there a GitHub Action or GitHub App that timestamps release artifacts?

Both, from the same account.

**The Action**, [ProofLedger Release Timestamp](https://github.com/marketplace/actions/proofledger-release-timestamp) in the GitHub Marketplace, hashes the artifact on the runner (the file never leaves it), submits the hash, waits for the Polygon anchor, writes the proof into the release notes and attaches the bundle (`<label>.proof.json`) to the release, which is what this tool verifies the file against later:

```yaml
name: Timestamp Release
on:
  release:
    types: [published]

jobs:
  timestamp:
    runs-on: ubuntu-latest
    permissions:
      contents: write  # needed to update the release body and attach the proof bundle
    steps:
      - uses: actions/checkout@v4

      - name: Build release artifact
        run: zip -r dist/release.zip src/

      - name: Timestamp with ProofLedger
        uses: Fulcrum-Enterprises/proofanchor-github-action@v2
        with:
          api-key: ${{ secrets.PROOFLEDGER_API_KEY }}
          file: dist/release.zip
```

(The repository kept its old name; `uses:` lines stay as above.)

**The App**, [github.com/apps/proofledger](https://github.com/apps/proofledger), needs no workflow: install it on a repository, connect it to a ProofLedger account once, and every release published there is anchored on its own, one proof per release file from the SHA-256 GitHub reports (no file is downloaded), with a proof table in the release notes and the bundle attached once the hash is on Polygon. It holds Contents read and write on the chosen repositories and nothing else. It installs from that page; it is not in the GitHub Marketplace. Docs: [proofledger.io/api.html#sec-github](https://proofledger.io/api.html#sec-github).

## Use it from an AI assistant (MCP server, Claude Code, Cursor)

`verify-proof` ships an optional [Model Context Protocol](https://modelcontextprotocol.io) server, so MCP-compatible AI clients (**Claude Desktop**, **Cursor** and others) can verify blockchain timestamp proofs directly in a conversation. The file never leaves your machine: hashing and verification run locally, and only the resulting hash is ever compared against the proof.

### Install with the MCP extra

```bash
pip install "verify-proof[mcp]"
```

The base install stays dependency-free; the `[mcp]` extra adds the MCP SDK and installs a `verify-proof-mcp` command (a stdio server).

### Tools exposed

| Tool | What it does |
|------|--------------|
| `compute_file_hash` | Compute the SHA-256 (or other) hash of a local file |
| `verify_file` | Verify a local file against a proof JSON file |
| `verify_hash` | Verify a known hash against inline or file-based proof data |
| `explain_proof` | Describe, in plain language, what a proof asserts and how to check it on a block explorer |
| `create_proof` | Anchor a file's hash on ProofLedger to create a new proof. Uses the network and needs an API key |
| `create_proofs_batch` | Anchor up to 100 files in one API call; file names double as external ids, so re-running on unchanged files returns their existing proofs. If a file changed but kept its name, you get its old proof back, so rename it or anchor it with `create_proof`. Network, API key |
| `get_proof_status` | Current anchoring status of one of your proofs. Network, API key |
| `save_proof_bundle` | Download a proof's bundle (this package's proof format) and save it next to the file, so verification needs nothing from ProofLedger later. Network, API key |
| `start_run_receipt` | Start an agent run receipt file (fresh secret, no steps). Offline |
| `add_receipt_step` | Fingerprint one step (prompt, tool_call, tool_result, output, note) into the receipt; the content is only hashed. Offline |
| `anchor_run_receipt` | Anchor the receipt's chain head as one proof and save the bundle into the receipt. Network, API key |
| `verify_run_receipt` | Recompute the chain and check it against the bundle, optionally checking one step's content. Offline |

### Claude Code (plugin)

This repository is also a Claude Code plugin marketplace. The `proofledger` plugin bundles the MCP server (started with `uvx`, so it needs [uv](https://docs.astral.sh/uv/) and nothing else) and three skills, `/proofledger:anchor`, `/proofledger:verify` and `/proofledger:receipt`:

```
/plugin marketplace add Fulcrum-Enterprises/verify-proof
/plugin install proofledger@proofledger
```

Then ask: *"Anchor `dist/app-1.4.0.zip` and save its proof next to it."* Creating proofs reads `PROOFLEDGER_API_KEY` from the shell that starts Claude Code; verifying needs no key. Details in [`claude-plugin/`](claude-plugin/).

### Claude Desktop

Add this to your `claude_desktop_config.json` (see [`examples/claude_desktop_config.json`](examples/claude_desktop_config.json)):

```json
{
  "mcpServers": {
    "verify-proof": {
      "command": "verify-proof-mcp"
    }
  }
}
```

Restart Claude Desktop. If `verify-proof-mcp` isn't found on your PATH, use the Python module form instead: `"command": "python"`, `"args": ["-m", "verify_proof_mcp"]`.

### Cursor

One click, with [uv](https://docs.astral.sh/uv/) installed (Cursor starts the server with `uvx`, nothing to pip install):

[![Add verify-proof to Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=verify-proof&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyItLWZyb20iLCJ2ZXJpZnktcHJvb2ZbbWNwXSIsInZlcmlmeS1wcm9vZi1tY3AiXX0=)

Or add it by hand to `~/.cursor/mcp.json` (or a project's `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "verify-proof": {
      "command": "uvx",
      "args": ["--from", "verify-proof[mcp]", "verify-proof-mcp"]
    }
  }
}
```

Creating proofs reads `PROOFLEDGER_API_KEY` from the environment Cursor runs in; verifying needs no key. The [`claude-plugin/`](claude-plugin/) folder also carries a Cursor plugin manifest (`.cursor-plugin/plugin.json`, `mcp.json`, the same three skills), so the repository can be imported as a Cursor marketplace.

Then ask the assistant things like:

- *"Verify `~/contract.pdf` against `~/contract-proof.json`."*
- *"What does this proof file actually prove?"*
- *"Timestamp this file and save its bundle next to it."*

> The verification tools need no account and make no network calls. To confirm the anchor itself, look up the transaction on any block explorer. The create, batch, status and bundle tools are the exception: they send hashes and file names, never files, to ProofLedger with your API key.

## Proof file format

A bundle is one JSON document. Abridged:

```json
{
  "format": "verify-proof/1",
  "service": "proofledger",
  "hash": "a1b2c3d4e5f6...",
  "algorithm": "sha256",
  "blockchain": "polygon",
  "tx_id": "0xabc123...",
  "anchored_at": "2026-10-15T02:11:09.512Z",
  "merkle_path": [],
  "proof_id": 42,
  "certificate_url": "https://proofledger.io/cert/42"
}
```

If a Merkle path is present, `verify` computes the Merkle root and prints it (see [How do I validate a Merkle proof in code?](#how-do-i-validate-a-merkle-proof-in-code)). Compare it with the root recorded in the transaction:

```json
"merkle_path": [
  {"hash": "def456...", "position": "right"},
  {"hash": "789abc...", "position": "left"}
]
```

[`examples/`](examples/) holds a format sample: `sample.txt` and a `proof.json` that carries its hash. The transaction in it is made up and does not exist on Polygon, so a block explorer finds nothing. It shows the file format only, not a real anchor.

## How it works

1. `verify-proof` computes the SHA-256 hash of your local file
2. It reads the proof JSON to get the originally anchored hash
3. If the hashes match, the file hasn't been modified since timestamping
4. If a Merkle path is present, it computes the Merkle root and prints it; compare it with the root recorded in the transaction
5. It does not read the chain: look the transaction up on any block explorer to confirm the anchor (for Polygon, the verdict prints the polygonscan link)

## What a proof shows, and what it does not

A proof shows that a file with this exact SHA-256 fingerprint existed by the anchor time, and that the file has not changed since. The record sits on a public chain rather than in any one company's database, so anyone can check it without an account and without seeing the file.

It does not show who made the file, it is not a copyright registration, and it does not stop anyone copying the file.

## Compatible services

This tool verifies proofs created by:

- **[ProofLedger](https://proofledger.io)**: proof of existence as an API. Send a hash, get a Polygon-anchored certificate anyone can verify without us. Free plan with 100 API proofs a month.
- **[ProofLedger Community](https://github.com/Fulcrum-Enterprises/proofledger-community)**: the same proof core as an open-source (AGPL-3.0) server you host with your own Polygon key. Same API and bundle format; point this tool at it with `--base-url` (Python `base_url=`, Node `baseUrl`).
- Any service producing SHA-256 hash proofs with blockchain transaction references.

## License

MIT License. Free to use, modify, and distribute.

## About

Built by [Fulcrum Enterprises LLC](https://fulcrumenterprises.tech), building tools for blockchain-verified proof of existence.
