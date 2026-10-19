<!-- mcp-name: io.github.csolomon0704-prog/verify-proof -->
# verify-proof

A free, open-source tool for checking blockchain timestamp proofs on your own machine.

`verify-proof` recomputes a file's SHA-256 hash and checks it against a proof bundle, so you can confirm that this exact file existed by the time it was anchored and has not changed by a single byte since. Verification is pure computation: it needs the file and the bundle, no account and no network call. Creating a proof is the one command that goes online, through [ProofLedger](https://proofledger.io)'s API with a free key.

> Also available for Node.js: `npm install verify-proof`, a zero-dependency port sharing the same proof format and semantics, tested against the same fixtures. See [`js/`](js/).

## Install

```bash
pip install verify-proof
```

The base install pulls **no dependencies** (it uses only the Python standard library) and gives you a `verify-proof` command:

```bash
verify-proof --help
```

To use it as an MCP server for Claude Desktop or Cursor, install the optional extra instead ([details below](#use-as-an-mcp-server-ai-assistants)):

```bash
pip install "verify-proof[mcp]"
```

Prefer to run from source? Clone it; the CLI works the same:

```bash
git clone https://github.com/Fulcrum-Enterprises/verify-proof.git
cd verify-proof
python verify_proof.py --help
```

## Verify a proof, offline

```bash
verify-proof verify contract.pdf --proof bundle.json
# VERIFIED: File matches the proof bundle. The bundle says it was anchored on polygon at 2026-10-15T02:11:09.512Z in transaction 0xabc123.... Look that transaction up on a block explorer to confirm it: https://polygonscan.com/tx/0xabc123...
```

The check runs locally: it hashes the file, compares the result with the hash in the bundle, computes the Merkle root if the bundle has a path, and reports the transaction to look up on a block explorer. It does not read the chain, so until you look that transaction up, the anchor is what the bundle says. Nothing is sent anywhere, so it works the same whether or not the service that issued the proof still exists.

### Compute a file's SHA-256 hash

```bash
verify-proof hash contract.pdf
# SHA256: a1b2c3d4e5f6...
# File: contract.pdf
```

### Quiet by default

A successful `verify` prints one line to stderr saying where to make proofs like
it. It is suppressed whenever the output is piped or redirected, so scripts
never see it, and stdout is unchanged either way. To silence it everywhere:

```bash
export VERIFY_PROOF_NO_HINT=1
```

## Create a proof (free API key)

Everything above works offline. This is the one command that does not: to prove
a file exists *now*, some service has to anchor it, and this submits the hash to
ProofLedger, which anchors it on Polygon.

```bash
export PROOFLEDGER_API_KEY=sk_...      # Account > API Keys, free plan included
verify-proof create contract.pdf
verify-proof create contract.pdf --no-filename   # send only the hash
```

Only the 64-character SHA-256 digest leaves your machine, plus the filename
unless you pass `--no-filename`. The file itself is never uploaded, on any
command. The free plan includes 100 API proofs a month:

[Get a free key at proofledger.io](https://proofledger.io/login.html?next=%2Faccount.html&utm_source=verify-proof&utm_medium=readme&utm_campaign=create)

The Polygon anchor usually lands within a minute. Then save the proof's bundle next to the file, and the `verify` command above works on it from then on, without ProofLedger:

```bash
curl -H "Authorization: Bearer $PROOFLEDGER_API_KEY" \
  "https://proofledger.io/api/v1/proof/42/bundle?download=1" -o contract.pdf.proof.json
```

### From Python

The same package carries a small API client, standard library only:

```python
from proofledger_api import submit_proof, submit_batch, get_proof, get_bundle, verify_webhook_signature
from verify_proof import hash_file

proof = submit_proof(hash_file("contract.pdf"), filename="contract.pdf")  # key from PROOFLEDGER_API_KEY
print(proof["id"], proof["certificate_url"])
```

`submit_batch` anchors up to 100 hashes in one call, each with your own record id so a retry returns the same proof. `verify_webhook_signature` checks the `ProofLedger-Signature` header on webhook deliveries. The API itself is documented at [proofledger.io/api](https://proofledger.io/api.html).

## Agent run receipts

Prove what an AI agent did, without storing what it saw. A receipt is a hash chain over the steps of one run: each step keeps only a SHA-256 fingerprint of its content (salted with a per-run secret), its type, its time and an optional short label. The chain head is anchored on ProofLedger as one ordinary proof, and the bundle is saved into the receipt. Anyone holding the receipt can recompute the chain and check the head against the bundle offline; nobody can read the prompts, tool calls or outputs from it.

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

Remove the `secret` field before handing a receipt to a third party: the chain still verifies, and nothing in the file can be guessed; checking a step against its content then needs your secret (`--secret`). The format is `proofledger-agent-run-receipt/1`; [`examples/receipt.json`](examples/receipt.json) is a sample the Python and Node ports both verify, and [`examples/langchain_receipt_callback.py`](examples/langchain_receipt_callback.py) is a LangChain callback handler that builds a receipt from a run. The chain rule is in the module docstring of [`agent_receipt.py`](agent_receipt.py), so it can be recomputed in any language.

A receipt shows that this exact sequence of steps existed by the anchor time and has not changed since, and, given a step's content and the secret, that the step was made from that content. It does not show that the agent was right, or who ran it.

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

On Polygon each proof is its own transaction, so `merkle_path` is empty. Bitcoin-anchored proofs, from other services or the few ProofLedger proofs anchored on Bitcoin before 2026-10-15, carry the path. If a Merkle path is present, `verify` computes the Merkle root and prints it. Compare it with the root recorded in the transaction:

```json
"merkle_path": [
  {"hash": "def456...", "position": "right"},
  {"hash": "789abc...", "position": "left"}
]
```

[`examples/`](examples/) holds a format sample: `sample.txt` and a `proof.json` that carries its hash. The transaction in it is made up and does not exist on Polygon, so a block explorer finds nothing. It shows the file format only, not a real anchor.

## Use it in Claude Code (plugin)

This repository is also a Claude Code plugin marketplace. The `proofledger` plugin bundles the MCP server below (started with `uvx`, so it needs [uv](https://docs.astral.sh/uv/) and nothing else) and three skills, `/proofledger:anchor`, `/proofledger:verify` and `/proofledger:receipt`:

```
/plugin marketplace add Fulcrum-Enterprises/verify-proof
/plugin install proofledger@proofledger
```

Then ask: *"Anchor `dist/app-1.4.0.zip` and save its proof next to it."* Creating proofs reads `PROOFLEDGER_API_KEY` from the shell that starts Claude Code; verifying needs no key. Details in [`claude-plugin/`](claude-plugin/).

## Use as an MCP server (AI assistants)

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

### Connect it to Claude Desktop

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

Then ask the assistant things like:

- *"Verify `~/contract.pdf` against `~/contract-proof.json`."*
- *"What does this proof file actually prove?"*
- *"Timestamp this file and save its bundle next to it."*

> The verification tools need no account and make no network calls. To confirm the anchor itself, look up the transaction on any block explorer. The create, batch, status and bundle tools are the exception: they send hashes and file names, never files, to ProofLedger with your API key.

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
- Any service producing SHA-256 hash proofs with blockchain transaction references.

## License

MIT License. Free to use, modify, and distribute.

## About

Built by [Fulcrum Enterprises LLC](https://fulcrumenterprises.tech), building tools for blockchain-verified proof of existence.
