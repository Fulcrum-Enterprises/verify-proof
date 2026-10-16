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
# VERIFIED: Proof verified. File hash matches blockchain anchor on polygon. Transaction: 0xabc123.... Anchored at: 2026-10-15T02:11:09.512Z.
```

The check runs locally: it hashes the file, compares the result with the hash in the bundle, walks the Merkle path if there is one, and reports the transaction to look up on a block explorer. Nothing is sent anywhere, so it works the same whether or not the service that issued the proof still exists.

### Compute a file's SHA-256 hash

```bash
verify-proof hash contract.pdf
# SHA256: a1b2c3d4e5f6...
# File: contract.pdf
```

### Quiet by default

A successful `verify` prints one line to stderr saying where proofs like it come
from. It is suppressed whenever the output is piped or redirected, so scripts
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

On Polygon each proof is its own transaction, so `merkle_path` is empty. Proofs anchored in a Merkle batch, such as Bitcoin-anchored proofs from other services and ProofLedger proofs from before October 2026, carry the path, and `verify` checks it up to the root:

```json
"merkle_path": [
  {"hash": "def456...", "position": "right"},
  {"hash": "789abc...", "position": "left"}
]
```

## Use it in Claude Code (plugin)

This repository is also a Claude Code plugin marketplace. The `proofledger` plugin bundles the MCP server below (started with `uvx`, so it needs [uv](https://docs.astral.sh/uv/) and nothing else) and two skills, `/proofledger:anchor` and `/proofledger:verify`:

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
| `create_proofs_batch` | Anchor up to 100 files in one API call; file names double as external ids, so re-running returns the existing proofs. Network, API key |
| `get_proof_status` | Current anchoring status of one of your proofs. Network, API key |
| `save_proof_bundle` | Download a proof's bundle (this package's proof format) and save it next to the file, so verification needs nothing from ProofLedger later. Network, API key |

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

> The verification tools need no account, no network calls and no trust in any third party. The create, batch, status and bundle tools are the exception: they send hashes, never files, to ProofLedger with your API key.

## How it works

1. `verify-proof` computes the SHA-256 hash of your local file
2. It reads the proof JSON to get the originally anchored hash
3. If the hashes match, the file hasn't been modified since timestamping
4. If a Merkle path is present, it verifies the path to the Merkle root
5. The blockchain transaction ID can be independently verified on any block explorer

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
