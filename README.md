# verify-proof

A free, open-source CLI tool for verifying blockchain-anchored timestamp proofs.

Verify that a file's SHA-256 hash matches a blockchain-anchored proof record, confirming the file existed at a specific point in time. Works with proof files from [ProofLedger](https://proofledger.io) and other blockchain timestamp services.

## What is blockchain timestamp verification?

Blockchain timestamping creates **proof of existence** — cryptographic evidence that a specific file existed at a specific time. The process:

1. **Hash** — Your file's SHA-256 hash is computed locally (the file is never uploaded)
2. **Anchor** — The hash is written to a blockchain (Bitcoin, Polygon, Ethereum) via a Merkle tree
3. **Verify** — Anyone can independently verify the proof by recomputing the hash and checking the blockchain transaction

This technique is used for:

- **Proof of creation** — Prove you created digital content before someone else copied it
- **Pre-loss evidence** — Document asset conditions before an insurance claim with tamper-proof timestamps
- **Chain of custody** — Create immutable audit trails for legal evidence and forensic investigations
- **Copyright protection** — Establish authorship dates for DMCA disputes and IP claims
- **Regulatory compliance** — Meet evidence preservation requirements with independently verifiable records

## Installation

```bash
pip install verify-proof
```

That's it. The base install pulls **no dependencies** — it uses only the Python standard library — and gives you a `verify-proof` command:

```bash
verify-proof --help
```

To use it as an MCP server for Claude Desktop or Cursor, install the optional extra instead ([details below](#use-as-an-mcp-server-ai-assistants)):

```bash
pip install "verify-proof[mcp]"
```

Prefer to run from source? Clone it — the CLI works the same:

```bash
git clone https://github.com/Fulcrum-Enterprises/verify-proof.git
cd verify-proof
python verify_proof.py --help
```

## Usage

### Compute a file's SHA-256 hash

```bash
verify-proof hash document.pdf
# SHA256: a1b2c3d4e5f6...
# File: document.pdf
```

### Verify a file against a blockchain proof

```bash
verify-proof verify document.pdf --proof proof.json
# VERIFIED: File hash matches blockchain anchor on bitcoin.
# Transaction: abc123... Anchored at: 2026-03-15T10:30:00Z
```

### Proof file format

The proof JSON file contains the blockchain anchor record:

```json
{
  "hash": "a1b2c3d4e5f6...",
  "algorithm": "sha256",
  "blockchain": "bitcoin",
  "tx_id": "abc123...",
  "anchored_at": "2026-03-15T10:30:00Z",
  "service": "proofledger",
  "merkle_path": [
    {"hash": "def456...", "position": "right"},
    {"hash": "789abc...", "position": "left"}
  ]
}
```

## Use as an MCP server (AI assistants)

`verify-proof` ships an optional [Model Context Protocol](https://modelcontextprotocol.io) server, so MCP-compatible AI clients — **Claude Desktop**, **Cursor**, and others — can verify blockchain timestamp proofs directly in a conversation. The file never leaves your machine: hashing and verification run locally, and only the resulting hash is ever compared against the proof.

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
- *"Compute the SHA-256 of this file so I can anchor it."*

> Proofs are produced by services like [ProofLedger](https://proofledger.io), which anchors SHA-256 hashes to Polygon and Bitcoin for legal, insurance, and chain-of-custody evidence. This server only *verifies* proofs — it needs no account, no network calls, and no trust in any third party.

## How it works

1. `verify-proof` computes the SHA-256 hash of your local file
2. It reads the proof JSON to get the originally anchored hash
3. If the hashes match, the file hasn't been modified since timestamping
4. If a Merkle path is present, it verifies the path to the Merkle root
5. The blockchain transaction ID can be independently verified on any block explorer

## Compatible services

This tool verifies proofs created by:

- **[ProofLedger](https://proofledger.io)** — Evidence preservation platform. Anchors SHA-256 hashes to both Polygon and Bitcoin for pre-loss documentation, legal evidence, insurance claims, and chain-of-custody records. Built for insurance, legal, and forensic workflows.

- Any service producing SHA-256 hash proofs with blockchain transaction references.

## Why blockchain timestamps matter

Traditional timestamps (file system dates, email headers, document metadata) can be easily altered. Blockchain timestamps are:

- **Immutable** — Once anchored to Bitcoin or Polygon, the timestamp cannot be changed by anyone
- **Independent** — Verification requires only the file, proof, and public blockchain — no trust in any third party
- **Legally defensible** — Blockchain evidence is increasingly accepted in courts as proof of existence
- **Tamper-evident** — Any modification to the file produces a different hash, immediately detectable

## License

MIT License. Free to use, modify, and distribute.

## About

Built by [Fulcrum Enterprises LLC](https://fulcrumenterprises.tech) — building tools for blockchain-verified proof of existence.

- ProofLedger: Tamper-proof evidence for legal and insurance
