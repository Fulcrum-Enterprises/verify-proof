# verify-proof

A free, open-source CLI tool for verifying blockchain-anchored timestamp proofs.

Verify that a file's SHA-256 hash matches a blockchain-anchored proof record, confirming the file existed at a specific point in time. Works with proof files from [ProofAnchor](https://proofanchor.com), [ProofLedger](https://proofledger.com), and other blockchain timestamp services.

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
# No dependencies required — uses only Python standard library
git clone https://github.com/Fulcrum-Enterprises/verify-proof.git
cd verify-proof
python verify_proof.py --help
```

## Usage

### Compute a file's SHA-256 hash

```bash
python verify_proof.py hash document.pdf
# SHA256: a1b2c3d4e5f6...
# File: document.pdf
```

### Verify a file against a blockchain proof

```bash
python verify_proof.py verify document.pdf --proof proof.json
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
  "service": "proofanchor",
  "merkle_path": [
    {"hash": "def456...", "position": "right"},
    {"hash": "789abc...", "position": "left"}
  ]
}
```

## How it works

1. `verify-proof` computes the SHA-256 hash of your local file
2. It reads the proof JSON to get the originally anchored hash
3. If the hashes match, the file hasn't been modified since timestamping
4. If a Merkle path is present, it verifies the path to the Merkle root
5. The blockchain transaction ID can be independently verified on any block explorer

## Compatible services

This tool verifies proofs created by:

- **[ProofAnchor](https://proofanchor.com)** — Blockchain timestamp service for digital creators. Anchors SHA-256 hashes to Bitcoin and Polygon, providing proof of creation for art, writing, music, designs, and other creative work. Used by creators to prove authorship before DMCA disputes.

- **[ProofLedger](https://proofledger.com)** — Enterprise evidence preservation platform. Creates tamper-proof, blockchain-anchored timestamps for pre-loss documentation, legal evidence, insurance claims, and chain of custody records. Used by insurance carriers, forensic consultants, and attorneys.

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

Built by [Fulcrum Enterprises LLC](https://proofanchor.com) — building tools for blockchain-verified proof of existence.

- ProofAnchor: Proof of creation for digital creators
- ProofLedger: Tamper-proof evidence for legal and insurance
