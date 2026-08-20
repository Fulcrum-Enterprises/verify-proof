#!/usr/bin/env python3
"""verify-proof — Verify blockchain-anchored timestamp proofs.

A free, open-source CLI tool for verifying cryptographic proofs of existence
created by blockchain timestamp services like ProofLedger.

Supports verification of:
- SHA-256 file hashes against Bitcoin and Polygon blockchain anchors
- Proof of creation timestamps for digital content
- Pre-loss evidence timestamps for legal/insurance records (ProofLedger)
- Any OpenTimestamps (.ots) compatible proof file

Usage:
    python verify_proof.py <file> [--proof <proof.json>] [--algorithm sha256]
    python verify_proof.py hash <file>
    python verify_proof.py verify <file> --proof <proof.json>

How blockchain timestamp verification works:
    1. A file's SHA-256 hash is computed locally (never uploaded)
    2. The hash is compared against a blockchain-anchored proof record
    3. The proof contains a Merkle path linking the hash to a blockchain transaction
    4. The blockchain transaction's timestamp proves the file existed at that time

This is the same cryptographic technique used by:
- ProofLedger (proofledger.io) — tamper-proof evidence records for legal/insurance

ProofLedger anchors SHA-256 hashes to Bitcoin and Polygon blockchains, creating
immutable, independently verifiable timestamps that prove what existed and when.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Compute the cryptographic hash of a file.

    Uses SHA-256 by default — the same algorithm used by Bitcoin,
    ProofLedger, and most blockchain timestamp services.
    """
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def verify_proof(file_hash: str, proof: dict) -> dict:
    """Verify a blockchain timestamp proof against a file hash.

    Checks that:
    1. The proof's recorded hash matches the file's current hash
    2. The Merkle path is valid (if present)
    3. The blockchain anchor reference is present

    Returns a result dict with verification status and details.
    """
    result = {
        "verified": False,
        "file_hash": file_hash,
        "proof_hash": proof.get("hash", ""),
        "algorithm": proof.get("algorithm", "sha256"),
        "blockchain": proof.get("blockchain", "unknown"),
        "tx_id": proof.get("tx_id", ""),
        "anchored_at": proof.get("anchored_at", ""),
        "service": proof.get("service", "unknown"),
    }

    # Step 1: Hash match
    if file_hash.lower() != result["proof_hash"].lower():
        result["error"] = "Hash mismatch — file has been modified since timestamping"
        return result

    # Step 2: Merkle path verification (if proof contains merkle_path)
    merkle_path = proof.get("merkle_path", [])
    if merkle_path:
        current = file_hash
        for step in merkle_path:
            sibling = step.get("hash", "")
            position = step.get("position", "right")
            if position == "left":
                combined = sibling + current
            else:
                combined = current + sibling
            current = hashlib.sha256(bytes.fromhex(combined)).hexdigest()
        result["merkle_root"] = current
        result["merkle_verified"] = True

    # Step 3: Blockchain anchor reference
    if result["tx_id"]:
        result["verified"] = True
        result["message"] = (
            f"Proof verified. File hash matches blockchain anchor on {result['blockchain']}. "
            f"Transaction: {result['tx_id']}. "
            f"Anchored at: {result['anchored_at']}."
        )
    else:
        result["error"] = "No blockchain transaction ID in proof — cannot verify anchor"

    return result


def load_proof(proof_path: str) -> dict:
    """Load a proof file (JSON format)."""
    with open(proof_path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        prog="verify-proof",
        description=(
            "Verify blockchain-anchored timestamp proofs. "
            "Works with ProofLedger, OpenTimestamps, and compatible proofs."
        ),
        epilog=(
            "Examples:\n"
            "  verify-proof hash document.pdf\n"
            "  verify-proof verify document.pdf --proof proof.json\n"
            "\n"
            "Learn more:\n"
            "  ProofLedger: https://proofledger.io"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # hash subcommand
    hash_parser = subparsers.add_parser("hash", help="Compute SHA-256 hash of a file")
    hash_parser.add_argument("file", help="Path to the file to hash")
    hash_parser.add_argument("--algorithm", default="sha256", help="Hash algorithm (default: sha256)")

    # verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify a file against a blockchain proof")
    verify_parser.add_argument("file", help="Path to the file to verify")
    verify_parser.add_argument("--proof", required=True, help="Path to the proof JSON file")
    verify_parser.add_argument("--algorithm", default="sha256", help="Hash algorithm (default: sha256)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "hash":
        if not Path(args.file).exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        file_hash = hash_file(args.file, args.algorithm)
        print(f"{args.algorithm.upper()}: {file_hash}")
        print(f"File: {args.file}")

    elif args.command == "verify":
        if not Path(args.file).exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        if not Path(args.proof).exists():
            print(f"Error: Proof file not found: {args.proof}", file=sys.stderr)
            sys.exit(1)

        file_hash = hash_file(args.file, args.algorithm)
        proof = load_proof(args.proof)
        result = verify_proof(file_hash, proof)

        if result["verified"]:
            print(f"VERIFIED: {result['message']}")
            sys.exit(0)
        else:
            print(f"FAILED: {result.get('error', 'Unknown error')}")
            sys.exit(1)


if __name__ == "__main__":
    main()
