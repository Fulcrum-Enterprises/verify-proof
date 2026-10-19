#!/usr/bin/env python3
"""verify-proof — Verify blockchain-anchored timestamp proofs.

A free, open-source CLI tool for verifying cryptographic proofs of existence
created by blockchain timestamp services like ProofLedger.

Supports:
- SHA-256 file hashes checked against a proof bundle that names a Polygon or
  Bitcoin transaction (look the transaction up on a block explorer to confirm it)
- Merkle paths, for proofs anchored in a batch: the root is computed and printed
  for comparison with the root recorded in the transaction
- JSON proof files carrying hash, blockchain, tx_id and merkle_path (ProofLedger bundles; binary OpenTimestamps .ots files are a different format and are not parsed here, use the ots tool)

Usage:
    python verify_proof.py <file> [--proof <proof.json>] [--algorithm sha256]
    python verify_proof.py hash <file>
    python verify_proof.py verify <file> --proof <proof.json>
    python verify_proof.py create <file> [--no-filename]
    python verify_proof.py receipt verify <receipt.json> [--step N --content <file>]
    python verify_proof.py receipt show <receipt.json>
    python verify_proof.py receipt anchor <receipt.json>

`hash`, `verify`, `receipt verify` and `receipt show` never touch the network.
`create` and `receipt anchor` are the exceptions: they submit a hash (never the
file, never a step's content) to ProofLedger to be anchored, and need a free
API key. Agent run receipts are built with the `agent_receipt` module.

How blockchain timestamp verification works:
    1. A file's SHA-256 hash is computed locally (never uploaded)
    2. The hash is compared against a blockchain-anchored proof record
    3. The proof names the blockchain transaction that carries the hash, directly
       or through a Merkle path
    4. The blockchain transaction's timestamp proves the file existed at that time

ProofLedger (proofledger.io) offers proof of existence as an API: send a hash,
get a Polygon-anchored certificate anyone can verify without it.
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from proofledger_api import (
    API_KEY_ENV,
    DEFAULT_BASE_URL,
    HOME_URL,
    ProofLedgerError,
    submit_proof,
    summarize,
)


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


def explorer_url(blockchain: str, tx_id: str) -> str:
    """Public block-explorer link for a transaction, where one is known."""
    b = (blockchain or "").lower()
    if tx_id and b in ("polygon", "matic"):
        return f"https://polygonscan.com/tx/{tx_id}"
    return ""


def verify_proof(file_hash: str, proof: dict) -> dict:
    """Verify a blockchain timestamp proof against a file hash.

    Checks that:
    1. The proof's recorded hash matches the file's current hash
    2. The bundle names a blockchain transaction

    If the proof carries a Merkle path, the Merkle root is computed from it and
    returned (`merkle_root`) so it can be compared with the root recorded in the
    transaction. Nothing here reads the chain: the transaction id and anchor
    time are what the bundle says until someone looks the transaction up on a
    block explorer. `merkle_verified` is kept for compatibility and means only
    that a root was computed.

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
        result["error"] = (
            "Hash mismatch: this is not the file the proof was made for "
            "(it was changed, or it is a different file)"
        )
        return result

    # Merkle path (if the proof carries one): compute the root. Nothing here can
    # compare it with the chain; the message tells the reader to do that.
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

    # Step 2: the bundle names a transaction. Reported as the bundle's claim,
    # because this offline check never reads the chain.
    if result["tx_id"]:
        result["verified"] = True
        when = f" at {result['anchored_at']}" if result["anchored_at"] else ""
        message = (
            "File matches the proof bundle. "
            f"The bundle says it was anchored on {result['blockchain']}{when} "
            f"in transaction {result['tx_id']}."
        )
        if "merkle_root" in result:
            message += (
                f" Merkle root computed from the path: {result['merkle_root']}. "
                "Compare it with the root recorded in the transaction."
            )
        message += " Look that transaction up on a block explorer to confirm it"
        link = explorer_url(result["blockchain"], result["tx_id"])
        if link:
            result["explorer_url"] = link
            message += f": {link}"
        else:
            message += "."
        result["message"] = message
    else:
        result["error"] = "No blockchain transaction ID in proof — cannot verify anchor"

    return result


def load_proof(proof_path: str) -> dict:
    """Load a proof file (JSON format)."""
    with open(proof_path) as f:
        return json.load(f)



def _hint() -> None:
    """One quiet line after a successful verify, pointing at where proofs come from.

    Almost everybody who installs this runs `verify`, and `verify` never touches
    the network, which is the product. So the only tagged link the package ever
    printed lived in the missing-key error on `create`, a path most users never
    reach: 417 installs in a month produced 10 tagged arrivals in 120 days. The
    tool was doing its job and saying nothing about who made it.

    Three manners rules, because a dev tool that nags gets uninstalled and the
    goodwill is the whole asset:

    * **stderr, never stdout.** Somebody is parsing `VERIFIED: ...` in a script
      and a marketing line in that stream would break them.
    * **Only when a human is watching.** Not a TTY means piped or scripted, and
      a pipeline does not need to hear from us.
    * **One env var turns it off for good** (`VERIFY_PROOF_NO_HINT=1`).
    """
    if os.environ.get("VERIFY_PROOF_NO_HINT"):
        return
    try:
        if not sys.stdout.isatty():
            return
    except Exception:  # pragma: no cover - exotic stdout
        return
    print(f"\n(make proofs like this with ProofLedger: {HOME_URL})", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        prog="verify-proof",
        description=(
            "Verify blockchain-anchored timestamp proofs. "
            "Reads JSON proofs (ProofLedger bundles and compatible); .ots files are not parsed."
        ),
        epilog=(
            "Examples:\n"
            "  verify-proof hash document.pdf\n"
            "  verify-proof verify document.pdf --proof proof.json\n"
            "  verify-proof create document.pdf   (needs a free API key)\n"
            "  verify-proof receipt verify run.receipt.json   (an agent run receipt, offline)\n"
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

    # create subcommand — the only subcommand that uses the network
    create_parser = subparsers.add_parser(
        "create",
        help="Anchor a file's hash on ProofLedger (sends the hash, never the file)",
    )
    create_parser.add_argument("file", help="Path to the file to timestamp")
    # Bitcoin anchoring ended 2026-10-15; the flag is still accepted so old scripts run.
    create_parser.add_argument("--bitcoin", action="store_true", help=argparse.SUPPRESS)
    create_parser.add_argument(
        "--label",
        help="Name to store with the proof (default: the filename)",
    )
    create_parser.add_argument(
        "--no-filename",
        action="store_true",
        help="Send only the hash — no filename leaves this machine",
    )
    create_parser.add_argument(
        "--api-key",
        help=f"ProofLedger API key (default: ${API_KEY_ENV})",
    )
    create_parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"API base URL (default: {DEFAULT_BASE_URL})",
    )

    # receipt subcommands: agent run receipts (format proofledger-agent-run-receipt/1)
    receipt_parser = subparsers.add_parser(
        "receipt",
        help="Agent run receipts: verify (offline), show, or anchor one",
    )
    receipt_sub = receipt_parser.add_subparsers(dest="receipt_command")
    rv = receipt_sub.add_parser("verify", help="Recompute the chain and check it against the bundle, offline")
    rv.add_argument("receipt", help="Path to the receipt JSON file")
    rv.add_argument("--step", type=int, help="Also check that step N was made from --content")
    rv.add_argument("--content", help="File holding the content of step --step")
    rv.add_argument("--secret", help="The run secret, if it was redacted from the receipt")
    rs = receipt_sub.add_parser("show", help="List the receipt's steps (labels and fingerprints, never content)")
    rs.add_argument("receipt", help="Path to the receipt JSON file")
    ra = receipt_sub.add_parser("anchor", help="Anchor a saved receipt's chain head on ProofLedger (one API proof)")
    ra.add_argument("receipt", help="Path to the receipt JSON file (rewritten with the bundle)")
    ra.add_argument("--wait", type=int, default=120, help="Seconds to wait for the Polygon anchor (default 120; 0 = do not wait)")
    ra.add_argument("--api-key", help=f"ProofLedger API key (default: ${API_KEY_ENV})")
    ra.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"API base URL (default: {DEFAULT_BASE_URL})")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "receipt":
        if not args.receipt_command:
            receipt_parser.print_help()
            sys.exit(1)
        _receipt_command(args)
        return

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
            _hint()
            sys.exit(0)
        else:
            print(f"FAILED: {result.get('error', 'Unknown error')}")
            sys.exit(1)

    elif args.command == "create":
        if not Path(args.file).exists():
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

        if args.bitcoin:
            print(
                "Note: --bitcoin is ignored. ProofLedger stopped anchoring on Bitcoin on "
                "2026-10-15; this proof is anchored on Polygon.",
                file=sys.stderr,
            )
        file_hash = hash_file(args.file)
        label = None if args.no_filename else (args.label or Path(args.file).name)
        try:
            proof = submit_proof(
                file_hash,
                filename=label,
                key=args.api_key,
                base_url=args.base_url,
            )
        except ProofLedgerError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        print(summarize(proof, base_url=args.base_url))


def _receipt_command(args) -> None:
    """`verify-proof receipt ...`. Imported here, not at module level: agent_receipt
    imports this module's verify_proof() for the bundle check."""
    import agent_receipt

    if not Path(args.receipt).exists():
        print(f"Error: Receipt file not found: {args.receipt}", file=sys.stderr)
        sys.exit(1)
    with open(args.receipt, encoding="utf-8") as f:
        receipt = json.load(f)

    if args.receipt_command == "show":
        print(agent_receipt.describe(receipt))
        return

    if args.receipt_command == "verify":
        result = agent_receipt.verify_receipt(receipt)
        if result["verified"]:
            print(f"VERIFIED: {result['message']}")
        else:
            print(f"FAILED: {result.get('error', 'Unknown error')}")
        if args.step is not None or args.content:
            if args.step is None or not args.content:
                print("Error: --step and --content go together", file=sys.stderr)
                sys.exit(2)
            if not Path(args.content).exists():
                print(f"Error: Content file not found: {args.content}", file=sys.stderr)
                sys.exit(1)
            with open(args.content, "rb") as f:
                content = f.read()
            step = agent_receipt.verify_step(receipt, args.step, content, secret=args.secret)
            print(("STEP OK: " + step["message"]) if step["verified"] else ("STEP FAILED: " + step["error"]))
            if not step["verified"]:
                sys.exit(1)
        if result["verified"]:
            _hint()
            sys.exit(0)
        sys.exit(1)

    if args.receipt_command == "anchor":
        try:
            r = agent_receipt.RunReceipt.from_dict(receipt)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        if r.proof:
            print("This receipt is already anchored and carries its bundle.")
            return
        try:
            if r.proof_id is None:
                r.anchor(key=args.api_key, base_url=args.base_url, wait=args.wait)
            else:
                r.attach_bundle(key=args.api_key, base_url=args.base_url)
        except ProofLedgerError as exc:
            print(str(exc), file=sys.stderr)
            r.save(args.receipt)
            sys.exit(1)
        r.save(args.receipt)
        if r.proof:
            print(f"Anchored: proof {r.proof_id}, {r.proof.get('blockchain')} transaction {r.proof.get('tx_id')} at {r.proof.get('anchored_at')}.")
            print(f"Bundle saved into {args.receipt}. Check it offline:  verify-proof receipt verify {args.receipt}")
        else:
            print(f"Submitted: proof {r.proof_id}. The Polygon anchor usually lands within a minute; run this again to save the bundle.")
        if r.certificate_url:
            print(f"Certificate: {r.certificate_url}")


if __name__ == "__main__":
    main()
