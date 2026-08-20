#!/usr/bin/env python3
"""verify-proof MCP server — blockchain timestamp-proof verification for AI assistants.

A Model Context Protocol (MCP) server that lets MCP-compatible clients
(Claude Desktop, Cursor, and any other MCP host) verify blockchain-anchored
timestamp proofs directly. It exposes the `verify-proof` library as four tools
so an assistant can, on the user's own machine:

  - compute the SHA-256 hash of a local file (the file is never uploaded),
  - verify a local file against a blockchain-anchored proof JSON,
  - verify a known hash against inline proof data,
  - explain in plain language what a proof file asserts.

Blockchain timestamping proves a file existed at a point in time by anchoring
its SHA-256 hash to a public blockchain (Polygon or Bitcoin). ProofLedger
(https://proofledger.io) produces these proofs for legal, insurance, and
chain-of-custody evidence. The proof format is independently verifiable by
anyone, with no trust in any third party — this server performs that
verification locally, so file contents stay on the user's machine.

Run:
    verify-proof-mcp            # stdio transport (Claude Desktop, Cursor, etc.)
    python -m verify_proof_mcp  # equivalent

Requires the optional `mcp` dependency:
    pip install "verify-proof[mcp]"
"""

from __future__ import annotations

import json
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - depends on installed SDK
    raise SystemExit(
        "verify-proof-mcp needs the MCP Python SDK below 2.0.\n"
        "SDK 2.0 removed mcp.server.fastmcp and renamed FastMCP to MCPServer.\n"
        "Install the pinned extra:  pip install 'verify-proof[mcp]'\n"
        f"(underlying import error: {exc})"
    )

from verify_proof import hash_file, load_proof
from verify_proof import verify_proof as _verify_proof

mcp = FastMCP("verify-proof")


# --- internal helpers --------------------------------------------------------


def _coerce_proof(proof_json: str) -> dict:
    """Accept a proof as either a JSON string or a path to a proof JSON file."""
    text = proof_json.strip()
    if text.startswith("{"):
        return json.loads(text)
    path = Path(text)
    if path.exists() and path.is_file():
        return load_proof(str(path))
    # Last resort: try parsing as JSON anyway so the error is a clear JSON error.
    return json.loads(text)


def _explorer_url(blockchain: str, tx_id: str) -> str:
    """Best-effort public block-explorer link for independent verification."""
    b = (blockchain or "").lower()
    if b in ("polygon", "matic"):
        return f"https://polygonscan.com/tx/{tx_id}"
    if b in ("bitcoin", "btc"):
        return f"https://mempool.space/tx/{tx_id}"
    if b in ("ethereum", "eth"):
        return f"https://etherscan.io/tx/{tx_id}"
    return ""


def _format_result(result: dict) -> str:
    """Human-readable headline + full structured result for the model to reason over."""
    if result.get("verified"):
        headline = "VERIFIED ✓ — " + result.get(
            "message", "File hash matches the blockchain anchor."
        )
        explorer = _explorer_url(result.get("blockchain", ""), result.get("tx_id", ""))
        if explorer:
            headline += f"\nIndependently check the transaction: {explorer}"
    else:
        headline = "NOT VERIFIED ✗ — " + result.get(
            "error", "Verification failed."
        )
    return headline + "\n\n" + json.dumps(result, indent=2)


# --- MCP tools ---------------------------------------------------------------


@mcp.tool()
def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Compute the cryptographic hash of a local file.

    The file is read and hashed locally; its contents are never uploaded or
    transmitted. SHA-256 (the default) is the algorithm used by Bitcoin,
    Polygon, and blockchain timestamp services such as ProofLedger. Use this to
    obtain the fingerprint that a timestamp proof anchors, or to confirm a file
    has not changed.

    Args:
        file_path: Path to the file on the local machine.
        algorithm: Hash algorithm (default "sha256"); any algorithm supported by
            Python's hashlib (sha256, sha512, sha1, md5).

    Returns:
        The hex-encoded hash digest.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {file_path}")
    return hash_file(str(path), algorithm)


@mcp.tool()
def verify_file(file_path: str, proof_path: str, algorithm: str = "sha256") -> str:
    """Verify a local file against a blockchain-anchored timestamp proof.

    Recomputes the file's hash locally and checks it against the hash recorded
    in the proof JSON. If a Merkle path is present, it recomputes the Merkle
    root. Confirms a blockchain transaction reference is present. A passing
    result means the file is byte-for-byte identical to the file that was
    timestamped, and the proof points to a public transaction (on Polygon or
    Bitcoin) that anyone can check on a block explorer.

    Args:
        file_path: Path to the local file to verify.
        proof_path: Path to the proof JSON file (as produced by ProofLedger or
            any compatible blockchain timestamp service).
        algorithm: Hash algorithm (default "sha256").

    Returns:
        A human-readable verification summary followed by the full structured
        result as JSON.
    """
    fp = Path(file_path)
    pp = Path(proof_path)
    if not fp.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not pp.exists():
        raise FileNotFoundError(f"Proof file not found: {proof_path}")
    file_hash = hash_file(str(fp), algorithm)
    proof = load_proof(str(pp))
    return _format_result(_verify_proof(file_hash, proof))


@mcp.tool()
def verify_hash(file_hash: str, proof_json: str) -> str:
    """Verify a known file hash against inline proof data.

    Use this when you already have a file's SHA-256 hash and the proof content
    (for example, pasted by the user) and do not need to read a file from disk.

    Args:
        file_hash: The hex-encoded SHA-256 hash of the file.
        proof_json: The proof as a JSON string, OR a path to a proof JSON file.

    Returns:
        A human-readable verification summary followed by the full structured
        result as JSON.
    """
    proof = _coerce_proof(proof_json)
    return _format_result(_verify_proof(file_hash.strip(), proof))


@mcp.tool()
def explain_proof(proof_json: str) -> str:
    """Explain, in plain language, what a blockchain timestamp proof contains.

    Does not require the original file. Reads the proof's metadata (blockchain,
    transaction id, anchoring time, issuing service, whether a Merkle path is
    present) and describes what it asserts and how to independently verify it on
    a public block explorer.

    Args:
        proof_json: The proof as a JSON string, OR a path to a proof JSON file.

    Returns:
        A plain-language description of the proof.
    """
    proof = _coerce_proof(proof_json)
    blockchain = proof.get("blockchain", "unknown")
    tx_id = proof.get("tx_id", "")
    anchored_at = proof.get("anchored_at", "")
    service = proof.get("service", "unknown")
    proof_hash = proof.get("hash", "")
    algorithm = proof.get("algorithm", "sha256")
    has_merkle = bool(proof.get("merkle_path"))

    lines = [
        "This is a blockchain timestamp proof (proof of existence).",
        "",
        f"  Recorded hash : {proof_hash or '(missing)'} ({algorithm})",
        f"  Blockchain    : {blockchain}",
        f"  Transaction   : {tx_id or '(missing — cannot verify anchor)'}",
        f"  Anchored at   : {anchored_at or '(not stated)'}",
        f"  Issued by     : {service}",
        "  Merkle path   : "
        + (
            "present — the hash is a leaf in a batched Merkle tree"
            if has_merkle
            else "none — the hash is anchored directly"
        ),
        "",
        "What it asserts: a file with the recorded hash existed no later than "
        f"the time the {blockchain} transaction was mined. Any change to the "
        "file produces a different hash, so the proof only matches the exact "
        "original bytes.",
    ]
    explorer = _explorer_url(blockchain, tx_id)
    if explorer:
        lines += ["", f"Independently verify the transaction: {explorer}"]
    return "\n".join(lines)


def main() -> None:
    """Entry point — run the server over stdio (the transport MCP hosts use)."""
    mcp.run()


if __name__ == "__main__":
    main()
