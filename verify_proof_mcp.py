#!/usr/bin/env python3
"""verify-proof MCP server — blockchain timestamp-proof verification for AI assistants.

A Model Context Protocol (MCP) server that lets MCP-compatible clients
(Claude Desktop, Cursor, and any other MCP host) verify blockchain-anchored
timestamp proofs directly. It exposes the `verify-proof` library as tools
so an assistant can, on the user's own machine:

  - compute the SHA-256 hash of a local file (the file is never uploaded),
  - verify a local file against a blockchain-anchored proof JSON,
  - verify a known hash against inline proof data,
  - explain in plain language what a proof file asserts,
  - create a new proof by anchoring a file's hash on ProofLedger,
  - create proofs for up to 100 files in one call, check a proof's status,
    and save a proof's bundle so it verifies later without ProofLedger,
  - keep an agent run receipt (start_run_receipt, add_receipt_step,
    anchor_run_receipt, verify_run_receipt): a hash chain over the steps of an
    agent's work, anchored as one proof, so what the agent did can be proven
    later without storing what it saw.

The verification tools run entirely offline and always will: verification that
depends on the issuing service is not verification. The ProofLedger tools
(create, batch, status, bundle, anchor_run_receipt) are the exception and say
so in their own descriptions: anchoring requires a service, and they send
hashes (never files, never a step's content) to ProofLedger, with a free API
key.

Blockchain timestamping proves a file existed at a point in time by anchoring
its SHA-256 hash to a public blockchain. ProofLedger (https://proofledger.io)
anchors on Polygon; proofs from other services, and the few ProofLedger proofs
anchored on Bitcoin before 2026-10-15, may be anchored on Bitcoin through a
Merkle path. The verification tools need no account and make no network calls,
so file contents stay on the user's machine. To confirm the anchor itself, look
up the transaction on any block explorer.

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

from proofledger_api import (
    DEFAULT_BASE_URL,
    ProofLedgerError,
    get_bundle,
    get_proof,
    submit_batch,
    submit_proof,
    summarize,
)
from verify_proof import hash_file, load_proof
from verify_proof import verify_proof as _verify_proof
import agent_receipt

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


def _absolute_url(url: str | None) -> str:
    """The API returns absolute links; older responses gave a path. Accept both."""
    if not url:
        return ""
    return url if url.startswith("http") else f"{DEFAULT_BASE_URL}{url}"


def _format_result(result: dict) -> str:
    """Human-readable headline + full structured result for the model to reason over."""
    if result.get("verified"):
        headline = "VERIFIED ✓ — " + result.get(
            "message", "File matches the proof bundle."
        )
        explorer = _explorer_url(result.get("blockchain", ""), result.get("tx_id", ""))
        if explorer and explorer not in headline:
            headline += f"\nLook the transaction up to confirm the anchor: {explorer}"
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
    transmitted. SHA-256 (the default) is the algorithm ProofLedger and most
    timestamp services use. Use this to
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
    in the proof JSON. If a Merkle path is present, it computes the Merkle
    root and returns it, to compare with the root recorded in the transaction.
    Confirms a blockchain transaction reference is present. A passing result
    means the file is byte-for-byte the one the bundle was made for. The tool
    does not read the chain: the transaction (on Polygon or Bitcoin) is what
    the bundle says until someone looks it up on a block explorer, so give the
    user that link.

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


@mcp.tool()
def create_proof(file_path: str, bitcoin: bool = False, send_filename: bool = True) -> str:
    """Create a blockchain timestamp proof for a local file, via ProofLedger.

    This tool, like the batch, status and bundle tools, uses the network and
    needs an API key. Use it when the user wants to PROVE a file exists as of
    now, rather than check an existing proof. The file's SHA-256 is computed
    locally. Only that digest is sent, plus the file name unless send_filename
    is false. The file itself never leaves the machine. The hash is anchored
    on Polygon, the only chain ProofLedger
    anchors to (Bitcoin anchoring was discontinued on 2026-10-15). Each call
    counts toward the plan's monthly API allowance (Free includes 100).

    Requires a ProofLedger API key in the PROOFLEDGER_API_KEY environment
    variable. If it is missing, this returns the steps to get a free one -
    show them to the user rather than treating it as a failure.

    Args:
        file_path: Path to the file to timestamp.
        bitcoin: Deprecated. Bitcoin anchoring was discontinued on
                 2026-10-15; leave this false.
        send_filename: Send the filename as a label so the proof is findable
                       in the dashboard. Set false to send only the hash.

    Returns:
        A plain-text summary of the created proof: its id, status, and the
        URLs for its certificate and public verification page.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return f"File not found: {file_path}"

    digest = hash_file(str(path))
    try:
        proof = submit_proof(
            digest,
            filename=path.name if send_filename else None,
        )
    except ProofLedgerError as exc:
        return str(exc)
    note = (
        "Note: Bitcoin anchoring was discontinued on 2026-10-15; this proof is "
        "anchored on Polygon.\n\n" if bitcoin else ""
    )
    return note + summarize(proof)


@mcp.tool()
def create_proofs_batch(file_paths: list[str], send_filenames: bool = True) -> str:
    """Create proofs for several local files in ONE ProofLedger API call (up to 100).

    Uses the network and needs PROOFLEDGER_API_KEY, like create_proof. Each
    file is hashed locally; the hashes and the file names are sent, never the
    files. The file name is used as the external_id, so re-running on
    unchanged files returns their existing proofs. If a file changed but kept
    its name, you get its old proof back (result "exists"), and that proof does
    not match the new file: rename the file, or anchor it with create_proof.
    Polygon anchoring only.

    Args:
        file_paths: Paths of the files to timestamp, 1 to 100.
        send_filenames: Send each file's name as its label. Set false to leave
                        the label out; the names are still sent as external ids.
    """
    paths = [Path(p) for p in file_paths]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        return "File not found: " + ", ".join(missing)
    if not paths or len(paths) > 100:
        return "Give between 1 and 100 files."
    items = [
        {"sha256": hash_file(str(p)), "external_id": p.name, "filename": p.name if send_filenames else None}
        for p in paths
    ]
    try:
        r = submit_batch(items)
    except ProofLedgerError as exc:
        return str(exc)
    summary = r.get("summary", {})
    lines = [
        f"Batch submitted: {summary.get('created', 0)} created, "
        f"{summary.get('exists', 0)} already existed, {summary.get('invalid', 0)} invalid.",
        "",
    ]
    for it, p in zip(r.get("items", []), paths):
        proof = it.get("proof") or {}
        if it.get("result") in ("created", "exists"):
            lines.append(
                f"  {p.name}: proof {proof.get('id')} ({it['result']})  "
                f"{_absolute_url(proof.get('certificate_url'))}"
            )
        else:
            lines.append(f"  {p.name}: {it.get('result')} - {it.get('error', '')}")
    return "\n".join(lines)


@mcp.tool()
def get_proof_status(proof_id: int) -> str:
    """Fetch the current status of one of YOUR ProofLedger proofs by id.

    Uses the network and needs PROOFLEDGER_API_KEY. Shows whether the Polygon
    anchor has landed (usually within a minute of creation), and the Bitcoin
    record for the few proofs anchored there before 2026-10-15. For checking
    somebody else's proof, use verify_file with their bundle instead; that
    needs no key and no network.
    """
    try:
        p = get_proof(proof_id)
    except ProofLedgerError as exc:
        return str(exc)
    lines = [
        f"Proof {p.get('id')}  ({p.get('filename') or 'no filename'})",
        f"  SHA-256        : {p.get('sha256')}",
        f"  Polygon        : {p.get('polygon_status')}" + (f"  tx {p.get('chain_tx')}" if p.get("chain_tx") else ""),
    ]
    if p.get("bitcoin_txid"):
        lines.append(
            f"  Bitcoin        : {p.get('bitcoin_status')}  tx {p.get('bitcoin_txid')}"
            "  (anchored on Bitcoin before 15 October 2026)"
        )
    lines += [
        f"  Created        : {p.get('created_at')}",
        f"  Certificate    : {_absolute_url(p.get('certificate_url'))}",
    ]
    if p.get("issued_via"):
        lines.append(f"  Recorded through {p['issued_via']} \u00b7 Anchored by ProofLedger")
    return "\n".join(lines)


@mcp.tool()
def save_proof_bundle(proof_id: int, output_path: str, chain: str = "polygon") -> str:
    """Download the bundle for one of YOUR proofs and save it as a JSON file.

    Uses the network and needs PROOFLEDGER_API_KEY. The bundle is everything
    needed to verify the proof WITHOUT ProofLedger: hash, chain, transaction
    id, anchor time and, for Bitcoin, the Merkle path. Save it next to the
    file; `verify_file` (or `verify-proof verify`) then works offline, for as
    long as the blockchain exists. Before the anchor lands the bundle says
    anchored: false; fetch it again afterwards.

    Args:
        proof_id: The ProofLedger proof id.
        output_path: Where to write the JSON (e.g. song.mp3.proof.json).
        chain: "polygon" (default) or "bitcoin" for the top-level fields.
    """
    try:
        bundle = get_bundle(proof_id, chain=chain)
    except ProofLedgerError as exc:
        return str(exc)
    out = Path(output_path)
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    state = "anchored" if bundle.get("anchored") else "NOT YET ANCHORED (fetch again later)"
    return (
        f"Saved bundle for proof {proof_id} to {out} ({bundle.get('blockchain')}, {state}). "
        f"Verify offline with: verify-proof verify <file> --proof {out}"
    )


# --- agent run receipts --------------------------------------------------------
#
# File-based on purpose: every tool reads and rewrites the receipt file, so the
# server keeps no state and a run survives a restart of the MCP host.


def _load_receipt_file(receipt_path: str) -> tuple[Path, dict] | str:
    path = Path(receipt_path)
    if not path.is_file():
        return f"Receipt file not found: {receipt_path}"
    try:
        return path, json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"Could not read {receipt_path}: {exc}"


@mcp.tool()
def start_run_receipt(receipt_path: str, run_id: str, agent_name: str = "", model: str = "") -> str:
    """Start an agent run receipt: a tamper-evident record of what an agent did.

    Runs offline. Creates a receipt file (format proofledger-agent-run-receipt/1)
    with a fresh random secret and no steps. Then call add_receipt_step for each
    prompt, tool call, tool result and output, and anchor_run_receipt at the end.
    The receipt stores only SHA-256 fingerprints of each step's content (salted
    with the run secret), the step type, time and an optional short label. The
    content itself is never written to the file and never sent anywhere.

    Args:
        receipt_path: Where to create the receipt JSON (e.g. run-48213.receipt.json).
        run_id: Your id for this run, 1 to 128 characters. It becomes the proof's
                external_id, so anchoring the same run twice returns the same proof.
        agent_name: Optional name of the agent, kept in the receipt.
        model: Optional model name, kept in the receipt.
    """
    path = Path(receipt_path)
    if path.exists():
        return f"{receipt_path} already exists; choose a new path or continue it with add_receipt_step."
    agent = {k: v for k, v in (("name", agent_name), ("model", model)) if v}
    try:
        r = agent_receipt.RunReceipt(run_id, agent=agent or None)
        r.save(str(path))
    except (ValueError, OSError) as exc:
        return f"Could not start the receipt: {exc}"
    return f"Started receipt for run {r.run_id} at {path}. Add steps with add_receipt_step, then anchor_run_receipt."


@mcp.tool()
def add_receipt_step(receipt_path: str, step_type: str, content: str, label: str = "") -> str:
    """Record one step of the agent run in the receipt. Offline.

    Only the fingerprint of `content` (SHA-256 over the run secret and the
    content) is stored, with the type, the time and the label. Pass the exact
    text of the step: the prompt as received, the tool call as sent (for
    example its JSON), the tool result as returned, the output as produced.
    The same text is what a later verify_step check must be given.

    Args:
        receipt_path: The receipt file from start_run_receipt.
        step_type: prompt, tool_call, tool_result, output or note.
        content: The step's content. Never stored; only hashed.
        label: Optional, up to 120 characters, one line. It is kept in the
               receipt in clear, so keep it non-sensitive (e.g. the tool name).
    """
    loaded = _load_receipt_file(receipt_path)
    if isinstance(loaded, str):
        return loaded
    path, data = loaded
    try:
        r = agent_receipt.RunReceipt.from_dict(data)
        step = r.add_step(step_type, content, label or None)
        r.save(str(path))
    except (ValueError, OSError) as exc:
        return f"Could not add the step: {exc}"
    return f"Step {step['index']} ({step['type']}) recorded; chain head is now {r.head}."


@mcp.tool()
def anchor_run_receipt(receipt_path: str, wait_seconds: int = 120) -> str:
    """Anchor the receipt's chain head on ProofLedger and save the bundle into it.

    Uses the network and needs PROOFLEDGER_API_KEY: one API proof per run,
    counted toward the plan's monthly allowance. Only the chain head (a hash),
    the label "agent run <run_id>" and the run id as external_id are sent;
    no step content, no labels. Waits up to wait_seconds for the Polygon
    anchor (it usually lands within a minute) and then stores the proof
    bundle in the receipt, which makes it verifiable offline. If the anchor
    has not landed in time, call this again later to fetch the bundle.
    """
    loaded = _load_receipt_file(receipt_path)
    if isinstance(loaded, str):
        return loaded
    path, data = loaded
    try:
        r = agent_receipt.RunReceipt.from_dict(data)
    except ValueError as exc:
        return f"Not a usable receipt: {exc}"
    if r.proof:
        return f"Receipt {r.run_id} is already anchored (proof {r.proof_id}, {r.proof.get('blockchain')} tx {r.proof.get('tx_id')})."
    try:
        if r.proof_id is None:
            r.anchor(wait=max(0, int(wait_seconds)))
        else:
            r.attach_bundle()
    except ProofLedgerError as exc:
        r.save(str(path))
        return str(exc)
    except ValueError as exc:
        return str(exc)
    r.save(str(path))
    if r.proof:
        return (
            f"Anchored receipt {r.run_id}: proof {r.proof_id}, {r.proof.get('blockchain')} transaction "
            f"{r.proof.get('tx_id')} at {r.proof.get('anchored_at')}. Bundle saved into {path}.\n"
            f"Certificate: {r.certificate_url}\n"
            f"Anyone can check it offline: verify-proof receipt verify {path}"
        )
    return (
        f"Submitted receipt {r.run_id} as proof {r.proof_id}; the Polygon anchor had not landed within "
        f"{wait_seconds}s. Run anchor_run_receipt again in a minute to save the bundle. Certificate: {r.certificate_url}"
    )


@mcp.tool()
def verify_run_receipt(receipt_path: str, step_index: int = -1, step_content: str = "") -> str:
    """Check an agent run receipt WITHOUT ProofLedger. Offline, needs no key.

    Recomputes the hash chain from the steps, checks that it ends at the
    receipt's chain head, then checks the head against the proof bundle the
    receipt carries (hash match and a named transaction), exactly like
    verify_file does for a file. Nothing here reads the chain: confirm the
    transaction on a block explorer. Give step_index and step_content to also
    check that one step was made from that exact content (needs the receipt's
    secret, present unless the owner redacted it before sharing).
    """
    loaded = _load_receipt_file(receipt_path)
    if isinstance(loaded, str):
        return loaded
    _path, data = loaded
    result = agent_receipt.verify_receipt(data)
    headline = ("VERIFIED ✓ — " + result["message"]) if result.get("verified") else ("NOT VERIFIED ✗ — " + result.get("error", ""))
    proof = result.get("proof") or {}
    explorer = _explorer_url(proof.get("blockchain", ""), proof.get("tx_id", ""))
    if result.get("verified") and explorer:
        headline += f"\nLook the transaction up to confirm the anchor: {explorer}"
    if step_index >= 0 or step_content:
        step = agent_receipt.verify_step(data, step_index, step_content)
        headline += "\n" + (("STEP OK — " + step["message"]) if step.get("verified") else ("STEP FAILED — " + step.get("error", "")))
        result["step"] = step
    return headline + "\n\n" + json.dumps(result, indent=2)


def main() -> None:
    """Entry point — run the server over stdio (the transport MCP hosts use)."""
    mcp.run()


if __name__ == "__main__":
    main()
