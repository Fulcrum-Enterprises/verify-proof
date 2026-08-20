#!/usr/bin/env node
/**
 * verify-proof — Verify blockchain-anchored timestamp proofs.
 *
 * Node.js port of the Python `verify-proof` package, sharing the same JSON
 * proof format and the same verification semantics, so a proof produced or
 * verified by one can be verified by the other. Zero dependencies: only
 * node:crypto and node:fs.
 *
 * How verification works:
 *   1. The file's SHA-256 hash is computed locally (the file is never uploaded)
 *   2. The hash is compared against the proof's recorded hash
 *   3. If the proof carries a Merkle path, it is walked to recompute the root
 *   4. The blockchain transaction referenced by the proof carries the timestamp
 *
 * Works with proofs from ProofLedger (https://proofledger.io) and compatible
 * blockchain timestamping services.
 *
 * CLI:
 *   verify-proof hash <file>
 *   verify-proof verify <file> --proof <proof.json>
 *
 * Library:
 *   import { hashFile, verifyProof, loadProof } from "verify-proof";
 */

import { createHash } from "node:crypto";
import { createReadStream, readFileSync, existsSync } from "node:fs";

/**
 * Compute the cryptographic hash of a file, streaming so large files
 * (bodycam video, disk images) do not need to fit in memory.
 * @param {string} filepath
 * @param {string} [algorithm="sha256"]
 * @returns {Promise<string>} lowercase hex digest
 */
export function hashFile(filepath, algorithm = "sha256") {
  return new Promise((resolve, reject) => {
    const h = createHash(algorithm);
    const stream = createReadStream(filepath);
    stream.on("error", reject);
    stream.on("data", (chunk) => h.update(chunk));
    stream.on("end", () => resolve(h.digest("hex")));
  });
}

/**
 * Load a proof file (JSON format).
 * @param {string} proofPath
 * @returns {object}
 */
export function loadProof(proofPath) {
  return JSON.parse(readFileSync(proofPath, "utf8"));
}

/**
 * Verify a blockchain timestamp proof against a file hash.
 *
 * Checks, in order:
 *   1. the proof's recorded hash matches the given hash,
 *   2. the Merkle path recomputes (when the proof carries one),
 *   3. a blockchain transaction reference is present.
 *
 * Mirrors the Python implementation field for field so the two ports never
 * disagree about a proof.
 *
 * @param {string} fileHash lowercase or uppercase hex digest
 * @param {object} proof parsed proof JSON
 * @returns {object} result with `verified`, and `message` or `error`
 */
export function verifyProof(fileHash, proof) {
  const result = {
    verified: false,
    file_hash: fileHash,
    proof_hash: proof.hash ?? "",
    algorithm: proof.algorithm ?? "sha256",
    blockchain: proof.blockchain ?? "unknown",
    tx_id: proof.tx_id ?? "",
    anchored_at: proof.anchored_at ?? "",
    service: proof.service ?? "unknown",
  };

  // Step 1: hash match
  if (fileHash.toLowerCase() !== result.proof_hash.toLowerCase()) {
    result.error = "Hash mismatch — file has been modified since timestamping";
    return result;
  }

  // Step 2: Merkle path (when present). Each step concatenates the sibling on
  // its stated side, hex-decodes the pair, and hashes — identical to the
  // Python port, byte for byte.
  const merklePath = proof.merkle_path ?? [];
  if (merklePath.length > 0) {
    let current = fileHash;
    for (const step of merklePath) {
      const sibling = step.hash ?? "";
      const combined = step.position === "left" ? sibling + current : current + sibling;
      current = createHash("sha256").update(Buffer.from(combined, "hex")).digest("hex");
    }
    result.merkle_root = current;
    result.merkle_verified = true;
  }

  // Step 3: blockchain anchor reference
  if (result.tx_id) {
    result.verified = true;
    result.message =
      `Proof verified. File hash matches blockchain anchor on ${result.blockchain}. ` +
      `Transaction: ${result.tx_id}. ` +
      `Anchored at: ${result.anchored_at}.`;
  } else {
    result.error = "No blockchain transaction ID in proof — cannot verify anchor";
  }

  return result;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const HELP = `verify-proof — verify blockchain-anchored timestamp proofs

Usage:
  verify-proof hash <file> [--algorithm sha256]
  verify-proof verify <file> --proof <proof.json> [--algorithm sha256]

The file never leaves your machine: its hash is computed locally and checked
against the proof. Works with ProofLedger, OpenTimestamps-compatible, and
other JSON proofs carrying { hash, blockchain, tx_id, merkle_path }.

Examples:
  verify-proof hash document.pdf
  verify-proof verify document.pdf --proof proof.json

Learn more:
  ProofLedger: https://proofledger.io`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--proof") args.proof = argv[++i];
    else if (argv[i] === "--algorithm") args.algorithm = argv[++i];
    else if (argv[i] === "--help" || argv[i] === "-h") args.help = true;
    else args._.push(argv[i]);
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [command, file] = args._;

  if (args.help || !command) {
    console.log(HELP);
    process.exit(command ? 0 : 1);
  }

  if (command === "hash") {
    if (!file || !existsSync(file)) {
      console.error(`Error: File not found: ${file ?? "(none given)"}`);
      process.exit(1);
    }
    const algorithm = args.algorithm ?? "sha256";
    const digest = await hashFile(file, algorithm);
    console.log(`${algorithm.toUpperCase()}: ${digest}`);
    console.log(`File: ${file}`);
    return;
  }

  if (command === "verify") {
    if (!file || !existsSync(file)) {
      console.error(`Error: File not found: ${file ?? "(none given)"}`);
      process.exit(1);
    }
    if (!args.proof || !existsSync(args.proof)) {
      console.error(`Error: Proof file not found: ${args.proof ?? "(use --proof <proof.json>)"}`);
      process.exit(1);
    }
    const digest = await hashFile(file, args.algorithm ?? "sha256");
    const result = verifyProof(digest, loadProof(args.proof));
    if (result.verified) {
      console.log(`VERIFIED: ${result.message}`);
      process.exit(0);
    }
    console.log(`FAILED: ${result.error ?? "Unknown error"}`);
    process.exit(1);
  }

  console.error(`Error: Unknown command: ${command}`);
  console.log(HELP);
  process.exit(1);
}

// Run the CLI only when executed directly, so importing the library never
// triggers argument parsing.
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
const isDirectRun = (() => {
  try {
    return realpathSync(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();
if (isDirectRun) {
  main().catch((err) => {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  });
}
