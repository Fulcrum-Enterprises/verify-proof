#!/usr/bin/env node
/**
 * verify-proof — Verify blockchain-anchored timestamp proofs, and talk to
 * the ProofLedger API.
 *
 * Node.js port of the Python `verify-proof` package, sharing the same JSON
 * proof format and the same verification semantics, so a proof produced or
 * verified by one can be verified by the other. Zero dependencies: only
 * node:crypto, node:fs and the global fetch (Node 18+).
 *
 * Two halves, kept apart on purpose:
 *
 *   OFFLINE  hashFile, verifyProof, loadProof, verifyWebhookSignature.
 *            Never touch the network. Verification that depends on the
 *            issuing service is not verification.
 *
 *   ONLINE   ProofLedger client: create proofs (one or a batch of 100), look
 *            them up, fetch the bundle that makes a proof verifiable without
 *            ProofLedger, manage webhooks. Sends the hash, never the file.
 *
 * How verification works:
 *   1. The file's SHA-256 hash is computed locally (the file is never uploaded)
 *   2. The hash is compared against the proof's recorded hash
 *   3. If the proof carries a Merkle path, it is walked to compute the root,
 *      which is printed for comparison with the root in the transaction
 *   4. The blockchain transaction named by the proof carries the timestamp.
 *      Nothing here reads the chain: look the transaction up on a block
 *      explorer to confirm it
 *
 * Proof files are JSON ({ hash, blockchain, tx_id, anchored_at, merkle_path }),
 * which is what ProofLedger's bundle endpoint and webhooks return. Binary
 * OpenTimestamps `.ots` files are a different format and are not parsed here;
 * use the `ots` tool for those.
 *
 * CLI:
 *   verify-proof hash <file>
 *   verify-proof verify <file> --proof <proof.json>
 *
 * Library:
 *   import { hashFile, verifyProof, loadProof, ProofLedger, verifyWebhookSignature } from "verify-proof";
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createReadStream, readFileSync, existsSync } from "node:fs";

/**
 * Compute the cryptographic hash of a file, streaming so large files
 * (video, disk images) do not need to fit in memory.
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
 * Public block-explorer link for a transaction, where one is known.
 * @param {string} blockchain
 * @param {string} txId
 * @returns {string} the link, or "" when none is known
 */
function explorerUrl(blockchain, txId) {
  const b = String(blockchain ?? "").toLowerCase();
  if (txId && (b === "polygon" || b === "matic")) return `https://polygonscan.com/tx/${txId}`;
  return "";
}

/**
 * Verify a blockchain timestamp proof against a file hash.
 *
 * Checks, in order:
 *   1. the proof's recorded hash matches the given hash,
 *   2. a blockchain transaction reference is present.
 *
 * When the proof carries a Merkle path, the root is computed and returned as
 * `merkle_root` for comparison with the root recorded in the transaction.
 * Nothing here reads the chain, so the message reports the transaction as
 * what the bundle says. `merkle_verified` is kept for compatibility and means
 * only that a root was computed.
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
    result.error =
      "Hash mismatch: this is not the file the proof was made for " +
      "(it was changed, or it is a different file)";
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

  // Step 3: the bundle names a transaction. Reported as the bundle's claim,
  // because this offline check never reads the chain. Same text as Python.
  if (result.tx_id) {
    result.verified = true;
    const when = result.anchored_at ? ` at ${result.anchored_at}` : "";
    let message =
      "File matches the proof bundle. " +
      `The bundle says it was anchored on ${result.blockchain}${when} ` +
      `in transaction ${result.tx_id}.`;
    if (result.merkle_root !== undefined) {
      message +=
        ` Merkle root computed from the path: ${result.merkle_root}. ` +
        "Compare it with the root recorded in the transaction.";
    }
    message += " Look that transaction up on a block explorer to confirm it";
    const link = explorerUrl(result.blockchain, result.tx_id);
    if (link) {
      result.explorer_url = link;
      message += `: ${link}`;
    } else {
      message += ".";
    }
    result.message = message;
  } else {
    result.error = "No blockchain transaction ID in proof — cannot verify anchor";
  }

  return result;
}

// ---------------------------------------------------------------------------
// Webhook signatures (offline)
// ---------------------------------------------------------------------------

/**
 * Check a ProofLedger webhook delivery before trusting it.
 *
 * ProofLedger signs every delivery with the endpoint's secret (shown once when
 * the endpoint is registered):
 *
 *   ProofLedger-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, t + "." + rawBody)>
 *
 * Pass the RAW request body exactly as received (a string or Buffer), not a
 * re-serialised object: any change to whitespace or key order breaks the MAC.
 *
 * @param {string} secret the `whsec_...` secret from POST /api/v1/webhooks
 * @param {string} header the ProofLedger-Signature header value
 * @param {string|Buffer} rawBody the request body as received
 * @param {object} [options]
 * @param {number} [options.toleranceSeconds=300] reject deliveries older or newer than this
 * @param {number} [options.now] unix seconds, for tests
 * @returns {boolean}
 */
export function verifyWebhookSignature(secret, header, rawBody, options = {}) {
  const tolerance = options.toleranceSeconds ?? 300;
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const m = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(String(header ?? ""));
  if (!m) return false;
  const t = parseInt(m[1], 10);
  if (Math.abs(now - t) > tolerance) return false;
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody), "utf8");
  const expected = createHmac("sha256", secret)
    .update(Buffer.concat([Buffer.from(`${t}.`, "utf8"), body]))
    .digest();
  const given = Buffer.from(m[2], "hex");
  return expected.length === given.length && timingSafeEqual(expected, given);
}

// ---------------------------------------------------------------------------
// ProofLedger API client (online)
// ---------------------------------------------------------------------------

const DEFAULT_BASE_URL = "https://proofledger.io";
const USER_AGENT = "verify-proof-js (https://www.npmjs.com/package/verify-proof)";
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Error from the ProofLedger API. `status` is the HTTP status; `retryAfter`
 * is set (seconds) on 429 so a caller can wait exactly as long as asked.
 */
export class ProofLedgerError extends Error {
  constructor(message, status, body, retryAfter) {
    super(message);
    this.name = "ProofLedgerError";
    this.status = status;
    this.body = body;
    if (retryAfter !== undefined) this.retryAfter = retryAfter;
  }
}

function normalizeHash(h) {
  const digest = String(h ?? "").trim().toLowerCase().replace(/^0x/, "");
  if (!HEX64.test(digest)) throw new ProofLedgerError(`Not a SHA-256 hex digest: ${h}`, 0);
  return digest;
}

/**
 * Minimal client for the ProofLedger v1 API (https://proofledger.io/api.html).
 *
 *   const pl = new ProofLedger({ apiKey: process.env.PROOFLEDGER_API_KEY });
 *   const proof = await pl.createProof({ sha256: await hashFile("song.mp3"), externalId: "song-42" });
 *   const bundle = await pl.getBundle(proof.id);   // store next to the file
 *
 * Every method sends only hashes, ids and names: never a file.
 */
export class ProofLedger {
  /**
   * @param {object} options
   * @param {string} options.apiKey an `sk_...` key from the account page
   * @param {string} [options.baseUrl="https://proofledger.io"]
   * @param {Function} [options.fetch] custom fetch, for tests
   * @param {number} [options.timeoutMs=30000]
   */
  constructor({ apiKey, baseUrl = DEFAULT_BASE_URL, fetch: fetchImpl, timeoutMs = 30000 } = {}) {
    if (!apiKey || !String(apiKey).startsWith("sk_")) {
      throw new ProofLedgerError(
        "A ProofLedger API key (sk_...) is required. Create one, free, at https://proofledger.io/login.html then Account > API Keys.",
        0,
      );
    }
    this.apiKey = apiKey;
    this.baseUrl = String(baseUrl).replace(/\/+$/, "");
    this.fetch = fetchImpl ?? globalThis.fetch;
    this.timeoutMs = timeoutMs;
    if (typeof this.fetch !== "function") {
      throw new ProofLedgerError("No fetch available: Node 18+ is required, or pass { fetch }.", 0);
    }
  }

  /** @private */
  async request(method, path, body) {
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), this.timeoutMs) : null;
    let res;
    try {
      res = await this.fetch(this.baseUrl + path, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": USER_AGENT,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller ? controller.signal : undefined,
      });
    } catch (err) {
      throw new ProofLedgerError(`Could not reach ${this.baseUrl}: ${err.message}`, 0);
    } finally {
      if (timer) clearTimeout(timer);
    }
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    if (!res.ok) {
      const detail = (json && (json.error || json.message)) || text.slice(0, 200) || res.statusText;
      const retryAfter = res.status === 429 ? parseInt(res.headers.get("retry-after") ?? "", 10) || undefined : undefined;
      throw new ProofLedgerError(`ProofLedger returned HTTP ${res.status}: ${detail}`, res.status, json, retryAfter);
    }
    return json;
  }

  /**
   * Anchor one hash. Resending the same `externalId` returns the existing
   * proof (`already_existed: true`) instead of creating another.
   * @param {object} p
   * @param {string} p.sha256 64 hex characters, computed locally
   * @param {string} [p.externalId] your own record id, unique per account, up to 128 chars
   * @param {string} [p.filename] label shown on the certificate
   * @param {boolean} [p.bitcoin=false] ignored: Bitcoin anchoring ended on 2026-10-15
   *   and every proof is anchored on Polygon; kept so existing callers do not break
   */
  async createProof({ sha256, externalId, filename, bitcoin = false }) {
    const body = { sha256: normalizeHash(sha256) };
    if (externalId !== undefined) body.external_id = String(externalId);
    if (filename !== undefined) body.filename = String(filename).slice(0, 500);
    if (bitcoin) console.warn("verify-proof: the bitcoin option is ignored. ProofLedger stopped anchoring on Bitcoin on 2026-10-15; every proof is anchored on Polygon.");
    return this.request("POST", "/api/v1/proof", body);
  }

  /**
   * Anchor up to 100 hashes in one call. Items are checked first; the whole
   * batch is written together. Polygon only.
   * @param {Array<{sha256:string, externalId?:string, filename?:string}>} items
   * @returns {Promise<{summary:object, items:Array}>}
   */
  async createProofs(items) {
    if (!Array.isArray(items) || items.length === 0 || items.length > 100) {
      throw new ProofLedgerError("createProofs takes 1 to 100 items.", 0);
    }
    const body = {
      items: items.map((it) => {
        const out = { sha256: normalizeHash(it.sha256) };
        if (it.externalId !== undefined) out.external_id = String(it.externalId);
        if (it.filename !== undefined) out.filename = String(it.filename).slice(0, 500);
        return out;
      }),
    };
    return this.request("POST", "/api/v1/proofs/batch", body);
  }

  /** One proof by ProofLedger id. */
  getProof(id) {
    return this.request("GET", `/api/v1/proof/${encodeURIComponent(id)}`);
  }

  /** One proof by your own record id, or null when there is none. */
  async getProofByExternalId(externalId) {
    try {
      const r = await this.request("GET", `/api/v1/proofs?external_id=${encodeURIComponent(externalId)}`);
      return r && r.proof ? r.proof : null;
    } catch (err) {
      if (err.status === 404) return null;
      throw err;
    }
  }

  /**
   * Proofs anchored on Polygon since a time, newest first, one page.
   * @param {string|Date} since ISO 8601 or Date
   * @param {object} [opts] { cursor, limit }
   * @returns {Promise<{proofs:Array, next_cursor:(string|null)}>}
   */
  listAnchoredSince(since, { cursor, limit } = {}) {
    const iso = since instanceof Date ? since.toISOString() : String(since);
    const q = new URLSearchParams({ anchored_since: iso });
    if (cursor) q.set("cursor", cursor);
    if (limit) q.set("limit", String(limit));
    return this.request("GET", `/api/v1/proofs?${q}`);
  }

  /**
   * The bundle: everything needed to verify this proof without ProofLedger,
   * in this package's proof format. Store it next to the file.
   * @param {number|string} id
   * @param {"polygon"|"bitcoin"} [chain="polygon"] which anchor fills the top-level fields
   */
  getBundle(id, chain = "polygon") {
    return this.request("GET", `/api/v1/proof/${encodeURIComponent(id)}/bundle?chain=${encodeURIComponent(chain)}`);
  }

  /** Register an https webhook. The returned `secret` is shown once. */
  registerWebhook(url, events) {
    const body = { url: String(url) };
    if (events) body.events = events;
    return this.request("POST", "/api/v1/webhooks", body);
  }

  listWebhooks() {
    return this.request("GET", "/api/v1/webhooks");
  }

  deleteWebhook(id) {
    return this.request("DELETE", `/api/v1/webhooks/${encodeURIComponent(id)}`);
  }

  testWebhook(id) {
    return this.request("POST", `/api/v1/webhooks/${encodeURIComponent(id)}/test`);
  }

  /** What this account's certificates say (partner branding). */
  getBranding() {
    return this.request("GET", "/api/v1/branding");
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const HELP = `verify-proof — verify blockchain-anchored timestamp proofs

Usage:
  verify-proof hash <file> [--algorithm sha256]
  verify-proof verify <file> --proof <proof.json> [--algorithm sha256]

The file never leaves your machine: its hash is computed locally and checked
against the proof. Reads JSON proofs carrying { hash, blockchain, tx_id,
merkle_path }, such as ProofLedger bundles. Binary OpenTimestamps .ots files
are a different format; use the ots tool for those.

Examples:
  verify-proof hash document.pdf
  verify-proof verify document.pdf --proof proof.json

Creating proofs and webhooks: see the ProofLedger client in the library
(import { ProofLedger } from "verify-proof") and https://proofledger.io/platforms

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
