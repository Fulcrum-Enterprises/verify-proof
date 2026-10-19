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
 * Agent run receipts (format proofledger-agent-run-receipt/1): a hash chain
 * over the steps of an agent's work, anchored as one proof, so what the agent
 * did can be proven later without storing what it saw. Same rule as the
 * Python package's agent_receipt module, so either port verifies the other's
 * receipts. See RunReceipt, verifyReceipt and verifyStep below.
 *
 * CLI:
 *   verify-proof hash <file>
 *   verify-proof verify <file> --proof <proof.json>
 *   verify-proof receipt verify <receipt.json> [--step N --content <file> --secret <hex>]
 *   verify-proof receipt show <receipt.json>
 *   verify-proof receipt anchor <receipt.json> [--wait 120]     (needs PROOFLEDGER_API_KEY)
 *
 * Library:
 *   import { hashFile, verifyProof, loadProof, ProofLedger, verifyWebhookSignature,
 *            RunReceipt, verifyReceipt, verifyStep } from "verify-proof";
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createReadStream, readFileSync, writeFileSync, existsSync } from "node:fs";

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

Agent run receipts (offline unless noted):
  verify-proof receipt verify run.receipt.json [--step N --content file]
  verify-proof receipt show run.receipt.json
  verify-proof receipt anchor run.receipt.json      (needs PROOFLEDGER_API_KEY)

Learn more:
  ProofLedger: https://proofledger.io`;

// ---------------------------------------------------------------------------
// Agent run receipts
//
// chain_start = SHA-256(secret bytes)
// link_i      = SHA-256(utf8(prev + "\n" + index + "\n" + type + "\n" + at + "\n" + fingerprint + "\n" + label))
// chain_head  = the last link (chain_start with no steps)
// fingerprint = SHA-256(secret bytes + content bytes)
//
// Only the fingerprints, types, times and optional short labels are written to
// the receipt; content never is. Remove `secret` before sharing a receipt and
// the chain still verifies, but nothing in it can be guessed.
// ---------------------------------------------------------------------------

export const RECEIPT_FORMAT = "proofledger-agent-run-receipt/1";
export const STEP_TYPES = ["prompt", "tool_call", "tool_result", "output", "note"];
const LABEL_MAX = 120;

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}
function contentBytes(content) {
  if (Buffer.isBuffer(content)) return content;
  if (content instanceof Uint8Array) return Buffer.from(content);
  return Buffer.from(String(content), "utf8");
}
function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
function requireSecret(secret) {
  if (!HEX64.test(String(secret ?? ""))) throw new Error("secret must be 64 hex characters (32 random bytes)");
  return secret;
}

/** SHA-256 over the run secret and a step's content. Pure computation. */
export function stepFingerprint(secret, content) {
  return sha256Hex(Buffer.concat([Buffer.from(requireSecret(secret), "hex"), contentBytes(content)]));
}
export function chainStart(secret) {
  return sha256Hex(Buffer.from(requireSecret(secret), "hex"));
}
export function chainLink(prev, index, type, at, fingerprint, label = "") {
  return sha256Hex(Buffer.from(`${prev}\n${index}\n${type}\n${at}\n${fingerprint}\n${label}`, "utf8"));
}
/** Recompute the chain head from chain_start and the steps as written. */
export function computeChainHead(start, steps) {
  let current = start;
  for (const s of steps) current = chainLink(current, Number(s.index), String(s.type), String(s.at ?? ""), String(s.fingerprint), String(s.label ?? ""));
  return current;
}

/**
 * Build a receipt step by step, then anchor its chain head.
 *
 *   const r = new RunReceipt("support-ticket-48213", { agent: { name: "support-bot" } });
 *   r.prompt(customerMessage, { label: "customer message" });
 *   r.toolCall(JSON.stringify(call), { label: "lookup_order" });
 *   r.toolResult(resultText);
 *   r.output(reply, { label: "reply sent" });
 *   await r.anchor(new ProofLedger({ apiKey }));   // one API proof; waits for the anchor
 *   r.save("run-48213.receipt.json");
 */
export class RunReceipt {
  constructor(runId, { agent, secret, startedAt } = {}) {
    runId = String(runId ?? "").trim();
    if (!runId || runId.length > 128) throw new Error("runId must be 1 to 128 characters");
    this.runId = runId;
    this.agent = agent ? { ...agent } : null;
    this.secret = requireSecret(secret ?? randomBytes(32).toString("hex"));
    this.startedAt = startedAt ?? nowIso();
    this.finishedAt = null;
    this.steps = [];
    this.proof = null;
    this.proofId = null;
    this.certificateUrl = null;
    this.verificationUrl = null;
  }

  addStep(type, content, { label, at } = {}) {
    if (this.proof !== null || this.proofId !== null) throw new Error("this receipt is anchored; start a new run for more steps");
    if (!STEP_TYPES.includes(type)) throw new Error(`step type must be one of ${STEP_TYPES.join(", ")}`);
    if (label !== undefined && label !== null) {
      label = String(label).trim();
      if (label.length > LABEL_MAX) throw new Error(`label is over ${LABEL_MAX} characters; labels are kept in the receipt, so keep them short and non-sensitive`);
      if (label.includes("\n")) throw new Error("label must be one line");
    }
    const step = { index: this.steps.length, type, at: at ?? nowIso(), fingerprint: stepFingerprint(this.secret, content) };
    if (label) step.label = label;
    this.steps.push(step);
    return step;
  }
  prompt(content, opts) { return this.addStep("prompt", content, opts); }
  toolCall(content, opts) { return this.addStep("tool_call", content, opts); }
  toolResult(content, opts) { return this.addStep("tool_result", content, opts); }
  output(content, opts) { return this.addStep("output", content, opts); }
  note(content, opts) { return this.addStep("note", content, opts); }

  get chainStart() { return chainStart(this.secret); }
  get head() { return computeChainHead(this.chainStart, this.steps); }
  finish(at) { if (this.finishedAt === null) this.finishedAt = at ?? nowIso(); }

  /**
   * Anchor the chain head on ProofLedger: one API proof. Sends only the head,
   * the label "agent run <runId>" and the run id as external_id. Waits up to
   * `wait` seconds for the Polygon anchor, then stores the bundle; with
   * wait 0 it returns at once and attachBundle() finishes the job later.
   * @param {ProofLedger} client
   */
  async anchor(client, { wait = 120, poll = 5 } = {}) {
    if (this.steps.length === 0) throw new Error("a receipt needs at least one step before it is anchored");
    this.finish();
    const proof = await client.createProof({ sha256: this.head, filename: `agent run ${this.runId}`, externalId: this.runId });
    this.proofId = Number(proof.id);
    this.certificateUrl = absolute(proof.certificate_url, client.baseUrl);
    this.verificationUrl = absolute(proof.verification_url, client.baseUrl);
    const deadline = Date.now() + Math.max(0, wait) * 1000;
    let status = String(proof.polygon_status ?? "").toUpperCase();
    while (status !== "ANCHORED") {
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      await new Promise((r) => setTimeout(r, Math.min(Math.max(1, poll) * 1000, remaining)));
      status = String((await client.getProof(this.proofId)).polygon_status ?? "").toUpperCase();
    }
    if (status === "ANCHORED") await this.attachBundle(client);
    return proof;
  }

  /** Fetch the proof bundle for an anchored receipt and keep it inside. */
  async attachBundle(client) {
    if (this.proofId === null) throw new Error("anchor() first");
    const bundle = await client.getBundle(this.proofId);
    if (!bundle.tx_id) throw new ProofLedgerError("The anchor has not landed yet; try attachBundle() again in a minute.", 0);
    this.proof = bundle;
    return bundle;
  }

  toObject({ includeSecret = true } = {}) {
    const out = { format: RECEIPT_FORMAT, run_id: this.runId, started_at: this.startedAt, finished_at: this.finishedAt };
    if (this.agent) out.agent = this.agent;
    if (includeSecret) out.secret = this.secret;
    out.chain_start = this.chainStart;
    out.steps = this.steps.map((s) => ({ ...s }));
    out.chain_head = this.head;
    if (this.proofId !== null) {
      out.proof_id = this.proofId;
      out.certificate_url = this.certificateUrl;
      out.verification_url = this.verificationUrl;
    }
    out.proof = this.proof;
    return out;
  }
  save(path, opts) { writeFileSync(path, JSON.stringify(this.toObject(opts), null, 2) + "\n"); }

  static fromObject(data) {
    if (!data || data.format !== RECEIPT_FORMAT) throw new Error(`not a ${RECEIPT_FORMAT} receipt`);
    if (!data.secret) throw new Error("this receipt has no secret, so steps cannot be added or checked against content; verifyReceipt() still works");
    const r = new RunReceipt(data.run_id, { agent: data.agent, secret: data.secret, startedAt: data.started_at });
    r.finishedAt = data.finished_at ?? null;
    r.steps = (data.steps ?? []).map((s) => ({ ...s }));
    r.proofId = data.proof_id ?? null;
    r.certificateUrl = data.certificate_url ?? null;
    r.verificationUrl = data.verification_url ?? null;
    r.proof = data.proof ?? null;
    if (r.chainStart !== data.chain_start) throw new Error("chain_start does not match the secret");
    if (r.head !== data.chain_head) throw new Error("chain_head does not match the steps");
    return r;
  }
  static load(path) { return RunReceipt.fromObject(JSON.parse(readFileSync(path, "utf8"))); }
}

function absolute(url, baseUrl) {
  if (!url) return null;
  return String(url).startsWith("/") ? `${String(baseUrl).replace(/\/+$/, "")}${url}` : String(url);
}

/**
 * Check a receipt without ProofLedger: structure, chain, then the bundle.
 * `verified` is true only when the chain recomputes AND the bundle names a
 * transaction for that head. Mirrors agent_receipt.verify_receipt in Python.
 */
export function verifyReceipt(receipt) {
  const result = { verified: false, chain_ok: false, anchored: false, steps: 0 };
  if (!receipt || typeof receipt !== "object" || receipt.format !== RECEIPT_FORMAT) {
    result.error = `Not a ${RECEIPT_FORMAT} receipt`;
    return result;
  }
  const { chain_start: start, chain_head: head, steps, secret } = receipt;
  if (!HEX64.test(String(start ?? "")) || !HEX64.test(String(head ?? "")) || !Array.isArray(steps)) {
    result.error = "Receipt is missing chain_start, chain_head or steps";
    return result;
  }
  if (secret !== undefined && secret !== null) {
    if (!HEX64.test(String(secret)) || chainStart(secret) !== start) {
      result.error = "chain_start does not match the secret";
      return result;
    }
  }
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    if (!s || typeof s !== "object" || s.index !== i) { result.error = `Step ${i} is out of order or missing`; return result; }
    if (!STEP_TYPES.includes(s.type) || !HEX64.test(String(s.fingerprint ?? ""))) { result.error = `Step ${i} has an unknown type or a bad fingerprint`; return result; }
  }
  result.steps = steps.length;
  result.chain_head = head;
  if (computeChainHead(start, steps) !== head) {
    result.error = "Chain mismatch: the steps do not add up to chain_head (a step was changed, dropped or reordered)";
    return result;
  }
  result.chain_ok = true;
  if (!receipt.proof) {
    result.error = "Chain is intact but the receipt carries no proof bundle (not anchored yet, or attachBundle() was never run)";
    return result;
  }
  const bundle = verifyProof(head, receipt.proof);
  result.proof = bundle;
  if (!bundle.verified) {
    result.error = "Bundle does not match the chain head: " + String(bundle.error ?? "");
    return result;
  }
  result.anchored = true;
  result.verified = true;
  const n = steps.length;
  result.message = `Receipt for run ${receipt.run_id ?? "?"}: ${n} step${n === 1 ? "" : "s"} chain to head ${head.slice(0, 16)}…, and ${bundle.message}`;
  return result;
}

/** Check that one step was made from this exact content. Needs the run secret. */
export function verifyStep(receipt, index, content, secret) {
  secret = secret ?? receipt?.secret;
  if (!secret) return { verified: false, error: "This receipt carries no secret; the owner must supply it to check step content" };
  const steps = receipt?.steps ?? [];
  index = Number(index);
  if (!(index >= 0 && index < steps.length)) return { verified: false, error: `No step ${index} in this receipt` };
  const step = steps[index];
  const ok = stepFingerprint(secret, content) === String(step.fingerprint ?? "");
  const out = { verified: ok, index, type: step.type, label: step.label };
  if (ok) out.message = `Step ${index} (${step.type}) was made from this content.`;
  else out.error = `Step ${index} (${step.type}) was not made from this content.`;
  return out;
}

/** Plain-text listing of a receipt, for humans. */
export function describeReceipt(receipt) {
  const lines = [`Agent run receipt: ${receipt.run_id ?? "?"}`];
  const agent = receipt.agent ?? {};
  if (Object.keys(agent).length) lines.push("  Agent      : " + Object.entries(agent).map(([k, v]) => `${k}=${v}`).join(", "));
  lines.push(`  Started    : ${receipt.started_at ?? ""}`);
  lines.push(`  Finished   : ${receipt.finished_at ?? "(not finished)"}`);
  lines.push(`  Secret     : ${receipt.secret ? "present (redact before sharing)" : "redacted"}`);
  lines.push(`  Chain head : ${receipt.chain_head ?? ""}`);
  const proof = receipt.proof ?? {};
  if (proof.tx_id) lines.push(`  Anchored   : ${proof.blockchain ?? ""} ${proof.tx_id} at ${proof.anchored_at ?? ""}`);
  else if (receipt.proof_id !== undefined && receipt.proof_id !== null) lines.push(`  Anchored   : pending (proof ${receipt.proof_id})`);
  else lines.push("  Anchored   : no");
  const steps = receipt.steps ?? [];
  lines.push(`  Steps      : ${steps.length}`);
  for (const s of steps) {
    const label = s.label ? `  ${s.label}` : "";
    lines.push(`    ${String(s.index).padStart(3)}  ${String(s.type ?? "").padEnd(11)} ${s.at ?? ""}  ${String(s.fingerprint ?? "").slice(0, 16)}…${label}`);
  }
  return lines.join("\n");
}

async function receiptCommand(sub, file, args) {
  if (!file || !existsSync(file)) {
    console.error(`Error: Receipt file not found: ${file ?? "(none given)"}`);
    process.exit(1);
  }
  const receipt = JSON.parse(readFileSync(file, "utf8"));
  if (sub === "show") {
    console.log(describeReceipt(receipt));
    return;
  }
  if (sub === "verify") {
    const result = verifyReceipt(receipt);
    console.log(result.verified ? `VERIFIED: ${result.message}` : `FAILED: ${result.error ?? "Unknown error"}`);
    let stepOk = true;
    if (args.step !== undefined || args.content) {
      if (args.step === undefined || !args.content) { console.error("Error: --step and --content go together"); process.exit(2); }
      if (!existsSync(args.content)) { console.error(`Error: Content file not found: ${args.content}`); process.exit(1); }
      const step = verifyStep(receipt, args.step, readFileSync(args.content), args.secret);
      console.log(step.verified ? `STEP OK: ${step.message}` : `STEP FAILED: ${step.error}`);
      stepOk = step.verified;
    }
    process.exit(result.verified && stepOk ? 0 : 1);
  }
  if (sub === "anchor") {
    const r = RunReceipt.fromObject(receipt);
    if (r.proof) { console.log("This receipt is already anchored and carries its bundle."); return; }
    const client = new ProofLedger({ apiKey: process.env.PROOFLEDGER_API_KEY, baseUrl: args.baseUrl ?? DEFAULT_BASE_URL });
    try {
      if (r.proofId === null) await r.anchor(client, { wait: args.wait ?? 120 });
      else await r.attachBundle(client);
    } finally {
      r.save(file);
    }
    if (r.proof) {
      console.log(`Anchored: proof ${r.proofId}, ${r.proof.blockchain} transaction ${r.proof.tx_id} at ${r.proof.anchored_at}.`);
      console.log(`Bundle saved into ${file}. Check it offline:  verify-proof receipt verify ${file}`);
    } else {
      console.log(`Submitted: proof ${r.proofId}. The Polygon anchor usually lands within a minute; run this again to save the bundle.`);
    }
    if (r.certificateUrl) console.log(`Certificate: ${r.certificateUrl}`);
    return;
  }
  console.error(`Error: Unknown receipt command: ${sub ?? "(none)"}. Use verify, show or anchor.`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--proof") args.proof = argv[++i];
    else if (argv[i] === "--algorithm") args.algorithm = argv[++i];
    else if (argv[i] === "--step") args.step = Number(argv[++i]);
    else if (argv[i] === "--content") args.content = argv[++i];
    else if (argv[i] === "--secret") args.secret = argv[++i];
    else if (argv[i] === "--wait") args.wait = Number(argv[++i]);
    else if (argv[i] === "--base-url") args.baseUrl = argv[++i];
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

  if (command === "receipt") {
    await receiptCommand(args._[1], args._[2], args);
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
