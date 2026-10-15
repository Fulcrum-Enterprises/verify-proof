/**
 * Parity tests: the JS port must agree with the Python package on the shared
 * fixtures in ../examples. Run with `node test.js` (or `npm test`).
 *
 * The ProofLedger client is tested against a local HTTP server that plays the
 * API, so the tests never touch the network. The webhook-signature helper is
 * tested against the exact header format the ProofLedger server emits.
 */
import { strict as assert } from "node:assert";
import { createServer } from "node:http";
import { createHash, createHmac } from "node:crypto";
import {
  hashFile, verifyProof, loadProof, verifyWebhookSignature, ProofLedger, ProofLedgerError,
} from "./verify-proof.js";

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`ok - ${name}`);
}

await test("hashFile matches the fixture's known digest", async () => {
  const digest = await hashFile(new URL("../examples/sample.txt", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
  assert.equal(digest, "00d3f851ccc4b5df700b648d548de8758bd634233da29289dcd22474c2695859");
});

await test("verifyProof verifies the fixture proof", async () => {
  const p = new URL("../examples/", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
  const digest = await hashFile(p + "sample.txt");
  const result = verifyProof(digest, loadProof(p + "proof.json"));
  assert.equal(result.verified, true);
  assert.equal(result.blockchain, "polygon");
  assert.equal(result.merkle_verified, true);
  assert.match(result.message, /Proof verified/);
});

await test("a modified file fails with a hash mismatch", () => {
  const result = verifyProof("deadbeef".repeat(8), { hash: "00d3f851".padEnd(64, "0"), tx_id: "0xabc" });
  assert.equal(result.verified, false);
  assert.match(result.error, /Hash mismatch/);
});

await test("a proof without a tx_id fails with the anchor error", () => {
  const h = "aa".repeat(32);
  const result = verifyProof(h, { hash: h });
  assert.equal(result.verified, false);
  assert.match(result.error, /No blockchain transaction ID/);
});

await test("merkle walk matches an independently computed root", () => {
  const leaf = "ab".repeat(32);
  const sib = "cd".repeat(32);
  // position right: current + sibling, hex-decoded then hashed
  const expected = createHash("sha256").update(Buffer.from(leaf + sib, "hex")).digest("hex");
  const result = verifyProof(leaf, {
    hash: leaf,
    tx_id: "0x1",
    merkle_path: [{ hash: sib, position: "right" }],
  });
  assert.equal(result.merkle_root, expected);
});

await test("a ProofLedger bundle verifies as a proof file (polygon on top, extra fields ignored)", () => {
  const h = "0f".repeat(32);
  const bundle = {
    format: "verify-proof/1", service: "proofledger", hash: h, algorithm: "sha256",
    blockchain: "polygon", tx_id: "0x" + "1".repeat(64), anchored_at: "2026-10-15T00:00:00.000Z",
    merkle_path: [], anchored: true, proof_id: 42, anchors: { polygon: {}, bitcoin: {} }, how_to_verify: [],
  };
  const result = verifyProof(h, bundle);
  assert.equal(result.verified, true);
  assert.equal(result.service, "proofledger");
});

// --- webhook signatures -------------------------------------------------------
// Same construction as ProofLedger's server: HMAC-SHA256(secret, `${t}.${body}`).
function sign(secret, t, body) {
  return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;
}
const secret = "whsec_" + "ab".repeat(16);
const body = JSON.stringify({ id: "evt_1", type: "proof.polygon.anchored", data: { proof: { id: 1 } } });
const now = 1_800_000_000;

await test("verifyWebhookSignature accepts a fresh, correct signature", () => {
  assert.equal(verifyWebhookSignature(secret, sign(secret, now, body), body, { now }), true);
  assert.equal(verifyWebhookSignature(secret, sign(secret, now, body), Buffer.from(body), { now }), true, "Buffer body");
});

await test("verifyWebhookSignature rejects a changed body, wrong secret, bad header, stale timestamp", () => {
  assert.equal(verifyWebhookSignature(secret, sign(secret, now, body), body + " ", { now }), false, "body changed");
  assert.equal(verifyWebhookSignature("whsec_other", sign(secret, now, body), body, { now }), false, "wrong secret");
  assert.equal(verifyWebhookSignature(secret, "garbage", body, { now }), false, "bad header");
  assert.equal(verifyWebhookSignature(secret, sign(secret, now - 301, body), body, { now }), false, "301 s old");
  assert.equal(verifyWebhookSignature(secret, sign(secret, now - 299, body), body, { now }), true, "299 s old");
  assert.equal(verifyWebhookSignature(secret, sign(secret, now - 1000, body), body, { now, toleranceSeconds: 2000 }), true, "custom tolerance");
});

// --- API client against a local fake --------------------------------------------
const calls = [];
const fake = createServer((req, res) => {
  let b = "";
  req.on("data", (c) => { b += c; });
  req.on("end", () => {
    calls.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: b ? JSON.parse(b) : null, ua: req.headers["user-agent"] });
    const send = (code, obj, headers = {}) => { res.writeHead(code, { "Content-Type": "application/json", ...headers }); res.end(JSON.stringify(obj)); };
    if (req.headers.authorization !== "Bearer sk_test") return send(401, { error: "Invalid API key." });
    if (req.method === "POST" && req.url === "/api/v1/proof") return send(201, { id: 7, sha256: JSON.parse(b).sha256, external_id: JSON.parse(b).external_id ?? null, status: "approved", issued_via: null });
    if (req.method === "POST" && req.url === "/api/v1/proofs/batch") return send(201, { summary: { created: JSON.parse(b).items.length }, items: JSON.parse(b).items.map((it, i) => ({ result: "created", proof: { id: 100 + i, external_id: it.external_id ?? null } })) });
    if (req.method === "GET" && req.url === "/api/v1/proof/7") return send(200, { id: 7, polygon_status: "ANCHORED" });
    if (req.method === "GET" && req.url === "/api/v1/proof/7/bundle?chain=polygon") return send(200, { format: "verify-proof/1", hash: "0f".repeat(32), blockchain: "polygon", tx_id: "0xabc", anchored: true });
    if (req.method === "GET" && req.url === "/api/v1/proofs?external_id=song-42") return send(200, { proof: { id: 7, external_id: "song-42" } });
    if (req.method === "GET" && req.url === "/api/v1/proofs?external_id=missing") return send(404, { error: "No proof with that external_id on this account." });
    if (req.method === "GET" && req.url.startsWith("/api/v1/proofs?anchored_since=")) return send(200, { proofs: [{ id: 7 }], next_cursor: null });
    if (req.method === "POST" && req.url === "/api/v1/webhooks") return send(201, { endpoint: { id: 3, url: JSON.parse(b).url }, secret: "whsec_x" });
    if (req.method === "GET" && req.url === "/api/v1/webhooks") return send(200, { endpoints: [] });
    if (req.method === "DELETE" && req.url === "/api/v1/webhooks/3") return send(200, { ok: true });
    if (req.method === "POST" && req.url === "/api/v1/webhooks/3/test") return send(200, { ok: true, status_code: 200 });
    if (req.method === "GET" && req.url === "/api/v1/branding") return send(200, { approved: false });
    if (req.method === "GET" && req.url === "/api/v1/proof/429") return send(429, { error: "Rate limit exceeded", retry_after: 12 }, { "Retry-After": "12" });
    send(404, { error: "not found" });
  });
});
await new Promise((r) => fake.listen(0, "127.0.0.1", r));
const baseUrl = `http://127.0.0.1:${fake.address().port}`;
const pl = new ProofLedger({ apiKey: "sk_test", baseUrl });

await test("constructor refuses a missing or non-sk_ key", () => {
  assert.throws(() => new ProofLedger({}), ProofLedgerError);
  assert.throws(() => new ProofLedger({ apiKey: "pl_live_x" }), ProofLedgerError);
});

await test("createProof sends the hash, external_id and filename with the Bearer key", async () => {
  const r = await pl.createProof({ sha256: "0F".repeat(32), externalId: "song-42", filename: "song.mp3" });
  assert.equal(r.id, 7);
  const c = calls.at(-1);
  assert.equal(c.auth, "Bearer sk_test");
  assert.deepEqual(c.body, { sha256: "0f".repeat(32), external_id: "song-42", filename: "song.mp3" });
  assert.match(c.ua, /verify-proof-js/);
});

await test("createProof rejects a non-hex hash before any request", async () => {
  const before = calls.length;
  await assert.rejects(() => pl.createProof({ sha256: "nope" }), /Not a SHA-256/);
  assert.equal(calls.length, before);
});

await test("createProofs batches up to 100 and refuses 0 or 101", async () => {
  const r = await pl.createProofs([{ sha256: "aa".repeat(32), externalId: "b-1" }, { sha256: "bb".repeat(32) }]);
  assert.equal(r.summary.created, 2);
  assert.equal(calls.at(-1).body.items[0].external_id, "b-1");
  await assert.rejects(() => pl.createProofs([]), ProofLedgerError);
  await assert.rejects(() => pl.createProofs(new Array(101).fill({ sha256: "aa".repeat(32) })), ProofLedgerError);
});

await test("getProof, getBundle, getProofByExternalId, listAnchoredSince", async () => {
  assert.equal((await pl.getProof(7)).polygon_status, "ANCHORED");
  const bundle = await pl.getBundle(7);
  assert.equal(bundle.blockchain, "polygon");
  assert.equal(verifyProof("0f".repeat(32), bundle).verified, true, "bundle verifies offline");
  assert.equal((await pl.getProofByExternalId("song-42")).id, 7);
  assert.equal(await pl.getProofByExternalId("missing"), null);
  const page = await pl.listAnchoredSince(new Date("2026-10-15T00:00:00Z"));
  assert.equal(page.proofs.length, 1);
  assert.match(calls.at(-1).url, /anchored_since=2026-10-15T00%3A00%3A00.000Z/);
});

await test("webhook management calls hit the documented routes", async () => {
  const reg = await pl.registerWebhook("https://example.com/hooks");
  assert.equal(reg.secret, "whsec_x");
  assert.deepEqual((await pl.listWebhooks()).endpoints, []);
  assert.equal((await pl.deleteWebhook(3)).ok, true);
  assert.equal((await pl.testWebhook(3)).ok, true);
  assert.equal((await pl.getBranding()).approved, false);
});

await test("errors carry the status, body and Retry-After", async () => {
  await assert.rejects(() => pl.getProof(429), (e) => e instanceof ProofLedgerError && e.status === 429 && e.retryAfter === 12 && e.body.error === "Rate limit exceeded");
  const bad = new ProofLedger({ apiKey: "sk_wrong", baseUrl });
  await assert.rejects(() => bad.getProof(7), (e) => e.status === 401 && /HTTP 401/.test(e.message));
});

fake.close();
console.log(`\n${passed} tests passed`);
