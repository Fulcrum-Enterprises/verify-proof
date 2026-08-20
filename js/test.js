/**
 * Parity tests: the JS port must agree with the Python package on the shared
 * fixtures in ../examples. Run with `node test.js` (or `npm test`).
 */
import { strict as assert } from "node:assert";
import { hashFile, verifyProof, loadProof } from "./verify-proof.js";
import { createHash } from "node:crypto";

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

console.log(`\n${passed} tests passed`);
