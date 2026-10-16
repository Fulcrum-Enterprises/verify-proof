# verify-proof (Node.js)

Verify blockchain-anchored timestamp proofs offline, and create them through the [ProofLedger](https://proofledger.io) API. Zero dependencies: only `node:crypto`, `node:fs` and the global `fetch` (Node 18+).

This is the Node.js port of the [`verify-proof` Python package](https://pypi.org/project/verify-proof/). Both share the same JSON proof format and the same verification semantics, tested against the same fixtures, so a proof verified by one is verified by the other.

Two halves, kept apart on purpose:

- **Offline:** `hashFile`, `verifyProof`, `loadProof`, `verifyWebhookSignature`. Never touch the network. Verification that depends on the issuing service is not verification.
- **Online:** the `ProofLedger` client. Creates proofs (one, or a batch of up to 100), looks them up, fetches the bundle that makes a proof verifiable without ProofLedger, manages webhooks. Sends the hash, never the file.

## Install

```bash
npm install -g verify-proof     # CLI
npm install verify-proof        # library
```

Or run without installing:

```bash
npx verify-proof hash document.pdf
```

## CLI

```bash
# Compute a file's SHA-256 (the file never leaves your machine)
verify-proof hash document.pdf

# Verify a file against a proof (a ProofLedger bundle, or any JSON proof with hash/blockchain/tx_id/merkle_path)
verify-proof verify document.pdf --proof bundle.json
# VERIFIED: Proof verified. File hash matches blockchain anchor on polygon. ...
```

Exit code `0` on verified, `1` on any failure, safe to gate a CI job on. Binary OpenTimestamps `.ots` files are a different format and are not parsed; use the `ots` tool for those.

## Verify (offline)

```js
import { hashFile, verifyProof, loadProof } from "verify-proof";

const digest = await hashFile("document.pdf");           // streaming, any size
const result = verifyProof(digest, loadProof("bundle.json"));

if (result.verified) {
  console.log(result.message);        // includes chain, tx id, anchored-at
} else {
  console.error(result.error);        // hash mismatch, missing anchor, ...
}
```

## Create proofs (ProofLedger API)

Needs an API key: free on every plan, from **Account > API Keys** at [proofledger.io](https://proofledger.io/login.html). The Free plan includes 100 API proofs a month. Full reference: [proofledger.io/api.html](https://proofledger.io/api.html); integration guide: [proofledger.io/platforms](https://proofledger.io/platforms).

```js
import { hashFile, verifyProof, ProofLedger } from "verify-proof";

const pl = new ProofLedger({ apiKey: process.env.PROOFLEDGER_API_KEY });

// One file. external_id is your own record id: resending it returns the same proof.
const proof = await pl.createProof({
  sha256: await hashFile("song.mp3"),
  externalId: "song-42",
  filename: "song.mp3",
});
console.log(proof.id, proof.certificate_url);   // e.g. 42, "/cert/42"

// Up to 100 at once, checked first and written together (Polygon only).
const batch = await pl.createProofs([
  { sha256: await hashFile("a.wav"), externalId: "a" },
  { sha256: await hashFile("b.wav"), externalId: "b" },
]);
console.log(batch.summary);                       // { created, exists, invalid }

// Later: status, lookup by your id, what was anchored since your last check.
await pl.getProof(proof.id);
await pl.getProofByExternalId("song-42");         // null when unknown
await pl.listAnchoredSince("2026-10-15T00:00:00Z");

// The bundle: store it next to the file. It verifies with nothing from ProofLedger.
const bundle = await pl.getBundle(proof.id);      // { hash, blockchain, tx_id, anchored_at, merkle_path, ... }
verifyProof(await hashFile("song.mp3"), bundle);  // .verified === true once anchored
```

Errors are `ProofLedgerError` with `status` (HTTP code), `body` (the API's JSON) and, on a 429 from the per-minute limit, `retryAfter` in seconds.

## Webhooks

ProofLedger POSTs a signed event when a proof's anchor lands. Register once, then check the signature on every delivery with the raw body:

```js
import { ProofLedger, verifyWebhookSignature } from "verify-proof";

const { secret } = await pl.registerWebhook("https://yourapp.example/hooks/proofledger");
// store `secret`; it is shown once

// Express example: use the RAW body, not a parsed object
app.post("/hooks/proofledger", express.raw({ type: "application/json" }), (req, res) => {
  if (!verifyWebhookSignature(secret, req.get("ProofLedger-Signature"), req.body)) {
    return res.status(400).end();
  }
  const event = JSON.parse(req.body);             // { id, type, data: { proof, bundle } }
  // event.type is "proof.polygon.anchored" or "proof.bitcoin.anchored"; dedupe on event.id
  res.status(200).end();
});
```

`pl.listWebhooks()`, `pl.deleteWebhook(id)`, `pl.testWebhook(id)` and `pl.getBranding()` cover the rest of the API.

## What verification checks

1. The file's SHA-256, computed locally, matches the proof's recorded hash
2. The Merkle path (when present) recomputes to its root
3. The proof references a blockchain transaction, whose timestamp is the evidence

## What it does not prove

A proof establishes that a digest existed no later than the block it was anchored in. It does not prove who created the file, that it is original, or that its contents are true.

## License

MIT © Fulcrum Enterprises LLC
