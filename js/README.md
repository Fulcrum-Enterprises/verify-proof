# verify-proof (Node.js)

Verify blockchain-anchored timestamp proofs offline. Zero dependencies — only `node:crypto` and `node:fs`.

This is the Node.js port of the [`verify-proof` Python package](https://pypi.org/project/verify-proof/). Both share the same JSON proof format and the same verification semantics, tested against the same fixtures, so a proof verified by one is verified by the other.

Works with proofs from [ProofLedger](https://proofledger.io) and compatible blockchain timestamping services.

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

# Verify a file against a blockchain proof
verify-proof verify document.pdf --proof proof.json
# VERIFIED: Proof verified. File hash matches blockchain anchor on polygon. ...
```

Exit code `0` on verified, `1` on any failure — safe to gate a CI job on.

## Library

```js
import { hashFile, verifyProof, loadProof } from "verify-proof";

const digest = await hashFile("document.pdf");           // streaming, any size
const result = verifyProof(digest, loadProof("proof.json"));

if (result.verified) {
  console.log(result.message);        // includes chain, tx id, anchored-at
} else {
  console.error(result.error);        // hash mismatch, missing anchor, ...
}
```

## What verification checks

1. The file's SHA-256, computed locally, matches the proof's recorded hash
2. The Merkle path (when present) recomputes to its root
3. The proof references a blockchain transaction, whose timestamp is the evidence

## What it does not prove

A proof establishes that a digest existed no later than the block it was anchored in. It does not prove who created the file, that it is original, or that its contents are true.

## License

MIT © Fulcrum Enterprises LLC
