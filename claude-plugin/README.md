# ProofLedger plugin for Claude Code

Lets Claude anchor a file's SHA-256 hash on Polygon through the [ProofLedger](https://proofledger.io) API, save the proof bundle next to the file, and verify files against bundles offline. It bundles the `verify-proof` MCP server and two skills, `/proofledger:anchor` and `/proofledger:verify`.

## Install

In a Claude Code session:

```
/plugin marketplace add Fulcrum-Enterprises/verify-proof
/plugin install proofledger@proofledger
```

Or from a shell:

```bash
claude plugin marketplace add Fulcrum-Enterprises/verify-proof
claude plugin install proofledger@proofledger
```

## Requirements

- [uv](https://docs.astral.sh/uv/), which starts the MCP server with `uvx`, so there is nothing to pip install.
- For creating proofs only: a ProofLedger API key in the `PROOFLEDGER_API_KEY` environment variable of the shell that starts Claude Code. Keys are free (Account > API Keys at [proofledger.io](https://proofledger.io/login.html?next=%2Faccount.html&utm_source=claude-plugin&utm_medium=readme)); the free plan includes 100 API proofs a month. Verifying needs no key.

## What leaves your machine

Hashing and verification run locally and send nothing. Creating a proof sends the 64-character SHA-256 hash, and the file name unless you ask Claude not to. The file itself is never sent.

## Use

- *"Anchor `dist/app-1.4.0.zip` and save its proof next to it."*
- *"Does `contract.pdf` still match `contract.pdf.proof.json`?"*
- *"What does this proof file actually prove?"*

A proof shows that a file with this exact fingerprint existed by the anchor time and has not changed since. It does not show who made the file.
