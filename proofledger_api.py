#!/usr/bin/env python3
"""proofledger_api — minimal client for creating a ProofLedger timestamp proof.

This is the one part of verify-proof that talks to a network. Everything else
in this package (hashing, verification, explanation) runs entirely offline and
always will: verification that depends on the issuing service is not
verification. Creating a proof is the opposite case — a proof has to be
anchored by somebody, and this submits a hash to ProofLedger to do that.

What leaves the machine: the 64-character SHA-256 hex digest, and the filename
if you allow it. Never the file. The API is documented at
https://proofledger.io/api.html and specified at
https://proofledger.io/openapi.json

Standard library only, so installing verify-proof still pulls in nothing.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "https://proofledger.io"
API_KEY_ENV = "PROOFLEDGER_API_KEY"

# Every link this module prints carries a source tag. The point is measurement:
# without it there is no way to tell whether anyone who installs this tool ever
# reaches ProofLedger.
_UTM = "utm_source=verify-proof&utm_medium=cli"
SIGNUP_URL = f"{DEFAULT_BASE_URL}/login.html?{_UTM}&utm_campaign=api-key"
PRICING_URL = f"{DEFAULT_BASE_URL}/pricing.html?{_UTM}&utm_campaign=quota"


class ProofLedgerError(RuntimeError):
    """A submission did not succeed. The message is meant to be shown as-is."""


def api_key(explicit: str | None = None) -> str:
    """Return the API key, or raise with the steps to get one.

    A missing key is the most likely first experience of this command, so the
    error is written as instructions rather than as a complaint.
    """
    key = (explicit or os.environ.get(API_KEY_ENV, "")).strip()
    if key:
        return key
    raise ProofLedgerError(
        "No ProofLedger API key found.\n"
        "\n"
        "  1. Sign in (free, no card) at " + SIGNUP_URL + "\n"
        "  2. Account > API Keys > create a key (shown once)\n"
        f"  3. Set it:  {API_KEY_ENV}=sk_...\n"
        "\n"
        "The free tier includes 25 API proofs a month. Hashing and verifying\n"
        "need no key and no account — they never touch the network."
    )


def submit_proof(
    sha256: str,
    filename: str | None = None,
    bitcoin: bool = False,
    key: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    timeout: int = 30,
) -> dict:
    """Submit a SHA-256 digest for anchoring. Returns the created proof.

    Args:
        sha256: 64-character hex digest, computed locally.
        filename: Optional label so the proof is findable in the dashboard.
                  Pass None to send nothing but the hash.
        bitcoin: Request Bitcoin anchoring as well as Polygon. Bitcoin is
                 metered per anchor on every tier, so the proof comes back
                 marked REQUIRED until the anchor is paid for.
        key: API key; falls back to the environment.
        base_url: Override for staging or a private deployment.
    """
    digest = sha256.strip().lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ProofLedgerError(f"Not a SHA-256 hex digest: {sha256!r}")

    payload: dict = {"sha256": digest}
    if filename:
        payload["filename"] = filename[:500]
    if bitcoin:
        payload["bitcoin_requested"] = True

    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/v1/proof",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key or api_key()}",
            "Content-Type": "application/json",
            "User-Agent": "verify-proof (https://pypi.org/project/verify-proof/)",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ProofLedgerError(_http_message(exc)) from exc
    except urllib.error.URLError as exc:
        raise ProofLedgerError(
            f"Could not reach {base_url}: {exc.reason}\n"
            "Hashing and verification still work offline."
        ) from exc


def _http_message(exc: urllib.error.HTTPError) -> str:
    """Turn an API error into something the reader can act on."""
    detail = ""
    try:
        body = json.loads(exc.read().decode("utf-8"))
        detail = body.get("error") or body.get("message") or ""
    except Exception:  # noqa: BLE001 - an unparseable body is not worth raising over
        detail = ""

    if exc.code == 401:
        return (
            "ProofLedger rejected the API key (401).\n"
            f"Check {API_KEY_ENV}, or create a new key at {SIGNUP_URL}"
            + (f"\n({detail})" if detail else "")
        )
    if exc.code == 429:
        return (
            "Monthly API proof limit reached (429).\n"
            "Free and Standard include 25 proofs a month, Professional 500, "
            "Business 5000.\n"
            f"Plans: {PRICING_URL}" + (f"\n({detail})" if detail else "")
        )
    if exc.code == 403:
        return f"ProofLedger refused the request (403). {detail}".strip()
    return f"ProofLedger returned HTTP {exc.code}. {detail}".strip()


def summarize(proof: dict, base_url: str = DEFAULT_BASE_URL) -> str:
    """Render a submitted proof as plain text, including where to see it."""
    root = base_url.rstrip("/")
    lines = [
        "Proof submitted to ProofLedger.",
        "",
        f"  Proof id      : {proof.get('id', '(none)')}",
        f"  SHA-256       : {proof.get('sha256', '')}",
        f"  Filename      : {proof.get('filename') or '(not sent)'}",
        f"  Status        : {proof.get('status', 'unknown')}",
        f"  Created       : {proof.get('created_at', '')}",
    ]

    if proof.get("bitcoin_requested"):
        payment = proof.get("btc_payment_status", "NONE")
        lines.append(f"  Bitcoin       : requested, payment {payment}")
        if payment == "REQUIRED":
            lines.append(
                "                  (Polygon anchoring is already under way; the "
                "Bitcoin anchor is metered and waits for payment)"
            )

    duplicate = proof.get("duplicate_of")
    if duplicate:
        lines += [
            "",
            "This hash was already on record: proof "
            f"{duplicate.get('id')} from {duplicate.get('created_at')}. "
            "Your submission is recorded separately; the earlier record is the "
            "earlier evidence.",
        ]

    for label, url_key in (("Certificate", "certificate_url"), ("Verify", "verification_url")):
        url = proof.get(url_key)
        if url:
            lines.append(f"  {label:<14}: {root}{url}" if url.startswith("/") else f"  {label:<14}: {url}")

    lines += [
        "",
        "Anchoring is not instant. Polygon usually settles within minutes; "
        "Bitcoin is Merkle-batched daily. Re-check the proof, or verify the "
        "downloaded proof file offline with:  verify-proof verify <file> "
        "--proof <proof.json>",
    ]
    return "\n".join(lines)
