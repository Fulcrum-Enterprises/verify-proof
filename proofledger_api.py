#!/usr/bin/env python3
"""proofledger_api — minimal client for the ProofLedger API.

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

import hashlib
import hmac
import json
import re
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

DEFAULT_BASE_URL = "https://proofledger.io"
API_KEY_ENV = "PROOFLEDGER_API_KEY"

# Every link this module prints carries a source tag. The point is measurement:
# without it there is no way to tell whether anyone who installs this tool ever
# reaches ProofLedger.
_UTM = "utm_source=verify-proof&utm_medium=cli"
SIGNUP_URL = f"{DEFAULT_BASE_URL}/login.html?{_UTM}&utm_campaign=api-key"
PRICING_URL = f"{DEFAULT_BASE_URL}/pricing.html?{_UTM}&utm_campaign=quota"
# The one printed after a successful `verify`, which is the command almost every
# install actually runs. Its own campaign so the scoreboard can tell the people who
# arrived after verifying somebody else's proof from the ones who went looking for
# an API key.
HOME_URL = f"{DEFAULT_BASE_URL}/?{_UTM}&utm_campaign=verified"


class ProofLedgerError(RuntimeError):
    """A submission did not succeed. The message is meant to be shown as-is."""


def api_key(explicit: str | None = None) -> str:
    """Return the API key, or raise with the steps to get one.

    A missing key is the most likely first experience of this command, so the
    error is written as instructions rather than as a complaint.
    """
    key = (explicit or os.environ.get(API_KEY_ENV, "")).strip()
    # A plugin or MCP config can hand over its placeholder unexpanded ("${PROOFLEDGER_API_KEY}")
    # when the variable is unset; that is no key, not a key to send.
    if key and not key.startswith("${"):
        return key
    raise ProofLedgerError(
        "No ProofLedger API key found.\n"
        "\n"
        "  1. Sign in (free, no card) at " + SIGNUP_URL + "\n"
        "  2. Account > API Keys > create a key (shown once)\n"
        f"  3. Set it:  {API_KEY_ENV}=sk_...\n"
        "\n"
        "The Free plan includes 100 API proofs a month. Hashing and verifying\n"
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
        bitcoin: Ignored. ProofLedger stopped anchoring on Bitcoin on
                 2026-10-15; every proof is anchored on Polygon. Kept so
                 existing callers do not break, with a DeprecationWarning.
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
        warnings.warn(
            "bitcoin=True is ignored: ProofLedger stopped anchoring on Bitcoin on "
            "2026-10-15. Every proof is anchored on Polygon.",
            DeprecationWarning,
            stacklevel=2,
        )

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


def _request(
    method: str,
    path: str,
    payload: dict | None = None,
    key: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    timeout: int = 30,
) -> dict:
    """One authenticated call to the v1 API. Errors become ProofLedgerError."""
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key or api_key()}",
            "Content-Type": "application/json",
            "User-Agent": "verify-proof (https://pypi.org/project/verify-proof/)",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raise ProofLedgerError(_http_message(exc)) from exc
    except urllib.error.URLError as exc:
        raise ProofLedgerError(
            f"Could not reach {base_url}: {exc.reason}\n"
            "Hashing and verification still work offline."
        ) from exc


def _digest(sha256: str) -> str:
    digest = sha256.strip().lower().removeprefix("0x")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ProofLedgerError(f"Not a SHA-256 hex digest: {sha256!r}")
    return digest


def submit_batch(
    items: list[dict],
    key: str | None = None,
    base_url: str = DEFAULT_BASE_URL,
    timeout: int = 60,
) -> dict:
    """Anchor up to 100 hashes in one call (POST /api/v1/proofs/batch).

    Each item: {"sha256": ..., "external_id": optional, "filename": optional}.
    Items are checked first and written together; Polygon only. The response
    has a `summary` and one entry per item with `result` created / exists /
    invalid and, for the first two, the `proof`.
    """
    if not items or len(items) > 100:
        raise ProofLedgerError("submit_batch takes 1 to 100 items.")
    payload = {"items": []}
    for it in items:
        out = {"sha256": _digest(it["sha256"])}
        if it.get("external_id") is not None:
            out["external_id"] = str(it["external_id"])
        if it.get("filename"):
            out["filename"] = str(it["filename"])[:500]
        payload["items"].append(out)
    return _request("POST", "/api/v1/proofs/batch", payload, key, base_url, timeout)


def get_proof(proof_id: int | str, key: str | None = None, base_url: str = DEFAULT_BASE_URL) -> dict:
    """One of your proofs by ProofLedger id (GET /api/v1/proof/:id)."""
    return _request("GET", f"/api/v1/proof/{urllib.parse.quote(str(proof_id))}", None, key, base_url)


def get_proof_by_external_id(external_id: str, key: str | None = None, base_url: str = DEFAULT_BASE_URL) -> dict | None:
    """One of your proofs by your own record id, or None when there is none."""
    try:
        r = _request("GET", "/api/v1/proofs?" + urllib.parse.urlencode({"external_id": external_id}), None, key, base_url)
    except ProofLedgerError as exc:
        if "404" in str(exc):
            return None
        raise
    return r.get("proof")


def get_bundle(proof_id: int | str, chain: str = "polygon", key: str | None = None, base_url: str = DEFAULT_BASE_URL) -> dict:
    """The bundle for a proof (GET /api/v1/proof/:id/bundle): everything needed
    to verify it without ProofLedger, in this package's proof-file format.
    Save it next to the file and `verify-proof verify <file> --proof bundle.json`
    works offline, for as long as the chain exists."""
    if chain not in ("polygon", "bitcoin"):
        raise ProofLedgerError("chain must be 'polygon' or 'bitcoin'")
    return _request("GET", f"/api/v1/proof/{urllib.parse.quote(str(proof_id))}/bundle?chain={chain}", None, key, base_url)


def verify_webhook_signature(
    secret: str,
    header: str,
    raw_body: bytes | str,
    tolerance_seconds: int = 300,
    now: int | None = None,
) -> bool:
    """Check a ProofLedger webhook delivery before trusting it.

    ProofLedger sends `ProofLedger-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, t + "." + body)>`.
    Pass the RAW request body exactly as received; re-serialising it breaks the MAC.
    Pure computation, no network.
    """
    m = re.fullmatch(r"t=(\d+),v1=([0-9a-f]{64})", str(header or ""))
    if not m:
        return False
    t = int(m.group(1))
    if abs((now if now is not None else int(time.time())) - t) > tolerance_seconds:
        return False
    body = raw_body if isinstance(raw_body, bytes) else str(raw_body).encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), f"{t}.".encode("utf-8") + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, m.group(2))


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
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        if retry_after:
            return (
                f"Rate limit: 120 requests per minute per key (429). Retry after {retry_after} s.\n"
                "One batch call carries up to 100 hashes." + (f"\n({detail})" if detail else "")
            )
        return (
            "Monthly API proof limit reached (429).\n"
            "The Free plan includes 100 API proofs a month and answers 429 past that\n"
            "until the 1st of next month (UTC). Developer includes 1,000 a month and\n"
            "Platform 10,000, then $0.01 per proof.\n"
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
        "Anchoring is not instant: the Polygon anchor usually lands within a "
        "minute. Re-check the proof, or save its bundle and verify it offline "
        "with:  verify-proof verify <file> --proof <proof.json>",
    ]
    return "\n".join(lines)
