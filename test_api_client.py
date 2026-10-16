"""The ProofLedger client half of the package, tested against a local fake API.

Nothing here touches proofledger.io. A tiny http.server plays the v1 API so the
request shapes, error handling and the webhook-signature helper can be checked
exactly, including the 429 cases the real server sends (per-minute limit with
Retry-After, monthly cap without).

Run:  python -m pytest test_api_client.py -q
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import proofledger_api as api

CALLS: list[dict] = []


class FakeAPI(BaseHTTPRequestHandler):
    def log_message(self, *_):  # quiet
        pass

    def _send(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        body = json.loads(raw) if raw else None
        CALLS.append({"method": self.command, "path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        if self.headers.get("Authorization") != "Bearer sk_test":
            return self._send(401, {"error": "Invalid API key."})
        m, p = self.command, self.path
        if m == "POST" and p == "/api/v1/proof":
            return self._send(201, {"id": 7, "sha256": body["sha256"], "status": "approved"})
        if m == "POST" and p == "/api/v1/proofs/batch":
            items = [{"result": "created", "proof": {"id": 100 + i, "external_id": it.get("external_id"), "certificate_url": f"/cert/{100 + i}"}} for i, it in enumerate(body["items"])]
            return self._send(201, {"summary": {"created": len(items), "exists": 0, "invalid": 0}, "items": items})
        if m == "GET" and p == "/api/v1/proof/7":
            return self._send(200, {"id": 7, "polygon_status": "ANCHORED", "chain_tx": "0xabc"})
        if m == "GET" and p == "/api/v1/proof/7/bundle?chain=polygon":
            return self._send(200, {"format": "verify-proof/1", "hash": "0f" * 32, "blockchain": "polygon", "tx_id": "0xabc", "anchored": True})
        if m == "GET" and p == "/api/v1/proofs?external_id=song-42":
            return self._send(200, {"proof": {"id": 7, "external_id": "song-42"}})
        if m == "GET" and p == "/api/v1/proofs?external_id=missing":
            return self._send(404, {"error": "No proof with that external_id on this account."})
        if m == "GET" and p == "/api/v1/proof/429m":
            return self._send(429, {"error": "Rate limit exceeded", "retry_after": 12}, {"Retry-After": "12"})
        if m == "GET" and p == "/api/v1/proof/429c":
            return self._send(429, {"error": "Monthly API proof limit reached."})
        return self._send(404, {"error": "not found"})

    do_GET = do_POST = do_DELETE = _handle


@pytest.fixture(scope="module")
def base_url():
    srv = HTTPServer(("127.0.0.1", 0), FakeAPI)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_submit_proof_sends_hash_and_label(base_url):
    r = api.submit_proof("0F" * 32, filename="song.mp3", key="sk_test", base_url=base_url)
    assert r["id"] == 7
    assert CALLS[-1]["body"] == {"sha256": "0f" * 32, "filename": "song.mp3"}
    assert CALLS[-1]["auth"] == "Bearer sk_test"


def test_bitcoin_flag_is_ignored_with_a_warning(base_url):
    with pytest.warns(DeprecationWarning, match="Bitcoin"):
        api.submit_proof("ab" * 32, filename="x.pdf", bitcoin=True, key="sk_test", base_url=base_url)
    assert "bitcoin_requested" not in CALLS[-1]["body"]


def test_summary_speaks_of_polygon_only():
    text = api.summarize({"id": 7, "sha256": "ab" * 32, "status": "approved", "bitcoin_requested": True,
                          "certificate_url": "https://proofledger.io/cert/7"})
    assert "Bitcoin" not in text and "Polygon" in text and "https://proofledger.io/cert/7" in text


def test_submit_batch_shapes_items_and_limits(base_url):
    r = api.submit_batch([{"sha256": "aa" * 32, "external_id": "b-1"}, {"sha256": "0xbb" + "bb" * 31}], key="sk_test", base_url=base_url)
    assert r["summary"]["created"] == 2
    assert CALLS[-1]["body"]["items"] == [{"sha256": "aa" * 32, "external_id": "b-1"}, {"sha256": "bb" * 32}]
    with pytest.raises(api.ProofLedgerError):
        api.submit_batch([], key="sk_test", base_url=base_url)
    with pytest.raises(api.ProofLedgerError):
        api.submit_batch([{"sha256": "aa" * 32}] * 101, key="sk_test", base_url=base_url)
    with pytest.raises(api.ProofLedgerError, match="Not a SHA-256"):
        api.submit_batch([{"sha256": "nope"}], key="sk_test", base_url=base_url)


def test_get_proof_bundle_and_lookup(base_url):
    assert api.get_proof(7, key="sk_test", base_url=base_url)["polygon_status"] == "ANCHORED"
    bundle = api.get_bundle(7, key="sk_test", base_url=base_url)
    assert bundle["blockchain"] == "polygon"
    import verify_proof
    assert verify_proof.verify_proof("0f" * 32, bundle)["verified"] is True, "a bundle verifies offline"
    assert api.get_proof_by_external_id("song-42", key="sk_test", base_url=base_url)["id"] == 7
    assert api.get_proof_by_external_id("missing", key="sk_test", base_url=base_url) is None
    with pytest.raises(api.ProofLedgerError, match="polygon"):
        api.get_bundle(7, chain="solana", key="sk_test", base_url=base_url)


def test_429_messages_tell_the_two_limits_apart(base_url):
    with pytest.raises(api.ProofLedgerError, match="per minute.*Retry after 12"):
        api.get_proof("429m", key="sk_test", base_url=base_url)
    with pytest.raises(api.ProofLedgerError, match="Monthly API proof limit"):
        api.get_proof("429c", key="sk_test", base_url=base_url)


def test_401_points_at_the_key(base_url):
    with pytest.raises(api.ProofLedgerError, match="401"):
        api.get_proof(7, key="sk_wrong", base_url=base_url)


def _sig(secret: str, t: int, body: bytes) -> str:
    return f"t={t},v1=" + hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()


def test_webhook_signature_helper_matches_the_server_format():
    secret = "whsec_" + "ab" * 16
    body = json.dumps({"id": "evt_1", "type": "proof.polygon.anchored"}).encode()
    now = 1_800_000_000
    assert api.verify_webhook_signature(secret, _sig(secret, now, body), body, now=now) is True
    assert api.verify_webhook_signature(secret, _sig(secret, now, body), body.decode(), now=now) is True, "str body"
    assert api.verify_webhook_signature(secret, _sig(secret, now, body), body + b" ", now=now) is False, "body changed"
    assert api.verify_webhook_signature("whsec_other", _sig(secret, now, body), body, now=now) is False
    assert api.verify_webhook_signature(secret, "garbage", body, now=now) is False
    assert api.verify_webhook_signature(secret, _sig(secret, now - 301, body), body, now=now) is False
    assert api.verify_webhook_signature(secret, _sig(secret, now - 299, body), body, now=now) is True
    assert api.verify_webhook_signature(secret, _sig(secret, now - 1000, body), body, tolerance_seconds=2000, now=now) is True
