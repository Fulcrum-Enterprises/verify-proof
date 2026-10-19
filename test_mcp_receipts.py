"""The receipt tools of the MCP server, called as plain functions (FastMCP's
decorator returns the function it registers). Skipped when the optional `mcp`
extra is not installed. The anchor tool is exercised against a local fake API.

Run:  python -m pytest test_mcp_receipts.py -q
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytest.importorskip("mcp")
import verify_proof_mcp as srv  # noqa: E402

TX = "0x" + "ef" * 32
STATE: dict = {}


class FakeAPI(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        STATE["post"] = body
        STATE["head"] = body["sha256"]
        self._send(201, {"id": 55, "sha256": body["sha256"], "polygon_status": "ANCHORED",
                         "certificate_url": "/cert/55", "verification_url": "/verify.html?hash=" + body["sha256"]})

    def do_GET(self):
        if self.path.startswith("/api/v1/proof/55/bundle"):
            self._send(200, {"hash": STATE["head"], "algorithm": "sha256", "blockchain": "polygon", "tx_id": TX,
                             "anchored_at": "2026-10-19T13:00:00Z", "merkle_path": [], "service": "proofledger"})
        else:
            self._send(200, {"id": 55, "polygon_status": "ANCHORED"})


@pytest.fixture(scope="module")
def base_url():
    server = HTTPServer(("127.0.0.1", 0), FakeAPI)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_receipt_tools_end_to_end(tmp_path, base_url, monkeypatch):
    path = str(tmp_path / "run.receipt.json")
    out = srv.start_run_receipt(path, "ticket-77", agent_name="support-bot", model="m")
    assert "Started receipt for run ticket-77" in out
    assert "already exists" in srv.start_run_receipt(path, "ticket-77")

    assert "Step 0 (prompt) recorded" in srv.add_receipt_step(path, "prompt", "customer text", label="customer message")
    assert "Step 1 (tool_call) recorded" in srv.add_receipt_step(path, "tool_call", '{"tool":"lookup"}', label="lookup")
    assert "Step 2 (output) recorded" in srv.add_receipt_step(path, "output", "reply")
    assert "Could not add the step" in srv.add_receipt_step(path, "thought", "x")
    data = json.loads(open(path, encoding="utf-8").read())
    assert "customer text" not in json.dumps(data) and len(data["steps"]) == 3

    # Not anchored yet: chain ok, not verified.
    out = srv.verify_run_receipt(path)
    assert out.startswith("NOT VERIFIED") and "no proof bundle" in out

    # Anchor against the fake API (the tool reads the key and base URL from the environment-free
    # client defaults, so point the module's client functions at the fake server).
    monkeypatch.setenv("PROOFLEDGER_API_KEY", "sk_test")
    import agent_receipt
    monkeypatch.setattr(agent_receipt, "DEFAULT_BASE_URL", base_url)
    real_anchor = agent_receipt.RunReceipt.anchor
    real_attach = agent_receipt.RunReceipt.attach_bundle
    monkeypatch.setattr(agent_receipt.RunReceipt, "anchor", lambda self, **kw: real_anchor(self, base_url=base_url, **{k: v for k, v in kw.items() if k != "base_url"}))
    monkeypatch.setattr(agent_receipt.RunReceipt, "attach_bundle", lambda self, **kw: real_attach(self, base_url=base_url, **{k: v for k, v in kw.items() if k != "base_url"}))
    out = srv.anchor_run_receipt(path, wait_seconds=5)
    assert out.startswith("Anchored receipt ticket-77") and TX in out, out
    assert STATE["post"] == {"sha256": data["chain_head"], "filename": "agent run ticket-77", "external_id": "ticket-77"}
    assert "already anchored" in srv.anchor_run_receipt(path)

    out = srv.verify_run_receipt(path, step_index=0, step_content="customer text")
    assert out.startswith("VERIFIED") and "STEP OK" in out and "polygonscan.com/tx/" in out
    out = srv.verify_run_receipt(path, step_index=0, step_content="other text")
    assert out.startswith("VERIFIED") and "STEP FAILED" in out
    assert "Could not add the step: this receipt is anchored" in srv.add_receipt_step(path, "note", "late")
