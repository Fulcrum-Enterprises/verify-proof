"""Agent run receipts: the chain, tamper detection, offline verification, anchoring
against a local fake API. Nothing here touches proofledger.io.

Run:  python -m pytest test_agent_receipt.py -q
"""
from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import agent_receipt as ar

SECRET = "ab" * 32
TX = "0x" + "cd" * 32


def bundle_for(head: str) -> dict:
    return {"hash": head, "algorithm": "sha256", "blockchain": "polygon", "tx_id": TX,
            "anchored_at": "2026-10-19T12:00:00.000Z", "merkle_path": [], "service": "proofledger"}


def test_fingerprint_and_links_are_plain_sha256():
    fp = ar.fingerprint(SECRET, "hello")
    assert fp == hashlib.sha256(bytes.fromhex(SECRET) + b"hello").hexdigest()
    assert ar.chain_start(SECRET) == hashlib.sha256(bytes.fromhex(SECRET)).hexdigest()
    prev = ar.chain_start(SECRET)
    expected = hashlib.sha256(f"{prev}\n0\nprompt\n2026-10-19T12:00:00Z\n{fp}\nhi".encode()).hexdigest()
    assert ar.link(prev, 0, "prompt", "2026-10-19T12:00:00Z", fp, "hi") == expected


def test_receipt_builds_a_deterministic_chain():
    r = ar.RunReceipt("run-1", agent={"name": "bot"}, secret=SECRET, started_at="2026-10-19T12:00:00Z")
    r.prompt("what is 2+2", label="question")
    r.tool_call(json.dumps({"tool": "calc", "args": [2, 2]}), label="calc")
    r.tool_result(b"4")
    r.output("4", label="answer")
    d = r.to_dict()
    assert d["format"] == ar.FORMAT
    assert [s["index"] for s in d["steps"]] == [0, 1, 2, 3]
    assert d["chain_head"] == ar.compute_head(d["chain_start"], d["steps"])
    # Recompute by hand with the documented rule.
    cur = ar.chain_start(SECRET)
    for s in d["steps"]:
        cur = hashlib.sha256(f"{cur}\n{s['index']}\n{s['type']}\n{s['at']}\n{s['fingerprint']}\n{s.get('label', '')}".encode()).hexdigest()
    assert cur == d["chain_head"]
    assert "what is 2+2" not in json.dumps(d)  # content never lands in the file


def test_step_rules():
    r = ar.RunReceipt("run-2", secret=SECRET)
    with pytest.raises(ValueError):
        r.add_step("thought", "x")
    with pytest.raises(ValueError):
        r.add_step("note", "x", label="y" * (ar.LABEL_MAX + 1))
    with pytest.raises(ValueError):
        r.add_step("note", "x", label="two\nlines")
    with pytest.raises(ValueError):
        ar.RunReceipt("", secret=SECRET)
    r.note("fine", label="  trimmed  ")
    assert r.steps[0]["label"] == "trimmed"


def test_verify_receipt_detects_tampering():
    r = ar.RunReceipt("run-3", secret=SECRET)
    r.prompt("a"); r.tool_call("b"); r.output("c", label="done")
    good = r.to_dict()
    good["proof"] = bundle_for(good["chain_head"])
    res = ar.verify_receipt(good)
    assert res["verified"] and res["chain_ok"] and res["anchored"] and res["steps"] == 3
    assert "3 steps" in res["message"]

    swapped = json.loads(json.dumps(good))
    swapped["steps"][0], swapped["steps"][1] = swapped["steps"][1], swapped["steps"][0]
    swapped["steps"][0]["index"], swapped["steps"][1]["index"] = 0, 1
    assert ar.verify_receipt(swapped)["chain_ok"] is False

    dropped = json.loads(json.dumps(good))
    dropped["steps"].pop(1)
    assert "out of order" in ar.verify_receipt(dropped)["error"]

    relabelled = json.loads(json.dumps(good))
    relabelled["steps"][2]["label"] = "not done"
    assert ar.verify_receipt(relabelled)["chain_ok"] is False

    retimed = json.loads(json.dumps(good))
    retimed["steps"][1]["at"] = "2020-01-01T00:00:00Z"
    assert ar.verify_receipt(retimed)["chain_ok"] is False

    wrong_bundle = json.loads(json.dumps(good))
    wrong_bundle["proof"]["hash"] = "ef" * 32
    res = ar.verify_receipt(wrong_bundle)
    assert res["chain_ok"] and not res["verified"] and "Bundle does not match" in res["error"]

    unanchored = json.loads(json.dumps(good))
    unanchored["proof"] = None
    res = ar.verify_receipt(unanchored)
    assert res["chain_ok"] and not res["verified"] and "no proof bundle" in res["error"]


def test_redacted_secret_still_verifies_but_cannot_check_content():
    r = ar.RunReceipt("run-4", secret=SECRET)
    r.prompt("private question")
    d = r.to_dict(include_secret=False)
    assert "secret" not in d
    d["proof"] = bundle_for(d["chain_head"])
    assert ar.verify_receipt(d)["verified"]
    assert ar.verify_step(d, 0, "private question")["verified"] is False
    assert ar.verify_step(d, 0, "private question", secret=SECRET)["verified"] is True
    assert ar.verify_step(d, 0, "other text", secret=SECRET)["verified"] is False
    with pytest.raises(ValueError):
        ar.RunReceipt.from_dict(d)   # needs the secret to continue a run


def test_load_round_trip_and_tamper_on_load(tmp_path):
    r = ar.RunReceipt("run-5", secret=SECRET)
    r.prompt("x"); r.output("y")
    p = tmp_path / "r.json"
    r.save(str(p))
    again = ar.RunReceipt.load(str(p))
    assert again.head == r.head and again.steps == r.steps
    data = json.loads(p.read_text())
    data["chain_head"] = "00" * 32
    with pytest.raises(ValueError):
        ar.RunReceipt.from_dict(data)


# ---- anchoring against a fake API ---------------------------------------------

CALLS: list[dict] = []
STATE = {"polls": 0}


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
        CALLS.append({"method": "POST", "path": self.path, "body": body, "auth": self.headers.get("Authorization")})
        if self.path == "/api/v1/proof":
            self._send(201, {"id": 7, "sha256": body["sha256"], "filename": body.get("filename"), "external_id": body.get("external_id"),
                             "polygon_status": "PENDING", "certificate_url": "/cert/7", "verification_url": "/verify.html?hash=" + body["sha256"]})
        else:
            self._send(404, {"error": "no"})

    def do_GET(self):
        CALLS.append({"method": "GET", "path": self.path})
        if self.path == "/api/v1/proof/7":
            STATE["polls"] += 1
            anchored = STATE["polls"] >= 2
            self._send(200, {"id": 7, "polygon_status": "ANCHORED" if anchored else "PENDING"})
        elif self.path.startswith("/api/v1/proof/7/bundle"):
            self._send(200, bundle_for(STATE["head"]))
        else:
            self._send(404, {"error": "no"})


@pytest.fixture(scope="module")
def base_url():
    server = HTTPServer(("127.0.0.1", 0), FakeAPI)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_anchor_sends_only_the_head_and_attaches_the_bundle(base_url):
    CALLS.clear(); STATE["polls"] = 0
    r = ar.RunReceipt("ticket-9", secret=SECRET)
    r.prompt("secret customer text", label="customer message")
    r.output("the reply")
    STATE["head"] = r.head
    proof = r.anchor(key="sk_test", base_url=base_url, wait=10, poll=1)
    assert proof["id"] == 7
    post = [c for c in CALLS if c["method"] == "POST"][0]
    assert post["body"] == {"sha256": r.head, "filename": "agent run ticket-9", "external_id": "ticket-9"}
    assert "secret customer text" not in json.dumps(CALLS)
    assert r.proof_id == 7 and r.proof["tx_id"] == TX
    assert r.certificate_url == f"{base_url}/cert/7"
    d = r.to_dict()
    assert ar.verify_receipt(d)["verified"]
    with pytest.raises(ValueError):
        r.output("no more steps after anchoring")


def test_anchor_without_waiting_then_attach_later(base_url):
    CALLS.clear(); STATE["polls"] = 0
    r = ar.RunReceipt("ticket-10", secret=SECRET)
    r.prompt("q")
    STATE["head"] = r.head
    r.anchor(key="sk_test", base_url=base_url, wait=0)
    assert r.proof is None and r.proof_id == 7
    res = ar.verify_receipt(r.to_dict())
    assert res["chain_ok"] and not res["verified"]
    STATE["polls"] = 5
    r.attach_bundle(key="sk_test", base_url=base_url)
    assert ar.verify_receipt(r.to_dict())["verified"]


def test_describe_lists_steps_without_content():
    r = ar.RunReceipt("run-6", secret=SECRET)
    r.prompt("hidden", label="shown")
    text = ar.describe(r.to_dict(include_secret=False))
    assert "shown" in text and "hidden" not in text and "redacted" in text


def test_shared_fixture_verifies_here_and_in_node():
    """examples/receipt.json is checked by js/test.js too; both ports must agree."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "examples", "receipt.json"), encoding="utf-8") as f:
        fixture = json.load(f)
    res = ar.verify_receipt(fixture)
    assert res["verified"] and res["steps"] == 4
    assert fixture["chain_head"] == "1e1cf8cb304891749efcaab20ca0d477a8c2ebe19e531061fef4a6a7d120ac97"
    assert ar.verify_step(fixture, 0, "What is the capital of France?")["verified"]
    assert ar.verify_step(fixture, 2, "Paris")["verified"]
    assert not ar.verify_step(fixture, 2, "Lyon")["verified"]


# ---- the CLI --------------------------------------------------------------------

def _cli(*args, env=None):
    import os, subprocess, sys
    e = {**os.environ, "VERIFY_PROOF_NO_HINT": "1", **(env or {})}
    here = os.path.dirname(os.path.abspath(__file__))
    return subprocess.run([sys.executable, os.path.join(here, "verify_proof.py"), *args], capture_output=True, text=True, env=e)


def test_cli_receipt_verify_show_and_step(tmp_path):
    r = ar.RunReceipt("run-7", secret=SECRET)
    r.prompt("the question", label="q")
    r.output("the answer")
    d = r.to_dict()
    d["proof"] = bundle_for(d["chain_head"])
    p = tmp_path / "run.receipt.json"
    p.write_text(json.dumps(d))
    content = tmp_path / "q.txt"
    content.write_text("the question")

    out = _cli("receipt", "verify", str(p))
    assert out.returncode == 0 and out.stdout.startswith("VERIFIED:") and TX in out.stdout

    out = _cli("receipt", "verify", str(p), "--step", "0", "--content", str(content))
    assert out.returncode == 0 and "STEP OK" in out.stdout

    content.write_text("another question")
    out = _cli("receipt", "verify", str(p), "--step", "0", "--content", str(content))
    assert out.returncode == 1 and "STEP FAILED" in out.stdout

    out = _cli("receipt", "show", str(p))
    assert out.returncode == 0 and "run-7" in out.stdout and "q" in out.stdout and "the question" not in out.stdout

    d["steps"][0]["label"] = "edited"
    p.write_text(json.dumps(d))
    out = _cli("receipt", "verify", str(p))
    assert out.returncode == 1 and out.stdout.startswith("FAILED:")


def test_cli_receipt_anchor_against_fake_api(base_url, tmp_path):
    CALLS.clear(); STATE["polls"] = 5
    r = ar.RunReceipt("run-8", secret=SECRET)
    r.prompt("q"); r.output("a")
    STATE["head"] = r.head
    p = tmp_path / "run8.receipt.json"
    r.save(str(p))
    out = _cli("receipt", "anchor", str(p), "--base-url", base_url, "--wait", "1", env={"PROOFLEDGER_API_KEY": "sk_test"})
    assert out.returncode == 0, out.stderr
    saved = json.loads(p.read_text())
    assert saved["proof_id"] == 7 and saved["proof"]["tx_id"] == TX
    out = _cli("receipt", "verify", str(p))
    assert out.returncode == 0 and out.stdout.startswith("VERIFIED:")
