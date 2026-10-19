"""Writes examples/receipt.json: a deterministic agent run receipt (fixed secret and
times, a made-up Polygon transaction) that the Python and Node tests both verify, so
the two ports can never disagree about a receipt. Run from the repo root:
    python examples/make_receipt_fixture.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent_receipt as ar  # noqa: E402

SECRET = "ab" * 32
r = ar.RunReceipt("example-run-1", agent={"name": "example-agent", "model": "example-model"}, secret=SECRET, started_at="2026-10-19T12:00:00Z")
r.add_step("prompt", "What is the capital of France?", label="user question", at="2026-10-19T12:00:01Z")
r.add_step("tool_call", json.dumps({"tool": "lookup", "args": {"q": "capital of France"}}), label="lookup", at="2026-10-19T12:00:02Z")
r.add_step("tool_result", "Paris", at="2026-10-19T12:00:03Z")
r.add_step("output", "The capital of France is Paris.", label="answer", at="2026-10-19T12:00:04Z")
r.finish("2026-10-19T12:00:05Z")
d = r.to_dict()
d["proof_id"] = 123
d["certificate_url"] = "https://proofledger.io/cert/123"
d["verification_url"] = "https://proofledger.io/verify.html?hash=" + d["chain_head"]
d["proof"] = {
    "hash": d["chain_head"], "algorithm": "sha256", "blockchain": "polygon",
    "tx_id": "0x9f2c" + "ab" * 30, "anchored_at": "2026-10-19T12:01:00Z",
    "merkle_path": [], "service": "proofledger", "proof_id": 123,
}
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "receipt.json")
with open(out, "w", encoding="utf-8", newline="\n") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
print("wrote", out, "chain_head", d["chain_head"])
