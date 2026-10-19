"""Agent run receipts from LangChain callbacks.

Drop `ReceiptCallbackHandler` into any LangChain run (`callbacks=[handler]`) and
every prompt, tool call, tool result and final output is fingerprinted into one
`RunReceipt`. Nothing the agent saw is stored: only SHA-256 fingerprints,
salted with the run secret, plus a short label. At the end, `handler.finish()`
anchors the chain head on ProofLedger (one API proof) and saves the receipt.

The handler only needs `langchain_core` when you actually run it inside
LangChain; it is written against the callback method names, so this file
imports nothing from LangChain and the demo at the bottom runs on its own.

    pip install verify-proof langchain-openai   # or any LangChain setup
    export PROOFLEDGER_API_KEY=sk_...

    from langchain_receipt_callback import ReceiptCallbackHandler
    handler = ReceiptCallbackHandler("ticket-48213", agent={"name": "support-bot"})
    agent_executor.invoke({"input": question}, config={"callbacks": [handler]})
    path = handler.finish()      # anchors, then writes ticket-48213.receipt.json

Verify later, offline:  verify-proof receipt verify ticket-48213.receipt.json
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent_receipt import RunReceipt  # noqa: E402

try:  # Subclass the real base when LangChain is installed, so callback dispatch works.
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:  # pragma: no cover - the demo below runs without LangChain
    class BaseCallbackHandler:  # type: ignore[no-redef]
        pass


def _text(value) -> str:
    """Stable text for anything LangChain hands a callback: strings as they are, else JSON."""
    if isinstance(value, (str, bytes)):
        return value if isinstance(value, str) else value.decode("utf-8", "replace")
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


class ReceiptCallbackHandler(BaseCallbackHandler):
    """Fingerprints each callback into a RunReceipt. Labels are short and non-sensitive
    (the tool name, "prompt", "output"); the content itself is only ever hashed."""

    def __init__(self, run_id: str, agent: dict | None = None, directory: str = ".", wait: int = 120):
        super().__init__()
        self.receipt = RunReceipt(run_id, agent=agent)
        self.directory = directory
        self.wait = wait

    # LangChain callback names (same signatures as BaseCallbackHandler, extras ignored)
    def on_llm_start(self, serialized, prompts, **kwargs):
        for p in prompts:
            self.receipt.prompt(_text(p), label="prompt")

    def on_chat_model_start(self, serialized, messages, **kwargs):
        for conversation in messages:
            self.receipt.prompt(_text([getattr(m, "content", m) for m in conversation]), label="chat prompt")

    def on_tool_start(self, serialized, input_str, **kwargs):
        name = (serialized or {}).get("name") or "tool"
        self.receipt.tool_call(_text({"tool": name, "input": input_str}), label=str(name)[:120])

    def on_tool_end(self, output, **kwargs):
        self.receipt.tool_result(_text(output), label="tool result")

    def on_tool_error(self, error, **kwargs):
        self.receipt.tool_result(_text({"error": str(error)}), label="tool error")

    def on_llm_end(self, response, **kwargs):
        try:
            text = _text([[getattr(g, "text", g) for g in gen] for gen in response.generations])
        except AttributeError:
            text = _text(response)
        self.receipt.output(text, label="model output")

    def on_chain_end(self, outputs, **kwargs):
        if kwargs.get("parent_run_id") is None:  # the top-level chain's final answer
            self.receipt.output(_text(outputs), label="final output")

    def finish(self, anchor: bool = True) -> str:
        """Anchor the chain head (one API proof) and write <run_id>.receipt.json. Returns the path."""
        if anchor:
            self.receipt.anchor(wait=self.wait)
        path = os.path.join(self.directory, f"{self.receipt.run_id}.receipt.json")
        self.receipt.save(path)
        return path


if __name__ == "__main__":
    # Demo without LangChain or a network: drive the callbacks by hand, then verify.
    from agent_receipt import verify_receipt, verify_step

    h = ReceiptCallbackHandler("demo-run", agent={"name": "demo-agent"})
    h.on_llm_start({}, ["What is the capital of France?"])
    h.on_tool_start({"name": "lookup"}, "capital of France")
    h.on_tool_end("Paris")
    h.on_chain_end({"output": "The capital of France is Paris."}, parent_run_id=None)
    receipt = h.receipt.to_dict()
    print(f"{len(receipt['steps'])} steps, chain head {receipt['chain_head']}")
    print("step 0 was the question:", verify_step(receipt, 0, "What is the capital of France?")["verified"])
    print("verified without a bundle:", verify_receipt(receipt)["verified"], "(anchor it with h.finish() and the key set)")
