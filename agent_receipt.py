#!/usr/bin/env python3
"""agent_receipt — receipts for what an AI agent did, without storing what it saw.

Format `proofledger-agent-run-receipt/1`. A receipt is a hash chain over the steps
of one agent run (prompt, tool calls, tool results, outputs). Each step holds only
a fingerprint of its content: SHA-256 over a per-run random secret plus the content,
computed on the machine that ran the agent. The content itself is never written to
the receipt and never sent anywhere. The last link of the chain, the chain head, is
anchored on ProofLedger as an ordinary proof, and the proof bundle is saved into
the receipt.

Anyone holding the receipt can recompute the chain from the steps and check the
head against the bundle offline, exactly like `verify-proof verify` checks a file.
To check what one step was, the owner supplies that step's content and the secret;
the fingerprint is recomputed. Remove the `secret` field before handing a receipt
to a third party and the chain still verifies, but nothing in it can be guessed.

Chain rule (reproducible in any language):

    chain_start = SHA-256(secret bytes)
    link_i      = SHA-256(ascii(prev + "\\n" + index + "\\n" + type + "\\n" + at + "\\n" + fingerprint + "\\n" + label))
    chain_head  = the last link (chain_start when there are no steps)

`fingerprint = SHA-256(secret bytes + content bytes)`. `at` is the step's time as
written in the receipt and `label` is the optional short label (empty string when
absent), so neither can be edited afterwards without breaking the chain.

Only `anchor()` and `attach_bundle()` use the network (through proofledger_api);
everything else is pure computation.
"""

from __future__ import annotations

import hashlib
import json
import secrets as _secrets
import time
from datetime import datetime, timezone

from proofledger_api import (
    DEFAULT_BASE_URL,
    ProofLedgerError,
    get_bundle,
    get_proof,
    submit_proof,
)
from verify_proof import verify_proof as verify_bundle

FORMAT = "proofledger-agent-run-receipt/1"
STEP_TYPES = ("prompt", "tool_call", "tool_result", "output", "note")
LABEL_MAX = 120
_HEX64 = frozenset("0123456789abcdef")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _is_hex64(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def _to_bytes(content: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    return bytes(content)


def fingerprint(secret: str, content: bytes | str) -> str:
    """SHA-256 over the run secret and the step content. Pure computation."""
    if not _is_hex64(secret):
        raise ValueError("secret must be 64 hex characters (32 random bytes)")
    return hashlib.sha256(bytes.fromhex(secret) + _to_bytes(content)).hexdigest()


def chain_start(secret: str) -> str:
    if not _is_hex64(secret):
        raise ValueError("secret must be 64 hex characters (32 random bytes)")
    return hashlib.sha256(bytes.fromhex(secret)).hexdigest()


def link(prev: str, index: int, step_type: str, at: str, fp: str, label: str = "") -> str:
    material = f"{prev}\n{index}\n{step_type}\n{at}\n{fp}\n{label}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def compute_head(start: str, steps: list[dict]) -> str:
    """Recompute the chain head from `chain_start` and the steps as written."""
    current = start
    for s in steps:
        current = link(current, int(s["index"]), str(s["type"]), str(s.get("at", "")), str(s["fingerprint"]), str(s.get("label") or ""))
    return current


class RunReceipt:
    """Build a receipt step by step, then anchor its chain head.

    >>> r = RunReceipt("support-ticket-48213", agent={"name": "support-bot"})
    >>> r.prompt(customer_message, label="customer message")
    >>> r.tool_call(json.dumps(call), label="lookup_order")
    >>> r.tool_result(result_text)
    >>> r.output(reply, label="reply sent")
    >>> r.anchor()            # one API proof; waits for the Polygon anchor
    >>> r.save("run-48213.receipt.json")
    """

    def __init__(self, run_id: str, agent: dict | None = None, secret: str | None = None, started_at: str | None = None):
        run_id = str(run_id).strip()
        if not run_id or len(run_id) > 128:
            raise ValueError("run_id must be 1 to 128 characters")
        self.run_id = run_id
        self.agent = dict(agent) if agent else None
        self.secret = secret or _secrets.token_hex(32)
        if not _is_hex64(self.secret):
            raise ValueError("secret must be 64 hex characters (32 random bytes)")
        self.started_at = started_at or _now()
        self.finished_at: str | None = None
        self.steps: list[dict] = []
        self.proof: dict | None = None          # the bundle, once anchored
        self.proof_id: int | None = None
        self.certificate_url: str | None = None
        self.verification_url: str | None = None

    # ---- building ---------------------------------------------------------

    def add_step(self, step_type: str, content: bytes | str, label: str | None = None, at: str | None = None) -> dict:
        """Record one step. Only the fingerprint of `content` is kept."""
        if self.proof is not None or self.proof_id is not None:
            raise ValueError("this receipt is anchored; start a new run for more steps")
        if step_type not in STEP_TYPES:
            raise ValueError(f"step type must be one of {', '.join(STEP_TYPES)}")
        if label is not None:
            label = str(label).strip()
            if len(label) > LABEL_MAX:
                raise ValueError(f"label is over {LABEL_MAX} characters; labels are kept in the receipt, so keep them short and non-sensitive")
            if "\n" in label:
                raise ValueError("label must be one line")
        step = {
            "index": len(self.steps),
            "type": step_type,
            "at": at or _now(),
            "fingerprint": fingerprint(self.secret, content),
        }
        if label:
            step["label"] = label
        self.steps.append(step)
        return step

    def prompt(self, content, label=None):
        return self.add_step("prompt", content, label)

    def tool_call(self, content, label=None):
        return self.add_step("tool_call", content, label)

    def tool_result(self, content, label=None):
        return self.add_step("tool_result", content, label)

    def output(self, content, label=None):
        return self.add_step("output", content, label)

    def note(self, content, label=None):
        return self.add_step("note", content, label)

    @property
    def chain_start(self) -> str:
        return chain_start(self.secret)

    @property
    def head(self) -> str:
        return compute_head(self.chain_start, self.steps)

    def finish(self, at: str | None = None) -> None:
        if self.finished_at is None:
            self.finished_at = at or _now()

    # ---- anchoring (network) ---------------------------------------------

    def anchor(self, key: str | None = None, base_url: str = DEFAULT_BASE_URL, wait: int = 120, poll: int = 5) -> dict:
        """Anchor the chain head on ProofLedger: one API proof.

        Sends only the head, the label "agent run <run_id>" and `run_id` as
        external_id (a retried call returns the same proof). Waits up to `wait`
        seconds for the Polygon anchor, then saves the bundle into the receipt;
        with wait=0 it returns at once and `attach_bundle()` finishes the job later.
        """
        if not self.steps:
            raise ValueError("a receipt needs at least one step before it is anchored")
        self.finish()
        proof = submit_proof(self.head, filename=f"agent run {self.run_id}", key=key, base_url=base_url, external_id=self.run_id)
        self.proof_id = int(proof["id"])
        self.certificate_url = _absolute(proof.get("certificate_url"), base_url)
        self.verification_url = _absolute(proof.get("verification_url"), base_url)
        deadline = time.monotonic() + max(0, wait)
        status = str(proof.get("polygon_status") or "").upper()
        while status != "ANCHORED":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(max(1, poll), remaining))
            status = str(get_proof(self.proof_id, key=key, base_url=base_url).get("polygon_status") or "").upper()
        if status == "ANCHORED":
            self.attach_bundle(key=key, base_url=base_url)
        return proof

    def attach_bundle(self, key: str | None = None, base_url: str = DEFAULT_BASE_URL) -> dict:
        """Fetch the proof bundle for an anchored receipt and keep it inside."""
        if self.proof_id is None:
            raise ValueError("anchor() first")
        bundle = get_bundle(self.proof_id, key=key, base_url=base_url)
        if not bundle.get("tx_id"):
            raise ProofLedgerError("The anchor has not landed yet; try attach_bundle() again in a minute.")
        self.proof = bundle
        return bundle

    # ---- files ------------------------------------------------------------

    def to_dict(self, include_secret: bool = True) -> dict:
        out = {
            "format": FORMAT,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
        if self.agent:
            out["agent"] = self.agent
        if include_secret:
            out["secret"] = self.secret
        out["chain_start"] = self.chain_start
        out["steps"] = [dict(s) for s in self.steps]
        out["chain_head"] = self.head
        if self.proof_id is not None:
            out["proof_id"] = self.proof_id
            out["certificate_url"] = self.certificate_url
            out["verification_url"] = self.verification_url
        out["proof"] = self.proof
        return out

    def save(self, path: str, include_secret: bool = True) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(include_secret=include_secret), f, indent=2)
            f.write("\n")

    @classmethod
    def from_dict(cls, data: dict) -> "RunReceipt":
        if data.get("format") != FORMAT:
            raise ValueError(f"not a {FORMAT} receipt")
        if not data.get("secret"):
            raise ValueError("this receipt has no secret, so steps cannot be added or checked against content; verify_receipt() still works")
        r = cls(data["run_id"], agent=data.get("agent"), secret=data["secret"], started_at=data.get("started_at"))
        r.finished_at = data.get("finished_at")
        r.steps = [dict(s) for s in data.get("steps", [])]
        r.proof_id = data.get("proof_id")
        r.certificate_url = data.get("certificate_url")
        r.verification_url = data.get("verification_url")
        r.proof = data.get("proof")
        if r.chain_start != data.get("chain_start"):
            raise ValueError("chain_start does not match the secret")
        if r.head != data.get("chain_head"):
            raise ValueError("chain_head does not match the steps")
        return r

    @classmethod
    def load(cls, path: str) -> "RunReceipt":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


def _absolute(url, base_url: str):
    if not url:
        return None
    return f"{base_url.rstrip('/')}{url}" if str(url).startswith("/") else str(url)


# ---- checking (offline) -------------------------------------------------------

def verify_receipt(receipt: dict) -> dict:
    """Check a receipt without ProofLedger: structure, chain, then the bundle.

    Returns {"verified", "steps", "chain_head", "chain_ok", "anchored", "proof", "message"|"error"}.
    `verified` is true only when the chain recomputes AND the bundle names a
    transaction for that head. A receipt without a bundle gets chain_ok but not
    verified, with an error saying so.
    """
    result: dict = {"verified": False, "chain_ok": False, "anchored": False, "steps": 0}
    if not isinstance(receipt, dict) or receipt.get("format") != FORMAT:
        result["error"] = f"Not a {FORMAT} receipt"
        return result
    start = receipt.get("chain_start")
    steps = receipt.get("steps")
    head = receipt.get("chain_head")
    if not _is_hex64(start) or not _is_hex64(head) or not isinstance(steps, list):
        result["error"] = "Receipt is missing chain_start, chain_head or steps"
        return result
    secret = receipt.get("secret")
    if secret is not None:
        if not _is_hex64(secret) or chain_start(secret) != start:
            result["error"] = "chain_start does not match the secret"
            return result
    for i, s in enumerate(steps):
        if not isinstance(s, dict) or s.get("index") != i:
            result["error"] = f"Step {i} is out of order or missing"
            return result
        if s.get("type") not in STEP_TYPES or not _is_hex64(s.get("fingerprint")):
            result["error"] = f"Step {i} has an unknown type or a bad fingerprint"
            return result
    result["steps"] = len(steps)
    result["chain_head"] = head
    computed = compute_head(start, steps)
    if computed != head:
        result["error"] = "Chain mismatch: the steps do not add up to chain_head (a step was changed, dropped or reordered)"
        return result
    result["chain_ok"] = True
    proof = receipt.get("proof")
    if not proof:
        result["error"] = "Chain is intact but the receipt carries no proof bundle (not anchored yet, or attach_bundle() was never run)"
        return result
    bundle = verify_bundle(head, proof)
    result["proof"] = bundle
    if not bundle.get("verified"):
        result["error"] = "Bundle does not match the chain head: " + str(bundle.get("error", ""))
        return result
    result["anchored"] = True
    result["verified"] = True
    n = len(steps)
    result["message"] = (
        f"Receipt for run {receipt.get('run_id', '?')}: {n} step{'s' if n != 1 else ''} chain to head {head[:16]}…, "
        "and " + bundle["message"]
    )
    return result


def verify_step(receipt: dict, index: int, content: bytes | str, secret: str | None = None) -> dict:
    """Check that one step was made from this exact content. Needs the run secret."""
    secret = secret or receipt.get("secret")
    if not secret:
        return {"verified": False, "error": "This receipt carries no secret; the owner must supply it to check step content"}
    steps = receipt.get("steps") or []
    if not (0 <= int(index) < len(steps)):
        return {"verified": False, "error": f"No step {index} in this receipt"}
    step = steps[int(index)]
    expected = str(step.get("fingerprint", ""))
    got = fingerprint(secret, content)
    ok = got == expected
    out = {"verified": ok, "index": int(index), "type": step.get("type"), "label": step.get("label")}
    if ok:
        out["message"] = f"Step {index} ({step.get('type')}) was made from this content."
    else:
        out["error"] = f"Step {index} ({step.get('type')}) was not made from this content."
    return out


def describe(receipt: dict) -> str:
    """Plain-text listing of a receipt, for humans."""
    lines = [f"Agent run receipt: {receipt.get('run_id', '?')}"]
    agent = receipt.get("agent") or {}
    if agent:
        lines.append("  Agent      : " + ", ".join(f"{k}={v}" for k, v in agent.items()))
    lines.append(f"  Started    : {receipt.get('started_at', '')}")
    lines.append(f"  Finished   : {receipt.get('finished_at') or '(not finished)'}")
    lines.append(f"  Secret     : {'present (redact before sharing)' if receipt.get('secret') else 'redacted'}")
    lines.append(f"  Chain head : {receipt.get('chain_head', '')}")
    proof = receipt.get("proof") or {}
    if proof.get("tx_id"):
        lines.append(f"  Anchored   : {proof.get('blockchain', '')} {proof.get('tx_id', '')} at {proof.get('anchored_at', '')}")
    elif receipt.get("proof_id") is not None:
        lines.append(f"  Anchored   : pending (proof {receipt.get('proof_id')})")
    else:
        lines.append("  Anchored   : no")
    steps = receipt.get("steps") or []
    lines.append(f"  Steps      : {len(steps)}")
    for s in steps:
        label = f"  {s['label']}" if s.get("label") else ""
        lines.append(f"    {s.get('index'):>3}  {s.get('type', ''):<11} {s.get('at', '')}  {str(s.get('fingerprint', ''))[:16]}…{label}")
    return "\n".join(lines)
