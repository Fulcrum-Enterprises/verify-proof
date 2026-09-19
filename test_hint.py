"""The post-verify pointer must never get in anybody's way (audit MK-06).

417 installs in a month produced 10 tagged arrivals in 120 days, because the only
tagged link the package printed lived in the missing-key error on `create`, and
almost everybody runs `verify`, which never touches the network by design.

So `verify` now prints one line saying where proofs come from. The risk in doing
that is real and it is not hypothetical: a developer tool that nags gets
uninstalled, and a marketing line in stdout breaks whoever is parsing VERIFIED.
These tests are the manners.

Run:  python -m pytest test_hint.py -q
"""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

import verify_proof
from proofledger_api import HOME_URL


@pytest.fixture()
def proof_pair(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("hello lab\n", encoding="utf-8")
    h = hashlib.sha256(f.read_bytes()).hexdigest()
    p = tmp_path / "proof.json"
    p.write_text(json.dumps({
        "hash": h, "algorithm": "sha256", "blockchain": "polygon",
        "tx_id": "0xabc", "anchored_at": "2026-09-19T00:00:00Z",
        "service": "proofledger"}), encoding="utf-8")
    return f, p


class _Tty(io.StringIO):
    def isatty(self):
        return True


def test_a_human_at_a_terminal_sees_it(monkeypatch, capsys):
    monkeypatch.delenv("VERIFY_PROOF_NO_HINT", raising=False)
    monkeypatch.setattr(sys, "stdout", _Tty())
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    verify_proof._hint()
    assert "ProofLedger" in err.getvalue()
    assert HOME_URL in err.getvalue()


def test_the_link_is_tagged_so_arrivals_can_be_counted():
    """An untagged link is indistinguishable from someone typing the address, and
    the whole reason for this change was that nobody could tell."""
    assert "utm_source=verify-proof" in HOME_URL
    assert "utm_campaign=verified" in HOME_URL, (
        "its own campaign, so arrivals from verifying somebody else's proof are "
        "not confused with people who went looking for an API key")


def test_a_pipeline_never_hears_from_us(monkeypatch):
    """Not a TTY means scripted. A script does not need marketing."""
    monkeypatch.delenv("VERIFY_PROOF_NO_HINT", raising=False)
    monkeypatch.setattr(sys, "stdout", io.StringIO())   # isatty() is False
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    verify_proof._hint()
    assert err.getvalue() == ""


def test_one_env_var_turns_it_off_for_good(monkeypatch):
    monkeypatch.setenv("VERIFY_PROOF_NO_HINT", "1")
    monkeypatch.setattr(sys, "stdout", _Tty())
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    verify_proof._hint()
    assert err.getvalue() == ""


def test_stdout_stays_machine_readable(proof_pair):
    """The end-to-end guard: somebody is parsing this output. Run the real CLI
    as a subprocess, which is not a TTY, and assert stdout is exactly what it
    always was."""
    f, p = proof_pair
    r = subprocess.run([sys.executable, "verify_proof.py", "verify", str(f), "--proof", str(p)],
                       capture_output=True, text=True, cwd=str(Path(__file__).parent))
    assert r.returncode == 0
    assert r.stdout.startswith("VERIFIED: ")
    assert "proofledger.io" not in r.stdout.lower()
    assert r.stderr.strip() == ""


def test_a_broken_stdout_cannot_crash_a_verify(monkeypatch):
    """`verify` returning 0 matters more than any link. If stdout is something
    exotic that raises on isatty, the hint gives up rather than taking the
    command down with it."""
    class Hostile:
        def isatty(self):
            raise OSError("no")

    monkeypatch.delenv("VERIFY_PROOF_NO_HINT", raising=False)
    monkeypatch.setattr(sys, "stdout", Hostile())
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    verify_proof._hint()          # must not raise
    assert err.getvalue() == ""
