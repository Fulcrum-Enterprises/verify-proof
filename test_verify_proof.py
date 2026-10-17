"""The verify verdict says what the offline check did, and nothing more.

The check compares the file with the bundle's hash and confirms the bundle names
a transaction. It never reads the chain, so the verdict reports the transaction
as the bundle's claim and points at a block explorer to confirm it. Same text as
the Node port (js/test.js), on the same fixtures.

Run:  python -m pytest test_verify_proof.py -q
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import verify_proof

HERE = Path(__file__).parent
EXAMPLES = HERE / "examples"


def test_the_fixture_matches_its_bundle_and_the_verdict_points_at_the_explorer():
    digest = verify_proof.hash_file(str(EXAMPLES / "sample.txt"))
    assert digest == "849e5f20ed851be78f67da44544a139386d79d6d4c5568abc49656469e485eb7"
    result = verify_proof.verify_proof(digest, verify_proof.load_proof(str(EXAMPLES / "proof.json")))
    assert result["verified"] is True
    msg = result["message"]
    assert msg.startswith(
        "File matches the proof bundle. The bundle says it was anchored on polygon at "
        "2026-03-15T10:30:00Z in transaction 0x9f2c"
    )
    assert (f"Merkle root computed from the path: {result['merkle_root']}. "
            "Compare it with the root recorded in the transaction.") in msg
    assert msg.endswith(
        f"Look that transaction up on a block explorer to confirm it: https://polygonscan.com/tx/{result['tx_id']}"
    )
    assert result["explorer_url"] == f"https://polygonscan.com/tx/{result['tx_id']}"
    assert "Proof verified" not in msg and "matches blockchain anchor" not in msg


def test_a_non_polygon_bundle_gets_the_same_wording_without_a_link():
    h = "ab" * 32
    result = verify_proof.verify_proof(h, {"hash": h, "blockchain": "bitcoin", "tx_id": "deadbeef"})
    assert result["verified"] is True
    assert result["message"] == (
        "File matches the proof bundle. The bundle says it was anchored on bitcoin in "
        "transaction deadbeef. Look that transaction up on a block explorer to confirm it."
    )
    assert "explorer_url" not in result


def test_a_mismatch_says_it_is_not_the_file_the_proof_was_made_for():
    result = verify_proof.verify_proof("de" * 32, {"hash": "00" * 32, "tx_id": "0xabc"})
    assert result["verified"] is False
    assert result["error"] == (
        "Hash mismatch: this is not the file the proof was made for "
        "(it was changed, or it is a different file)"
    )


def test_cli_exit_codes_are_unchanged(tmp_path):
    ok = subprocess.run(
        [sys.executable, "verify_proof.py", "verify", str(EXAMPLES / "sample.txt"), "--proof", str(EXAMPLES / "proof.json")],
        capture_output=True, text=True, cwd=str(HERE))
    assert ok.returncode == 0 and ok.stdout.startswith("VERIFIED: File matches the proof bundle.")
    other = tmp_path / "other.txt"
    other.write_text("not the sample\n", encoding="utf-8")
    bad = subprocess.run(
        [sys.executable, "verify_proof.py", "verify", str(other), "--proof", str(EXAMPLES / "proof.json")],
        capture_output=True, text=True, cwd=str(HERE))
    assert bad.returncode == 1 and bad.stdout.startswith("FAILED: Hash mismatch: this is not the file")
