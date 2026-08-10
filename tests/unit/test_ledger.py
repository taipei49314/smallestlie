"""Ledger chain integrity."""

from __future__ import annotations

from pathlib import Path

from smallestlie.ledger.chain import Ledger
from smallestlie.ledger.verify import verify_ledger


def test_ledger_verify_ok(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    led = Ledger(path)
    led.append("campaign_created", {"id": "1"})
    led.append("policy_validated", {"ok": True})
    result = verify_ledger(path)
    assert result["ok"] is True
    assert result["entries_checked"] == 2


def test_ledger_tamper_detected(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    led = Ledger(path)
    led.append("campaign_created", {"id": "1"})
    led.append("policy_validated", {"ok": True})
    text = path.read_text(encoding="utf-8")
    # Tamper payload without fixing digests.
    tampered = text.replace('"ok": true', '"ok": false')
    path.write_text(tampered, encoding="utf-8")
    result = verify_ledger(path)
    assert result["ok"] is False
