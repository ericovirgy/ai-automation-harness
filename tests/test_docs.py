"""Documentation references must not rot: every test named in the threat model must exist."""

from __future__ import annotations

import re
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REFERENCE = re.compile(r"`(tests/[a-z_]+\.py)::([A-Za-z0-9_]+)`")


def test_every_test_named_in_the_threat_model_exists() -> None:
    text = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    references = REFERENCE.findall(text)
    assert len(references) >= 40
    missing = []
    for path, name in references:
        source = ROOT / path
        if not source.exists() or f"def {name}(" not in source.read_text(encoding="utf-8"):
            missing.append(f"{path}::{name}")
    assert missing == []


def test_threat_model_covers_every_required_threat_class() -> None:
    text = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8").lower()
    for phrase in (
        "unauthorized tool invocation",
        "privilege escalation via scope",
        "prompt or tool-output injection",
        "approval bypass",
        "verification bypass",
        "evidence tampering",
        "ambiguous state interpreted as success",
    ):
        assert phrase in text, phrase


def test_library_usage_example_runs_and_completes(capsys: pytest.CaptureFixture[str]) -> None:
    runpy.run_path(str(ROOT / "examples" / "library_usage.py"), run_name="__main__")
    out = capsys.readouterr().out
    assert "REQUIRE_APPROVAL PENDING_APPROVAL" in out
    assert "COMPLETED VERIFIED" in out
