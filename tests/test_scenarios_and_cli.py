from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ai_automation_harness import Policy, verify_chain
from ai_automation_harness.cli import main
from ai_automation_harness.errors import HarnessError
from ai_automation_harness.scenarios import load_scenarios, parse_scenarios, run_scenarios

from .conftest import EXAMPLES

POLICY = str(EXAMPLES / "policy.yaml")
EMAIL_POLICY = str(EXAMPLES / "policy-email-enabled.yaml")
SCENARIOS = str(EXAMPLES / "scenarios.json")
EMAIL_SCENARIOS = str(EXAMPLES / "scenarios-email-enabled.json")


# ------------------------------------------------------------------ scenarios


@pytest.mark.parametrize(
    ("policy", "scenarios"), [(POLICY, SCENARIOS), (EMAIL_POLICY, EMAIL_SCENARIOS)]
)
def test_example_scenarios_match_their_expected_outcomes(policy: str, scenarios: str) -> None:
    results, audit, evidence = run_scenarios(load_scenarios(scenarios), Policy.load(policy))
    failures = [r.scenario.name for r in results if not r.passed]
    assert failures == []
    assert verify_chain(audit.events) == len(audit.events)
    assert len(evidence.refs()) == len(results)


def test_simulation_is_byte_for_byte_deterministic() -> None:
    def run() -> str:
        _, audit, _ = run_scenarios(load_scenarios(SCENARIOS), Policy.load(POLICY))
        return audit.to_jsonl()

    assert run() == run()


def test_example_scenario_counts_cover_every_required_threat() -> None:
    names = {s.name for s in load_scenarios(SCENARIOS)}
    assert {
        "unknown_tool",
        "undeclared_action",
        "excessive_scope",
        "draft_rejected",
        "draft_approval_expired",
        "draft_silent_drop",
        "draft_observer_down",
        "read_file_path_traversal",
        "injected_instruction_delete",
        "send_email_default_deny",
        "delete_file_default_deny",
    } <= names


@pytest.mark.parametrize(
    "raw",
    [
        {"not": "a list"},
        ["not an object"],
        [{"name": "x"}],
        [{"name": "x", "request": {}, "expect": {"decision": "MAYBE", "outcome": "DENIED"}}],
        [{"name": "x", "request": {}, "zzz": 1, "expect": {"decision": "DENY", "outcome": "X"}}],
        [
            {"name": "x", "request": {}, "expect": {"decision": "DENY", "outcome": "DENIED"}},
            {"name": "x", "request": {}, "expect": {"decision": "DENY", "outcome": "DENIED"}},
        ],
        [{"name": "x", "request": {}, "approval": "maybe",
          "expect": {"decision": "DENY", "outcome": "DENIED"}}],
        [{"name": "x", "request": {}, "faults": ["nope"],
          "expect": {"decision": "DENY", "outcome": "DENIED"}}],
    ],
)  # fmt: skip
def test_malformed_scenario_files_are_rejected(raw: object) -> None:
    with pytest.raises(HarnessError):
        parse_scenarios(raw)


def test_unreadable_scenario_file(tmp_path: Path) -> None:
    with pytest.raises(HarnessError):
        load_scenarios(tmp_path / "missing.json")


# ------------------------------------------------------------------ CLI


def test_evaluate_prints_a_human_readable_decision(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        ["evaluate", "--policy", POLICY, "--tool", "send_email", "--action", "send",
         "--scope", "email:send", "--args",
         '{"to": "a@example.org", "subject": "s", "body": "b"}']
    )  # fmt: skip
    out = capsys.readouterr().out
    assert code == 20
    assert "DENY" in out and "tool_not_in_allowed_tools" in out and "risk      high" in out


def test_evaluate_exit_codes_distinguish_the_three_decisions(
    capsys: pytest.CaptureFixture[str],
) -> None:
    allow = main(["evaluate", "--policy", POLICY, "--tool", "read_account", "--action", "read",
                  "--scope", "accounts:read", "--args", '{"account_id": "acct-1001"}'])  # fmt: skip
    approval = main(["evaluate", "--policy", POLICY, "--tool", "create_draft", "--action",
                     "create", "--scope", "drafts:write", "--args",
                     '{"to": "a@example.org", "subject": "s", "body": "b"}'])  # fmt: skip
    assert (allow, approval) == (0, 10)
    capsys.readouterr()


def test_evaluate_json_output_matches_the_documented_shape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = ["--tool", "delete_file", "--action", "delete", "--scope", "files:delete"]
    main(["evaluate", "--policy", POLICY, *args, "--args", '{"path": "docs/readme.txt"}', "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["decision"] == "DENY" and data["risk"] == "critical"
    assert data["reason_code"] == "tool_denied_by_policy"


def test_evaluate_side_effect_flag_and_bad_inputs(capsys: pytest.CaptureFixture[str]) -> None:
    base = ["evaluate", "--policy", POLICY, "--tool", "read_account", "--action", "read",
            "--scope", "accounts:read", "--args", '{"account_id": "acct-1001"}']  # fmt: skip
    assert main([*base, "--side-effect", "external"]) == 20
    assert main([*base[:-2], "--args", "{broken"]) == 2
    assert main(["evaluate", "--policy", POLICY, "--tool", "bad tool", "--action", "x",
                 "--scope", "a:b"]) == 2  # fmt: skip
    capsys.readouterr()


def test_simulate_exports_audit_and_evidence_and_audit_verify_accepts_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    audit = tmp_path / "audit.jsonl"
    evidence = tmp_path / "evidence"
    code = main(["simulate", "--policy", POLICY, "--scenarios", SCENARIOS,
                 "--audit-out", str(audit), "--evidence-dir", str(evidence)])  # fmt: skip
    out = capsys.readouterr().out
    assert code == 0
    assert "20/20 scenarios matched" in out
    assert len(audit.read_text().splitlines()) > 20
    assert len(list(evidence.glob("*.json"))) == 20

    assert main(["audit", "verify", str(audit)]) == 0
    assert "audit chain valid" in capsys.readouterr().out
    assert main(["audit", "summary", str(audit)]) == 0
    summary = capsys.readouterr().out
    assert "EXECUTED_NOT_VERIFIED=1" in summary and "DENIED=" in summary


def test_simulate_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["simulate", "--policy", POLICY, "--scenarios", SCENARIOS, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 20 and all(item["passed"] for item in data)


def test_simulate_reports_failure_when_an_expectation_is_not_met(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps([{
        "name": "optimistic",
        "request": {"request_id": "x1", "tool": "send_email", "action": "send",
                    "scope": "email:send", "arguments": {}},
        "expect": {"decision": "ALLOW", "outcome": "COMPLETED"},
    }]))  # fmt: skip
    assert main(["simulate", "--policy", POLICY, "--scenarios", str(wrong)]) == 1
    assert "!!" in capsys.readouterr().out


def test_audit_verify_detects_tampering(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    audit = tmp_path / "audit.jsonl"
    main(["simulate", "--policy", POLICY, "--scenarios", SCENARIOS, "--audit-out", str(audit)])
    capsys.readouterr()
    audit.write_text(audit.read_text().replace('"DENY"', '"ALLOW"', 1))
    assert main(["audit", "verify", str(audit)]) == 2
    assert "error:" in capsys.readouterr().err


def test_audit_verify_with_hmac_key_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ai_automation_harness.audit import AuditLog

    from .test_audit import event

    log = AuditLog(b"top-secret-key")
    log.append(event())
    path = tmp_path / "keyed.jsonl"
    log.write_jsonl(path)
    monkeypatch.setenv("HARNESS_KEY", "top-secret-key")
    assert main(["audit", "verify", str(path), "--hmac-key-env", "HARNESS_KEY"]) == 0
    monkeypatch.setenv("HARNESS_KEY", "other-key")
    assert main(["audit", "verify", str(path), "--hmac-key-env", "HARNESS_KEY"]) == 2
    monkeypatch.delenv("HARNESS_KEY")
    assert main(["audit", "verify", str(path), "--hmac-key-env", "HARNESS_KEY"]) == 2
    capsys.readouterr()


def test_policy_check_and_tools_listing(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    assert main(["policy", "check", "--policy", POLICY]) == 0
    assert "policy valid" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\ndefault_decision: allow\n")
    assert main(["policy", "check", "--policy", str(bad)]) == 2
    assert "unknown keys" in capsys.readouterr().err
    assert main(["tools"]) == 0
    listing = capsys.readouterr().out
    assert "send_email" in listing and "critical" in listing and "external" in listing


def test_audit_summary_of_empty_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert main(["audit", "summary", str(empty)]) == 0
    assert main(["audit", "verify", str(empty)]) == 2  # an empty log proves nothing
    assert main(["audit", "verify", str(empty), "--allow-empty"]) == 0
    capsys.readouterr()


def test_module_entry_point_runs_offline() -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("HTTP_PROXY", "HTTPS_PROXY")}
    proc = subprocess.run(
        [sys.executable, "-m", "ai_automation_harness", "--version"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert proc.returncode == 0 and "ai-automation-harness" in proc.stdout


@pytest.mark.parametrize(
    ("policy", "scenarios"), [(POLICY, SCENARIOS), (EMAIL_POLICY, EMAIL_SCENARIOS)]
)
def test_completed_is_reachable_only_through_verified(policy: str, scenarios: str) -> None:
    from ai_automation_harness import Outcome, VerificationStatus

    results, _, _ = run_scenarios(load_scenarios(scenarios), Policy.load(policy))
    for item in results:
        completed = item.result.outcome is Outcome.COMPLETED
        verified = item.result.verification_status is VerificationStatus.VERIFIED
        assert completed == verified, item.scenario.name
