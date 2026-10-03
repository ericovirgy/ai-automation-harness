from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ai_automation_harness import (
    ArgSpec,
    Decision,
    Policy,
    PolicyEngine,
    ReasonCode,
    Risk,
    SideEffect,
    ToolRegistry,
    ToolRequest,
    ToolSpec,
)
from ai_automation_harness.errors import MalformedPolicyError
from ai_automation_harness.tools.demo import build_demo_registry
from ai_automation_harness.verification import state_unchanged

from .conftest import EXAMPLES, draft_req, email_policy, mail_req, make_policy, policy_dict, req


def evaluate(policy: Policy, request: ToolRequest) -> Any:
    return PolicyEngine(policy, build_demo_registry()).evaluate(request)


# ------------------------------------------------------------------ loading and ambiguity


def test_example_policies_load() -> None:
    for name in ("policy.yaml", "policy-email-enabled.yaml"):
        policy = Policy.load(EXAMPLES / name)
        PolicyEngine(policy, build_demo_registry())


def test_json_policy_is_equivalent_to_yaml(tmp_path: Path) -> None:
    path = tmp_path / "p.json"
    path.write_text(json.dumps(policy_dict()))
    assert Policy.load(path).allowed_tools.keys() == make_policy().allowed_tools.keys()


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": 2},
        {"version": True},
        {"version": None},
        {"default_decision": "allow"},  # deny-by-default is not configurable
        {"allowed_tools": ["read_account"]},
        {"allowed_tools": {"Bad-Name": {"scopes": ["accounts:read"]}}},
        {"allowed_tools": {"read_account": {}}},  # scopes are mandatory (least privilege)
        {"allowed_tools": {"read_account": {"scopes": []}}},
        {"allowed_tools": {"read_account": {"scopes": ["accounts:admin"]}}},  # outside ceiling
        {"allowed_tools": {"read_account": {"scopes": ["bad scope"]}}},
        {"allowed_tools": {"read_account": {"scopes": ["accounts:read"], "approval": "never"}}},
        {"allowed_tools": {"read_account": {"scopes": ["accounts:read"], "actions": []}}},
        {"allowed_tools": {"read_account": {"scopes": ["accounts:read"], "extra": 1}}},
        {
            "allowed_tools": {
                "read_account": {"scopes": ["accounts:read"], "argument_allowlists": {"a": []}}
            }
        },
        {"denied_tools": ["read_account"]},  # allowed and denied: ambiguous
        {"denied_tools": ["x_tool", "x_tool"]},
        {"denied_tools": "delete_file"},
        {"allowed_scopes": ["bad scope"]},
        {"risk": {"max_auto_risk": "critical"}},
        {"risk": {"max_auto_risk": "high", "max_risk": "high"}},
        {"risk": {"max_auto_risk": "medium", "max_risk": "low"}},
        {"risk": {"max_auto_risk": "LOW"}},
        {"risk": {"surprise": "low"}},
        {"approvals": {"ttl_seconds": 0}},
        {"approvals": {"ttl_seconds": 10**9}},
        {"approvals": {"ttl_seconds": True}},
        {"verification": {"required_from_risk": "nope"}},
    ],
)
def test_malformed_or_ambiguous_policies_fail_closed(overrides: dict[str, Any]) -> None:
    with pytest.raises(MalformedPolicyError):
        make_policy(**overrides)


def test_non_mapping_policy_is_rejected() -> None:
    with pytest.raises(MalformedPolicyError):
        Policy.from_mapping(["version", 1])


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\nversion: 1\n",  # duplicate key
        "version: 1\nallowed_tools:\n  a: {scopes: [x:y]}\n  a: {scopes: [x:y]}\n",
        "version: &v 1\nother: *v\n",  # alias
        "version: [1",  # syntax error
        "- not\n- a mapping\n",
        "",
    ],
)
def test_yaml_pitfalls_are_rejected(text: str) -> None:
    with pytest.raises(MalformedPolicyError):
        Policy.from_text(text)


def test_json_duplicate_keys_are_rejected() -> None:
    with pytest.raises(MalformedPolicyError):
        Policy.from_text('{"version": 1, "version": 1}', "json")
    with pytest.raises(MalformedPolicyError):
        Policy.from_text("{not json", "json")


def test_policy_file_checks(tmp_path: Path) -> None:
    with pytest.raises(MalformedPolicyError):
        Policy.load(tmp_path / "missing.yaml")
    wrong = tmp_path / "policy.txt"
    wrong.write_text("version: 1")
    with pytest.raises(MalformedPolicyError):
        Policy.load(wrong)
    big = tmp_path / "big.yaml"
    big.write_text("# " + "x" * (300 * 1024) + "\nversion: 1\n")
    with pytest.raises(MalformedPolicyError):
        Policy.load(big)
    with pytest.raises(MalformedPolicyError):
        Policy.from_text("# " + "x" * (300 * 1024), "yaml")


def test_policy_digest_is_stable_and_changes_with_content() -> None:
    assert make_policy().digest == make_policy().digest
    other = make_policy(denied_tools=["delete_file", "send_email"])
    assert other.digest != make_policy().digest


# ------------------------------------------------------------------ policy vs registry


def test_policy_referencing_undeclared_tool_is_rejected() -> None:
    data = policy_dict()
    data["allowed_tools"]["transfer_funds"] = {"scopes": ["accounts:read"]}
    with pytest.raises(MalformedPolicyError):
        PolicyEngine(Policy.from_mapping(data), build_demo_registry())


def test_policy_cannot_grant_scope_a_tool_never_declared() -> None:
    data = policy_dict()
    data["allowed_scopes"].append("accounts:admin")
    data["allowed_tools"]["read_account"]["scopes"].append("accounts:admin")
    with pytest.raises(MalformedPolicyError):
        PolicyEngine(Policy.from_mapping(data), build_demo_registry())


def test_policy_cannot_name_undeclared_actions_or_arguments() -> None:
    data = policy_dict()
    data["allowed_tools"]["read_account"]["actions"] = ["read", "write"]
    with pytest.raises(MalformedPolicyError):
        PolicyEngine(Policy.from_mapping(data), build_demo_registry())
    data = policy_dict()
    data["allowed_tools"]["read_account"]["argument_allowlists"] = {"nonexistent": ["*"]}
    with pytest.raises(MalformedPolicyError):
        PolicyEngine(Policy.from_mapping(data), build_demo_registry())


def test_policy_requiring_verification_rejects_tools_without_checks() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="unchecked",
            description="No verification declared.",
            risk=Risk.READ,
            scopes=frozenset({"accounts:read"}),
            side_effects=SideEffect.NONE,
            allowed_actions=frozenset({"read"}),
            requires_approval=False,
            arguments={"a": ArgSpec(required=False)},
        ),
        lambda ctx: {},
    )
    with pytest.raises(MalformedPolicyError):
        PolicyEngine(make_policy(allowed_tools={}), registry)
    relaxed = make_policy(allowed_tools={}, verification={"required_from_risk": "critical"})
    PolicyEngine(relaxed, registry)


# ------------------------------------------------------------------ the five reference decisions


def test_example_1_read_account_is_allowed() -> None:
    d = evaluate(make_policy(), req())
    assert (d.decision, d.risk, d.reason_code) == (Decision.ALLOW, Risk.READ, ReasonCode.ALLOWED)


def test_example_2_create_draft_requires_approval() -> None:
    d = evaluate(make_policy(), draft_req())
    assert d.decision is Decision.REQUIRE_APPROVAL
    assert d.risk is Risk.MEDIUM
    assert d.reason_code is ReasonCode.APPROVAL_RISK_THRESHOLD


def test_example_3_send_email_is_denied_without_explicit_policy() -> None:
    d = evaluate(make_policy(), mail_req())
    assert d.decision is Decision.DENY
    assert d.risk is Risk.HIGH
    assert d.reason_code is ReasonCode.TOOL_NOT_ALLOWED


def test_example_3_send_email_needs_approval_once_policy_allows_it() -> None:
    d = evaluate(email_policy(), mail_req())
    assert d.decision is Decision.REQUIRE_APPROVAL
    assert d.reason_code is ReasonCode.APPROVAL_TOOL_DECLARATION


def test_example_4_delete_file_is_denied_by_default() -> None:
    request = req("r1", "delete_file", "delete", "files:delete", {"path": "docs/readme.txt"})
    assert evaluate(make_policy(), request).reason_code is ReasonCode.TOOL_DENIED
    # not listed at all: still denied
    assert (
        evaluate(make_policy(denied_tools=[]), request).reason_code is ReasonCode.TOOL_NOT_ALLOWED
    )


def test_example_5_unknown_tool_is_denied_fail_closed() -> None:
    d = evaluate(make_policy(), req("r1", "transfer_funds", "run", "payments:write", {}))
    assert d.decision is Decision.DENY
    assert d.reason_code is ReasonCode.UNKNOWN_TOOL
    assert d.risk is None
    assert d.to_dict()["risk"] == "unknown"


# ------------------------------------------------------------------ adversarial evaluation


def test_undeclared_action_is_denied() -> None:
    d = evaluate(make_policy(), req(action="write"))
    assert d.reason_code is ReasonCode.UNDECLARED_ACTION


def test_attempted_write_through_read_only_tool_is_denied() -> None:
    d = evaluate(make_policy(), req(action="delete", arguments={"account_id": "acct-1001"}))
    assert d.decision is Decision.DENY
    d = evaluate(
        make_policy(),
        req(arguments={"account_id": "acct-1001"}, side_effect=SideEffect.INTERNAL),
    )
    assert d.reason_code is ReasonCode.SIDE_EFFECT_MISMATCH


def test_understated_side_effect_is_denied_too() -> None:
    d = evaluate(make_policy(), draft_req(side_effect=SideEffect.NONE))
    assert d.reason_code is ReasonCode.SIDE_EFFECT_MISMATCH


def test_excessive_scope_is_denied() -> None:
    assert evaluate(make_policy(), req(scope="accounts:admin")).reason_code is (
        ReasonCode.SCOPE_NOT_DECLARED
    )


def test_scope_declared_by_tool_but_not_granted_by_policy_is_denied() -> None:
    policy = make_policy(
        allowed_tools={
            "read_file": {"scopes": ["files:read"]},
            "create_draft": {"scopes": ["drafts:write"]},
        }
    )
    request = req("r1", "read_file", "read", "files:read", {"path": "docs/readme.txt"})
    assert evaluate(policy, request).decision is Decision.ALLOW
    # a tool that declares two scopes only gets the one the policy names
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="two_scopes",
            description="Reads from two places.",
            risk=Risk.READ,
            scopes=frozenset({"a:read", "b:read"}),
            side_effects=SideEffect.NONE,
            allowed_actions=frozenset({"read"}),
            requires_approval=False,
        ),
        lambda ctx: {},
        checks=[state_unchanged()],
    )
    engine = PolicyEngine(
        make_policy(
            allowed_scopes=["a:read", "b:read"],
            allowed_tools={"two_scopes": {"scopes": ["a:read"]}},
        ),
        registry,
    )
    ok = engine.evaluate(ToolRequest("r1", "two_scopes", "read", "a:read", {}))
    bad = engine.evaluate(ToolRequest("r2", "two_scopes", "read", "b:read", {}))
    assert ok.decision is Decision.ALLOW
    assert bad.reason_code is ReasonCode.SCOPE_NOT_GRANTED


def test_policy_can_restrict_actions_further_than_the_declaration() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="multi_action",
            description="Two read actions.",
            risk=Risk.READ,
            scopes=frozenset({"a:read"}),
            side_effects=SideEffect.NONE,
            allowed_actions=frozenset({"read", "list"}),
            requires_approval=False,
        ),
        lambda ctx: {},
        checks=[state_unchanged()],
    )
    engine = PolicyEngine(
        make_policy(
            allowed_scopes=["a:read"],
            allowed_tools={"multi_action": {"scopes": ["a:read"], "actions": ["read"]}},
        ),
        registry,
    )
    assert engine.evaluate(ToolRequest("r1", "multi_action", "read", "a:read", {})).decision is (
        Decision.ALLOW
    )
    assert engine.evaluate(ToolRequest("r2", "multi_action", "list", "a:read", {})).reason_code is (
        ReasonCode.ACTION_NOT_PERMITTED
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {"account_id": "acct-1001", "admin": True},  # unexpected argument
        {},  # missing
        {"account_id": "acct-1001; DROP TABLE"},  # pattern
        {"account_id": 1001},  # wrong type
        {"account_id": "acct-1001" + "0" * 50},  # too long
    ],
)
def test_unexpected_or_invalid_arguments_are_denied(arguments: dict[str, Any]) -> None:
    d = evaluate(make_policy(), req(arguments=arguments))
    assert d.reason_code is ReasonCode.INVALID_ARGUMENTS


@pytest.mark.parametrize(
    "path",
    [
        "secrets/credentials.txt",
        "docs/../secrets/credentials.txt",
        "../docs/readme.txt",
        "docs/./../x",
        "docs\\..\\secrets",
        "/etc/passwd",
    ],
)
def test_path_allowlist_cannot_be_bypassed(path: str) -> None:
    d = evaluate(make_policy(), req("r1", "read_file", "read", "files:read", {"path": path}))
    assert d.decision is Decision.DENY


def test_valid_looking_request_is_still_denied_by_allowlist() -> None:
    """Passes every structural check but targets a recipient outside the allowlist."""
    d = evaluate(make_policy(), draft_req(to="mallory@evil.test"))
    assert d.reason_code is ReasonCode.ARGUMENT_NOT_ALLOWLISTED
    assert d.details["argument"] == "to"


def test_risk_ceiling_denies_even_when_listed() -> None:
    data = policy_dict(denied_tools=[], risk={"max_auto_risk": "low", "max_risk": "medium"})
    data["allowed_scopes"].append("files:delete")
    data["allowed_tools"]["delete_file"] = {"scopes": ["files:delete"]}
    request = req("r1", "delete_file", "delete", "files:delete", {"path": "docs/readme.txt"})
    d = evaluate(Policy.from_mapping(data), request)
    assert d.reason_code is ReasonCode.RISK_ABOVE_CEILING


def test_critical_actions_always_need_approval_when_allowed() -> None:
    data = policy_dict(denied_tools=[], risk={"max_auto_risk": "medium", "max_risk": "critical"})
    data["allowed_scopes"].append("files:delete")
    data["allowed_tools"]["delete_file"] = {"scopes": ["files:delete"]}
    request = req("r1", "delete_file", "delete", "files:delete", {"path": "docs/readme.txt"})
    d = evaluate(Policy.from_mapping(data), request)
    assert d.decision is Decision.REQUIRE_APPROVAL


def test_policy_cannot_remove_an_approval_requirement_the_tool_declares() -> None:
    """Whatever the policy says about auto thresholds, send_email stays approval-gated."""
    policy = email_policy()
    assert policy.max_auto_risk <= Risk.MEDIUM
    assert evaluate(policy, mail_req()).decision is Decision.REQUIRE_APPROVAL


def test_policy_rule_can_add_approval_to_a_low_risk_tool() -> None:
    data = policy_dict()
    data["allowed_tools"]["read_account"]["approval"] = "required"
    d = evaluate(Policy.from_mapping(data), req())
    assert d.reason_code is ReasonCode.APPROVAL_POLICY_RULE


def test_same_request_gets_different_decisions_under_different_policies() -> None:
    request = mail_req()
    assert evaluate(make_policy(), request).decision is Decision.DENY
    assert evaluate(email_policy(), request).decision is Decision.REQUIRE_APPROVAL


def test_evaluation_is_deterministic() -> None:
    engine = PolicyEngine(make_policy(), build_demo_registry())
    first = engine.evaluate(draft_req())
    assert all(engine.evaluate(draft_req()) == first for _ in range(25))


def test_decision_has_machine_readable_shape() -> None:
    d = evaluate(make_policy(), mail_req()).to_dict()
    assert d["decision"] == "DENY"
    assert d["tool"] == "send_email"
    assert d["risk"] == "high"
    assert d["reason_code"] == "tool_not_in_allowed_tools"
    assert isinstance(d["reason"], str) and d["reason"]
    json.dumps(d)
