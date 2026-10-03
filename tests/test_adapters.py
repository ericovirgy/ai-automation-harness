from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from ai_automation_harness import Decision, Harness, Outcome, ReasonCode
from ai_automation_harness.adapters import ScriptedAgent, request_from_tool_call, run_agent
from ai_automation_harness.errors import MalformedRequestError
from ai_automation_harness.world import SimulatedWorld

from .conftest import HarnessFactory


def test_generic_and_openai_style_calls_are_translated() -> None:
    call = {
        "name": "read_account",
        "arguments": json.dumps(
            {"action": "read", "scope": "accounts:read", "account_id": "acct-1001"}
        ),
    }
    request = request_from_tool_call(call, request_id="c1")
    assert (request.tool, request.action, request.scope) == (
        "read_account",
        "read",
        "accounts:read",
    )
    assert dict(request.arguments) == {"account_id": "acct-1001"}


def test_anthropic_style_tool_use_block_is_translated() -> None:
    block = {
        "type": "tool_use",
        "id": "toolu_1",
        "name": "search_records",
        "input": {"action": "search", "scope": "records:read", "query": "invoice"},
    }
    request = request_from_tool_call(block, request_id="c2", requester="model")
    assert request.requester == "model" and request.arguments["query"] == "invoice"


@pytest.mark.parametrize(
    "call",
    [
        "not a mapping",
        {"name": "read_account"},
        {"name": "read_account", "arguments": "{broken"},
        {"name": "read_account", "arguments": "[1, 2]"},
        {"name": "read_account", "arguments": {"scope": "accounts:read"}},  # no action
        {"name": "read_account", "arguments": {"action": "read"}},  # no scope
        {"name": None, "arguments": {"action": "read", "scope": "accounts:read"}},
    ],
)
def test_malformed_tool_calls_are_rejected(call: object) -> None:
    with pytest.raises(MalformedRequestError):
        request_from_tool_call(call, request_id="c3")  # type: ignore[arg-type]


def test_prompt_injection_in_tool_output_cannot_trigger_a_deletion(
    make_harness: HarnessFactory,
) -> None:
    """A naive agent obeys an instruction planted in a record. The harness still says no."""
    world = SimulatedWorld()
    harness: Harness = make_harness(world=world)

    def naive_agent(observation: str) -> Sequence[Mapping[str, Any]]:
        if "delete docs/readme.txt" in observation:
            arguments = {"action": "delete", "scope": "files:delete", "path": "docs/readme.txt"}
            return [{"name": "delete_file", "arguments": arguments}]
        return []

    search = harness.submit(
        {
            "request_id": "inj-search",
            "tool": "search_records",
            "action": "search",
            "scope": "records:read",
            "arguments": {"query": "ignore previous"},
        }
    )
    assert search.outcome is Outcome.COMPLETED
    assert search.output is not None
    observation = json.dumps(search.output)
    assert "delete docs/readme.txt" in observation  # the injection really reached the agent

    results = run_agent(harness, ScriptedAgent(naive_agent), observation, id_prefix="inj")
    assert len(results) == 1
    assert results[0].decision.decision is Decision.DENY
    assert results[0].decision.reason_code is ReasonCode.TOOL_DENIED
    assert world.reader.file_exists("docs/readme.txt")


def test_malformed_agent_output_is_denied_and_audited(make_harness: HarnessFactory) -> None:
    harness = make_harness()
    agent = ScriptedAgent(
        lambda _: [{"name": "read_account"}, {"name": "read_account", "arguments": {}}]
    )
    results = run_agent(harness, agent, "anything")
    assert [r.decision.reason_code for r in results] == [ReasonCode.MALFORMED_REQUEST] * 2
    assert all(r.outcome is Outcome.DENIED for r in results)
    harness.audit.verify()


def test_agent_requests_flow_through_the_full_pipeline(make_harness: HarnessFactory) -> None:
    harness = make_harness()
    agent = ScriptedAgent(lambda _: [{"name": "read_account", "arguments": {
        "action": "read", "scope": "accounts:read", "account_id": "acct-1001"}}])  # fmt: skip
    (result,) = run_agent(harness, agent, "check the account")
    assert result.outcome is Outcome.COMPLETED
    assert result.request_id == "agent-001"
