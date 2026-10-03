"""Minimal adapter interface: Agent -> ToolRequest -> Harness -> Decision."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Protocol

from ai_automation_harness.adapters.tool_calls import request_from_tool_call
from ai_automation_harness.errors import MalformedRequestError
from ai_automation_harness.harness import Harness, HarnessResult


class AgentAdapter(Protocol):
    """Anything that can propose tool calls given an observation. An LLM client would live here."""

    def propose(self, observation: str) -> Iterable[Mapping[str, Any]]: ...


class ScriptedAgent:
    """Deterministic stand-in for a model, used in tests and demos.

    `policy_fn` receives the latest observation (for example tool output) and returns the
    next tool calls. A naive fn that obeys instructions found in data models prompt injection.
    """

    def __init__(self, policy_fn: Callable[[str], Sequence[Mapping[str, Any]]]) -> None:
        self._policy_fn = policy_fn

    def propose(self, observation: str) -> Iterable[Mapping[str, Any]]:
        return self._policy_fn(observation)


def run_agent(
    harness: Harness, agent: AgentAdapter, observation: str, *, id_prefix: str = "agent"
) -> list[HarnessResult]:
    """Submit every proposed call through the harness. Malformed calls are denied, not raised."""
    results: list[HarnessResult] = []
    for index, call in enumerate(agent.propose(observation), start=1):
        request_id = f"{id_prefix}-{index:03d}"
        try:
            request = request_from_tool_call(call, request_id=request_id)
        except MalformedRequestError as exc:
            results.append(harness.reject_malformed(str(exc)))
            continue
        results.append(harness.submit(request))
    return results
