"""Integration boundary between an external agent and the harness. No provider is required."""

from ai_automation_harness.adapters.base import AgentAdapter, ScriptedAgent, run_agent
from ai_automation_harness.adapters.tool_calls import request_from_tool_call

__all__ = ["AgentAdapter", "ScriptedAgent", "request_from_tool_call", "run_agent"]
