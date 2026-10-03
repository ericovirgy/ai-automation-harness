"""Translate provider-style tool calls into harness requests, strictly.

Accepted shapes (all plain dicts, no SDK needed):
  {"name": ..., "arguments": {...} | "<json string>"}          generic / OpenAI-style
  {"type": "tool_use", "id": ..., "name": ..., "input": {...}} Anthropic-style

The model must name `action` and `scope` inside its arguments. They are validated like any
other claim; the adapter never invents or widens them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from ai_automation_harness.errors import MalformedRequestError
from ai_automation_harness.models import ToolRequest


def request_from_tool_call(
    call: Mapping[str, Any], *, request_id: str, requester: str = "agent"
) -> ToolRequest:
    if not isinstance(call, Mapping):
        raise MalformedRequestError("tool call must be a mapping")
    payload = call.get("input", call.get("arguments"))
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise MalformedRequestError("tool call arguments are not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise MalformedRequestError("tool call arguments must be an object")
    arguments = dict(payload)
    if "action" not in arguments or "scope" not in arguments:
        raise MalformedRequestError("tool call must include 'action' and 'scope'")
    action = arguments.pop("action")
    scope = arguments.pop("scope")
    return ToolRequest.from_mapping(
        {
            "request_id": request_id,
            "tool": call.get("name"),
            "action": action,
            "scope": scope,
            "arguments": arguments,
            "requester": requester,
        }
    )
