"""Simulated demo tools. They only ever touch the in-memory `SimulatedWorld`."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from ai_automation_harness.errors import ToolFailure
from ai_automation_harness.models import Risk, SideEffect
from ai_automation_harness.registry import ArgSpec, ToolContext, ToolRegistry, ToolSpec
from ai_automation_harness.verification import (
    VerificationContext,
    evidence_exists,
    expected_state,
    invariant,
    output_schema,
)

EMAIL_PATTERN = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
PATH_PATTERN = r"[A-Za-z0-9_./-]+"


def _writer(ctx: ToolContext) -> Any:
    if ctx.writer is None:
        raise ToolFailure("tool has no write access")
    return ctx.writer


def _arg(ctx: ToolContext, name: str) -> str:
    value = ctx.request.arguments[name]
    if not isinstance(value, str):
        raise ToolFailure("argument has an unexpected type")
    return value


# ---------------------------------------------------------------- handlers


def read_account(ctx: ToolContext) -> Mapping[str, Any]:
    account_id = _arg(ctx, "account_id")
    account = ctx.reader.get_account(account_id)
    if account is None:
        raise ToolFailure("account not found")
    return {"account_id": account_id, **account}


def search_records(ctx: ToolContext) -> Mapping[str, Any]:
    matches = ctx.reader.search_records(_arg(ctx, "query"))
    return {"count": len(matches), "matches": matches}


def read_file(ctx: ToolContext) -> Mapping[str, Any]:
    path = _arg(ctx, "path")
    content = ctx.reader.read_file(path)
    if content is None:
        raise ToolFailure("file not found")
    return {
        "path": path,
        "content": content,
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
    }


def create_draft(ctx: ToolContext) -> Mapping[str, Any]:
    draft_id = _writer(ctx).create_draft(_arg(ctx, "to"), _arg(ctx, "subject"), _arg(ctx, "body"))
    return {"draft_id": draft_id, "receipt_ref": f"receipt:{draft_id}"}


def send_email(ctx: ToolContext) -> Mapping[str, Any]:
    message_id, receipt_ref = _writer(ctx).send_email(
        _arg(ctx, "to"), _arg(ctx, "subject"), _arg(ctx, "body")
    )
    result: dict[str, Any] = {"message_id": message_id, "status": "queued"}
    if receipt_ref is not None:
        result["receipt_ref"] = receipt_ref
    return result


def delete_file(ctx: ToolContext) -> Mapping[str, Any]:
    path = _arg(ctx, "path")
    if not _writer(ctx).delete_file(path):
        raise ToolFailure("file not found")
    return {"path": path, "deleted": True}


# ---------------------------------------------------------------- verification helpers


def _out(ctx: VerificationContext, key: str) -> str:
    value = ctx.output.get(key)
    return value if isinstance(value, str) else ""


def _counter_delta(ctx: VerificationContext, key: str) -> int:
    return ctx.world.counters()[key] - ctx.before_counters[key]


def _find_message(ctx: VerificationContext) -> dict[str, str] | None:
    wanted = _out(ctx, "message_id")
    return next((m for m in ctx.world.outbox_messages() if m["id"] == wanted), None)


def build_demo_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="read_account",
            description="Read one account record by id.",
            risk=Risk.READ,
            scopes=frozenset({"accounts:read"}),
            side_effects=SideEffect.NONE,
            allowed_actions=frozenset({"read"}),
            requires_approval=False,
            arguments={"account_id": ArgSpec(pattern=r"acct-[0-9]{4}", max_length=9)},
        ),
        read_account,
        checks=(
            output_schema({"account_id": str, "owner": str, "status": str, "plan": str}),
            expected_state(
                "account_matches_source",
                lambda c: c.world.get_account(_out(c, "account_id")),
                lambda c: {k: v for k, v in c.output.items() if k != "account_id"},
            ),
        ),
    )
    registry.register(
        ToolSpec(
            name="search_records",
            description="Search records by text. Read-only, returns matching records.",
            risk=Risk.LOW,
            scopes=frozenset({"records:read"}),
            side_effects=SideEffect.NONE,
            allowed_actions=frozenset({"search"}),
            requires_approval=False,
            arguments={"query": ArgSpec(pattern=r"[A-Za-z0-9 ._-]+", max_length=64)},
        ),
        search_records,
        checks=(
            output_schema({"count": int, "matches": list}),
            invariant(
                "count_matches_length", lambda c: c.output.get("count") == len(c.output["matches"])
            ),
            expected_state(
                "matches_equal_source",
                lambda c: c.world.search_records(str(c.request.arguments["query"])),
                lambda c: c.output["matches"],
            ),
        ),
    )
    registry.register(
        ToolSpec(
            name="read_file",
            description="Read a text file from the simulated file store.",
            risk=Risk.READ,
            scopes=frozenset({"files:read"}),
            side_effects=SideEffect.NONE,
            allowed_actions=frozenset({"read"}),
            requires_approval=False,
            arguments={"path": ArgSpec(pattern=PATH_PATTERN, max_length=128)},
        ),
        read_file,
        checks=(
            output_schema({"path": str, "content": str, "sha256": str}),
            expected_state(
                "content_matches_source",
                lambda c: c.world.read_file(_out(c, "path")),
                lambda c: c.output["content"],
            ),
        ),
    )
    mail_args = {
        "to": ArgSpec(pattern=EMAIL_PATTERN, max_length=254),
        "subject": ArgSpec(max_length=120),
        "body": ArgSpec(max_length=2000),
    }
    registry.register(
        ToolSpec(
            name="create_draft",
            description="Create an email draft in the simulated drafts store. Does not send.",
            risk=Risk.MEDIUM,
            scopes=frozenset({"drafts:write"}),
            side_effects=SideEffect.INTERNAL,
            allowed_actions=frozenset({"create"}),
            requires_approval=False,
            arguments=mail_args,
        ),
        create_draft,
        checks=(
            output_schema({"draft_id": str, "receipt_ref": str}),
            expected_state(
                "draft_exists_with_claimed_content",
                lambda c: c.world.get_draft(_out(c, "draft_id")),
                lambda c: {
                    "to": c.request.arguments["to"],
                    "subject": c.request.arguments["subject"],
                    "body": c.request.arguments["body"],
                },
            ),
            invariant(
                "exactly_one_draft_and_nothing_sent",
                lambda c: _counter_delta(c, "drafts") == 1 and _counter_delta(c, "outbox") == 0,
            ),
            evidence_exists("receipt_ref", lambda c, ref: c.world.get_receipt(ref)),
        ),
    )
    registry.register(
        ToolSpec(
            name="send_email",
            description="Send an email (simulated: appends to an in-memory outbox).",
            risk=Risk.HIGH,
            scopes=frozenset({"email:send"}),
            side_effects=SideEffect.EXTERNAL,
            allowed_actions=frozenset({"send"}),
            requires_approval=True,
            arguments=mail_args,
        ),
        send_email,
        checks=(
            output_schema({"message_id": str, "status": str}),
            expected_state(
                "message_in_outbox",
                _find_message,
                lambda c: {
                    "id": _out(c, "message_id"),
                    "to": c.request.arguments["to"],
                    "subject": c.request.arguments["subject"],
                    "body": c.request.arguments["body"],
                },
            ),
            invariant("exactly_one_message_queued", lambda c: _counter_delta(c, "outbox") == 1),
            evidence_exists("receipt_ref", lambda c, ref: c.world.get_receipt(ref)),
        ),
    )
    registry.register(
        ToolSpec(
            name="delete_file",
            description="Delete a file (simulated: moves the entry to an in-memory tombstone map).",
            risk=Risk.CRITICAL,
            scopes=frozenset({"files:delete"}),
            side_effects=SideEffect.INTERNAL,
            allowed_actions=frozenset({"delete"}),
            requires_approval=True,
            arguments={"path": ArgSpec(pattern=PATH_PATTERN, max_length=128)},
        ),
        delete_file,
        checks=(
            output_schema({"path": str, "deleted": bool}),
            expected_state(
                "file_is_absent",
                lambda c: "absent" if not c.world.file_exists(_out(c, "path")) else "present",
                lambda c: "absent",
            ),
            invariant(
                "exactly_one_file_removed",
                lambda c: (
                    _counter_delta(c, "files") == -1 and _counter_delta(c, "deleted_files") == 1
                ),
            ),
        ),
    )
    return registry
