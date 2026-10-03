"""Command line interface. Exit codes are part of the contract (see README)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from collections.abc import Sequence
from typing import Any

from ai_automation_harness import __version__
from ai_automation_harness.audit import load_jsonl, verify_chain
from ai_automation_harness.errors import HarnessError
from ai_automation_harness.models import Decision, PolicyDecision, ToolRequest
from ai_automation_harness.policy import Policy, PolicyEngine
from ai_automation_harness.scenarios import ScenarioResult, load_scenarios, run_scenarios
from ai_automation_harness.tools.demo import build_demo_registry

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_REQUIRE_APPROVAL = 10
EXIT_DENY = 20


def _format_decision(decision: PolicyDecision, policy: Policy) -> str:
    rows = [
        ("decision", decision.decision.value),
        ("tool", f"{decision.tool} (action: {decision.action}, scope: {decision.scope})"),
        ("risk", decision.risk_label),
        ("reason", f"{decision.reason_code.value}: {decision.reason}"),
    ]
    if decision.details:
        rows.append(("details", json.dumps(dict(decision.details), sort_keys=True)))
    rows.append(("policy", f"sha256:{policy.digest[:16]}"))
    return "\n".join(f"{key:<9} {value}" for key, value in rows)


def _cmd_evaluate(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy)
    engine = PolicyEngine(policy, build_demo_registry())
    try:
        arguments = json.loads(args.args)
    except json.JSONDecodeError as exc:
        raise HarnessError("--args must be valid JSON") from exc
    raw: dict[str, Any] = {
        "request_id": args.request_id,
        "tool": args.tool,
        "action": args.action,
        "scope": args.scope,
        "arguments": arguments,
    }
    if args.side_effect is not None:
        raw["side_effect"] = args.side_effect
    decision = engine.evaluate(ToolRequest.from_mapping(raw))
    if args.json:
        print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
    else:
        print(_format_decision(decision, policy))
    return {
        Decision.ALLOW: EXIT_OK,
        Decision.REQUIRE_APPROVAL: EXIT_REQUIRE_APPROVAL,
        Decision.DENY: EXIT_DENY,
    }[decision.decision]


def _format_scenarios(results: Sequence[ScenarioResult]) -> str:
    header = (
        f"{'':<4}{'scenario':<32}{'decision':<18}{'outcome':<24}"
        f"{'verification':<14}{'decision_reason'}"
    )
    lines = [header, "-" * len(header)]
    for item in results:
        mark = "ok" if item.passed else "!!"
        lines.append(
            f"{mark:<4}{item.scenario.name:<32}{item.result.decision.decision.value:<18}"
            f"{item.result.outcome.value:<24}{item.result.verification_status.value:<14}"
            f"{item.result.decision.reason_code.value}"
        )
    passed = sum(1 for r in results if r.passed)
    lines.append(f"\n{passed}/{len(results)} scenarios matched their expected outcome")
    return "\n".join(lines)


def _cmd_simulate(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy)
    scenarios = load_scenarios(args.scenarios)
    results, audit, evidence = run_scenarios(scenarios, policy)
    audit.verify()
    if args.audit_out:
        audit.write_jsonl(args.audit_out)
    if args.evidence_dir:
        evidence.export(args.evidence_dir)
    if args.json:
        payload = [
            {
                "scenario": r.scenario.name,
                "passed": r.passed,
                "decision": r.result.decision.to_dict(),
                "outcome": r.result.outcome.value,
                "verification": r.result.verification.to_dict() if r.result.verification else None,
                "evidence_ref": r.result.evidence_ref,
            }
            for r in results
        ]
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_format_scenarios(results))
        if args.audit_out:
            print(f"audit log written to {args.audit_out} (head {audit.head_hash[:16]})")
    return EXIT_OK if all(r.passed for r in results) else EXIT_FAILED


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    key = _hmac_key(args.hmac_key_env)
    events = load_jsonl(args.file)
    if not events and not args.allow_empty:
        raise HarnessError("audit log is empty (use --allow-empty to accept)")
    count = verify_chain(events, key)
    print(f"audit chain valid: {count} events, head {events[-1].hash[:16] if events else '-'}")
    return EXIT_OK


def _hmac_key(env_name: str | None) -> bytes | None:
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if not value:
        raise HarnessError(f"environment variable {env_name} is not set")
    return value.encode("utf-8")


def _cmd_audit_summary(args: argparse.Namespace) -> int:
    events = load_jsonl(args.file)
    verify_chain(events, _hmac_key(args.hmac_key_env))
    finals = [e for e in events if e.event_type == "request.finished"]
    print(f"{len(events)} events, {len(finals)} finished requests")
    for title, values in (
        ("decisions", Counter(e.policy_decision for e in finals)),
        ("outcomes", Counter(e.outcome for e in finals)),
        ("verification", Counter(e.verification_status for e in finals)),
    ):
        print(f"{title:<13}" + ", ".join(f"{k}={v}" for k, v in sorted(values.items())))
    return EXIT_OK


def _cmd_policy_check(args: argparse.Namespace) -> int:
    policy = Policy.load(args.policy)
    PolicyEngine(policy, build_demo_registry())
    print(
        f"policy valid: {len(policy.allowed_tools)} allowed tools, "
        f"{len(policy.denied_tools)} denied, max_auto_risk={policy.max_auto_risk.label}, "
        f"max_risk={policy.max_risk.label}, sha256:{policy.digest[:16]}"
    )
    return EXIT_OK


def _cmd_tools(_: argparse.Namespace) -> int:
    registry = build_demo_registry()
    print(f"{'tool':<16}{'risk':<10}{'side effects':<14}{'approval':<10}{'scopes'}")
    for name in registry.names():
        spec = registry.get(name)
        if spec is None:
            continue
        print(
            f"{spec.name:<16}{spec.risk.label:<10}{spec.side_effects.label:<14}"
            f"{'required' if spec.requires_approval else 'by policy':<10}"
            f"{','.join(sorted(spec.scopes))}"
        )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-automation-harness",
        description="Policy-controlled, observable, verifiable tool execution for AI automation.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("evaluate", help="evaluate one tool request against a policy")
    ev.add_argument("--policy", required=True)
    ev.add_argument("--tool", required=True)
    ev.add_argument("--action", required=True)
    ev.add_argument("--scope", required=True)
    ev.add_argument("--args", default="{}", help="JSON object with tool arguments")
    ev.add_argument("--side-effect", choices=["none", "internal", "external"])
    ev.add_argument("--request-id", default="cli-request")
    ev.add_argument("--json", action="store_true", help="machine-readable output")
    ev.set_defaults(func=_cmd_evaluate)

    sim = sub.add_parser("simulate", help="run scenarios end to end and export evidence")
    sim.add_argument("--policy", required=True)
    sim.add_argument("--scenarios", required=True)
    sim.add_argument("--audit-out", help="write the hash-chained audit log as JSONL")
    sim.add_argument("--evidence-dir", help="write one evidence JSON file per request")
    sim.add_argument("--json", action="store_true")
    sim.set_defaults(func=_cmd_simulate)

    audit = sub.add_parser("audit", help="inspect exported audit logs")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    av = audit_sub.add_parser("verify", help="verify the hash chain of a JSONL audit log")
    av.add_argument("file")
    av.add_argument("--hmac-key-env", help="name of an env var holding the HMAC key")
    av.add_argument("--allow-empty", action="store_true", help="accept a log with no events")
    av.set_defaults(func=_cmd_audit_verify)
    asum = audit_sub.add_parser("summary", help="summarise a JSONL audit log")
    asum.add_argument("file")
    asum.add_argument("--hmac-key-env", help="name of an env var holding the HMAC key")
    asum.set_defaults(func=_cmd_audit_summary)

    pol = sub.add_parser("policy", help="policy utilities")
    pol_sub = pol.add_subparsers(dest="policy_command", required=True)
    pc = pol_sub.add_parser("check", help="validate a policy against the demo registry")
    pc.add_argument("--policy", required=True)
    pc.set_defaults(func=_cmd_policy_check)

    tools = sub.add_parser("tools", help="list the declared demo tools")
    tools.set_defaults(func=_cmd_tools)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
