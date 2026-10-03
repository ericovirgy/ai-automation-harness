"""Minimal library usage: submit a gated request, approve it as a named human, inspect the audit."""

from pathlib import Path

from ai_automation_harness import Harness, Policy
from ai_automation_harness.tools.demo import build_demo_registry
from ai_automation_harness.world import SimulatedWorld

policy = Policy.load(Path(__file__).with_name("policy.yaml"))
harness = Harness(build_demo_registry(), policy, SimulatedWorld())

pending = harness.submit(
    {
        "request_id": "demo-1",
        "tool": "create_draft",
        "action": "create",
        "scope": "drafts:write",
        "arguments": {"to": "alice@example.org", "subject": "Q3 summary", "body": "Draft body"},
        "requester": "report-agent",
    }
)
print(pending.decision.decision.value, pending.outcome.value)  # REQUIRE_APPROVAL PENDING_APPROVAL

if pending.approval_id is None:
    raise SystemExit("expected a pending approval")
harness.approve(pending.approval_id, "alice")  # explicit, named, not the requester
final = harness.resume("demo-1")
print(final.outcome.value, final.verification_status.value)  # COMPLETED VERIFIED

harness.audit.verify()
print(len(harness.audit.events), "audit events, head", harness.audit.head_hash[:12])
