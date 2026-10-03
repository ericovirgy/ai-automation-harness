from __future__ import annotations

import pytest

from ai_automation_harness.world import FAULTS, ObservationError, SimulatedWorld


def test_world_is_seeded_and_isolated_per_instance() -> None:
    a, b = SimulatedWorld(), SimulatedWorld()
    a.writer.delete_file("docs/readme.txt")
    assert not a.reader.file_exists("docs/readme.txt")
    assert b.reader.file_exists("docs/readme.txt")


def test_unknown_faults_are_rejected() -> None:
    with pytest.raises(ValueError):
        SimulatedWorld(frozenset({"explode"}))
    assert FAULTS


def test_read_side_basics() -> None:
    world = SimulatedWorld()
    assert world.reader.get_account("acct-1001") == {
        "owner": "Acme",
        "status": "active",
        "plan": "business",
    }
    assert world.reader.get_account("acct-0000") is None
    assert world.reader.read_file("nope") is None
    assert len(world.reader.search_records("invoice")) == 2


def test_deletion_is_a_simulated_tombstone_and_second_delete_reports_false() -> None:
    world = SimulatedWorld()
    assert world.writer.delete_file("docs/readme.txt") is True
    assert world.writer.delete_file("docs/readme.txt") is False
    assert world.reader.counters()["deleted_files"] == 1


def test_observer_fault_makes_readback_fail_but_not_counters() -> None:
    world = SimulatedWorld(frozenset({"observer_unavailable"}))
    with pytest.raises(ObservationError):
        world.reader.get_draft("draft-0001")
    with pytest.raises(ObservationError):
        world.reader.outbox_messages()
    with pytest.raises(ObservationError):
        world.reader.get_receipt("x")
    assert world.reader.counters()["drafts"] == 0


def test_digest_changes_with_state() -> None:
    world = SimulatedWorld()
    before = world.reader.digest()
    world.writer.create_draft("a@example.org", "s", "b")
    assert world.reader.digest() != before
