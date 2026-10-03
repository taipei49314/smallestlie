"""Synthetic coordinator relationships, not evidence of actual launch timing."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from test_evidence_sources import ctx as ec_context, plan
from test_source_map import make_map
from test_multi_dispatch_sources import assemble, change_order, make_multi_map, multi_mapped, verify
from smallestlie.campaign.preregistration import canonical_digest
from smallestlie.campaign.provenance import ProvenanceError
from smallestlie.campaign.publication_order import verify_publication_order


@pytest.mark.parametrize("damage", ["missing_ack", "previous_ack", "release_hash", "dispatch", "ticket", "prefix",
    "journal", "bool_sequence", "bool_interval", "duplicate_identity", "duplicate_receipt", "extra", "epoch",
    "reverse", "future_hash", "archive_receipt"])
def test_reaccepted_journal_cannot_replace_original_relations(multi_mapped, damage):
    def mutate(raw):
        events = raw["events"]
        if damage == "missing_ack": events.pop(2)
        elif damage == "previous_ack": events[3]["facts"]["previous_ack_sha256"] = "0" * 64
        elif damage == "release_hash": events[2]["facts"]["release_sha256"] = "0" * 64
        elif damage == "dispatch": events[1]["facts"]["dispatch"]["job_id"] += 1
        elif damage == "ticket": events[1]["facts"]["reservation_sha256"] = "0" * 64
        elif damage == "prefix": events[1]["facts"]["prefix_sha256"] = "0" * 64
        elif damage == "journal": events[2]["facts"]["action_journal_sha256"] = "0" * 64
        elif damage == "bool_sequence": events[2]["seq"] = True
        elif damage == "bool_interval": events[1]["facts"]["last_event_sequence"] = True
        elif damage == "duplicate_identity": events[3]["facts"]["action_id"] = events[1]["facts"]["action_id"]
        elif damage == "duplicate_receipt": events[4]["facts"]["receipt_commit"] = events[2]["facts"]["receipt_commit"]
        elif damage == "extra": events[0]["self_commit"] = "a" * 40
        elif damage == "epoch": raw["epoch"] = "other-epoch"
        elif damage == "reverse": events[1], events[2] = events[2], events[1]
        elif damage == "future_hash": events[1]["facts"]["action_journal_sha256"] = events[2]["facts"]["action_journal_sha256"]
        else: events[2]["facts"]["receipt_commit"] = multi_mapped["root"].publications[0].receipt_commit
    change_order(multi_mapped, mutate)
    assert verify(multi_mapped) is None


def test_coordinator_sequences_are_not_compared_to_child_native_intervals(multi_mapped):
    raw = json.loads(multi_mapped["files"]["archive/publisher.json"])
    assert raw["events"][2]["seq"] < raw["events"][1]["facts"]["last_event_sequence"]
    assert verify(multi_mapped) is not None


def test_native_sequence_gaps_preserve_exact_links_and_external_sequence_grants(multi_mapped):
    def mutate(raw):
        events = raw["events"]
        for index, event in enumerate(events[1:], 1):
            event["seq"] = 10 * index + 1
            if event["event"] == "action_release":
                event["facts"]["previous_ack_sha256"] = canonical_digest(events[index - 1])
            else:
                event["facts"]["release_sha256"] = canonical_digest(events[index - 1])
        sequences = {event["facts"]["reservation_sha256"]: event["seq"] for event in events[1:]
                     if event["event"] == "action_release"}
        acknowledgments = {event["facts"]["reservation_sha256"]: event["seq"] for event in events[1:]
                           if event["event"] == "action_publication_durable_ack"}
        multi_mapped["members"] = tuple(replace(item, release_sequence=sequences[canonical_digest(item.ticket.to_dict())],
            publication_sequence=acknowledgments[canonical_digest(item.ticket.to_dict())]) if item.authority is not None
            else item for item in multi_mapped["members"])
    change_order(multi_mapped, mutate)
    assert verify(multi_mapped) is not None


def order_arguments(*, status="completion_missing"):
    """Standalone parser fixture; its expectations have no source authority."""
    dispatch = {"repository": "example/ec", "repository_id": 202, "workflow_id": 300,
        "workflow_sha256": "1" * 64, "collector_sha256": "2" * 64, "source_commit": "3" * 40,
        "ec_source_commit": "4" * 40, "request_sha256": "5" * 64, "lock_digest": "6" * 64,
        "run_id": 600, "attempt": 1, "job_id": 700, "host": "synthetic-host", "generation": "synthetic-generation"}
    anchor = {"commit": "a" * 40, "sha256": "b" * 64, "prefix_sha256": "c" * 64}
    first = {"event": "anchor_durable_ack", "seq": 1, "facts": {"anchor_commit": anchor["commit"],
        "anchor_sha256": anchor["sha256"], "locked_prefix_sha256": anchor["prefix_sha256"]}}
    ticket = "d" * 64
    expected = {"ticket_seq": 4, "prefix_sha256": "e" * 64, "context_sha256": "f" * 64,
        "status": status, "completion_sha256": None, "action_publication_sha256": None,
        "provenance_ref": None, "source": None}
    release = {"event": "action_release", "seq": 2, "facts": {"reservation_sha256": ticket,
        "prefix_sha256": expected["prefix_sha256"], "context_sha256": expected["context_sha256"],
        "dispatch": dispatch, "action_epoch": "synthetic-epoch", "action_id": "synthetic-action",
        "first_event_sequence": 1, "last_event_sequence": 5, "previous_ack_sha256": canonical_digest(first)}}
    journal = {"schema_version": "smallestlie.lifecycle-publication-journal/v2", "session_sha256": "7" * 64,
        "epoch": "synthetic-epoch", "events": [first, release]}
    kwargs = {"session_sha256": "7" * 64, "epoch": "synthetic-epoch", "anchor": anchor, "anchor_sequence": 1,
        "expectations": {ticket: expected}, "common_dispatch": dispatch,
        "input_refs": {"3" * 40, "4" * 40}, "authority_input_refs": {"2" * 40},
        "output_refs": {"a" * 40, "8" * 40, "9" * 40}}
    return journal, kwargs


def test_final_missing_completion_keeps_unacknowledged_release_without_continuation():
    from smallestlie.campaign.lifecycle import encoded
    journal, kwargs = order_arguments()
    assert verify_publication_order(encoded(journal), **kwargs) is None
    other = deepcopy(journal["events"][-1])
    other["seq"] = 3
    other["facts"]["reservation_sha256"] = "0" * 64
    other["facts"]["action_id"] = "another-action"
    kwargs["expectations"]["0" * 64] = {**kwargs["expectations"]["d" * 64], "ticket_seq": 5}
    journal["events"].append(other)
    with pytest.raises(ProvenanceError, match="preceding ACK"):
        verify_publication_order(encoded(journal), **kwargs)


@pytest.mark.parametrize("status", ["completed", "timeout", "completion_rejected"])
def test_unacknowledged_release_cannot_hide_observed_or_rejected_completion(status):
    from smallestlie.campaign.lifecycle import encoded
    journal, kwargs = order_arguments(status=status)
    with pytest.raises(ProvenanceError, match="final missing"):
        verify_publication_order(encoded(journal), **kwargs)


def test_even_missing_source_cannot_release_using_a_known_admission_commit():
    from smallestlie.campaign.lifecycle import encoded
    journal, kwargs = order_arguments()
    journal["events"][1]["facts"]["dispatch"]["ec_source_commit"] = "2" * 40
    with pytest.raises(ProvenanceError, match="admission role"):
        verify_publication_order(encoded(journal), **kwargs)


@pytest.mark.parametrize("same_dispatch", [True, False])
def test_native_interval_scope_is_each_exact_child_dispatch_and_epoch(same_dispatch):
    from smallestlie.campaign.lifecycle import encoded
    journal, kwargs = order_arguments(status="completed")
    expected = kwargs["expectations"]["d" * 64]
    expected.update(completion_sha256="0" * 64, action_publication_sha256="1" * 64, provenance_ref="1" * 40)
    first_release = journal["events"][1]
    ack = {"event": "action_publication_durable_ack", "seq": 3, "facts": {
        "release_sha256": canonical_digest(first_release), "reservation_sha256": "d" * 64,
        "dispatch": first_release["facts"]["dispatch"], "receipt_commit": "1" * 40,
        "completion_sha256": "0" * 64, "action_publication_sha256": "1" * 64,
        "publication_sha256": "2" * 64, "action_journal_sha256": "3" * 64}}
    journal["events"].append(ack)
    second = deepcopy(first_release)
    second["seq"] = 4
    second["facts"].update(reservation_sha256="0" * 64, action_id="another-action",
                            previous_ack_sha256=canonical_digest(ack))
    if not same_dispatch:
        second["facts"]["dispatch"].update(ec_source_commit="7" * 40, run_id=601, attempt=2, job_id=701)
    kwargs["expectations"]["0" * 64] = {**expected, "ticket_seq": 5, "status": "completion_missing",
        "completion_sha256": None, "action_publication_sha256": None, "provenance_ref": None}
    journal["events"].append(second)
    if same_dispatch:
        with pytest.raises(ProvenanceError, match="intervals overlap"):
            verify_publication_order(encoded(journal), **kwargs)
    else:
        assert verify_publication_order(encoded(journal), **kwargs) is None
