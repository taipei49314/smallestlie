"""Recorded cross-dispatch relations, never proof of actual launch order.

The source-map reader supplies expectations from frozen tickets, sealed ledger
bytes and exact external grants. A separate accepted coordinator must enforce
these relations. Child event intervals and coordinator sequences are distinct.
"""

from __future__ import annotations

from smallestlie.attacks.adjudication import mapping, sha256, string
from smallestlie.campaign.completion_source import _same
from smallestlie.campaign.preregistration import canonical_digest, commit, integer, json_mapping
from smallestlie.campaign.provenance import ProvenanceError, _repository
from smallestlie.ledger.lifecycle import OBSERVED

JOURNAL_SCHEMA = "smallestlie.lifecycle-publication-journal/v2"
DISPATCH_VARIABLES = {"ec_source_commit", "run_id", "attempt", "job_id"}


def _dispatch_claim(value, common):
    mapping(value, "coordinator action dispatch", set(common))
    for key in ("repository_id", "workflow_id", "run_id", "attempt", "job_id"):
        integer(value[key], key, minimum=1)
    for key in ("workflow_sha256", "collector_sha256", "request_sha256", "lock_digest"):
        sha256(value[key], key)
    for key in ("source_commit", "ec_source_commit"):
        commit(value[key], key)
    _repository(value["repository"])
    for key in ("host", "generation"):
        string(value[key], key)
    _same({key: val for key, val in value.items() if key not in DISPATCH_VARIABLES},
          {key: val for key, val in common.items() if key not in DISPATCH_VARIABLES},
          "coordinator action differs from frozen common dispatch")


def verify_publication_order(data: bytes, *, session_sha256: str, epoch: str,
                             anchor: dict, anchor_sequence: int, expectations: dict,
                             common_dispatch: dict, input_refs: set, authority_input_refs: set,
                             output_refs: set) -> None:
    """Validate a bounded serial journal, without making an authority envelope.

An action with unavailable independent source still requires its recorded
release/ACK when the ledger says observed. Its claims never create a proof.
Only a final dangling release for completion_missing is allowed; no recovery
ACK or later release may be invented to continue the session.
"""
    if type(data) is not bytes or not data or len(data) > 5_000_000:
        raise ProvenanceError("bounded complete coordinator journal required")
    journal = json_mapping(data, "cross-dispatch coordinator journal")
    mapping(journal, "coordinator journal", {"schema_version", "session_sha256", "epoch", "events"})
    _same({key: val for key, val in journal.items() if key != "events"},
          {"schema_version": JOURNAL_SCHEMA, "session_sha256": session_sha256, "epoch": epoch},
          "coordinator session/epoch mismatch")
    events = journal["events"]
    if type(events) is not list or not events or len(events) > 2 * len(expectations) + 1:
        raise ProvenanceError("bounded complete coordinator event denominator required")
    first = {"event": "anchor_durable_ack", "seq": anchor_sequence,
             "facts": {"anchor_commit": anchor["commit"], "anchor_sha256": anchor["sha256"],
                       "locked_prefix_sha256": anchor["prefix_sha256"]}}
    _same(events[0], first, "independent anchor ACK mismatch")
    previous_sequence = integer(events[0]["seq"], "anchor ACK sequence", minimum=1)
    previous_ack = canonical_digest(events[0])
    pending, released, acknowledged, receipts, identities, intervals = None, set(), set(), set(), set(), []
    prior_ticket_seq = 0
    release_inputs = input_refs | authority_input_refs
    non_action_refs = output_refs - {item["source"]["receipt_commit"] for item in expectations.values()
                                    if item["source"] is not None}
    for event in events[1:]:
        mapping(event, "coordinator event", {"event", "seq", "facts"})
        seq = integer(event["seq"], "coordinator sequence", minimum=1)
        if seq <= previous_sequence:
            raise ProvenanceError("coordinator sequences must strictly increase")
        previous_sequence = seq
        facts = event["facts"]
        if event["event"] == "action_release":
            mapping(facts, "action release", {"reservation_sha256", "prefix_sha256", "context_sha256", "dispatch",
                "action_epoch", "action_id", "first_event_sequence", "last_event_sequence", "previous_ack_sha256"})
            for key in ("reservation_sha256", "prefix_sha256", "context_sha256", "previous_ack_sha256"):
                sha256(facts[key], key)
            expected = expectations.get(facts["reservation_sha256"])
            if pending is not None or expected is None or facts["reservation_sha256"] in released:
                raise ProvenanceError("release needs one unused frozen ticket and preceding ACK")
            if expected["ticket_seq"] <= prior_ticket_seq or facts["previous_ack_sha256"] != previous_ack:
                raise ProvenanceError("release contradicts ticket order or exact preceding ACK")
            _same({key: facts[key] for key in ("prefix_sha256", "context_sha256")},
                  {key: expected[key] for key in ("prefix_sha256", "context_sha256")},
                  "release does not bind the original ticket prefix/context")
            _dispatch_claim(facts["dispatch"], common_dispatch)
            if facts["dispatch"]["ec_source_commit"] in output_refs | authority_input_refs:
                raise ProvenanceError("release source aliases an output or admission role")
            release_inputs.add(facts["dispatch"]["ec_source_commit"])
            string(facts["action_epoch"], "child journal epoch")
            string(facts["action_id"], "one-use child identity")
            identity = facts["action_epoch"], facts["action_id"]
            start = integer(facts["first_event_sequence"], "child first event", minimum=1)
            end = integer(facts["last_event_sequence"], "child last event", minimum=1)
            if facts["action_epoch"] != epoch or identity in identities or end <= start:
                raise ProvenanceError("child identity/epoch/interval invalid or reused")
            scope = canonical_digest(facts["dispatch"]), facts["action_epoch"]
            if any(scope == old_scope and not (end < lo or start > hi) for old_scope, lo, hi in intervals):
                raise ProvenanceError("native intervals overlap in the same child dispatch")
            identities.add(identity)
            intervals.append((scope, start, end))
            source = expected["source"]
            if source is not None:
                _same({key: facts[key] for key in ("dispatch", "action_epoch", "action_id",
                        "first_event_sequence", "last_event_sequence")},
                      {"dispatch": source["dispatch"], **source["identity"]},
                      "release contradicts independently configured action source")
                if seq != source["release_sequence"]:
                    raise ProvenanceError("release sequence differs from exact external grant")
            released.add(facts["reservation_sha256"])
            prior_ticket_seq = expected["ticket_seq"]
            pending = event, expected
        elif event["event"] == "action_publication_durable_ack":
            mapping(facts, "action publication ACK", {"release_sha256", "reservation_sha256", "dispatch",
                "receipt_commit", "completion_sha256", "action_publication_sha256", "publication_sha256",
                "action_journal_sha256"})
            for key in ("release_sha256", "reservation_sha256", "completion_sha256", "action_publication_sha256",
                        "publication_sha256", "action_journal_sha256"):
                sha256(facts[key], key)
            commit(facts["receipt_commit"], "original action receipt")
            if pending is None:
                raise ProvenanceError("publication ACK without a released action")
            release, expected = pending
            ticket_sha = release["facts"]["reservation_sha256"]
            if (facts["release_sha256"] != canonical_digest(release) or facts["reservation_sha256"] != ticket_sha
                    or expected["status"] not in OBSERVED or facts["receipt_commit"] in receipts
                    or facts["receipt_commit"] in input_refs | authority_input_refs | non_action_refs):
                raise ProvenanceError("ACK release/ticket/native disposition/role mismatch")
            _same(facts["dispatch"], release["facts"]["dispatch"], "ACK changes the released dispatch")
            _same({key: facts[key] for key in ("completion_sha256", "action_publication_sha256")},
                  {key: expected[key] for key in ("completion_sha256", "action_publication_sha256")},
                  "ACK contradicts the preserved ledger artifacts")
            if expected["provenance_ref"] is not None and expected["provenance_ref"] != facts["receipt_commit"]:
                raise ProvenanceError("ACK changes the recorded provenance")
            source = expected["source"]
            if source is not None:
                _same({key: facts[key] for key in ("receipt_commit", "completion_sha256", "action_publication_sha256",
                        "publication_sha256", "action_journal_sha256")},
                      {"receipt_commit": source["receipt_commit"], "completion_sha256": source["completion"]["sha256"],
                       "action_publication_sha256": source["publication"]["sha256"],
                       "publication_sha256": source["publication_sha256"],
                       "action_journal_sha256": source["journal_sha256"]},
                      "ACK contradicts independently configured raw publication")
                if seq != source["publication_sequence"]:
                    raise ProvenanceError("publication sequence differs from exact external grant")
            receipts.add(facts["receipt_commit"])
            acknowledged.add(ticket_sha)
            previous_ack = canonical_digest(event)
            pending = None
        else:
            raise ProvenanceError("unsupported coordinator event")
    if receipts & release_inputs:
        raise ProvenanceError("action receipt aliases a released EC input source")
    if pending is not None and (pending[1]["status"] != "completion_missing" or pending[1]["source"] is not None):
        raise ProvenanceError("only a final missing completion may retain an unacknowledged release")
    if any((item["status"] in OBSERVED or item["source"] is not None) and key not in acknowledged
           for key, item in expectations.items()):
        raise ProvenanceError("coordinator journal omits an observed action readback")
