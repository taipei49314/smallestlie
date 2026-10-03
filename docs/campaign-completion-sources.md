# Reservation-aware offline completion sources (M12 D)

`EcLifecycleCompletionAuthority` implements the new `CompletionAuthority` as
GET-only single-action offline revalidation. It performs no launch, recording,
local-file or grant discovery, and does not activate campaign/replay/minimize
gates. Existing `outer-supervisor/v1` providers retain their original contract;
relabeling their JSON or copying a sequence cannot approve a v2 reservation.

## Independent configuration

The trusted caller supplies an `EcReceiptStore`, one
`LifecycleCollectorAdmission` and a tuple of `LifecycleActionGrant`s, outside
the product and witness bundle. Constructors cannot authenticate their caller
or make its declarations true: arbitrary Python callers remain a trust boundary.

Admission binds the exact request/lock/product source, EC source, repository/
workflow/collector pins, numeric run/attempt/job, measured host and generation.
Separate collector, host/storage and prelaunch journal acceptance references
are required, as are immutable governance bytes at an exact commit/path/raw
SHA-256 matching that dispatch and those contracts. The execution archive
cannot supply its own admission evidence commit. Reading/hashing these bytes
does not establish acceptance; the external trusted process must independently
accept the actual measurement, isolation, no-ACK-no-work, crash/identity and
concrete host/storage contracts. No actual admission is introduced here.

Each action grant binds the canonical exact ticket digest, raw wrapper/facts/
action-publication paths and hashes, journal epoch, one-use identity and bounded
event interval. Tickets/identities/artifact roles cannot be reused. Event
intervals cannot overlap within an epoch. No default root or registry exists.

## Measured sources and order

The provider first calls `EcReceiptStore.read()` to independently check the
terminal exact run/job/runner, pinned workflow/collector, complete raw Git
inventory and final EC publication. It does not call v1 `supervisor()`.
Generic job success or publication acceptance never approves an action.

`smallestlie.lifecycle-source/v1` binds dispatch, reservation, context, complete
measured file maps, measured command/runtime/environment, termination/native
exit, writer/output disposition and raw artifact references. Runner facts match
the frozen collector/runtime/runner, installed dependencies and lock,
environment, instantiated argv/cwd/config. Verifier facts match the separately
configured runtime/environment, frozen engine, measured paths and Git range.
Configured Checkwash policy remains unsupported; default `high` requires a
complete baseline with no policy directory. Materialization has no command or
output roles. Expected context hashes cannot substitute for measured facts.

The referenced raw JSONL prefix contains every entry from one, strict integer
sequences and valid payload/entry hash chains. The explicit v2 marker, full plan
and original exact lock are revalidated; the last entry must be precisely this
reservation, including sequence and entry digest. A later disposition or seal
cannot stand in for that reservation. The prefix does not endorse earlier
actions' artifacts, authority or policy; those need independent checks.

`smallestlie.prelaunch-journal/v1` binds exact dispatch, epoch, one-use identity,
prefix/ticket/context digests. Five native integer events lie in the granted
interval and strictly follow:

1. `ticket_durable_ack`: exact persisted prefix/ticket;
2. `work_started`: measured context/file maps/command;
3. `termination_observed`: native termination/exit;
4. `writer_disposition`: actual descendant-writer boolean;
5. `outputs_sealed`: actual output references/completeness.

An event does not turn a false completeness/writer value into true. Incomplete
dispositions retain their native kind/values. Completed actions need expected
complete file maps, native exit and complete outputs with reaped descendants;
completed materialization exits zero. Assertion/semantic validation remains
separate. Archived hashes, sequences and Git timestamps alone do not prove
past launch order; actual independently accepted coordinator enforcement is
required. Synthetic fixtures establish only this provider's contract.

## Acyclic publication roles and remaining limitation

The final EC receipt archives the wrapper and independent action sources. A
separate `smallestlie.action-publication/v1` binds dispatch/ticket and exactly
inventories sorted raw facts/prefix/journal/outputs. It excludes itself, wrapper
and final EC publication; facts contain no wrapper or publication backreference.
The canonical raw `smallestlie.lifecycle-completion/v1` wrapper hashes that
action publication and facts, with output hashes/dispositions derived from the
measured sources. Equivalent JSON reencoding cannot borrow raw byte authority.

The envelope's `immutable_ref` is the final receipt commit. Existing provenance
guards are unchanged. A prefix containing an earlier disposition with that same
final commit is rejected: its containing Git tree would depend on its own hash.
Legal earlier dispositions reference earlier independent publications; this
action grant does not approve them on their behalf.

The store accepts one publication per request/lock and is not a composite
authority for earlier publications. It cannot release a live job's next action
while requiring that same job to be terminal. Full multi-command runner
aggregation still needs a separately versioned prelaunch anchor/action source/
final archive/aggregate mapping: identical final refs for every command conflict
with a later prefix embedding an earlier command disposition. This subcut
retains unsupported/unknown and makes no full paired-run, headline, real
collector adoption or W3 claim. No alias, ancestor inference, retrospective
ticket filling or weakened provenance guard hides that limitation.

The [native single-action producer](campaign-native-producer.md) now authors
local raw sources for one runner materialization or Windows CPython/pytest
command and reacquires exact prior terminal materialization sources. It supplies
no immutable publication ACK or actual admission and does not solve the live
multi-action publication contract.

The separate [offline source map](campaign-source-map.md) now checks distinct
action receipts, one original locked anchor, a final raw archive and external
mapping evidence. Its mapped carriers preserve per-command refs and complete
slots; they are not legacy envelopes and do not activate `FormalLifecycle`.

## Validation

Synthetic contracts cover positive own-action materialization/runner/verifier
paths into `validate_completion`, wrong admission/dispatch, malformed tickets
and coherent prefixes, missing/late ACK, journal identity/sequence reuse,
runtime/command replacement, incomplete outputs/writers, raw byte/inventory
substitution, JSON reencoding and circular source/prefix roles. The admitted
full `tests` suite includes them; original focused groups, workload declaration/
payload and uv.lock remain unchanged.

NOT_RUN: work-machine rule (`POLICY work-machine-local`); no local product,
pytest/collection, syntax probe, compilation, lint, typecheck, build or install.
PR31 source `d4f42c7bf0c714453c0bc995779259c406a79a9f` passed focused222/full671
and merged as `ca4accfad87de9fec68fdf882a71ee6f68d9e68c`; its consumed grant does
not validate this new source. A new exact-source single pool dispatch is needed.

Remaining D: versioned cross-action/live publication contract, actual collector/
coordinator/storage and policy-resolver admission, launch/CLI/report/witness
integration, independent human Phase 1 and separately authorized formal W3.
Historical rt4 captures remain historical, including their missing own red logs.
