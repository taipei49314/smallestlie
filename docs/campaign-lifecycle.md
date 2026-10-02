# Formal lifecycle recording (M12 D lifecycle subcut)

`campaign.lifecycle.FormalLifecycle` records an explicit `smallestlie.m12/v2`
ledger around the original `smallestlie.m12/v1` `PreparedRun.lock`. It keeps
that approved lock's bytes, digest and meaning. `verify_ledger()` dispatches
by the explicit marker; legacy and formal v1 semantics remain unchanged.

The API records work supplied by an independently trusted integration process.
It supplies no subprocess, launch callback, real collector, default authority,
CLI entry point or activation of the existing campaign/replay/minimize gates.
Synthetic tests establish contract behavior, not W3 runner results or approval.

## Reservation and completion

`begin()` takes a freshly prepared exact-source run, a new output directory,
externally configured authorities and the trusted caller's prior policy result.
The policy snapshot binds the request, authorization reference and provider;
this module does not authenticate its caller or perform the policy/containment
check. It stores the original manifest, lock, profiles and all frozen assets.

The action plan derives its complete slots, expected file maps and command
context from that lock and the raw frozen profiles. Each declared runner arm
has its own materialization and command. The verifier has independent baseline
and attack materializations followed by its command. A parent's twin and its
control's attack keep distinct action identities even when their trees match.

`reserve_action()` appends and reads back a unique reservation before returning
an `ActionReservation`. The ticket binds case/kind/arm, binding/context/lock
digests, and the persisted ledger sequence and entry digest. It does not place
the entry's digest inside its own hashed payload. A command requires accepted,
completed materialization of its own inputs, revalidated before reservation.

The writer is single-writer and rejects stale handles. File content is flushed,
`fsync`ed and read back before a ticket or artifact reference is returned. An
existing content-addressed file must also synchronize successfully; a previous
failed write cannot be accepted merely because matching bytes remain. POSIX
directory entries are synchronized for created directories/files and ledger
appends. Python's portable implementation here supplies no Windows directory
entry power-loss primitive. This is a file synchronization/readback contract,
not a cross-platform claim that tickets survive power loss. Formal collector
adoption must establish the actual host/storage durability contract as well as
its prelaunch enforcement. A ticket alone does not establish isolation.

`complete_action()` binds raw `smallestlie.lifecycle-completion/v1` bytes to
that exact ticket, context, measured file maps, outputs and immutable
publication/supervisor sources. Its new `CompletionAuthority` must independently
authenticate the accepted collector's receipt of the durable ticket before
work began, actual materialization/launch, measured runtime/environment and
command, output completion and termination of descendant writers. Hashing an
input document or copying expected values cannot establish those facts.

Existing `outer-supervisor/v1` providers do not implement this new authority.
Their sequence numbers cannot be retrofitted into reservation entry digests.
Runner/verifier envelopes are eligible only after their own new completions
and raw output bindings validate. Runner eligibility is per arm: a proven
baseline target already green or attack target still red can retain a genuine
kill while another arm is missing. Missing repair/twin evidence cannot provide
confirmation or pair credit. The original envelope's identities and first
command sequence are checked before filtering eligible arm exits.

Each slot is consumed once. Reserved work without completion is retained as
`completion_missing`; never-reserved work is `not_run`. Rejected present bytes
are retained as `completion_rejected`. Observed timeout, spawn error, signal,
quota, incomplete output or internal error keeps its own disposition. These
facts do not manufacture assertion refutations. A crash/retry requires a new
bounded request; a failed synchronization cannot return a reusable ticket.

## Observation, review and adjudication

`seal_observations()` first disposes every frozen slot, retaining all cases.
It captures raw receipts, native reports/stdout/stderr, verifier metadata and
outputs, every auxiliary runner artifact, action completions/sources, and
first-pass validation artifacts. Each reference explicitly denotes present or
missing bytes. Malformed present data remains present; raw invalid UTF-8 and
line endings are preserved. Review bytes are forbidden before sealing.

The returned `ObservationSnapshot` identifies one complete ordered case/action
index. `finalize()` accepts that same session's snapshot once, reads back every
bound frozen input, policy, observation, auxiliary artifact and action source
before recording review, then binds post-run review to the actual parent/twin
observation validation digests. Accepted source readings are cached within
this snapshot; mutable authorities cannot supply different readings between
the first pass and adjudication.

All review dispositions precede every case row. Every row binds its raw
adjudication artifact and review validation; the summary binds the whole report
and exact frozen denominator/counts. Existing adjudication preserves finding
attachments, genuine kills, residual reconciliation, unknowns and qualified
paired headline counts. Protocol completeness does not establish execution
authority or a successful defense.

## Evidence-only revalidation

`verify_formal_lifecycle()` is read-only. Its caller supplies its own freshly
prepared exact-source run and independent authorities outside the bundle. It
reads raw size/digests, compares frozen input bytes, revalidates each completion,
reconstructs native capture roles, reacquires runner/verifier/review and human
preregistration authority, and recomputes first-pass facts and every case/report
row. Each source is read once per exact digest within this verification; caches
are not shared with another verification or request.

The result distinguishes `chain_ok`, `protocol_ok`, `complete`, `artifact_ok`,
`authority_ok` and `semantic_ok`. A coherent rewritten hash chain and report
cannot skip semantic checks. A complete retained missing-evidence report may
be internally consistent while `authority_ok=False`; its independently proven
refutations remain visible without claiming full-run acceptance. Bundled
declarations never grant their own authority. This verifier does not rerun any
command; execution replay remains a later, separately authorized entry point.

## Validation and remaining work

Synthetic tests cover full own-action pairing, malformed/misbound completion,
unobserved/incomplete slots, synchronization faults and stale writers, missing
authorities, partial genuine kills, bad envelope filtering, early/duplicate
reviews, byte substitution, post-seal source deletion/replacement, coherent
report fabrication, marker removal and denominator/finalization violations.

NOT_RUN: work-machine rule (`POLICY work-machine-local`); no local product/test
execution, collection, compilation, lint, build or installation. The admitted
`m12-adjudication-verify` payload/declaration/uv.lock are unchanged; its full
suite includes these tests. A new exact-source one-dispatch pool grant is
required. Earlier verified PR30 source `255f10d3f1a6bfdb38bea4b250c3f0f9378a5fcc`
passed focused 222/full 616 and merged as `dd396745a7b891e6ec77951607c09fb0ef7365aa`;
that consumed grant and evidence do not validate this new lifecycle source.

Remaining D work includes the accepted real collector and policy resolver,
production launch driver and CLI/gates, report/witness integration, independent
human Phase 1 and separately authorized formal W3 execution. Historical rt4
evidence remains historical, including its known missing own base captures.
