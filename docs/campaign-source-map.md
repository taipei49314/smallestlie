# Offline cross-action source map (M12 D)

This document describes the original same-dispatch v1 contract. The separate
[cross-terminal v2 source map](campaign-multi-dispatch-sources.md) supports each
action's independently configured terminal dispatch without changing this
reader or its exact-type consumers.

`EcLifecycleSourceMapAuthority.verify(prepared)` reads a complete sealed
action map from independent immutable sources. Each action keeps its own
receipt commit. The reader checks that all action prefixes belong to the same
raw ledger, that earlier proven dispositions survive unchanged, and that
publication readback precedes the next accepted action. Missing sources retain
their frozen slots and do not erase unrelated valid evidence.

This is a separate GET-only contract. Its `VerifiedLifecycleSourceMap`,
`MappedRunnerSources` and `MappedVerifierSources` are not legacy completion or
execution envelopes. It does not record, launch, finalize, adjudicate, replay
or activate `FormalLifecycle`. The v1 providers and v2 aggregate provenance
guards are unchanged; they still reject aggregates whose one `immutable_ref`
differs from their command completions. A future consumer needs an explicit
new contract rather than aliases or ancestor inference.

## Independent grants and source roles

The trusted integration caller imports one final `EcReceiptStore`, one
`LifecycleSourceMapGrant` and a tuple of `LifecycleMappedAction` entries,
including entries without a source. Each configured observed action has its
own `EcLifecycleCompletionAuthority`, exact ticket and externally granted
publication ACK sequence. These are caller-supplied trust boundaries, never
discovered from a witness or arbitrary map JSON.

Every source store has the same request, lock, product/EC source, numeric
run/attempt/job, host/generation, workflow/collector/runtime/dependency context.
Only the exact per-role publication grant differs. The existing single-action
reader independently revalidates each action's raw facts, outputs, wrapper,
complete inventory and externally accepted collector/storage/ticket journal.
The map also reads the exact independently accepted assembler/publisher source
pin at the executed EC source commit.

| Role | Contents and allowed references |
| --- | --- |
| Initial anchor `A` | Exact original lock, complete plan and raw prefix ending at `preregistration_locked`; no reservations or future commits. |
| Action receipt `R_i` | Canonical wrapper, measured facts, raw prefix ending at its ticket, journal and outputs. Prefixes may refer to earlier `R_j`, never their containing `R_i`. |
| Final archive `F` | Complete ledger through `observations_sealed`, content-addressed action artifacts, index and publication journal referencing earlier `A`/`R_i`. |
| External map evidence `M` | Exact dispatch/contracts, assembler pin, `A`, all slots and `R_i`, and exact `F` publication/index. |

`A`, all configured `R_i`, `F` and `M` must be distinct and cannot alias the
executed EC source or frozen product source/Phase-1 commits. The archive index
contains no `F` or `M` backreference; `M` contains no own-commit/digest field.
Current canonical `ActionValidation` bytes include `provenance_ref=R_i`, so
they belong in the later ledger/archive, never inside their own `R_i`.

Likewise, a readback ACK mentioning `A` cannot be inside `A`, and an ACK
mentioning `R_i` cannot be inside `R_i`. Both are preserved in `F`'s independent
publisher journal. Git timestamps, ancestry, byte equality or generic green
publication cannot substitute for the actual source role or execution order.

`LifecycleAnchorGrant` pins exact anchor/prefix paths and raw hashes, publisher
epoch and native ACK sequence. The map grant pins exact `M`, archive index,
ledger, publisher journal and assembler bytes, and separate anchor, publisher
and mapping acceptance references. The external trusted process must accept
the actual pinned publisher/assembler's durable anchor readback, one-use
identities, no-ACK-no-work, receipt publication/delivery and no-next-work before
readback. A constructor or a matching hash cannot establish those facts. No
production implementation or admission of these external contracts is added.

## Raw closure and publication order

Both `smallestlie.lifecycle-source-map/v1` and
`smallestlie.lifecycle-source-archive/v1` contain exactly the frozen slots in
lock order. Each entry retains its explicit slot, original reservation (or
null), and exact source paths/hashes/ref/publication sequence (or null).
Omitted, extra, duplicate or borrowed slots are rejected before filtering.

The initial anchor's raw JSONL is an exact beginning of `F`'s raw ledger. Every
proven action prefix is byte-for-byte that same ledger from its first entry
through the action's persisted reservation. Native integer sequences, string
envelope fields, complete hash chains, v2 protocol, original lock and complete
plan are revalidated. Equivalent JSON or newline reencoding does not count as
the same prefix. The final ledger must dispose all frozen slots and end at its
full observation seal, before reviews/adjudication.

Every disposition's completion, validation, source and output references,
including missing references, are checked against content-addressed archive
copies. The observation-index artifact is checked for raw preservation only;
this contract does not authenticate its runner/verifier semantics or approvals.
For each independently proven action, the reader recomputes `ActionValidation`
from its actual `R_i` and checks the entire final disposition and canonical
validation bytes, plus every raw source/output copy. A known disagreement
rejects the complete map; it cannot be filtered into a missing slot.

`smallestlie.lifecycle-publication-journal/v1` binds exact dispatch and epoch:

1. `anchor_durable_ack` binds the exact anchor commit, raw record and locked
   prefix hashes, at the independently granted native sequence.
2. Each `action_publication_durable_ack` binds exact ticket, `R_i`, completion,
   action publication and outer EC publication hashes.

ACK sequences and ticket reservations increase without reuse. Every observed
ledger action needs its publication ACK, including an action whose independent
source is unavailable. ACK receipt commits cannot be reused by another slot or
alias input/anchor/map/archive roles. A configured action's first native event
must follow the preceding ACK, and its publication ACK must follow its own
output seal; its original single-action journal checks ACK/work/termination/
writer/seal internally. Known action identities cannot recur within an epoch.
Missing source intervals are not inferred or independently authenticated.

## Results and eligibility

The result retains all slots as `observed`, `source_missing` or
`source_rejected`. An `observed` proof preserves actual source ref, reservation,
raw bytes and native termination/output/writer disposition. It never rewrites
an incomplete disposition as completed.

Source proof and dependency eligibility are separate. A command with a valid
own proof but missing/rejected/noncompleted materialization keeps its proof
and becomes ineligible. An unrelated missing twin, repair or case keeps its
slot and does not poison independent baseline/attack proof. This preserves
evidence a later semantic consumer can use for honest refutation, without
creating a verdict or a headline here. `eligible` means source/dependency
eligibility; it does not mean completed, effective cheating or verifier bypass.

Malformed full mapping, source-role reuse, journal contradictions, forked
prefixes or disagreements with known proof return no verified map. Failure
to independently validate one configured action returns `source_rejected` for
that slot while preserving other proofs. It supplies no facts for command
prerequisites. Map membership and raw archive claims alone supply no authority.

## Validation and remaining work

Synthetic contracts exercise distinct sequential source refs, all frozen
slots, byte preservation, incomplete outputs, partial sources/dependencies,
coherent contradictory dispositions and forks, raw reencoding, admission/pin
replacement, role aliases, publication ACK ordering/reuse and legacy carrier
rejection. They require independently configured synthetic stores and grants;
passing them cannot establish actual publisher or collector adoption.

NOT_RUN: work-machine rule (`POLICY work-machine-local`); no local product,
pytest/collection, syntax probe, compilation, lint, typecheck, build or install.
PR32 source `a99cadcd5f3752f5ef3f1f585182f4ad0eea293f` passed focused 222/full
740 and merged as `581533771a70cb08b7a747e03d7c84fc649eab49`. Its consumed
grant does not validate this new source; a new exact-source pool run is needed.

The separate [mapped observation consumer](campaign-mapped-observations.md)
revalidates F's index/captures and computes native runner/verifier semantics
while retaining every per-action source. It does not turn the carriers in this
module into legacy execution authority or activate lifecycle recording.

Remaining D includes mapped recording/review/adjudication integration, actual
live publication and collector/coordinator/storage/policy-resolver admission,
launch/CLI/report/witness integration, independent human Phase 1 and separately
authorized formal W3. Historical rt4 captures retain their original scope and
missing red-side logs.
