# Cross-terminal action source map (M12 D)

`EcMultiDispatchSourceMapAuthority.verify(prepared)` reacquires original action
receipts from their individually configured terminal EC dispatches. It retains
the complete frozen slot denominator and checks a later sealed archive against
those sources. Each action can have its own EC source commit, run, attempt and
job. This closes the one-dispatch limitation of the existing GET-only map.

The new provider is `ec-multi-dispatch-source-map/v2`. Its
`VerifiedMultiDispatchSourceMap`, `TerminalActionProof` and
`TerminalActionResult` are separate carriers. They expose original source data
and source/dependency eligibility, without runner/verifier semantic views,
adjudication or recording authority. The existing v1 map and its exact-type
consumers are unchanged. No public v2 campaign/replay/minimize gate is enabled.

The separate [multi-dispatch semantic consumer](campaign-multi-dispatch-semantics.md)
now defines fresh per-action runner/verifier semantics, independent exact reviews
and full-denominator adjudication. It does not turn this source carrier into a
legacy envelope or enable recording/replay/public gates.

## External configuration and common session

The trusted caller imports one exact final `EcReceiptStore`, a
`MultiDispatchSourceMapGrant`, and the full tuple of `TerminalMappedAction`
slots. A configured source supplies its exact original reservation, one
`EcLifecycleCompletionAuthority`, coordinator release/ACK sequences and raw
child-journal SHA-256. Source-less slots retain their reservation or null and
cannot invent accepted sequences or a child journal grant.

All fields of `EcReceiptTrustRoot` except `publications` must match across
actions and final archive. This includes repository/workflow, workflow and
collector hashes, host/runner/generation, workload/declaration and configured
verifier runtime/environment pins. Frozen runner dependency bytes remain
action-reader checks. Publication grants retain the same
request, lock and product source. Only each grant's own EC source, run, attempt,
job, receipt/publication and external acceptance fields can vary.

The prospective v2 anchor freezes a session with request, lock, product source,
Phase-1 commit, full plan hash, common trust-root hash and coordinator epoch.
Its original raw ledger prefix ends at `preregistration_locked`. It cannot
name future dispatches, action/final receipts, map evidence or its own commit.
The common-root hash excludes publications, so no future dispatch is needed
to create the anchor.

Each fresh original reader checks its own terminal native run/job, workflow
and collector source bytes at that dispatch's EC commit, complete regular-file
Git inventory, raw publication manifest and saved workload context. It then
reads the action's independent collector/storage/prelaunch-journal admission
from that action's configured evidence commit. A final archive admission cannot
stand in for an action admission. Legacy outer-supervisor fields never grant
the new action authority.

`declaration_sha256` remains an externally configured pin compared with the
saved workload context. The existing receipt reader does not reacquire the
workload registry or recompute a declaration hash from registry source bytes.
No stronger declaration-source authentication is claimed here.

## Acyclic source roles and raw closure

| Role | Contents and references |
| --- | --- |
| Prospective anchor `A` | Frozen common session and exact raw pre-reservation lock prefix. |
| Original action `R_i` | Own terminal dispatch, raw prefix through its ticket, child journal, measured facts, outputs and acyclic completion/publication. |
| Final archive `F` | Complete ledger through `observations_sealed`, content-addressed artifacts, earlier `A`/`R_i` index and coordinator journal. |
| External map `M` | Exact session, archive dispatch, independent contracts, assembler pin, all slots/sources and exact `F` publication/index. |

`A`, every configured `R_i`, `F` and `M` are distinct. They cannot alias any
configured executed EC source, product source, Phase-1 commit or known action
admission evidence commit. The archive index has no `F`/`M` backreference; `M`
has no own-commit/digest field. An ACK containing `A` or `R_i` is preserved in
the later coordinator journal, outside the commit it acknowledges.

All configured admission commits remain known authority inputs even when a
different slot lacks its own source. Such a slot cannot borrow an admission
commit as its ACK receipt or claimed executed EC source. Unknown journal-only
source claims supply no proof or eligibility.

The map checks exact v2 schemas, complete slots in lock order, original tickets,
raw ledger hash chain and full protocol. `F` must extend the exact anchor bytes
and seal every frozen disposition before reviews. Every independently proven
child prefix must be the identical original ledger slice through its ticket.
Equivalent JSON, newline reencoding and rehashed forks cannot substitute.

Completion, validation, source/output references and the observation index are
checked against preserved content-addressed bytes, including explicit missing
references. For known source grants, completion/supervisor/action-publication
hashes and provenance must already match the sealed disposition before source
acquisition. Known configured admission/dispatch contradictions also reject the
whole map. An unavailable native job cannot hide those contradictions.

Each proven action independently recomputes its `ActionValidation`, checks the
entire final disposition and verifies original raw artifact copies. The index
and unproven artifacts receive raw closure checks only; that does not
authenticate their runner/verifier semantics or review approvals.

## Coordinator order and child order

`smallestlie.lifecycle-publication-journal/v2` has a separate coordinator
sequence, common session hash and epoch. Serial relations are:

1. `anchor_durable_ack` binds the exact `A`, raw anchor and locked-prefix hashes
   at the externally granted sequence.
2. `action_release` binds an unused original ticket, raw prefix/context, exact
   child dispatch, one-use identity, granted child interval and preceding ACK
   relation hash. It contains no future receipt or raw child-journal hash.
3. `action_publication_durable_ack` binds the release relation hash and original
   `R_i`, completion, action/outer publication and raw child-journal hashes.
4. The next release requires that ACK. An observed source-less slot still
   requires its recorded release/ACK, but the record creates no source proof.

Coordinator sequences strictly increase and tickets release in ledger order.
Configured sequences must match exact external grants. The release and prior
ACK relation hashes use canonical event JSON; they are not hashes of original
event text bytes. Separately, the grant pins the whole original journal bytes.

Child event sequences stay local to each exact dispatch and epoch. Different
dispatches can each use `1..5`; they are never compared to coordinator numbers.
Overlapping child intervals in the same dispatch/epoch are rejected. One-use
`(epoch, action_id)` identities cannot recur across actions. This contract
requires each child epoch to equal the common coordinator epoch.

Only a final dangling release with `completion_missing` and no independently
configured source is permitted. It retains the consumed ticket and missing
slot. There is no automatic recovery/abandonment ACK, retry or later release.

These checks authenticate recorded relations against imported grants and raw
sources. They do not prove actual launch timing. Four distinct external
acceptances cover anchor durability, publisher delivery, coordinator
no-ACK-no-work enforcement and complete mapping. Constructors, hashes, native
sequence numbers, Git dates or generic successful jobs cannot establish those
operational facts. Actual publisher/coordinator implementation and admission
remain required outside this reader.

## Results, rejection and remaining D

Every frozen slot returns `observed`, `source_missing` or `source_rejected`.
Unavailable or unaccepted original action bytes/admission/job reject that
source while preserving unrelated proofs. Known raw/grant/role/journal/fork
contradictions reject the whole map. Fresh exact store and authority instances
use the original implementations, bypassing caller instance `read`, `verify`
and `_action` hooks; no caller-created proof/result or registry is consulted.

An observed proof retains original dispatch/ref, reservation, completion,
sources, outputs, raw prefix/journal and actual native validation. Nonzero,
timeout, quota and incomplete output/writer dispositions keep their values.
Source/dependency eligibility does not mean completed, effective cheating or
verifier bypass. A command with valid own proof but unavailable or noncompleted
materialization keeps its proof and becomes ineligible. Missing twins/repairs
remain in the denominator.

The authored tests use synthetic independent API, admission, coordinator and
publication contracts. They cover distinct run/attempt/job/EC-source tuples,
raw bytes, separate sequence clocks, partial sources/dependencies, native
incomplete values, coherent contradictory grants/dispositions, role aliases,
raw prefix/copy replacement and forbidden future anchor references. A final
missing release is tested without fabricating a recovery ACK. These contracts
are not actual action publication, operational admission or formal W3 evidence.

PR36's consumed exact source `6cfb6da2d1a1fa32e1c333f208a0f38c706679de`
passed focused 222/full 964 and merged as
`a098fbe47c459860c4e2d2a80103c4292e2f0bfe`. Those results do not test this new
source. PR37's first authorized source
`1818998ddf2f7b00bbecbee23a342397fd0c5c24` ran once on host50 in
[run 37128696841/1](https://github.com/taipei49314/estate-consolidation/actions/runs/37128696841).
Focused 222 passed with zero failures/errors/skips. The full command timed out
at its 1600-second bound, exit 124, without `full.xml`; partial progress dots
cannot establish testcase identities, complete coverage or a passing result.
The original failure remains in immutable receipt
`c00bd028364558598c350b7e4800d89f51e95629`, tree
`a93e94f8b76658d4683284b88f50a3a69cbc4746` (23 raw blobs).

The test-fixture follow-up reuses a sealed default synthetic fixture once per
module, returning a separate deep copy of its complete object graph for every
case. Nondefault selections, incomplete actions and native mutators still build
independently. No source-reader verification result is cached: API, stores,
authorities and hooks are isolated, and every verification reacquires native
objects as before. A separate isolation/reacquisition test changes one copy's
job, hook and local files, then changes another copy's job after its first read.
All previous testcase identities and assertions remain.

NOT_RUN: work-machine rule (`POLICY work-machine-local`); the fixture follow-up
has not run locally or on pool. Its effect on runtime is unmeasured. The first
grant is consumed; a new bounded exact-source pool request must preserve all
964 prior test identities and independently inspect native receipt/JUnit/log
bytes. No local product, pytest/collection, syntax probe, compilation, lint,
typecheck, build or install is performed.
Workload declaration, dependencies, engine pins and existing five focused
groups are unchanged.

Remaining D includes an explicit semantic consumer for this new carrier,
recording/review/adjudication/CLI/report/witness integration, actual live
publisher/coordinator and collector/host/storage/policy-resolver admission,
native verifier and Mocha/Vitest adoption, independent human Phase 1 and
separately authorized formal W3. Historical rt4 results and missing red-side
logs retain their original scope. Agent framework merges cannot establish
human Phase 1.
