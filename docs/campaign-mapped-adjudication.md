# Mapped review, adjudication and follow-up recording (offline v1)

The mapped observation reader separates per-action R_i receipts from the
prospective anchor A, immutable final archive F and independent source map M.
`adjudication.mapped_engine.adjudicate_mapped_campaign` consumes that reader
directly, independently validates post-run semantic reviews and produces one
row for every frozen case. `campaign.mapped_recording` stores those results in
a separate follow-up journal J and replays them by reacquiring the sources.

## Independent review contract

`smallestlie.mapped-case-review/v1` has a new `context`, separate from legacy
`case-review/v1` observation envelopes. It binds the whole snapshot digest,
request/lock/plan/index, A/F/M identities and mapping acceptance, all ordered
action source/disposition summaries and the complete own/frozen twin semantic
summaries. Case binding, engine and pinned residual index remain explicit.
Constructing this context or a snapshot does not grant source authority.

`GitHubMappedReviewAuthority` requires the independently configured review
repository/account role, exact human merge registry and new
`MappedPostRunReviewGrant` entries. A grant binds exact raw review bytes,
request/lock/case, snapshot digest, context digest and external exact semantic
approval reference. The provider reads the actual approved blob; neither an
allowed actor, a request approval, an old review grant nor a caller-supplied
verification hook supplies that authority. Review commits must differ from
A/F/M and every R_i. The trusted integration must import genuine semantic
approvals; this framework and its synthetic tests cannot mint them.

After those guards, the shared pure content validator checks complete pinned
THREATMODEL/SPEC documents, raw digests, citations/line spans, case-specific
residual row coverage, actual frozen diff paths, theater declaration and exact
twin contrast/fingerprints. Partial-index absence cannot establish novelty.
Version-specific legacy review identity and provenance guards remain intact.

## Adjudication and complete counts

The entry point accepts raw review bytes or explicit missing reviews and
configured source/review readers. It obtains its own complete mapped snapshot;
there is no snapshot, report, accepted flag or effectiveness override input.
A structural source rejection aborts the acquisition; it cannot reuse an older
PASS or produce a new closed recording. Incomplete semantic observations remain
visible as unknown in the frozen denominator.

`smallestlie.mapped-adjudication/v1` retains the complete snapshot, every case's
runner/verifier facts, findings including unknown attachments, review digest,
source/semantic approval references and reasons. The shared pure verdict order
retains controls without defect credit, proven DEF refutations as
`killed_candidate` before missing review/repair/twin checks, valid verifier
blocks, unknowns, boundaries and documented residuals.

The basic `confirmed_defect` case count remains separate from
`paired_defect_case_count`, which is the headline. A headline additionally
requires matching frozen detectable-control roles/variants/command profiles,
parent twin effectiveness and control's own baseline/attack/repair effectiveness,
the control's own valid mapped verifier command/materializations and block,
reviewed near-shape relation, and a nonallowlisted finding simultaneously
matching declared rule/path, reviewed fingerprint and effective threshold.
An honest or repaired test is a different control; a matching fixture tree
cannot lend another action's evidence.

## Separate journal and replay

`record_mapped_adjudication` recomputes the complete report before creating a
fresh single-writer root. It refuses an existing or interrupted root. Artifacts
are content addressed, synchronized and read back before `journal.jsonl` is
written, synchronized and read back. Windows directory-entry power-loss
durability still requires the external host/storage adoption contract.

`smallestlie.mapped-recording/v1` is a distinct hash-chained protocol:

1. One anchor with frozen roster, request/lock, whole snapshot digest and raw
   snapshot artifact. The snapshot retains A/F/M and every R_i.
2. In frozen order, one review disposition per case with raw bytes or an
   explicit missing reference and review validation artifact, followed by its
   complete adjudicated row artifact.
3. One full report artifact, then EOF. Counts are recomputed from all cases.

The strict parser rejects duplicate/drop/reorder, bool sequence values,
duplicate JSON keys, incomplete bytes, absent summary and post-summary entries.
It checks syntax/order/chain only and supplies no observation authority.
Generic legacy `Ledger`/`verify_ledger`, FormalLifecycle and both M12 protocols
are unchanged. Nothing is appended into F; J contains no reference to its own
future publication commit.

`verify_mapped_recording` requires an externally supplied exact raw J digest.
The trusted caller must obtain it from its independent J reference; calculating
it from the bundle cannot prove original identity or publication acceptance.
Replay loads raw reviews, reacquires M/F/R_i and the separately configured exact
review grants, recomputes every semantic snapshot/review/row/report, compares the
entire native journal and verifies every referenced artifact's raw size/digest.
Even a coherently rehashed row/count/artifact substitution cannot override those
checks. Changed/rejected authorities cannot borrow a previously recorded PASS.

## Scope and proposed verification

This is an offline framework contract. Actual collector/publisher/storage/
coordinator and independent reviewer admission, formal human Phase 1 registry,
launcher/CLI/report/witness wiring, configured-policy resolver adoption and
formal W3 remain unfinished. Historical missing rt4 red-side logs remain missing.
The Checkwash pin, runner versions and dependency locks are unchanged.

New synthetic contracts cover complete pairs/unknowns/kills, exact semantic
grants and source roles, swapped case/twin/context, legacy authority rejection,
partial source/citation/residual review, control's own evidence, full journal
closure, raw/coherent tampering, source/grant rejection during replay and refused
second/interrupted recording. Tests are authored; their results are not inferred
from source.

NOT_RUN: `POLICY work-machine-local`; no local product/test/import/collection,
syntax probe, compile, lint, typecheck, build or install. A fresh exact-source
bounded pool grant is required. The proposal retains the original five focused
groups and the full test suite, including all prior 858 native testcase
identities/multiplicities. `m12-adjudication-verify` now explicitly selects a
1600-second internal full-suite deadline (previously 1200; PR34 used 1082.641).
Other workloads retain the 1200-second default. The admitted declaration, empty
parameters, cache=false, dependency pins and outer 35-minute bound stay the same;
the harness source change must be included in the new execution grant.
