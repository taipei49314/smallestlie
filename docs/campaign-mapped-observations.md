# Mapped semantic observations (offline v1)

Sequential actions have distinct immutable receipt commits. The source-map
reader proves their ledger/publisher relationships, but its `eligible` flag
does not mean a command completed, cheating worked or Checkwash accepted.
`campaign.mapped_observations.read_mapped_observations` adds those semantic
checks in a separate GET-only snapshot contract.

## Input and source authority

The entry point accepts a trusted `PreparedRun` and an externally configured
exact `EcLifecycleSourceMapAuthority`. It revalidates the provider's source
contract, rather than adopting a caller supplied verified result or replacing
the provider with a `verify` callback. Constructing a mapped dataclass does not
authorize a read. Actual collector, publisher, storage and coordinator contract
acceptance remains an external trust boundary; this reader cannot establish it.

The reader obtains the accepted final archive F, exact ledger bytes and sealed
observation index through the immutable Git source. It verifies frozen manifest,
lock, profiles/assets and policy bytes, the full case/action denominator, index
bindings, fixed capture roles and every content-addressed artifact's size/hash.
It reconstructs capture aliases from the raw aggregate receipt and artifact
index without writing anything. Reaccepted outer bytes cannot replace these
checks. Structural source/index contradictions return no snapshot; callers must
retain their already frozen denominator and record the acquisition as unknown.

F's existing `validations.runner`, `validations.verifier` and
`validations.effectiveness` are old first-pass raw artifacts. The new snapshot
retains their digests for inspection and computes mapped observations separately.
It neither adopts their claimed results nor writes replacements into F.

## Runner semantics

Every frozen runner arm remains present. Its observation includes its own
command R_i and materialization reference, ticket/completion/supervisor/
publication/prefix digests, native disposition and raw capture digests. A
missing/rejected source cannot borrow another arm's receipt. An authenticated
own command with missing/noncompleted materialization retains its reference
but cannot supply semantic evidence.

Semantic eligibility additionally requires independently valid completed
execution, an integer exit (never bool), complete outputs and reaped writers.
The aggregate receipt header must match the exact accepted dispatch and case.
Each arm's runtime, runner, installed dependencies/lock, semantic environment,
command, cwd and config must match its independently measured command facts.
Fixture/production identities match frozen complete files; termination, output
references and stdout/stderr/report bytes match the own command proof exactly.
The existing native JUnit/Vitest-JUnit/Mocha parsers validate testcase records,
assertion identity and report/exit agreement.

The shared pure `assess_bound_change` contains the original arm decision order.
Baseline target already green, or baseline assertion red plus changed assertion
still red, refutes the candidate before checking repair calibration. Thus
missing twin/repair does not erase an independently proven refutation. A
positive needs the bound assertion red, changed green and repaired target green;
unproved arms remain unknown. `confirmed` here describes runner effectiveness,
not `confirmed_defect`, a paired headline or final research adjudication.

Legacy `assess_effectiveness` still checks its original prepared-run and singular
provenance guards before calling the same pure helper. No mapped source is made
into a `TrustedExecutionEnvelope` or a legacy `RunnerEvidenceValidation`.

## Verifier semantics

The verifier needs independently completed baseline and attack materializations
and its own completed command proof. Exact metadata/stdout/stderr bytes must
match that proof; metadata binds the complete frozen trees, engine, resolved
commits, actual command, native termination and effective threshold. Metadata's
logical `cwd="."` matches the measured logical cwd; the source authority already
checks the separate absolute native cwd/runtime/engine paths and environment.

Policy support remains the previously admitted default: a complete base without
`.checkwash`/`.greenwash`, fail-on high and no allowlist. Configured-policy
resolver adoption remains external and unsupported. The native findings schema,
severity counts, range labels, diagnostics, verdict and integer exit must agree
with the effective policy. A critical finding with exit zero remains unknown.
Parsed findings retain complete source spans and unknown attachments, including
when a subsequent channel/policy check rejects acceptance; skipped files remain
in the snapshot too. No green exit hides a known critical finding.

## Output and subsequent integration

`smallestlie.mapped-observations/v1` has distinct A/F/M source roles, the mapping
acceptance reference, raw index digest, complete ordered action summaries and
complete ordered case observations. Per-action R_i references remain distinct;
there is no invented aggregate `immutable_ref`. Missing/rejected/incomplete
slots retain their states, captures and reasons alongside unrelated valid facts.

`MappedObservationSnapshot.validation_sha256` binds the entire schema, request,
lock, plan, index, source roles, all action references/dispositions and all case
results. Mapped recording/review binds this summary plus case/twin identity
through the separately versioned [mapped adjudication contract](campaign-mapped-adjudication.md).
Neither this digest nor constructing
the dataclass supplies source authority by itself.

The snapshot reader itself does not activate `FormalLifecycle`, `_EligibleAuthority`,
launch, CLI or witness integration. The linked mapped adjudication contract now
supplies separate review, follow-up recording and complete case counts.
Legacy runner/verifier validators continue rejecting mapped carriers. It does
not establish formal human Phase 1, execute W3, adopt real runners/collectors/
publishers/storage/coordinators or repair missing historical rt4 red-side logs.

## Validation status

Synthetic contracts include three native report formats, distinct action refs,
effective cheating with a detectable near shape, full missing denominators,
partial refutations, failed eligibility/completion, raw source/metadata/capture
replacement, structural F-index contradictions, complete findings on channel
disagreement, original first-pass retention and legacy carrier rejection.

NOT_RUN: `POLICY work-machine-local`; no local product/test/collection/import,
syntax probe, compilation, lint, typecheck, build or install. Git whitespace
verification and independent read-only review are separate from execution.
PR33 exact source18ff passed focused222/full802 and merged e3285be1; its consumed
grant does not validate this source. A new exact-source bounded pool grant is
required before executing this synthetic framework regression. Full M12 D and
formal W3 remain unfinished.
