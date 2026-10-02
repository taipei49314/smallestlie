# M12 research adjudication (slice C)

`adjudication.engine.adjudicate_campaign()` consumes the immutable `PreparedRun`
and raw `CaseInputs` for the entire frozen catalog. It validates runner captures
again, independently authenticates verifier observations and post-run reviews,
then adjudicates once per case. It performs no filesystem or process operations;
configured authorities may retrieve independently trusted evidence. No provider
means unknown. This is a contract, not a production provenance implementation.
Slice D must supply the independent providers and connect campaign/report/replay;
the v2 execution gates remain closed in this PR.

No v1 `ComparisonResult`, false-accept count, exit code or campaign expectation
changes. The Checkwash adapter adds `raw.findings_payload`, including attachments,
resolved-label evidence and diagnostics, without recomputing its legacy policy.
Legacy exit/report disagreement remains observable; research qualification does
not use either channel alone.

## Verifier capture and trust

`smallestlie.verifier-observation/v1` metadata binds `case_binding()` to the
`attack` arm, real `checkwash` adapter, full engine identity, complete frozen
baseline/attack tree digests, actual resolved base/head commits, argv/cwd,
effective `fail_on`, supervisor termination/exit, truncation status and raw
stdout/stderr SHA-256. A separate `VerifierAuthority` supplies an authenticated
`TrustedVerifierEnvelope`. The provider must verify actual fixture preparation,
mutation, source, interpreter/environment and published artifact; the real
baseline configuration/allowlist and effective policy; and outer supervisor
observations. Copying expected/metadata values is not a provider implementation.

M12 supports the six-argument `check HEAD~1..HEAD --format json` invocation with
logical cwd `.`. Report base/head labels may be the requested `HEAD~1`/`HEAD` or
the authenticated resolved commits; labels do not replace commit evidence.
Only completed integer exit 0/pass or 1/block, consistent with the authenticated
effective threshold and nonallowlisted findings, qualifies. Engine error,
configuration diagnostics, timeout, malformed output, channel disagreement or
binding mismatch remains unknown. Findings preserve rule/path/severity/unit,
opaque fingerprint, allowlist status and all native attachment fields. Empty
global paths are preserved but cannot match a declared confined detection path.

## Independent post-run review

`smallestlie.case-review/v1` binds complete formal case identity, engine pin,
residual index and canonical validation digests of the case and declared
control's actual runner/verifier observations. `ReviewAuthority` authenticates
the exact review bytes and case binding independently of attack YAML. It attests
the reviewer's case-specific semantic judgments; cryptographic hashes alone do
not establish scope or novelty.

Every pinned source (THREATMODEL and SPEC) must have a complete-document review
rationale with its exact raw-byte digest. Resolved scope requires a verified
source quote/span. Residual coverage includes case-specific rationale per row.
`no_match_reviewed` is a full-source post-review conclusion, never partial-index
absence. `matched_residual` only references explicitly documented residual
entries; `reopened_closed` only references closed entries. Mixed/narrowed rows
remain unresolved unless a later contract supports explicit variant coverage.
YAML declarations remain unchanged hypotheses, even if post-review disagrees.

Theater review binds the full actual changed-path set of frozen baseline/attack
variants and requires the declared theater paths to materialize. The separately
authenticated semantic rationale establishes why the change is cheating. A twin
review binds the exact declared contrast and relevant finding fingerprints.
Replacing any linked observation invalidates the old review.

## Verdicts and case counting

Real authenticated runner refutation of a preregistered DEF leaves a
`killed_candidate`, even when verifier evidence is missing. Missing or untrusted
execution is never a kill. Other refuted candidates remain
`ineffective_candidate`. Valid verifier blocks are `attack_rejected`, with
runner effectiveness stored separately. CTL cases retain their control outcome
and never receive defect credit. Authenticated unresolved/out-of-scope/theater
decisions remain `boundary`; missing review provenance remains `unknown`.
Effective in-scope bypasses covered by an explicit residual become
`documented_residual`. Effective, reviewed theater bypasses with complete
no-match or reopened-closed coverage become `confirmed_defect`.

`paired_headline` additionally requires all of:

- Parent attack and twin-arm effectiveness confirmed, and control case's own
  baseline/attack/repair effectiveness confirmed.
- Frozen same-bug, baseline/repair and exact twin/control attack variant identity,
  correct detectable-attack control role, and matching twin/control commands.
- Control case's own authenticated, normally completed verifier block.
- Reviewed semantic near-shape relation, plus one finding that simultaneously
  matches declared rule and exact path, reaches effective `fail_on`, is not
  allowlisted, and has a fingerprint named by that review.

An unrelated critical plus related warning, rule/path from different findings,
honest control, missing control receipt or parser failure cannot create a pair.
Multiple findings count one frozen case. Input order/repeated report generation
does not change counts; missing cases keep their rows. Undeclared input IDs are
rejected. `confirmed_defect_case_count` and `paired_defect_case_count` are separate
research metrics; headline uses the latter. They are case counts, not independent
mechanism counts: no root-cause grouping is inferred in this slice. Cross-run
aggregation must not sum repeated observations as new cases.

Unit tests use synthetic authorities/captures only. No W3 result, formal
Phase-1/2 run or new defect count is produced by this implementation. Local
validation is NOT_RUN under POLICY work-machine-local. The prepared separate
pool workload requires admission and exact-source authorization before dispatch.
