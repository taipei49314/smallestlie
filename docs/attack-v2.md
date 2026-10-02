# M12 attack v2: design declarations and pinned statement sources

This is the first M12 slice. It loads and validates research designs; v2
campaign, replay and minimize execution remain blocked until preregistration
and evidence validation are integrated. Existing v1 catalogs, comparisons,
false-accept counts and CI expectations keep their meaning. No W3 case result
or M12 campaign verification is recorded by this slice.

## Declaration contract

Use explicit `schema_version: smallestlie.attack/v2`. All existing required
attack fields remain required. Additional fields are:

```yaml
adjudication:
  preregistered_class: DEF # CTL | DEF | BND | RES; hypothesis, not ground truth
  expected_verifier_outcome: accept # accept | block | visible-warn; prediction
  claim_scope:
    status: unresolved # in_scope | out_of_scope | unresolved
    rationale: Product claim review still required.
  residual_mapping:
    status: unresolved # matched_residual | no_match_reviewed | unresolved
    row_refs: []
    rationale: Full pinned sources have not yet been reviewed for this case.
  control_role: null # CTL: detectable_attack_control | honest_control | repair_control
  twin:
    case_id: EXAMPLE-CONTROL
    role: detectable_attack_control
    contrast: One predeclared detection-relevant edit; semantic equivalence still needs evidence.
    detection:
      rule_ids: [EXPECTED_RULE_ID]
      paths: [tests/test_billing.py]
runner_protocol:
  profile_id: case-runner-protocol
  profile_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  baseline_assertion: test_total_exact_value
```

This snippet illustrates schema only, not an actual fixture, rule mapping,
runner profile or result. The real cases/twins must be read and reviewed first.

A DEF design requires a non-self twin. Its referenced case must be CTL with
`detectable_attack_control`, predict `block`, and share the runner protocol.
Honest and repair controls remain separate roles. The declared contrast and
rules are design inputs; loader validation does not prove matching cheating
semantics or a real red-to-green transition.

Observed exits, counts and logs belong in Phase-2 receipts. `runner_evidence`
and unknown declaration keys are rejected, including v2 fields under v1.
Null residual claims and absent rows are unresolved, not evidence of novelty.
`no_match_reviewed` is a declared hypothesis needing later case-bound review;
this slice does not certify it. Unknown schemas and ambiguous YAML keys fail.

## Complete v2 catalogs

Use explicit `schema_version: smallestlie.catalog/v2`, `name`, `attacks`,
`residual_index`, and `engine` (version, artifact_sha256, source_revision).
The index reference is repository-relative. Only single/full catalogs are
supported; a v2 catalog must contain its twins and cannot mix v1 cases,
auto-compose, or pass through diff filtering. Selected malformed definitions,
duplicate case/file IDs and invalid control references fail explicitly.
`catalog_snapshot()` has its own `smallestlie.catalog-snapshot/v1` schema;
it contains resolved case specifications and is not a reloadable catalog file.

## Pinned statements

`catalogs/residual-rows-checkwash-v0.5.0.json` indexes exact THREATMODEL and SPEC
snapshots at published source `24b60a2019a5900291ecb35ab8290f34af2d5438`.
Their original bytes, document SHA-256, Git blob SHA-1 and inclusive quote
spans/hashes are preserved. Git attributes prevent newline conversion in the
snapshots. Version, artifact digest and source revision must match the engine
pin; this slice does not re-pin the engine. The reviewed index's exact bytes
are independently pinned in code, so changing a row's interpretation or
substituting a source while updating its self-reported hashes is rejected.
The index also has Git attributes preserving its bytes on Windows checkouts.

The index is explicitly **partial**. Entries are statement locators, not
automatic case-coverage decisions. SPEC's SUBJECT_NORMALIZED two-hop residual
is different from THREATMODEL's one-hop repair-call-graph limit. Closed,
out-of-scope, narrowed and mixed rows retain their distinct status; a mixed
Closed-with-residuals row cannot excuse every variant. Cases can refer to such
rows for review, but `matched_residual` may only refer to explicitly indexed
residual statements. Future adjudication still requires case-coverage evidence.

## Validation

New regression tests cover v1 roundtrip, rejected v2 downgrades/unknown fields,
control dependencies, duplicate/malformed selected cases, source/quote/pin
tampering, Closed/mixed-row misuse, and execution gates including CLI replay
and single-step minimization. They are prepared for pool execution.

NOT_RUN: work-machine rule (`POLICY work-machine-local`); no local product,
pytest collection, compilation, lint or dependency installation. Source reads,
Git review and static agent review are not passing test results.
