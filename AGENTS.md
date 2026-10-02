# Collaboration protocol (humans and coding agents)

## checkwash pin follows an authorized published release

- The vendored engine `verifiers/checkwash.pyz` is re-pinned **only** in the
  PR that follows a published checkwash release, and only with a one-time
  human authorization that names that re-pin, recorded in this repository
  (in the re-pin PR). estate-consolidation no longer governs this repository
  and does not claim, authorize or release for it (EC POLICY
  `independent-repos`, T-451, 2026-09-26). The weekly slot was canceled by
  T-197. The one-time grants for v0.3.3 (T-229), for v0.4.2 (Nelson,
  2026-09-29, recorded in `docs/adapters/CHECKWASH_M10.md`) and for v0.5.0
  (Nelson, 2026-10-01, recorded in `docs/adapters/CHECKWASH_M11.md`) are
  consumed by their re-pins; none authorizes a later pin.
  Never between authorized releases, never to a dev build, never to
  anything that is not a published release asset.
- A re-pin moves four things together: the artifact, `PINNED_VERSION` and
  `PINNED_SHA256` in `src/smallestlie/adapters/checkwash.py`, the table in
  `verifiers/README.md`, and `docs/adapters/checkwash.md`.
  `tests/unit/test_checkwash_pin_consistency.py` fails when the first three
  disagree.
- Frozen: the greenwash adapter line (`adapter greenwash`, `greenwash-wave-a`)
  is superseded by the real-engine line. No further work on it.
- Public repository: open a PR, do not merge it. The human merges.

## M12 second-wave campaign protocol

- Follow the authorized published pin's diff, enumerate its repaired surfaces,
  and read the pinned repair source before designing nearby shapes. Do not
  change the pin as part of a campaign or reuse a consumed re-pin grant.
- Freeze cases, hypotheses, preregistered class and declared twins in a
  results-free Phase-1 PR before formal execution. A detectable twin retains
  the same bug and effective cheating, with a nearby shape the engine catches;
  an honest or repaired test is a separate control. Declare the relevant
  blocking rule/path and contrast before running.
- Formal Phase 1 requires the independent exact human approval/merge registry.
  Permission for an agent to merge framework PRs does not establish that fact
  or authorize formal runner execution. Preserve the actual actor/provenance.
- Phase 2 binds the exact approved Phase-1 commit, request/source, complete
  frozen catalog, pin and residual-source bytes, and durable lock before any
  launch. Use the separately authorized execution host and bounded workload;
  verify immutable raw observations and independent supervisor/review sources.
- Adjudicate the complete frozen denominator in two passes. Preserve genuine
  DEF refutations in the kill table, incomplete evidence as unknown, residual
  reconciliation and relevant detectable twins. Count only qualified paired
  cases as the headline; never silently drop unsupported or missing cases.
- Record the M-record and Phase-2 artifacts with raw digests, actual runtime,
  source/dispatch, lock order and honest limitations. Historical local rt4
  results may inform design; do not relabel them as formal preregistration or
  invent missing logs. Formal replay reacquires independent source authority;
  a witness bundle cannot authorize itself, and rerunning needs a new request.
