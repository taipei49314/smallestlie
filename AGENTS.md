# Collaboration protocol (humans and coding agents)

## checkwash pin follows an authorized published release

- The vendored engine `verifiers/checkwash.pyz` is re-pinned **only** in the
  PR that follows a published checkwash release, and only with a one-time
  human authorization that names that re-pin, recorded in this repository
  (in the re-pin PR). estate-consolidation no longer governs this repository
  and does not claim, authorize or release for it (EC POLICY
  `independent-repos`, T-451, 2026-09-26). The weekly slot was canceled by
  T-197. The one-time grants for v0.3.3 (T-229) and for v0.4.2 (Nelson,
  2026-09-29, recorded in `docs/adapters/CHECKWASH_M10.md`) are consumed by
  their re-pins; neither authorizes a later pin.
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
