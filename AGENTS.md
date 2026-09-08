# Collaboration protocol (humans and coding agents)

## checkwash pin follows an authorized published release

- The vendored engine `verifiers/checkwash.pyz` is re-pinned **only** in the
  PR that follows an explicitly authorized checkwash release under the
  current estate PLAN. The automatic weekly slot was canceled by T-197;
  T-229 authorizes v0.3.3 and its pin handoff once, then refreezes.
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
