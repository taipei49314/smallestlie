# Architecture

See the North Star document for the full system design.

## Implemented core pipeline (M0–M5)

1. Policy & authorization gate
2. Immutable baseline capture
3. Fixture gate adapter (`fixture_gate`)
4. Deterministic campaign planner (+ compound / pairwise)
5. Allowlisted mutator
6. Disposable sandbox executor
7. Independent O2/O3 oracles
8. Verdict comparator
9. Append-only ledger
10. JSON/Markdown reports + replay witnesses
11. Delta minimization + regression export
12. CI gate (`smallestlie ci-gate`) — offline fixtures, budgets, diff select, baseline compare

Network remains denied by default. Model-assisted hypotheses are out of scope until M7.

## CI

- [ci-gate.md](./ci-gate.md)
- Workflow: `.github/workflows/smallestlie-ci.yml`

## Real adapters (design → implement)

- Design index: [adapters/README.md](./adapters/README.md)
- Implemented adapters (`get_adapter` in `src/smallestlie/adapters/base.py`):
  `fixture_gate`; `greenwash` (synthetic SUT, frozen 2026-09-03); `checkwash`
  and `checkwash_blind` (real engine, vendored `verifiers/checkwash.pyz`, current
  pin v0.4.2)
- ClaimGate: `DESIGN_ONLY`
- TomorrowCI: retired (repositories deleted 2026-09-26, estate T-457)

Implementation of real adapters requires a filled authorization package and does not begin from design docs alone. Target selection is deferred until progress/CI is stable.
