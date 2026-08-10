# Architecture

See the North Star document for the full system design.

## Implemented (M0–M5)

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
- TomorrowCI / ClaimGate / Greenwash: `DESIGN_ONLY`

Implementation of real adapters requires a filled authorization package and does not begin from design docs alone. Target selection is deferred until progress/CI is stable.
