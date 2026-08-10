# Architecture

See the North Star document for the full system design.

## Implemented (M0–M3)

1. Policy & authorization gate
2. Immutable baseline capture
3. Fixture gate adapter (`fixture_gate`)
4. Deterministic campaign planner
5. Allowlisted mutator
6. Disposable sandbox executor
7. Independent O2/O3 oracles
8. Verdict comparator
9. Append-only ledger
10. JSON/Markdown reports + replay witnesses
11. Delta minimization + regression export

Network remains denied by default. Model-assisted hypotheses are out of scope until M7.

## Real adapters (design → implement)

- Design index: [adapters/README.md](./adapters/README.md)
- First real target design: [adapters/tomorrowci.md](./adapters/tomorrowci.md) (`DESIGN_ONLY`)

Implementation of real adapters requires a filled authorization package and does not begin from design docs alone.
