# M2 / M3 notes

## M2 — Oracle hardening

Fact-based plugins (target verdict never defines truth):

| Plugin | Invariant |
|---|---|
| discovery / execution_trace | required tests actually executed |
| revision_binding | evidence revision == target revision |
| artifact_hash | artifact bytes match manifest sha256 |
| workflow | required jobs not skipped |
| authority | approver on allowlist when approval present |
| semantic_policy | no PASS/FAIL inversion |
| fail_closed_defaults | critical fields present |
| path_canonical | full protected path intact |
| report_exit | channels agree; no forced disagreement marker |
| policy_presence | required policy file exists |

Unknown oracle types → `INCONCLUSIVE` (fail-closed).

## M3 — Minimization & regression

On each `FALSE_ACCEPT_OBSERVED`:

1. ddmin over mutation steps (when >1 step)
2. replay minimized witness 3/3
3. export `regressions/<ATTACK>-regression.yaml` + finding markdown

CLI: `smallestlie minimize <run-dir> --target <fixture>`

## M4 — Compound campaigns

- `plan_mode`: single | pairwise | mixed
- declarative corpus: `attacks/composition/CMP-*.yaml`
- auto pairwise SEQUENCE with budgets + truncation disclosure
- `composition_blind_gate` fixture (compound-only false accept)
- `interaction-report.json` with compound-only detection

## Not yet

- real-repository adapter implementation (designs exist)
- model hypothesis layer (M7)
- CI release-gate integration (M5)
