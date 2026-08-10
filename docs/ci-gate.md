# M5 — CI gate

Offline release-confidence gate for **SmallestLie itself** (and any repo that vendors the harness + fixtures).

## What it does

1. Runs **required profiles** against synthetic fixtures:
   - `naive_gate` + fast catalog → **must** observe false accepts  
   - `honest_gate` + fast catalog → **must** observe zero false accepts  
2. Enforces a **wall-clock budget** (disclosed; overrun → warning, not silent pass).  
3. Optional **diff-aware** attack family filter.  
4. Optional **baseline compare** (new false accepts = fail).  
5. Stages artifacts under `artifacts/smallestlie/`.  
6. Projects status with the rule: **SKIPPED / BLOCKED never succeed**.

## Commands

```bash
uv run smallestlie ci-gate
uv run smallestlie ci-gate --budget-seconds 600
uv run smallestlie ci-gate --diff-file changed.txt
uv run smallestlie ci-gate --baseline artifacts/smallestlie/ci-summary.json
```

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Required profile expectations met |
| 2 | Unexpected false accept (e.g. honest went green-wrong) |
| 3 | Warnings / budget |
| 4 | Blocked or required profile not run |
| 5 | Harness error / naive stopped finding seeded FAs |
| 6 | Invalid config |

## Artifact layout

```text
artifacts/smallestlie/
  ci-summary.json
  ci-summary.md
  campaigns/<campaign-id>/
    plan.json
    ledger.jsonl
    campaign-report.json
    runs/
    witnesses/
```

## Anti-theater rules

- Empty diff selection that removes all attacks → **not a pass** (`SKIPPED_NOT_RUN` / failure).  
- Missing catalog → failure.  
- Budget exhaustion mid-run → remaining profiles marked not-run (failure if required).  
- Never print `SECURE` or `NO VULNERABILITIES`.

## Diff → families

| Path pattern | Families |
|---|---|
| evidence/, artifacts/ | evidence, freshness |
| tests/ | execution, evidence |
| .github/, workflow | workflow, projection |
| policy, config | config, semantic |
| authority/ | authority |
| protected/, identity | path |

## Not this gate

Real-repository adapters (TomorrowCI / ClaimGate / Greenwash) are **not** selected here. Pick targets only after authorization packages exist.
