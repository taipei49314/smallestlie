# Measurement discipline

> **先建立量測器 → 再相信行為 → 回頭測試抓盲區**  
> Build meters first. Trust behavior only after meters pass. Retest blind spots.

## Why

SmallestLie must not issue self-completion. The same rule applies to the harness itself:

| Step | Meaning |
|---|---|
| **1. Measure** | Instruments produce evidence (`MEASURED_*`) |
| **2. Trust** | Behavior claims become `trust_allowed` only if required meters are `MEASURED_PASS` |
| **3. Blind spots** | Gaps (catalog, fixtures, tests, unused oracles, deferred claims) become a retest queue |

`MEASURED_PASS` is **not** `SECURE`.

## Commands

```bash
# Full structural suite
uv run smallestlie measure

# Also meter a campaign directory
uv run smallestlie measure --campaign outputs/CMP-...

# Blind-spot queue (refreshes measure by default if no report)
uv run smallestlie blindspots --refresh

# Recommended order for confidence
uv run pytest -q
uv run smallestlie ci-gate --budget-seconds 600
uv run smallestlie measure
uv run smallestlie blindspots
```

## Outputs

```text
outputs/measurements/
  measurement-report.json
  measurement-report.md
```

## Meter catalog (core)

| Meter ID | What it measures |
|---|---|
| `containment.policy_surface` | path/source/command/network/env primitives |
| `catalog.family_coverage` | attack families vs North Star taxonomy |
| `catalog.m1_minimum` | M1 attack ID presence |
| `catalog.composition_presence` | compound corpus |
| `oracle.independence_static` | oracle not wired to target.accepted |
| `fixture.matrix` | naive/honest/composition fixtures |
| `inventory.test_surface` | critical modules have tests |
| `ci.status_projection` | SKIPPED/BLOCKED never success |
| `campaign.*` | yield, rejection, replay, minimize, regression (needs campaign dir) |

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | suite_ok and no soft findings |
| 2 | MEASURED_FAIL or untrusted (non-deferred) claims |
| 3 | warnings, deferred claims, or high/medium blind spots |

## Anti-patterns

- Green CI without `measure`
- Asserting “oracle independent” without `oracle.independence_static`
- Treating empty diff / skipped campaign as pass
- Optimizing for raw mutant count (see North Star anti-metrics)
