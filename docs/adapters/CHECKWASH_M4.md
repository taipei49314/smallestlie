# Checkwash campaign log (real engine, M4 re-pin)

**Status:** EXECUTED — checkwash **v0.2.11** pyz from GitHub Release
**Date:** 2026-09-02 · **Machine:** LAPTOP-01AGNPJU · estate **T-47**
**Human go:** 「smallestlie 重釘 v0.2.11」
**Artifact:** `verifiers/checkwash.pyz` SHA-256 `614d18890c036dedca53465992ae107b7ce5d2bf078ac0ef9f07293d2caf4eb9` (`python checkwash.pyz --version` → `checkwash 0.2.11`)
**Source:** annotated tag `v0.2.11` @ `283db52`; release https://github.com/taipei49314/checkwash/releases/tag/v0.2.11

M0–M3 logs are not rewritten. They record v0.2.8 (M0–M2) and v0.2.9 (M3).

## What changed in the engine

v0.2.10 and v0.2.11 contain **no detector logic change**. v0.2.10 advanced
the Action trust-lag pin; v0.2.11 closed five rename-residue and first-run
defects (checkwash issues #68–#72: `.checkwash/**` guardrail role, one
config-directory resolver, bare `hook` exit code, BOM-tolerant config,
Action identity). None of them touches a rule this harness probes, so the
re-pin expectation is: **every verdict identical to v0.2.9.**

## Observed on this pin

The same 23 checkwash tests (`tests/unit/test_checkwash_adapter.py`,
`tests/integration/test_checkwash_m2.py`, `test_checkwash_campaigns.py`,
`test_checkwash_wave1.py`) were run twice in the same environment — once
against the v0.2.9 artifact as a baseline, once against v0.2.11. Both runs:
23 passed. The expectations those tests pin:

| Attack | v0.2.9 | v0.2.11 |
|---|---|---|
| CW-W0-03 | `ATTACK_REJECTED` | `ATTACK_REJECTED` |
| CW-W1-TWIN | `ATTACK_REJECTED` | `ATTACK_REJECTED` |
| CW-W2-75 | `ATTACK_REJECTED` | `ATTACK_REJECTED` |
| CW-W1-2HOP | `FALSE_ACCEPT_OBSERVED` | `FALSE_ACCEPT_OBSERVED` (SPEC two-hop residual, unchanged) |

Wave0 theater 8/8 rejected. Honest control still `TRUE_ACCEPT_OBSERVED`.
Blind stand-in unchanged: wave0 8/8 FA, wave1 7/7 FA, wave2 2/2 FA.

## Still open

| Attack | Verdict | Why |
|---|---|---|
| CW-W1-2HOP | `FALSE_ACCEPT_OBSERVED` | SPEC `SUBJECT_NORMALIZED` two-hop residual; the checkwash maintainer has ruled it priced and not pursued. No new issue. |

`catalogs/checkwash-regressions.yaml` still holds only this residual.

No new checkwash issue. No checkwash code in this repo. Language rule held.
