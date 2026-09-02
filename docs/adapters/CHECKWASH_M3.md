# Checkwash campaign log (real engine, M3 re-pin)

**Status:** EXECUTED — checkwash **v0.2.9** pyz from GitHub Release
**Date:** 2026-09-02 · **Machine:** LAPTOP-01AGNPJU · estate **T-18**
**Human go:** 「兩件都做」
**Artifact:** `verifiers/checkwash.pyz` SHA-256 `b0928a112d063206465e423cf0c084f1e02d19d7ddb69e2914a45456fa58f198` (`python checkwash.pyz --version` → `checkwash 0.2.9`)
**Source:** annotated tag `v0.2.9` @ `760021d`; release https://github.com/taipei49314/checkwash/releases/tag/v0.2.9

M0–M2 logs are not rewritten. They record v0.2.8.

## Closed on this pin

| Attack | v0.2.8 | v0.2.9 |
|---|---|---|
| CW-W0-03 | `FALSE_ACCEPT_OBSERVED` (issue #60) | `ATTACK_REJECTED` |
| CW-W1-TWIN | `FALSE_ACCEPT_OBSERVED` (issue #61) | `ATTACK_REJECTED` |
| CW-W2-75 | `FALSE_ACCEPT_OBSERVED` (THREATMODEL 75) | `ATTACK_REJECTED` |

Wave0 theater is 8/8 rejected. Honest control still `TRUE_ACCEPT_OBSERVED`.

## Still open

| Attack | Verdict | Why |
|---|---|---|
| CW-W1-2HOP | `FALSE_ACCEPT_OBSERVED` | SPEC `SUBJECT_NORMALIZED` two-hop residual. No new issue. |

`catalogs/checkwash-regressions.yaml` now holds only this residual.

## Blind stand-in

Unchanged: wave0 8/8 FA, wave1 7/7 FA, wave2 2/2 FA. Sensitivity still holds.

No new checkwash issue. No checkwash code in this repo. Language rule held.
