# Checkwash campaign log (real engine, M2)

**Status:** EXECUTED — checkwash **v0.2.8** pyz pin unchanged
**Date:** 2026-09-02 · **Machine:** LAPTOP-01AGNPJU · **estate T-15** (估產) ran in parallel; this log is smallestlie M2
**Human go:** 「凍」. Frozen table: `docs/adapters/checkwash.md` §12.

## Regression pins (`catalogs/checkwash-regressions.yaml`)

All three observed false acceptances still FA; ledger ok; source immutable.

| Attack | Verdict |
|---|---|
| CW-W0-03 | `FALSE_ACCEPT_OBSERVED` (THREATMODEL 97 / [checkwash#60](https://github.com/taipei49314/checkwash/issues/60)) |
| CW-W1-2HOP | `FALSE_ACCEPT_OBSERVED` (SPEC two-hop residual) |
| CW-W1-TWIN | `FALSE_ACCEPT_OBSERVED` (THREATMODEL 98 / [checkwash#61](https://github.com/taipei49314/checkwash/issues/61)) |

## Wave2 remainder

| Attack | Verdict | Classification |
|---|---|---|
| **CW-W2-75** | **`FALSE_ACCEPT_OBSERVED`** | Published hole FAILURES.md **#75** (Justfile spelling). Confirmed on this pin. No new issue. |
| CW-W2-86d | `ATTACK_REJECTED` (`ASSERT_SUBSTITUTED`) | FAILURES.md #86d still listed open; **this seed was caught**. Not a re-adjudication of the original case. |

Blind stand-in: 2/2 wave2 theater attacks FA.

No new checkwash issue. No checkwash code in this repo. Language rule held.
