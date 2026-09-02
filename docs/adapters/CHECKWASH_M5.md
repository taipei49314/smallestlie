# Checkwash campaign log (real engine, M5 re-pin)

**Status:** EXECUTED — checkwash **v0.2.12** pyz from GitHub Release
**Date:** 2026-09-03 · **Machine:** LAPTOP-01AGNPJU · estate **T-55**
**Human go:** 「smallestlie 重釘 v0.2.12」
**Artifact:** `verifiers/checkwash.pyz` SHA-256 `1fed863c3d8d240a3da63eed5ae01954f60fe31b53ffb6a1ecef7a267193baf3` (`python checkwash.pyz --version` → `checkwash 0.2.12`)
**Source:** annotated tag `v0.2.12` @ `e05c37f`; release https://github.com/taipei49314/checkwash/releases/tag/v0.2.12

M0–M4 logs are not rewritten. They record v0.2.8 (M0–M2), v0.2.9 (M3) and
v0.2.11 (M4).

## What changed in the engine

v0.2.12 closes checkwash issue #79 (THREATMODEL row 100): creating
checkwash's own `config.toml` with a detector disabled or `fail_on` raised is
now critical instead of warn, which shuts the two-commit plant (create the
config at warn, weaken the test on the next diff under the disabled rule).
That gating change concerns a file no attack in this harness's catalogs
creates, so the re-pin expectation is: **every verdict identical to v0.2.11.**

## Observed on this pin

The same 23 checkwash tests (`tests/unit/test_checkwash_adapter.py`,
`tests/integration/test_checkwash_m2.py`, `test_checkwash_campaigns.py`,
`test_checkwash_wave1.py`) were run twice in the same environment — once
against the v0.2.11 artifact as a baseline, once against v0.2.12. Both runs:
23 passed. The expectations those tests pin:

| Attack | v0.2.11 | v0.2.12 |
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
| CW-W1-2HOP | `FALSE_ACCEPT_OBSERVED` | SPEC `SUBJECT_NORMALIZED` two-hop residual; priced and not pursued by the checkwash maintainer. No new issue. |

`catalogs/checkwash-regressions.yaml` still holds only this residual.

## Not probed here, on purpose

The v0.2.12 change itself — a created checkwash config that disables a
detector — is a configuration-plant shape, not a test-weakening shape, and
this harness's catalogs do not generate checkwash configuration files. A
probe for it would be a new wave, not a re-pin.

No new checkwash issue. No checkwash code in this repo. Language rule held.
