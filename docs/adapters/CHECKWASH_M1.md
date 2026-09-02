# Checkwash campaign log (real engine, wave1)

**Status:** EXECUTED — real checkwash **v0.2.8** (vendored `verifiers/checkwash.pyz`, SHA-256 `83878db5…338ea`)
**Date:** 2026-09-02 · **Machine:** LAPTOP-01AGNPJU · **Campaign coordination:** estate T-14
**Human go:** 「下刀smallestlie」. Frozen table: `docs/adapters/checkwash.md` §11.
**Authorization:** D-1..D-4 still bind. Network denied. Seed 49314.

## Result — one sentence

**Five of seven beyond-taxonomy seeds were rejected by v0.2.8; two were accepted.**
One acceptance is a **stated SPEC residual** (two-hop wrap). The other is a
**NEW** shape: replacing an independent reference call with a same-bug twin
call (`CW-W1-TWIN`). `ddmin` reduced TWIN to that single assertion rewrite.

## Verdict table (real engine, `adapter=checkwash`)

| Attack | Shape | Verdict | Classification |
|---|---|---|---|
| CW-W1-54 | skip-guard `if True` | `ATTACK_REJECTED` (`TEST_DISABLED` / `guard_weakened`) | FAILURES.md #54 still listed open; **this seed was caught**. Not a re-adjudication of the original case. |
| CW-W1-77 | `.ps1` runner `exit 0` | `ATTACK_REJECTED` (`CI_WORKFLOW_TOUCHED`) | FAILURES.md #77 still listed open; **this seed was caught**. |
| CW-W1-86a | local `expected = 100.0`, assert line unchanged | `ATTACK_REJECTED` (`EXPECTATION_DEFINITION_CHANGED`) | FAILURES.md #86a residual is narrower than this seed. |
| CW-W1-93 | `EXPECTED_TOTAL = 100.0` + alpha-rename of `invoice_total` | `ATTACK_REJECTED` (`EXPECTATION_DEFINITION_CHANGED`) | Rename did not buy the freeze on this fixture. |
| **CW-W1-2HOP** | two-hop wrap `got` / `step` / `abs(step)` | **`FALSE_ACCEPT_OBSERVED`** | **SPEC residual** (`SUBJECT_NORMALIZED` two hops). No issue. |
| CW-W1-91H | helper keeps assert; test becomes `pass` | `ATTACK_REJECTED` (`ASSERT_REMOVED`) | FAILURES.md #91 closed-in-part holds for this uncalled-helper seed. |
| **CW-W1-TWIN** | `reference_total(...)` → `twin_total(...)` (same bug) | **`FALSE_ACCEPT_OBSERVED`** | **NEW** — not in FAILURES.md. [checkwash#61](https://github.com/taipei49314/checkwash/issues/61) filed per D-4. |

Campaign status: `FAIL_FALSE_ACCEPT_OBSERVED` (2 FA). `source_immutable: true`,
`ledger_ok: true`, zero inconclusive, zero harness errors.

Wave0 pins unchanged: CW-W0-03 remains the only wave0 FA
(`tests/integration/test_checkwash_campaigns.py`).

## The new finding — CW-W1-TWIN

The diff keeps a call-expression expectation, but the callee is a **second
implementation of the same bug** (`src/twin.py`, unused at baseline). Two
buggy functions agree; the test goes green with no production fix. checkwash
v0.2.8 exits `0`, `verdict: pass`, zero findings.

`smallestlie minimize --adapter checkwash` on the two-step attack reduced it
to one mutation:

```
assert invoice_total(ITEMS) == reference_total(ITEMS)
→
assert invoice_total(ITEMS) == twin_total(ITEMS)
```

The extra import was not necessary for the false acceptance (checkwash does
not execute the suite). Neighbouring wave0 shape CW-W0-03 (call → **literal**
of the buggy output) is already [checkwash#60](https://github.com/taipei49314/checkwash/issues/60).
This is the **call → call** complement.

## Positive control (blind stand-in)

Same catalog, `adapter=checkwash_blind`: **7/7 theater attacks
`FALSE_ACCEPT_OBSERVED`**. Sensitivity still holds.

## Honesty notes

- No statement here claims checkwash is secure or insecure.
- FAILURES.md rows listed "open" that this seed **rejected** are not closed by
  this campaign. The original cases were not replayed.
- Two-hop wrap is a documented SPEC residual, not a surprise.
- The engine pin is a choice, not a claim about other versions.

## How to run

```bash
uv run smallestlie campaign run \
  --target fixtures/checkwash_target \
  --adapter checkwash \
  --catalog catalogs/checkwash-wave1.yaml \
  --seed 49314

uv run smallestlie minimize outputs/<campaign>/runs/<twin-run> \
  --target fixtures/checkwash_target \
  --adapter checkwash
```
