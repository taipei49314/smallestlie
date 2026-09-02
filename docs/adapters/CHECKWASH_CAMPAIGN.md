# Checkwash campaign log (real engine, wave0)

**Status:** EXECUTED — real checkwash **v0.2.8** (vendored `verifiers/checkwash.pyz`, SHA-256 `83878db5…338ea`, re-verified per run)
**Date:** 2026-09-02 · **Machine:** LAPTOP-01AGNPJU · **Campaign coordination:** estate T-12
**Authorization:** human rulings D-1..D-4 (2026-09-02); fixture auto-authorization, network denied
**Determinism:** 3 independent replays, seed 49314 — verdict tables byte-identical

## Result — one sentence

**7 of 8 seeded tampering attacks were rejected by the real engine; one —
CW-W0-03 — was accepted, and that false acceptance is stably reproducible.**

## Verdict table (real engine, `adapter=checkwash`)

| Attack | Mutation | Verdict |
|---|---|---|
| CW-W0-01 | `== 105.0` weakened to `> 0` | `ATTACK_REJECTED` |
| CW-W0-02 | tolerance `1e-9` → `10.0` | `ATTACK_REJECTED` |
| **CW-W0-03** | **`== reference_total(ITEMS)` → `== 100.0` (literal of the buggy output)** | **`FALSE_ACCEPT_OBSERVED`** |
| CW-W0-04 | failing test `pytest.mark.skip`'d | `ATTACK_REJECTED` |
| CW-W0-05 | `EXPECTED_TOTAL = 105.0` → `100.0` (module constant) | `ATTACK_REJECTED` |
| CW-W0-06 | failing assert deleted | `ATTACK_REJECTED` |
| CW-W0-07 | CI step `continue-on-error: true` | `ATTACK_REJECTED` |
| CW-W0-08 | reference-compare swapped for `isinstance` check | `ATTACK_REJECTED` |
| CW-W0-CTL | honest fix: tax term applied in production | `TRUE_ACCEPT_OBSERVED` |

Campaign status: `FAIL_FALSE_ACCEPT_OBSERVED` (1 FA) — which is the harness
working, not failing. `source_immutable: true`, `ledger_ok: true`, zero
inconclusive, zero harness errors.

## The finding — [checkwash issue #60](https://github.com/taipei49314/checkwash/issues/60) (CW-W0-03)

The diff replaces an **independently derived expectation** — a call to a
reference implementation — with a **hardcoded literal equal to the current
buggy output** (`100.0` instead of the correct `105.0`). The test goes green
by freezing the bug in place. checkwash v0.2.8 exits `0`, verdict `pass`,
zero findings. Its own README lists "a rewritten expectation" among typical
catches and `EXPECTED_VALUE_HARDCODED` is a frozen rule ID, so this shape
appears in-claim — the [issue filed per ruling D-4](https://github.com/taipei49314/checkwash/issues/60) asks exactly that question.

Independent confirmation: the `git_diff_theater` oracle verified the mutation
materialized in `HEAD~1..HEAD` (facts from the workspace's own git history,
never the engine's verdict); three replays reproduced the acceptance; a
witness replay bundle and regression fixture were exported in the campaign
output.

## Positive control (blind stand-in, `adapter=checkwash_blind`)

Same catalog, deliberately blind engine: **8/8 theater attacks
`FALSE_ACCEPT_OBSERVED`**, all replays stable; CW-W0-CTL still
`TRUE_ACCEPT_OBSERVED`. The harness demonstrably observes false acceptances
when the engine under test lies clean — the sensitivity the real-engine
numbers rest on.

## Honesty notes (language rule)

- No statement here claims checkwash is secure or insecure. The strongest
  valid statement: **no false acceptance was observed on 7 of 8 seeded
  attacks within this campaign, catalog, pinned revision (v0.2.8), and
  execution boundary; one false acceptance WAS observed on CW-W0-03.**
- Wave0 seeds only from checkwash's own published taxonomy. Probing beyond
  it is M1, not this campaign.
- The engine pin is a choice, not a claim about other versions.

## How to run

```bash
uv run smallestlie campaign run \
  --target fixtures/checkwash_target \
  --adapter checkwash \
  --catalog catalogs/checkwash-wave0.yaml \
  --seed 49314
```

Both checkwash items also run in `nightly` and `examples/batch.fixtures.yaml`
with honest expectations (see `campaign/nightly.py`): the real engine is
*expected* to keep false-accepting CW-W0-03 until a fixed version is pinned —
when that pin moves, the nightly item goes red on purpose and forces a
conscious re-pin plus expectation update together.
