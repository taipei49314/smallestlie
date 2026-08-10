# Greenwash campaign log (synthetic SUT)

**Status:** EXECUTION on **synthetic** Greenwash only  
**Date:** 2026-08-10  
**Note:** No external Greenwash repository was present on disk. SUT is shipped under `fixtures/greenwash_*` per design `docs/adapters/greenwash.md`.

## SUT

| Path | Role |
|---|---|
| `fixtures/greenwash_naive` | Weak auditor (seeded misses) |
| `fixtures/greenwash_honest` | Strong auditor (detects Wave A theater) |

## Adapter

- id: `greenwash`
- command: `python -m greenwash audit --package package --json`
- false accept: `classification=clean` / `accepted=true` while theater oracle says dirty

## Catalog

`catalogs/greenwash-wave-a.yaml` — GW-EXE-003, GW-EXE-002, GW-EVD-002, GW-CFG-001, GW-PATH-001, GW-PROJ-005, GW-SEM-003

## How to run

```bash
uv run smallestlie campaign run \
  --target fixtures/greenwash_naive \
  --adapter greenwash \
  --catalog catalogs/greenwash-wave-a.yaml \
  --seed 49314

uv run smallestlie campaign run \
  --target fixtures/greenwash_honest \
  --adapter greenwash \
  --catalog catalogs/greenwash-wave-a.yaml \
  --seed 49314
```

## Expected

| Target | Expectation |
|---|---|
| greenwash_naive | false accepts on Wave A theater mutations |
| greenwash_honest | ATTACK_REJECTED for same mutations; clean control TRUE_ACCEPT |

## Limitations

- Synthetic product, not a third-party Greenwash clone
- Does not authorize attacks on any remote system
- Results are campaign-bounded observations only
