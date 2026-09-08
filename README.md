# SmallestLie

> Find the smallest lie your verifier still accepts.

SmallestLie examines whether a repository's verifier accepts a claim it should
reject. It works locally on **authorized disposable copies**, compares the
verifier's answer with a separately declared oracle, and records the result.

Its reports describe specific observations. They do not certify a repository
as secure or establish that checkwash is ready for 1.0.

## Which project do I need?

| Project | Purpose |
|---|---|
| [checkwash](https://github.com/taipei49314/checkwash) | The tool you install to flag known patterns of test weakening in a Git diff |
| [checkwash-corpus](https://github.com/taipei49314/checkwash-corpus) | Historical data and measurement work used to evaluate checkwash |
| **SmallestLie** | Case-level evidence about what a pinned verifier accepts or rejects |

If you want to review your own code changes before merge, start with
**checkwash**. This repository holds evaluation work about verifiers.

## Current pin and recorded checkwash results

The current published engine pin is **v0.3.3**. Its own fixed-catalog
verification status is in [M9](docs/adapters/CHECKWASH_M9.md); the completed
v0.3.2 fixed-catalog record is [M8](docs/adapters/CHECKWASH_M8.md).

### Historical model-arm results

**M6 is partially recorded, not complete.** Two model runs are in the merged
record against checkwash **v0.2.12**: Claude Fable 5.1 and GLM 5.3. Their
reports include false acceptances and blocked honest refactors. The Grok 4.6
and OpenAI Codex arms remain pending in that record.

- [M6 brief and recorded results](docs/adapters/CHECKWASH_M6.md)
- Merged results: [Fable, PR #11](https://github.com/taipei49314/smallestlie/pull/11)
  and [GLM, PR #12](https://github.com/taipei49314/smallestlie/pull/12)
- Earlier records: [wave0](docs/adapters/CHECKWASH_CAMPAIGN.md),
  [M1](docs/adapters/CHECKWASH_M1.md), [M2](docs/adapters/CHECKWASH_M2.md),
  [M3](docs/adapters/CHECKWASH_M3.md), [M4](docs/adapters/CHECKWASH_M4.md),
  [M5](docs/adapters/CHECKWASH_M5.md)

These are observations on declared fixtures, verifier versions and evaluation
conditions. They are not estimates of natural user behavior or results for
an unreleased checkwash candidate. Keep the separate model runs and honest
controls separate when reading their counts.

## What it is / is not

| It is | It is not |
|---|---|
| An authorized adversarial verification harness | A remote scanner |
| A false-acceptance detector | A malware / exploit framework |
| A mutation + campaign engine for owned repos | A tool for third-party systems |
| A regression-fixture factory | Proof that a repo is “secure” |

## Language rule

SmallestLie may report:

- `FALSE_ACCEPT_OBSERVED`
- `ATTACK_REJECTED`
- `TRUE_REJECT_OBSERVED` / `TRUE_ACCEPT_OBSERVED`
- `INCONCLUSIVE`
- `HARNESS_ERROR`
- `BLOCKED_BY_POLICY`

It **never** reports `SECURE`, `UNHACKABLE`, or `NO VULNERABILITIES`.

The strongest valid positive statement is:

> No false acceptance was observed within the declared campaign, attack catalog, target revision, oracle version, and execution boundary.

## Quick start (synthetic fixtures only)

```bash
# from repo root, with Python 3.12+
uv sync --extra dev
uv run smallestlie doctor
uv run pytest -q

# full offline CI gate (naive must FA; honest must clean)
uv run smallestlie ci-gate --budget-seconds 600

# single campaign
uv run smallestlie campaign run \
  --target fixtures/naive_gate \
  --catalog catalogs/canonical-m1.yaml \
  --seed 49314
uv run smallestlie ledger verify outputs/<campaign-id>
uv run smallestlie report outputs/<campaign-id>
```

## Safety

- Network denied by default
- Mutations only in disposable workspaces
- Source fixtures must remain byte-identical
- Commands are allowlisted by adapter ID (no arbitrary shell from attack YAML)
- See [AUTHORIZED_USE.md](AUTHORIZED_USE.md) and [SECURITY.md](SECURITY.md)

## Status

**Current source version: v0.7.1** ([package metadata](pyproject.toml)).
The checkwash verifier is pinned to the published **v0.2.13** asset.
This maintenance update does not rerun or relabel M0–M6; the recorded results
above retain their original engine versions, including M6's v0.2.12 pin.
The v0.7.0 automation summary and its commands are retained below as history.
The older synthetic greenwash line is frozen.

| Capability | Command |
|---|---|
| Nightly known fixtures | `smallestlie nightly` (cron workflow) |
| Multi-target batch | `smallestlie campaign batch --config …` |
| Diff attack preview | `smallestlie select-attacks --path …` |
| Greenwash SUT campaigns | `adapter greenwash` + `greenwash-wave-a` (synthetic SUT; **frozen 2026-09-03**, superseded by the real-engine line) |
| Checkwash **real-engine** campaigns | `adapter checkwash` + wave0 / wave1 / wave2 / `checkwash-regressions` (current pin: v0.3.3 pyz; recorded runs keep their original pins) — [adapter and recorded history](docs/adapters/README.md) · [M6 partial results](docs/adapters/CHECKWASH_M6.md) |

See [docs/automation.md](docs/automation.md).

### Automation (local / cron)

```bash
# nightly: all known fixtures
uv run smallestlie nightly --budget-seconds 7200

# batch: multi-target YAML
uv run smallestlie campaign batch --config examples/batch.fixtures.yaml

# diff-aware preview + campaign
uv run smallestlie select-attacks --catalog catalogs/ci-offline-full.yaml --path package/junit/results.xml
uv run smallestlie campaign run --target fixtures/naive_gate --catalog catalogs/ci-offline-full.yaml --diff-file changed.txt
```

### Confidence loop

```bash
uv run pytest -q
uv run smallestlie ci-gate
uv run smallestlie measure
uv run smallestlie blindspots
```

Docs: [automation.md](docs/automation.md) · [meters.md](docs/meters.md) · [GREENWASH_CAMPAIGN.md](docs/adapters/GREENWASH_CAMPAIGN.md) · [CHECKWASH_CAMPAIGN.md](docs/adapters/CHECKWASH_CAMPAIGN.md)

Does **not** claim any repository is secure. No remote scanning; real repos need authorization packages.

## Docs

- [docs/ci-gate.md](docs/ci-gate.md) — CI gate contract
- [docs/adapters/README.md](docs/adapters/README.md) — real adapter designs
- [docs/architecture.md](docs/architecture.md) — architecture index
