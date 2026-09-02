# SmallestLie

> Find the smallest lie your verifier still accepts.

SmallestLie is a **local-first adversarial verification harness** for repositories that make claims about completion, evidence, provenance, testing, and trust. It mutates **authorized disposable copies**, independently establishes ground truth, and reports when a repository accepts a false claim.

Every confirmed false acceptance is recorded, replayed, and can become a regression fixture.

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

**v0.7.0** — automation: **nightly** + **campaign batch** + stronger **diff-select**

| Capability | Command |
|---|---|
| Nightly known fixtures | `smallestlie nightly` (cron workflow) |
| Multi-target batch | `smallestlie campaign batch --config …` |
| Diff attack preview | `smallestlie select-attacks --path …` |
| Greenwash SUT campaigns | `adapter greenwash` + `greenwash-wave-a` (synthetic SUT; superseded for the real-engine line) |
| Checkwash **real-engine** campaigns | `adapter checkwash` + wave0 / wave1 / wave2 / `checkwash-regressions` (v0.2.9 pyz) — [wave0](docs/adapters/CHECKWASH_CAMPAIGN.md) · [M1](docs/adapters/CHECKWASH_M1.md) · [M2](docs/adapters/CHECKWASH_M2.md) · [M3](docs/adapters/CHECKWASH_M3.md) |

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
