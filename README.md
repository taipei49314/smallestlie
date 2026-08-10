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

M0–M1 prototype: containment + deterministic single-attack kernel against synthetic `naive_gate` / `honest_gate` fixtures.
