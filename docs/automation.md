# Automation: nightly, batch, diff-select

## 1. Nightly fixtures (known SUT, cron)

Auto-attack **all known synthetic fixtures** every night.

```bash
uv run smallestlie nightly --budget-seconds 7200 --output outputs/nightly
```

GitHub Actions: `.github/workflows/smallestlie-nightly.yml`  
Schedule: `17 2 * * *` UTC (also `workflow_dispatch`).

Includes:

| Item | Expect |
|---|---|
| naive_gate full | fail_false_accept |
| honest_gate full-no-vrf | pass_no_false_accept |
| composition_blind | fail_false_accept (compound) |
| isolation stale/path/authority | fail_false_accept |
| greenwash naive/honest | FA / clean |

---

## 2. Campaign batch (multi-target authorized)

```bash
# fixtures example
uv run smallestlie campaign batch --config examples/batch.fixtures.yaml

# owned repos (fill template + enable items)
uv run smallestlie campaign batch --config examples/batch.authorized-repos.local.yaml
```

Batch YAML shape:

```yaml
batch:
  name: my-batch
  seed: 49314
  budget_seconds: 3600
  output_root: outputs/batch
  items:
    - name: repo-a
      target: C:/path/to/owned/repo
      adapter: fixture_gate
      catalog: catalogs/ci-offline-full-no-vrf.yaml
      authorization: C:/path/to/repo-a.authorization.yaml
      expect: any   # or fail_false_accept | pass_no_false_accept
      required: true
      enabled: true
```

Rules:

- each item can carry its **own authorization**
- wall-clock **budget** enforced; required-not-run ⇒ fail (not pass)
- optional shared `--diff-file` filters every item’s catalog

---

## 3. Diff-aware attack selection (strengthened)

```bash
# preview only
uv run smallestlie select-attacks \
  --catalog catalogs/canonical-m1.yaml \
  --path fixtures/naive_gate/evidence/evidence.json \
  --path authority/approval.json

# campaign with filter
uv run smallestlie campaign run \
  --target fixtures/naive_gate \
  --catalog catalogs/ci-offline-full.yaml \
  --diff-file changed.txt

# batch with filter
uv run smallestlie campaign batch \
  --config examples/batch.fixtures.yaml \
  --diff-file changed.txt
```

Enhancements:

- richer path + filename keyword → family map
- attack-id prefix / GW-* family inference
- composition included when parent families match
- smoke always-include (`CFG-001`, `EXE-003`, `PROJ-005`) when filtering
- empty selection is **fail-closed** (exit 4), never green

---

## Anti-theater reminders

- Nightly / batch / diff never claim `SECURE`
- Skipped required items are failures
- Real repos still need authorization packages
