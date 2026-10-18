# SmallestLie

> Find the smallest lie your verifier still accepts.

**Archived on 2026-10-18.** This repository is read-only. It is kept as the
record of an adversarial evaluation of
[checkwash](https://github.com/taipei49314/checkwash) that ran from August to
October 2026. If you want to check your own code changes, use checkwash.

## Why it is archived

SmallestLie did two jobs for checkwash:

1. It ran attacks against released checkwash builds to find diffs that weaken
   tests yet still pass.
2. It reran those cases on later pins to confirm they stayed rejected.

checkwash now does both itself. Missed cheats are reported and fixed through
checkwash's own issues. Released-build regression runs in checkwash's
previous-release verdict gate
([checkwash#201](https://github.com/taipei49314/checkwash/issues/201)), which
runs the previous release and the candidate on the same cases.

## What it found

- Its findings were filed as checkwash issues
  [#60](https://github.com/taipei49314/checkwash/issues/60),
  [#61](https://github.com/taipei49314/checkwash/issues/61) and
  [#84](https://github.com/taipei49314/checkwash/issues/84)–[#88](https://github.com/taipei49314/checkwash/issues/88).
  #87 is an honest change that checkwash wrongly blocked; the others are
  false acceptances. All seven are closed as completed.
- checkwash
  [PR #150](https://github.com/taipei49314/checkwash/pull/150) (2026-09-08)
  cited this repository's 19 fixed-catalog observations as regression
  evidence.
- One false acceptance was never fixed by design: `CW-W1-2HOP`, a two-hop
  case that checkwash's SPEC lists as a stated residual of
  `SUBJECT_NORMALIZED`.

Per-run records are in [docs/adapters/README.md](docs/adapters/README.md).

## Final state

- **Engine pin:** checkwash 0.6.0 (`verifiers/checkwash.pyz`, see
  [verifiers/README.md](verifiers/README.md)). checkwash 0.7.0 and 0.8.0 were
  released later and were never evaluated here.
- **Version:** `pyproject.toml` says 0.7.1. The only tag, `v0.7.1`, points to
  `c9f2049` (2026-09-02); more than 100 commits landed on `master` after it.
  Use commit SHAs, not the version number, to identify code.
- **Last executed fixed-catalog record:** [M9](docs/adapters/CHECKWASH_M9.md)
  (checkwash v0.3.3). The [M10](docs/adapters/CHECKWASH_M10.md),
  [M11](docs/adapters/CHECKWASH_M11.md) and
  [M12 0.6.0](docs/adapters/CHECKWASH_M12_060.md) records still say pending.
  The CI on each of those re-pin pull requests passed, but the records were
  not updated afterwards.
- **M12 / W3:** the second-wave framework (pull requests #25–#51) was merged,
  but the formal W3 run never started. Its qualification runs and receipts
  are in a private repository and cannot be checked from here.
- **Model arms:** only the Claude Fable 5.1 and GLM 5.3 arms of
  [M6](docs/adapters/CHECKWASH_M6.md) were recorded. The other arms were
  never run.

## Known limits

Read these before reusing anything here.

- For wave0–M2, whether a case is a lie was declared by the person who wrote
  the case. The oracle only checks that the declared paths changed.
- Every case run against the real checkwash engine used one small synthetic
  fixture (`fixtures/checkwash_target`). The blind controls used a second one
  (`fixtures/checkwash_blind`).
- "Network denied" means proxy variables are removed and a marker variable is
  set. There is no OS-level network isolation, and the `doctor` network check
  only checks that marker.
- Attack YAML cannot add shell commands, but its mutations can rewrite code
  that the verifier then runs.
- A campaign in which every run is `INCONCLUSIVE` reports
  `PASS_WITH_WARNINGS`.
- Minimization keeps the smallest diff that the verifier still accepts. The
  minimized diff may not run.

## Language rule

Each run reports one of `FALSE_ACCEPT_OBSERVED`, `ATTACK_REJECTED`,
`TRUE_ACCEPT_OBSERVED`, `FALSE_REJECT_OBSERVED`, `INCONCLUSIVE`,
`HARNESS_ERROR`, `BLOCKED_BY_POLICY`, `INAPPLICABLE` or `NOT_RUN`
(`src/smallestlie/models.py`). It never reports a repository as secure. The strongest positive statement it makes is:

> No false acceptance was observed within the declared campaign, attack
> catalog, target revision, oracle version, and execution boundary.

## Running the code

The code still runs from a checkout with Python 3.12+ and
[uv](https://github.com/astral-sh/uv). `e7c3b24`, the last code change,
passed this repository's CI.

```bash
uv sync --extra dev
uv run pytest -q
uv run smallestlie ci-gate --budget-seconds 600
```

Run it only on synthetic fixtures, or on repositories you own. See
[AUTHORIZED_USE.md](AUTHORIZED_USE.md).

## License

MIT. See [LICENSE](LICENSE).
