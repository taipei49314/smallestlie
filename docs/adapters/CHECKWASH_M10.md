# Checkwash M10 — published v0.4.2 (2026-09-29)

**Authorization.** One-time named human grant from the repository owner,
Nelson, on 2026-09-29: 「第 5 項也授權，重釘到 v0.4.2」 ("item 5 is also
authorized; re-pin to v0.4.2"). Item 5 of that day's version-audit follow-up
is the re-pin of the downstream checkwash consumers to v0.4.2. The grant
covers this re-pin once. It does not authorize a SmallestLie version bump,
tag or release, or any later pin advance. estate-consolidation does not
govern this repository (EC POLICY `independent-repos`, T-451) and issued no
task for this pin.

**Pin.** Published annotated tag `v0.4.2`, source
`23ef5929896187e4aac5889735c792e65af3e721`; release asset `checkwash.pyz`,
546,241 bytes, SHA-256
`423ce220365d0e179cfd9caa7e45724d71b8bd7c67d3cbfc51eca19e8a626ee7`. The
asset was downloaded independently from the GitHub Release; its SHA-256
matches the digest the release records and the vendored file byte for byte,
and `python verifiers/checkwash.pyz --version` prints `checkwash 0.4.2`.
Previous pin v0.3.3 (`583de5a1…f451007`); reference campaign
[M9](CHECKWASH_M9.md). v0.3.4, v0.4.0 and v0.4.1 were published in between
and were never pinned here.

## Engine changes since v0.3.3

Summarized from the checkwash v0.3.4–v0.4.2 release notes; not re-measured
here.

- **v0.3.4**: row-identity, table, helper and wrapper provenance repairs;
  runtime-shadow and stand-in installation checks; pytest collection options
  compared by literal value.
- **v0.4.0**: new oracle rule `SUBJECT_INPUT_CHANGED` (checkwash D-060);
  runtime suppression hooks, fixture subject replacement, import-path
  providers, inherited test methods and collection overrides; JavaScript
  declaration scanning.
- **v0.4.1**: Node assertion weakening to truthiness.
- **v0.4.2**: JS/TS test-callback ownership and scalar evidence. The release
  notes state Python behavior and frozen contracts are unchanged.

Findings/IR schema versions, exit codes and the severity lattice are
unchanged according to those notes. The fixed catalogs here are Python-only,
so the v0.3.4 and v0.4.0 Python detector changes are the ones that could move
a verdict.

## Campaign verification: **PENDING** (PR CI)

The full fixed catalogs were not rerun locally for this re-pin. The
verification is hosted CI on the re-pin PR: `offline-gate-fast` runs
`uv run pytest -q`, whose integration tests assert each of the 19
fixed-catalog observations recorded in M9 and the blind-control arms of
wave0, wave1 and wave2:

| Fixed catalog | Asserted (unchanged from M9) |
|---|---|
| wave0 | 8 attacks rejected; honest control CW-W0-CTL accepted |
| wave1 | 6 rejected; CW-W1-2HOP false accepted |
| wave2 | 2 rejected |
| regressions | CW-W1-2HOP false accepted |

This PR does not change those expectations. A green run on the PR head means
no fixed-catalog verdict moved from M9; a red run names the attack whose
verdict moved, and its expectation must then be changed consciously, with the
reason recorded here, not relaxed. The nightly `checkwash_real` item
(`pass_no_false_accept` on wave0) runs against this pin after merge.

Seconds-level spot checks before the PR was opened (Python 3.12):

| Check | Result |
|---|---|
| `verifiers/checkwash.pyz --version` | `checkwash 0.4.2` |
| `test_checkwash_pin_consistency`, `test_checkwash_adapter`, `test_checkwash_wave1_catalog` | 20 passed |
| `checkwash-regressions` catalog (CW-W1-2HOP), real engine | `FALSE_ACCEPT_OBSERVED`, as in M9; the two-hop residual remains open |
| CW-W0-CTL alone, real engine | `TRUE_ACCEPT_OBSERVED`, as in M9 |

The two campaign spot checks are not the campaign record. This fixed-catalog
check, once recorded, is not population recall evidence. M9 and earlier
records keep their original engine versions and are not relabeled as v0.4.2
measurements.
