# Checkwash M11 — published v0.5.0 (2026-10-01)

**Authorization.** One-time human grant from the repository owner, Nelson,
on 2026-10-01, in the checkwash v0.5.0 release conversation. Asked whether to
re-pin checkwash-corpus and smallestlie after publication, he chose
「要，照交接順序（推薦）」 ("yes, in the handoff order"). The chosen option
names checkwash-corpus first and smallestlie second, each as its own PR merged
only after he reviews it. The grant covers this re-pin once. It does not
authorize a SmallestLie version bump, tag or release, or any later pin advance.
estate-consolidation does not govern this repository (EC POLICY
`independent-repos`, T-451) and issued no task for this pin.

**Pin.** Published annotated tag `v0.5.0` (tag object
`2f2f9296752a5ef971c74ebaf6abccfbba2bfcf2`), source
`24b60a2019a5900291ecb35ab8290f34af2d5438`. Release asset `checkwash.pyz`,
588,886 bytes, SHA-256
`b305bc3f7d35f827190051f7a676ac40e3e86badf9eaed750f22f082fd10b05c`. The
asset was downloaded from the GitHub Release, and its SHA-256 matches the
digest the release API records and the vendored file byte for byte. It was
not executed on the authoring host, a work machine where engine runs are not
allowed. The previous pin was v0.4.2
(`423ce220…6ee7`, record [M10](CHECKWASH_M10.md)).

## Engine changes since v0.4.2

These are summarized from the checkwash v0.5.0 release notes and were not
re-measured here.

- **Python:**
  - an unconditional skip or xfail in the setup a test runs (checkwash #172);
  - a first-config pytest selector over tests the same diff edits (#173, closed
    in part);
  - a Pipfile `[scripts]` test command as CI (#174);
  - CI control flow that stops a runner (#181, closed in part).
- **JS/TS:** Jest layouts, unit liveness, module mocks, hand-rolled tolerances
  and chai assertions (#175–#180).
- **Contracts:** v0.5.0 is a minor release because some existing finding
  fingerprints changed (checkwash D-063). Findings/IR shapes, rule IDs, the
  severity model and exit codes are unchanged according to those notes.

The fixed catalogs here are Python-only, so #172, #173, #174 (Pipfile) and
#181 are the changes that could move a verdict.

## Fixed-catalog regression verification: **RECORDED** (2026-10-02)

### Scope at re-pin PR creation

The fixed catalogs were not rerun for this re-pin before the PR. The
planned verification was hosted CI for the re-pin. `offline-gate-fast` runs
`uv run pytest -q`, whose integration tests assert each of the 19 fixed-catalog
observations recorded in M9, and the blind-control arms of wave0, wave1 and
wave2:

| Fixed catalog | Asserted (unchanged from M9) |
|---|---|
| wave0 | 8 attacks rejected; honest control CW-W0-CTL accepted |
| wave1 | 6 rejected; CW-W1-2HOP false accepted |
| wave2 | 2 rejected |
| regressions | CW-W1-2HOP false accepted |

The re-pin PR did not change those expectations.

- A green run on the PR head means no fixed-catalog verdict moved from M9.
- A red run names the attack whose verdict moved. Its expectation must then
  be changed consciously, with the reason recorded here, not relaxed. That
  change is the owner's decision.

### Completed evidence

[PR #23](https://github.com/taipei49314/smallestlie/pull/23) merged at
`7cb3b4b1a85008dcbaee1e7bbdd179520600077e`, 2026-10-02T00:49:25Z.
Its post-merge [CI run 36947915071, attempt 1](https://github.com/taipei49314/smallestlie/actions/runs/36947915071)
tested that exact SHA on Ubuntu with Python 3.12.13. `offline-gate-fast`
logged **103 passed in 47.14 s**. The doctor, fast gate, full gate and
measurement jobs also succeeded. The CheckWash wave0, wave1, wave2,
regression and blind-control assertions were part of this pytest suite.
The full CI-gate job exercises the synthetic fixture catalog; its green
status is not an additional CheckWash wave result.

The later execution-validity/binding changes in [PR #22](https://github.com/taipei49314/smallestlie/pull/22)
were separately revalidated against this same published v0.5.0 pin.
EC T-498 [run 36951896511, attempt 1](https://github.com/taipei49314/estate-consolidation/actions/runs/36951896511)
tested product `9cf9432614f3394b937751e535cbd4766834efc2` on
LAPTOP-50KP71KA, Windows Python 3.12.10: **138 focused / 220 full tests**,
zero failures, errors or skips. Focused is a subset of full. The full suite
kept the fixed-catalog and blind-control expectations above and includes
current-pin output regressions and fixture binding regressions, including
rejection of stale v0.4.2 output.
Immutable receipt: `de10040b19ed0a81943432a87ccca8d2a8ce71d3`.
The exact source, receipt and closeout details are in
[execution-verdicts.md](../execution-verdicts.md).

PR #22 merged at `ba979215e682d7bfdfc3db27f0ef7ede76c45c4f`,
2026-10-02T01:52:08Z. The reviewed head and merge trees match; the only delta
from the pool-tested product is its result documentation. No additional run
is claimed for the document commit or merge, which carry `[skip ci]`.

These passing assertions record 19 fixed-catalog observations over 18 distinct
attack/control IDs, with the repeated `CW-W1-2HOP` false acceptance still
expected in wave1 and the regression catalog. They establish no verdict
movement from M9 within this declared regression scope. A separate new wave
batch, model campaign or population recall measurement was not dispatched
for this closeout. M6's pending model arms and earlier pin records retain
their original status and versions.

The nightly `checkwash_real` item (`pass_no_false_accept` on wave0) runs
against this pin after merge.

Unlike M10, no seconds-level spot checks were run before the PR was opened:
NOT_RUN under the work-machine rule (EC POLICY `work-machine-local`). The PR CI
also runs `test_checkwash_pin_consistency`, which executes the vendored pyz and
checks that it reports `checkwash 0.5.0`. The recorded fixed-catalog check
is still not population recall evidence. M10 and earlier records
keep their original engine versions and are not relabeled as v0.5.0
measurements.
