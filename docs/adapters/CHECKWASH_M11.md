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

## Campaign verification: **PENDING** (PR CI)

The fixed catalogs were not rerun for this re-pin before the PR. The
verification is hosted CI on the re-pin PR. `offline-gate-fast` runs
`uv run pytest -q`, whose integration tests assert each of the 19 fixed-catalog
observations recorded in M9, and the blind-control arms of wave0, wave1 and
wave2:

| Fixed catalog | Asserted (unchanged from M9) |
|---|---|
| wave0 | 8 attacks rejected; honest control CW-W0-CTL accepted |
| wave1 | 6 rejected; CW-W1-2HOP false accepted |
| wave2 | 2 rejected |
| regressions | CW-W1-2HOP false accepted |

This PR does not change those expectations.

- A green run on the PR head means no fixed-catalog verdict moved from M9.
- A red run names the attack whose verdict moved. Its expectation must then
  be changed consciously, with the reason recorded here, not relaxed. That
  change is the owner's decision.

The nightly `checkwash_real` item (`pass_no_false_accept` on wave0) runs
against this pin after merge.

Unlike M10, no seconds-level spot checks were run before the PR was opened:
NOT_RUN under the work-machine rule (EC POLICY `work-machine-local`). The PR CI
also runs `test_checkwash_pin_consistency`, which executes the vendored pyz and
checks that it reports `checkwash 0.5.0`. Once this fixed-catalog check is
recorded, it is still not population recall evidence. M10 and earlier records
keep their original engine versions and are not relabeled as v0.5.0
measurements.
