# Checkwash M9 — published v0.3.3 (2026-09-08)

Campaign verification: **EXECUTED** on estate pool, T-229 run `34197245879`,
Python 3.12.10. [Machine-readable results](CHECKWASH_M9_RESULTS.json).

Published tag source `498064f095bd892550a917219798b3f44c42ccef`; official pyz SHA-256
`583de5a186662c4f4c550e5d712eb9af7647c7b0af4dbbe21864c8f10f451007`. The independently downloaded GitHub Release
asset matched the vendored file byte for byte. Campaigns used the normal
adapter pin without experimental pin overrides. The tested SmallestLie
source was `7147ee7b1cd1b87723ded86faf44a2ebf66608bb`; this follow-up adds the result record.

| Fixed catalog | Published v0.3.3 | Difference from completed v0.3.2 M8 |
|---|---|---|
| wave0 | 8 attacks rejected; honest control accepted | none |
| wave1 | 6 rejected; CW-W1-2HOP false accepted | none |
| wave2 | 2 rejected | none |
| regressions | CW-W1-2HOP false accepted | none |

All **19 observations match M8** across **18 distinct attack/control IDs**.
The regression catalog repeats the wave1 two-hop case. There are no skipped
or inconclusive observations; all source-immutability and ledger checks
pass. This fixed-catalog result is not population recall evidence.

The blind control false accepts 8/8, 7/7 and 2/2 theater attacks in
wave0/1/2, plus the repeated regression case, matching M8. Its honest
control remains accepted. The known two-hop residual remains open.

Historical model-generated M6 partial results against v0.2.12 remain
separate from the unexecuted v0.3.0/M6 and v0.3.1/M7 release-pin wave
reruns. M8 and M9 do not backfill or relabel those records.

This published pin handoff completes the T-229 release scope. After final
cross-repository verification, estate policy refreezes further releases
and pin advances; there is no automatic weekly release.
