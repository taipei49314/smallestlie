# Checkwash M8 — re-pin to v0.3.2 (2026-09-07)

Estate T-218. Pin: `b503d29fc916691136a2a63e0a762844e22930c57fc51e211c2ebdb4b34e8816` (release asset from tag `v0.3.2`).

Campaign re-run: **EXECUTED 2026-09-08 on estate pool**, T-228, run
`34188939740`, Python 3.12.10. [Machine-readable results](CHECKWASH_M8_RESULTS.json).

The current v0.3.2 asset was compared against **v0.2.12**, the last pin with a
completed campaign record (M5), and the reviewed Checkwash candidate source
`242c920869a6c441f45b32f44b59445e59f898d4`. The v0.3.0/M6 and v0.3.1/M7 release-pin wave reruns remain unexecuted;
this does not invent a v0.3.1 campaign or backfill either log. These are
separate from the model-generated M6 partial results against v0.2.12.

| Fixed catalog | v0.2.12 | v0.3.2 | Candidate |
|---|---|---|---|
| wave0 | 8 attacks rejected; honest control accepted | same | same |
| wave1 | 6 rejected; CW-W1-2HOP false accepted | same | same |
| wave2 | 2 rejected | same | same |
| regressions | CW-W1-2HOP false accepted | same | same |

All **19 campaign observations match** across the three engine arms; the
regression catalog repeats the wave1 two-hop case, so these are **18 distinct
attack/control IDs**, not 19 independent samples. No inconclusive or skipped
run; every source-immutability and ledger check passes. The priced two-hop
residual remains open, with no new false acceptance in these fixed catalogs.

The blind stand-in false accepts 8/8, 7/7 and 2/2 theater attacks in wave0/1/2,
plus the repeated regression case. Its honest control remains accepted.
The current-pin adapter, consistency and campaign test selection passes
**26 tests**. These are campaign-bounded observations, not product-user or
population recall evidence.

The candidate and historical arms used process-local experimental pin
constants in the private harness after verifying their explicit hashes.
The public `verifiers/checkwash.pyz`, adapter constants, and pin table were
not changed. The candidate is a locally built experimental archive; its
version string is still 0.3.2 and its source/hash in the JSON distinguishes it
from the released asset. It is not a published release or a downstream re-pin.
