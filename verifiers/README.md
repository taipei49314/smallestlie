# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.2.8 |
| Source revision | `50e969fdbbe169284b380c7f544c8afcd5990cdf` (observed HEAD, 2026-09-02) |
| Artifact | release asset `checkwash.pyz` from tag `v0.2.8` |
| SHA-256 | `83878db57a243386a10fa49b3f4a2d4d2863c808f7b2f77a516e35c99b3338ea` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T-11/T-12; human approval D-1..D-4, 2026-09-02 |

The checkwash repository itself is never modified by this harness (M0 exit
criterion #7; release freeze respected). Re-pinning is a conscious, human-visible
step: update this table, the pin in `adapters/checkwash.py`, and
`docs/adapters/checkwash.md` §1 together.
