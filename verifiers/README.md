# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.3.3 |
| Source revision | `498064f095bd892550a917219798b3f44c42ccef` (annotated tag `v0.3.3`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.3.3` |
| SHA-256 | `583de5a186662c4f4c550e5d712eb9af7647c7b0af4dbbe21864c8f10f451007` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T-229; verified published asset, 2026-09-08 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.

This update uses the published v0.3.3 shared-fixture precision release.
[M9](../docs/adapters/CHECKWASH_M9.md) records its own campaign verification.
All earlier records retain their original engine versions and results;
a pin update alone does not establish new evaluation results.
