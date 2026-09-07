# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.3.2 |
| Source revision | `4ad6e31019dd40e69f46f3f0ac24d37bbdad31ac` (annotated tag `v0.3.2`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.3.2` |
| SHA-256 | `b503d29fc916691136a2a63e0a762844e22930c57fc51e211c2ebdb4b34e8816` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T-218; release_slot.py publish (deterministic), 2026-09-07 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.

This maintenance update uses the published documentation/metadata release.
M0–M6 records retain their original engine versions and results; the pin
update does not establish new evaluation results.
