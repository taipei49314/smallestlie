# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.2.11 |
| Source revision | `283db528cd3d8e5e38173e14d766a8915efa2c90` (annotated tag `v0.2.11`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.2.11` |
| SHA-256 | `614d18890c036dedca53465992ae107b7ce5d2bf078ac0ef9f07293d2caf4eb9` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T-47; human 「smallestlie 重釘 v0.2.11」, 2026-09-02 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.
