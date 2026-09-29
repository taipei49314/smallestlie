# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.4.2 |
| Source revision | `23ef5929896187e4aac5889735c792e65af3e721` (annotated tag `v0.4.2`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.4.2` |
| SHA-256 | `423ce220365d0e179cfd9caa7e45724d71b8bd7c67d3cbfc51eca19e8a626ee7` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | one-time named human grant (Nelson, 2026-09-29); verified published asset, 2026-09-29 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.

This update uses the published v0.4.2 release (JS/TS assertion boundaries and
scalar evidence; it also carries the v0.3.4–v0.4.1 detector changes).
[M10](../docs/adapters/CHECKWASH_M10.md) records its own campaign verification.
All earlier records retain their original engine versions and results;
a pin update alone does not establish new evaluation results.
