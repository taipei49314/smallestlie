# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.2.13 |
| Source revision | `042f69da93f6bc3663b2ee707b9f6a619a90bc41` (annotated tag `v0.2.13`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.2.13` |
| SHA-256 | `6ba5660f0be7e164ddf3d306b7837662af52b97e296fbb3ee7e8bf0872a2f854` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T154; owner-authorized v0.2.13 release exception and family pin update, 2026-09-06 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.

This maintenance update uses the published documentation/metadata release.
M0–M6 records retain their original engine versions and results; the pin
update does not establish new evaluation results.
