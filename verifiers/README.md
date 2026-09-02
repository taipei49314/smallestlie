# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.2.12 |
| Source revision | `e05c37f0e1673cdf218ec62fcfb7c6712cce704b` (annotated tag `v0.2.12`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.2.12` |
| SHA-256 | `1fed863c3d8d240a3da63eed5ae01954f60fe31b53ffb6a1ecef7a267193baf3` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T-55; human 「smallestlie 重釘 v0.2.12」, 2026-09-03 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.
