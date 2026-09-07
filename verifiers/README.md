# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.3.0 |
| Source revision | `4387097ad07994ef594dcc0c5f9e43d4475321e0` (annotated tag `v0.3.0`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.3.0` |
| SHA-256 | `51b4cc86cef3b50b3ebf47fbf2fa4006b9861ef46639b84755eea27b86354af5` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T-199; release_slot.py publish (deterministic), 2026-09-07 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.

This maintenance update uses the published documentation/metadata release.
M0–M6 records retain their original engine versions and results; the pin
update does not establish new evaluation results.
