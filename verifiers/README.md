# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.3.1 |
| Source revision | `3a4cfcd5733d35915b87794c355af2df07ca24f7` (annotated tag `v0.3.1`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.3.1` |
| SHA-256 | `8fd7181effe05e9ef14532aafc646289caa64a71d16c269bb948dd9520a648f7` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T-208; release_slot.py publish (deterministic), 2026-09-07 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.

This maintenance update uses the published documentation/metadata release.
M0–M6 records retain their original engine versions and results; the pin
update does not establish new evaluation results.
