# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.5.0 |
| Source revision | `24b60a2019a5900291ecb35ab8290f34af2d5438` (annotated tag `v0.5.0`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.5.0` |
| SHA-256 | `b305bc3f7d35f827190051f7a676ac40e3e86badf9eaed750f22f082fd10b05c` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | one-time human grant (Nelson, 2026-10-01); verified published asset, 2026-10-01 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.

This update uses the published v0.5.0 release (the #172–#181 red-team round;
a minor release because some existing finding fingerprints changed).
[M11](../docs/adapters/CHECKWASH_M11.md) records its own campaign verification.
All earlier records retain their original engine versions and results;
a pin update alone does not establish new evaluation results.
