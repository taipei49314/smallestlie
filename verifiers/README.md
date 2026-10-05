# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.6.0 |
| Source revision | `8c70efbf93975bf3210acb8eafbaf4b38044a770` (annotated tag `v0.6.0`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.6.0` |
| SHA-256 | `4f9c7b836d1e1c40dc0a7b88ef6d63f25d482c8eafda18c05eb5a4fbac9ad949` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | one-time named human grant (Nelson, 2026-10-06 Asia/Taipei): 已發佈 套過去繼續; published asset verified, 2026-10-06 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.

This update uses the published v0.6.0 release, asset 613073648, from
release 403905268. Its downloaded bytes match the GitHub asset SHA-256.
[M12: 0.6.0 migration](../docs/adapters/CHECKWASH_M12_060.md) records the
one-time named authorization, tag/source identities and pending validation.
All earlier records retain their original engine versions and results;
a pin update alone does not establish new evaluation results.
