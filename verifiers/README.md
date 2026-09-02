# Pinned external verifiers

Third-party verifier artifacts vendored so campaigns are byte-reproducible on
every machine with zero per-machine setup. Each artifact records its origin,
revision, and SHA-256 here; the adapter that consumes it re-verifies the pin
at preflight and refuses to run on mismatch.

## checkwash.pyz — `checkwash` adapter SUT

| Field | Value |
|---|---|
| Product | [checkwash](https://github.com/taipei49314/checkwash) (owned repo; consumed read-only) |
| Version | v0.2.9 |
| Source revision | `760021d56b13af1332a5cb8eedd7ba20a9bfce47` (annotated tag `v0.2.9`) |
| Artifact | release asset `checkwash.pyz` from tag `v0.2.9` |
| SHA-256 | `b0928a112d063206465e423cf0c084f1e02d19d7ddb69e2914a45456fa58f198` |
| License | Apache-2.0 (redistribution with notice permitted) |
| Pinned by | estate-consolidation T-18; human 「兩件都做」, 2026-09-02 |

The checkwash repository itself is never mutated by this harness. Re-pinning is
a conscious, human-visible step: update this table, the pin in
`adapters/checkwash.py`, and `docs/adapters/checkwash.md` together.
