# M12 preregistration contract (slice B)

Slice B provides `campaign.preregistration.prepare_run()` and an opt-in ledger
protocol. The v2 campaign/replay/minimize execution gates remain in place until
Slice D connects these contracts. No W3 fixtures, formal results or defect
adjudications are introduced here.

A Phase-1 `smallestlie.preregistration/v1` JSON manifest contains:

- `campaign_id`, `catalog_path`, ordered `cases` and an `assets` map.
- Every asset's repository-relative POSIX path, raw-byte SHA-256 and Git blob
  SHA-1; the manifest does not contain its own digest or commit SHA.
- `closed_roots`, covering each complete fixture variant, profile directory and
  execution-contract directory. All files and their implied directories are
  included. Extra files, empty directories, symlinks and Windows reparse/junction
  inputs are rejected. No cache/dependency/output exclusions are implicit.
- `engine_path`, `residual_index_path`, their source snapshots and
  `contract_paths`, including the actual collector file and the entire
  `src/smallestlie` package as a mandatory closed root. `pyproject.toml` and
  `uv.lock` must be frozen as well, so a descendant cannot swap the validator.
- Each case's `case_id`, `spec_path`, `profile_path`, and `variants`. Each variant
  declares `root` and `production_paths`. Baseline/attack/repair are required;
  cases declaring a twin also require its variant.

The complete ordered catalog, v2 declarations, published engine/index pin and
paired control references are checked from the same captured asset bytes.
Attack/twin production maps must equal baseline. Repair changes production at
the same paths and preserves every other input. A parent's twin arm must equal
the control case's attack arm, with identical baseline and repair arms.

The narrow frozen-mutation contract currently supports `replace_text`,
`write_text` and `write_json`. It derives the attack from captured baseline bytes
in memory and compares the full resulting byte map. Structured/directory
operations are explicitly unsupported in this slice. Replacement reads UTF-8
with universal-newline normalization; materialized text uses explicit UTF-8
bytes. Slice D must use the returned frozen/derived bytes, not the legacy v1
filesystem writer's host-dependent newline conversion.

Use Git attributes to preserve all frozen raw bytes on every checkout. Phase-1
assets must exist as regular Git blobs at the authorized commit. The formal
source must be that commit or a descendant, with all frozen assets unchanged and
a clean checkout. Results outside the closed inputs may be added later.
`PreparedRun` owns immutable captured bytes; getters return newly parsed data.

`RunRequest` supplies campaign/request/run identity, `phase1_commit`,
`source_commit`, raw `manifest_sha256` and `authorization_ref`. A configured
`PreregistrationAuthority` must independently retrieve human merge/approval and
the later bounded formal request, returning identities that match that request.
There is no default provider, local `approved` flag or declaration-based fallback.
Git ancestry and timestamps alone do not establish approval or execution order.

The prepared lock binds the entire ordered case denominator, case/spec/profile
and fixture/production identities, request, approval reference, source and
published pins. Its canonical digest excludes its own `lock_digest` field.
Before any formal workspace or command, Slice D must persist the unique
`preregistration_locked` event and call `require_locked_run(..., action=...)` with
the externally prepared expected lock. The guard durably reserves one of
`workspace_create`, `workspace_prepare`, `mutation_apply`, or `verifier_command`
before invoking external work. Corresponding completion records use distinct
`mutant_created` stages (`created`/`prepared`), then `mutation_applied` and
`command_executed`. Mutation is mandatory before command. Reservations cannot
be retried, including after a crash; use a new bounded request. Formal writes
require a single writer, reject stale Ledger handles, and read back the valid
persisted head. Multi-writer coordination is outside this contract.
A ledger hash chain proves internal consistency; it is
not independent proof against rewriting the whole ledger. Trusted collector
sequence evidence is required as well.

`smallestlie.m12/v1` is explicit in the first `campaign_created` event. Legacy v1
hashing, ordering and result format keep their old meaning. Formal logs additionally
reject duplicate JSON keys, missing/double locks, changed case bindings, duplicate
receipt dispositions, late execution, unsupported replay/minimization, and
summary distributions inconsistent with the frozen denominator. Missing/rejected
receipts can only produce unknown effectiveness. Legal partial logs return
`complete=False`; finalization requires a receipt disposition and effectiveness
row for every declared case, including missing evidence. `complete=True` describes
this evidence-ledger protocol, not a successful verifier defense or a defect.

All callers consuming formal logs must pass `required_protocol`/`expected_lock`;
otherwise removing every protocol marker could make a rewritten file appear
legacy. Claim scope, residual coverage, theater and relevant blocked twin findings
still belong to later adjudication.

Validation: adversarial unit tests are prepared for pool execution. NOT_RUN:
work-machine rule (`POLICY work-machine-local`); no local product/test execution,
collection, compilation, lint or installation.

The independent [formal lifecycle recording contract](campaign-lifecycle.md)
adds an explicit `smallestlie.m12/v2` wrapper around this unchanged v1 lock.
It records per-arm reservation/completion, observation sealing and full
review/adjudication artifacts without activating a production launch driver.
