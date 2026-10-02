# External runner evidence (M12 slice B)

`oracle.runner_evidence` validates externally captured raw bytes and assesses
effectiveness. It does not invoke runners or map `confirmed` to `OracleResult`
validity or `confirmed_defect`. The existing comparison/count/exit meanings remain
unchanged. Actual EC provenance retrieval and campaign/report integration follow
in Slice D; without an independent provider, evidence stays unknown.

A frozen `smallestlie.runner-profile/v1` JSON profile specifies `profile_id`,
`baseline_assertion`, runner/runtime name/version/artifact SHA-256,
`dependencies` (frozen `lock_path` and expected actual `installed_sha256`),
`collector_path`/`collector_sha256`, effective `semantic_env` values, `report_format`,
`assertion_exit_codes`, `assertion_failure`, and all four arm command definitions
(`argv` array, logical `cwd`, `config_paths`). Baseline and repair commands/config
must match; predeclared attack/twin configuration changes may differ. Only
`${WORKSPACE}` and `${RUNTIME}` substitutions are performed; actual absolute
workspace/runtime paths and argv/cwd are retained in receipts.

Current parsers support pytest/JUnit and Mocha/native JSON with unique test IDs.
Only assertion exit 1 is supported for this first contract; other exits remain
unknown. JUnit test IDs are `classname::name` (or `name` if no classname); Mocha
uses `fullTitle`. Summary totals must agree with per-test records. JUnit DTD/entity
declarations, ambiguous IDs, bool JSON counts, duplicate JSON keys, nonstandard
JSON constants and unsupported report formats fail validation.

Pytest failures may omit a type attribute. Freeze `assertion_failure` as
`message_contains` and `text_contains` specific to the designated assertion.
Both must match to recognize that assertion; an absent type is supported and an explicit
non-AssertionError type cannot be overridden. Mocha requires native AssertionError
name/ERR_ASSERTION identity without a contradictory type/code, plus a frozen
`message_contains` predicate. Its duplicate arrays must agree on exception
identity and any explicit pending flag; error values must be objects or null.
Generic exceptions and runner failures do not refute candidates merely because
their numeric exit is nonzero.

Each `smallestlie.runner-receipt/v1` JSON contains formal `binding`, external
`source_run_id`, `job_id`, actual `host`, and captured `arms`. Formal binding comes
from the shared `case_binding()` helper. Each arm includes:

- Full fixture file/tree/production map; frozen config map; actual runner/runtime,
  dependency-lock/installed identity and effective semantic environment.
- Actual workspace root, runtime path, argv/cwd, supervisor termination kind and
  numeric exit (never bool); explicit `truncated: false`.
- Confined artifact references (`path`, raw-byte SHA-256) for stdout, stderr and
  the original native report. Validator hashes and parses the supplied same bytes.

A separately configured `ExecutionAuthority` retrieves a
`TrustedExecutionEnvelope` from independently authenticated dispatch/job/immutable
receipt evidence. It must verify the actual source, collector artifact, host,
request and phase1 identities; lock/first-command sequence; receipt digest; and
outer supervisor exits. It must not copy expected fields from the profile or
receipt and call that authentication. The narrow provider interface is a trusted
integration boundary, not an attestation implementation. Receipt fields such as
`authenticated: true` are rejected, and self-reported hashes cannot grant trust.

Missing/tampered arms remain separate: a missing twin does not erase an otherwise
confirmed attack. Assessment is bound to the prepared lock/spec/profile; it cannot
be reused for a different formal request with the same case ID.

| Effectiveness | Required observation |
|---|---|
| confirmed | Verified baseline designated assertion red; same bug attack/twin exit 0 with consistent native green/skip/focus report; repair original assertion passed |
| refuted | Verified baseline designated assertion already passed, or verified changed arm still fails that designated assertion |
| unknown | Missing provenance/arm/log, binding/hash mismatch, timeout/spawn/internal error, unsupported parsing, unexpected exit, or incomplete repair calibration |

Skip/focus may legitimately leave the baseline assertion absent on the changed
arm; repair must actually run and pass it. Green report cannot override nonzero
supervisor exit, and green exit cannot override native failures/errors.

This contract assumes an independently trusted collector and reviewed frozen
skip/focus/mock shapes. Capturing a native report does not alone prove arbitrary
test code cannot forge that report. A lock or receipt validates identities and
observations; later adjudication still needs theater, scope/residual coverage and
a relevant blocked effective twin. Historical rt4 bare logs cannot be upgraded
by filling missing fields or borrowing a merely similar baseline.

Tests use synthetic contract records and Git repositories; none is W3 evidence.
NOT_RUN locally: `POLICY work-machine-local`. A separate bounded workload prepares
focused contract tests and existing full-suite regression on LAPTOP-50KP71KA.
