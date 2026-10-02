# Raw command capture and external Vitest evidence (M12 D capture subcut)

`ByteCaptureExecutor.run_bytes()` supplies a separate command capture API for
a future trusted collector. It preserves stdout/stderr bytes, including CRLF
and invalid UTF-8, before hashing. It records the resolved argv/cwd, effective
scrubbed environment, actual command-process exit and supervisor disposition.
Environment metadata exports a digest; full values remain with the collector.
No raw output is decoded, newline-normalized or decorated with a truncation
marker. Per-stream returned prefixes have captured/observed byte lengths and
explicit truncation flags. A green exit with truncated output is incomplete
evidence. Timeouts retain the actual post-kill exit and `termination_kind=timeout`;
spawn errors have no invented exit code. Extra environment values are scrubbed
before launch, including credentials and proxy variables. Windows keys are
normalized before merging/scrubbing so case collisions cannot change the launch
environment or override the denied marker.

The legacy `SandboxExecutor.run()` text API and v1 result serialization remain
unchanged. This new primitive neither authenticates execution nor creates a
`TrustedExecutionEnvelope`. Its supervisor scope is the command process only.
Temporary binary files avoid waiting on stdout/stderr pipe EOF from descendants;
they retain a snapshot after command-process disposition. Independent read handles
leave writers' offsets untouched, and each read is bounded by the file length
observed before reading. Reader file identity must match the authoritative writer
descriptor; path replacement or capture I/O failure returns no substituted bytes,
unknown lengths and an incomplete/internal-error disposition. Short reads are
explicitly incomplete. These are file
snapshots, not a byte-by-byte event history of seek/rewrite operations. Retained prefixes are
bounded in memory; temporary-file growth is **not** governed by `max_output_bytes`.
The future outer collector must enforce storage quotas and descendant cleanup,
establish that all output writers ended, and independently observe runtime,
runner/dependency artifacts, effective config and fixture trees before admitting
these snapshots as complete formal evidence. Command-process completion alone
cannot attest process-tree cleanup, network isolation or a complete run.

The runner profile additionally recognizes `runner.name=vitest`,
`runner.version=3.2.7`, `report_format=vitest-junit`. This is an external report
contract for the version found in the historical SELFREF material, based on the
[v3.2.7 JUnit reporter source](https://github.com/vitest-dev/vitest/blob/v3.2.7/packages/vitest/src/node/reporters/junit.ts).
It does not adopt, vendor, install or run Vitest. Other versions fail preflight
until their contracts are checked separately. The existing runner artifact,
runtime, dependencies, environment, argv/cwd/config, raw artifact digest and
independent supervisor requirements all still apply.

The preregistered assertion identity is the emitted `classname::name`: default
relative file classname and nested names joined with ` > `, or the exact emitted
classname when the approved config customizes it. `skipped` includes skipped/todo
cases. A failed baseline requires the exact target, approved assertion exit 1,
`failure type=AssertionError`, and both frozen message/trace predicates. An
untyped failure, runtime/collection exception or ambiguous identity remains
unknown. Multiple failure elements on one testcase are conservatively unsupported
and remain unknown; summary counters must agree with testcase records. An attack
whose bound target still fails its assertion is refuted. Missing/failed/truncated
capture is never converted into a killed candidate.

Tests use tiny Python commands for the capture primitive and synthetic native
XML/test-double authorities for Vitest parsing. They are regression contracts,
not formal W3 runner receipts or historical replacement logs. Real SELFREF
baseline capture is still missing. Execution/verifier/review providers, formal
lock-before-command orchestration, ledger/report/replay integration and Phase
1/2 remain later D work; v2 campaign gates remain closed.
