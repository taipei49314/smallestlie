# Execution validity before verdict comparison

This draft changes how SmallestLie adjudicates incomplete executions.
The engine pin follows the separately authorized published release on master.
PR #23 advanced it to CheckWash v0.5.0; PR #22 incorporates that merged base.

## Contract

Campaign execution, delta minimization and witness replay use
`Adapter.read_verdict`. A timeout or an exit outside the adapter's declared
`verdict_exit_codes` is `INCONCLUSIVE`; partial output is not parsed and the
truth oracle is not evaluated. The current adapters declare exit 0 and 1 as
normal accepting/rejecting executions. New adapters can declare their own
completed verdict exit codes.

Fixture verifiers must emit a readable JSON object containing a boolean
`accepted` or a recognized verdict status. A missing, malformed, unreadable or
unusable report is `INCONCLUSIVE`, including a missing report after exit 1.
A valid report remains the target's accepting/rejecting claim, with its exit
channel preserved separately for the independent oracle.

Fixture campaigns, minimization and replay also use `Adapter.execute`. The
fixture adapter clears only disposable `outputs/report.json` and
`outputs/execution_trace.json`, then supplies a fresh `SMALLESTLIE_RUN_ID` and
`SMALLESTLIE_INPUT_SHA256`. All six fixture verifiers echo these two values in
the report's `execution_binding`. The expected values live on the harness-owned
`ExecutionResult`, not in adapter state or target output. A report with missing
or mismatched binding is inconclusive, even when its verdict and exit are valid.
Unbound direct executor calls cannot adjudicate fixture reports.

The input digest covers sorted directory/file paths and file contents before
execution. It excludes root `outputs`, `.git`, Python/pytest caches and venvs;
`.pyc` files are excluded too. The harness recomputes it after execution and
rejects changed or unreadable inputs. Linked/reparse input or generated-output
paths are refused. Expected binding is preserved in execution records, ledger
events, verdict channels and replay details. Clearing output never changes the
source fixture or unrelated output artifacts.

Real CheckWash output must be exactly one unambiguous JSON object with findings
schema 2, run version matching `PINNED_VERSION` (currently `0.5.0`), nonempty
base/head, a typed findings list, severity
counts matching that list, string-list skipped files/config errors, and a
`pass`/`block` verdict. Empty/malformed output, missing or mistyped fields,
duplicate keys, nonstandard constants and banner salvage are inconclusive.
The blind control keeps its separate schema 1 / `blind-control` contract.
CheckWash acceptance still follows its documented exit 0/1 contract; a valid
report/exit disagreement remains visible in separate channels. Counts, findings
and config warnings do not cause the harness to recompute engine gating policy.
These adapter contracts are versioned as `0.2.0`; the engine pin stays unchanged.

`target_verdict.execution_error` records the reason. The comparison uses
`target_accepted: null` when an execution cannot adjudicate; the boolean on the
target model is not a defense observation. No false-accept witness or regression
is produced from such a comparison. Both batch and CI `pass_no_false_accept`
expectations require `PASS_NO_FALSE_ACCEPT_OBSERVED`, so an inconclusive campaign
cannot meet that confidence gate. Existing budget/soft-warning projections and
explicit `any` observations retain their existing semantics.
The required CI profile then fails as a harness error (or preserves a blocked
projection), without inventing a false-accept observation from the unknown result.

## Limits

This change does not provide an OS sandbox, independently attest actual test
execution, or establish attack semantics. A hostile verifier can read the
current nonce/digest and forge a correctly bound report; it can also rewrite and
restore input between the two digest observations. Binding detects stale or
cross-run reports, not honest execution. Traces still come from the fixture.
The frozen greenwash adapter retains its output-parser contract. Historical
campaign records and expected known false acceptances are not rewritten.

## Validation status

### CheckWash v0.5.0 revalidation (2026-10-02)

Nelson requested: 「Checkwash 0.5.0已發佈 pr 要重新測」. Master PR #23 had
already merged the separately authorized published v0.5.0 artifact and pin.
PR #22 incorporates master and updates parser regression payloads to the
current pin, with an explicit regression refusing a prior v0.4.2 report.
The artifact SHA matches the published release digest
`b305bc3f7d35f827190051f7a676ac40e3e86badf9eaed750f22f082fd10b05c`;
read-only archive inspection confirms findings schema 2 is unchanged.

This exact updated PR has not yet been tested. The bounded workload description
now refers to the repository's published pin, keeping its entry/profile,
parameters, no-cache policy and 35-minute budget unchanged. Its approval metadata
must be refreshed before dispatch. This human request authorizes this v0.5.0
retest; it grants no standing authority to advance future pins or run workloads.
All v0.4.2 results below remain dated evidence, not passes for v0.5.0.

### Output validity / execution binding follow-up

Nelson said 「繼續」 after the proposed next slice: real CheckWash output validity
and fixture report freshness/binding, followed by the same bounded pool workflow
and an update to draft PR #22. Static review completed and corrected the
deeply nested JSON exception path. EC T-492 [run 36881268126](https://github.com/taipei49314/estate-consolidation/actions/runs/36881268126)
tested `2151bca29007e0752eafad06c25c64ca1deabfc2` on 50K: 133/134 focused and
215/216 full tests passed. One shared failure was an overly specific test
expectation: Python 3.12 parsed a deeply nested array and the adapter correctly
returned `invalid_report_type`, while the test expected `invalid_report_json`.
Both outcomes remain inconclusive. The assertion was corrected to the actual
contract, and explicit decoder-recursion fault injection was added for both
adapters. Failure receipt
`087202078b230469e3a232cc40b9a3f785f9fbe9` remains immutable; its file manifest
was verified against raw Git blobs. T-488 remains the completed first slice.

The corrected product `89a84ec15cf2de06e8d37f68ce0e646a2da03b36` then passed
EC [run 36881928902, attempt 1](https://github.com/taipei49314/estate-consolidation/actions/runs/36881928902),
with EC source `ffd41c930dcaa9d10e2a3f9946b99de81560448a`, actual
`LAPTOP-50KP71KA`, generation `8b1bcfb4b5dc0588.1`, Windows Python 3.12.10.
Focused JUnit passed 136 tests in 3.787 s; full JUnit passed 218 tests in
154.887 s, with zero failures/errors/skips. Focused is a subset of full, not
136 additional independent tests. All subprocess exits and the EC entry exit
were 0; entry duration was 179.453 s and no timeout occurred. Initial/final
source SHA matched the requested commit and both Git status observations were
clean. Product check `ec / execution-verdict-verify` (110437151900), job and
private receipt publication all succeeded.

Immutable receipt `68183762fe5da965f5c6badb56271b305e0e3462`, ref
`sweep-receipts/36881928902/1/workload-execution-verdict-verify`, preserves JSON,
both JUnit reports, raw logs, dependency pins, runtime/generation and QoS.
All 23 manifest-listed file sizes/hashes matched raw Git blobs when read back;
product result, JUnit and EC workload result agreed. The final result-document
commit changes only this file; product code, tests and workload remain exactly
those of the tested SHA. No additional test run is claimed for that document.

NOT_RUN: work-machine policy prohibits local product
execution, pytest collection, compilation, lint and dependency installation.
The approved EC workload declaration and its 35-minute budget are unchanged;
the focused phase adds CheckWash adapter and fixture binding regressions.

### First slice (historical result, not validation of the follow-up)

Nelson authorized the bounded pool verification with 「自行選一台空閒的 授權」.
On 2026-10-01, EC [run 36876256944, attempt 1](https://github.com/taipei49314/estate-consolidation/actions/runs/36876256944)
verified product commit `d549c0df92e549b014743461810ac9c5f30b2161` on
`LAPTOP-50KP71KA-workload`, generation `8b1bcfb4b5dc0588.1`, Windows Python 3.12.10.
The focused regression/comparator phase passed 42 tests in 1.045 s; full pytest
passed 140 tests in 147.376 s. Both JUnit reports recorded zero failures, errors
and skips. Both pytest exits and the EC entry exit were 0, with no timeout.
Source SHA and clean status matched before and after execution.

The product check `ec / execution-verdict-verify`, Actions job and private
receipt publication all succeeded. Receipt commit
`b9a3f224a48ae4e4f22a2547f7b917d6916e8684` in the private EC repository preserves
the result, JUnit, raw stdout/stderr, pinned dependencies and runtime evidence;
all file sizes/hashes matched `ec-publication.json` when read back from Git blobs.
The receipt ref is `sweep-receipts/36876256944/1/workload-execution-verdict-verify`.

These results include the existing naive/honest fixtures, CheckWash adapter/pin
and fixed-catalog expectations, and the frozen greenwash regressions. Known
false accepts remain expected observations; passing those assertions does not
close the limits above. This is one Windows regression, with no new adversarial
campaign, cross-OS verification, product acceptance or release.

NOT_RUN on the work machine: no local dependency installation, product execution,
pytest collection, compilation, lint or campaign was performed. Existing Linux
CI campaigns and measurement were not dispatched by this bounded verification.
The documentation-only result commit carries `[skip ci]` to keep this review
draft within that scope; skipped workflows are not passes. Public PR merge is
reserved for the human under AGENTS.md.
