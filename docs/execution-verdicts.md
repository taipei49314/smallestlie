# Execution validity before verdict comparison

This draft changes how SmallestLie adjudicates incomplete executions.
It does not change the vendored CheckWash engine or its published v0.4.2 pin.

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
execution, or establish attack semantics. In particular, exit 1 accompanied by
a structurally valid stale report still requires freshness/execution evidence.
Other adapters retain their existing output-parser contracts. Historical
campaign records and expected known false acceptances are not rewritten.

## Validation status

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
