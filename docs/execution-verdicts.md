# Execution validity before verdict comparison

This local draft changes how SmallestLie adjudicates incomplete executions.
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

NOT_RUN：工作機規則（AGENTS.md §1／EC POLICY work-machine-local），本次只做本地碼與案例準備。

The new regression files cover interrupted executions with leftover reports,
missing/invalid fixture reports, normal report/exit disagreement, campaign
aggregation, and minimization/replay. They are written but not executed.
The existing naive/honest fixtures and published CheckWash fixed-catalog
expectations must also be verified on an authorized pool workload before this
draft is accepted. No local dependency installation, product execution,
pytest collection, compilation, lint or campaign was performed.
