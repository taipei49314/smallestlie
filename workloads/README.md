# Authorized EC verification workload

## Prepared M12 slice-A workload (not yet authorized)

`m12-schema-v2-verify` is a new, separate declaration requiring human EC
admission approval before any dispatch. The authorizations below do not cover
it. It checks only the exact reviewed source SHA on LAPTOP-50KP71KA with the
same pinned Python 3.12 Windows x64 dependency/environment and receipt checks.
The existing entry's default verification scope is unchanged; its new internal
arguments let this entry select a separately declared focused suite and title.

The focused phase covers the new v2/source contracts, composition, diff
selection and the v1 wave1 catalog (5-minute limit), followed by the entire
existing pytest suite (20-minute limit). Total budget is 35 minutes, no cache,
no workload parameters. Source status is checked before and after. No W3 case
run, benchmark, measurement, nightly, release, runner adoption or re-pin is
included. Outputs are raw logs, JUnit, result.json and SUMMARY.md, with exact
source, runtime, wheel hashes, commands and exit/timeout details.

Status: NOT_RUN; prepared for human approval and EC dispatch only.

## Earlier execution-verdict authorizations

Nelson authorized this bounded pool regression in the current Codex conversation
on 2026-10-01: 「自行選一台空閒的 授權」, responding to the prepared execution-verdict
patch and its verification plan. EC dispatch is recorded as T-488; this does not
authorize a public PR merge, publication or CheckWash re-pin.
Nelson subsequently said 「繼續」 for the output-validity / execution-binding
follow-up on the same draft PR and the same bounded pool workflow. The follow-up
has EC dispatch T-492 and its own exact product SHA; T-488 remains the completed
first-slice receipt.

On 2026-10-02 Nelson requested 「Checkwash 0.5.0已發佈 pr 要重新測」 after
master merged re-pin PR #23. PR #22 incorporates that base and is revalidated
at a new exact SHA. The declaration description now refers to the repository's
published pin; entry/profile, parameters, no-cache policy and all budgets remain
unchanged. EC approval metadata must match this new description before dispatch.
This request applies to this v0.5.0 retest only, not future pins or executions.

`execution-verdict-verify` runs on LAPTOP-50KP71KA only, because the existing full
suite includes isolation/boundary regressions. The entry checks its actual host,
EC workload identity and exact source SHA before execution. It uses the pinned
generation Python 3.12 and a disposable job-local venv with the eight verification
dependencies selected from `uv.lock` and installed by exact wheel URL/hash.

It first runs execution-verdict/binding/failure tests, CheckWash adapter tests
and the existing comparator
(5-minute subprocess limit), then the full pytest suite (20-minute limit).
Existing frozen greenwash regressions and intentional false-accept expectations
remain part of the suite. No additional benchmark, model campaign, nightly sweep
or engine re-pin is performed. The overall EC declaration is bounded to 35 minutes.

Receipts include source/status checks before and after, exact commands, raw logs,
JUnit for both phases, dependency pins, runtime and result/SUMMARY. A nonzero exit,
timeout, missing JUnit, zero tests, failed/skipped test or dirty source cannot pass.
EC adds the generation/job/QoS records and publishes the private receipt ref.

This runs the pytest regression scope, not both complete GitHub CI-gate jobs.
Passing fixed synthetic regressions does not establish complete adversarial
coverage or product acceptance. The work-machine prohibition remains in effect.
