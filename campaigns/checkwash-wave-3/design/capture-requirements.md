# W3 external capture inputs before profiles

This is an input contract checklist for the result-free case design. It is not
an admission, a workload declaration, a source provider, or permission to run.

## Runtime, runner and dependencies

The profile's three digests identify actual bytes measured by the chosen
collector. Version labels, wheel/archive integrity and installed identity are
different facts. The profile parser defines field shapes, not a universal
archive-to-installation hash algorithm.

For the existing native CPython/pytest producer, runtime identity hashes the
actual executable; runner identity hashes complete installed pytest/_pytest
file maps; installed identity hashes the complete regular-file `sys.prefix`
map, including bytecode. Use that exact measurement definition if selecting
that producer. It currently has no Node or native verifier command producer.
Mocha/Vitest need an actual external collector with an explicit complete
runtime/runner/installation measurement and module-resolution contract.

Provide actual raw lock files and reproducible installation inputs, the full
original measured inventories, per-file hashes and canonical map definitions.
The runtime's transitive loader/DLL/package locations and the stable dependency
placement must be independently accounted for. Copies of a historical junction
or a hash copied from the intended profile do not establish actual identity.
Do not fill profile fields before these source bytes and definitions exist.

## Per-family native contracts

| Family | Required native format | Design assertion | Inputs to freeze |
| --- | --- | --- | --- |
| D1 | Mocha native JSON | `billing computes invoice total with tax` fullTitle | same `test/` selection, native reporter argv, Node/Mocha/Chai closure |
| D2 | pytest JUnit | `test_invoice_total` in `tests/test_billing.py` | exact emitted classname/name identity, isolated argv, explicit pyproject config and assertion message/text predicates |
| B1 | Vitest3.2.7 JUnit | `billing` / `computes invoice total with tax` | exact emitted classname/name identity, native reporter argv, Node/Vitest closure and package self-reference resolution |

Readable source assertion labels are design locators, not assumed JUnit IDs.
Select deterministic native reporter options and case-specific assertion
predicates from their supported emitter contracts; exact IDs and predicates
remain explicit profile inputs. Attack/twin command and config must be equal,
and baseline/repair command and config must be equal. Record the actual argv,
cwd, semantic environment and report destination, not only command labels.

## External responsibilities

The integration must identify an actual capture/host-storage responsibility,
an immutable publisher, a coordinator enforcing durable ACK before release,
and independent source and semantic review authorities. Their acceptance binds
the collector bytes, isolation/protected storage, journal/crash behaviour and
exact request/dispatch/host/generation. Constructors and a generic successful
EC job cannot accept those contracts on their behalf.

Each row and each declared arm independently captures full fixture/config/
production maps, runtime/runner/installed/lock identity before and after work,
actual command/environment, native termination/exit and descendant-writer
closure. Preserve bounded raw stdout/stderr/native report bytes. Archive raw
facts/prefix/journal/action inventory/completion sources and authenticate their
immutable Git identities through the configured independent provider before
releasing later actions. Missing, truncated, timed-out or internally failed
evidence remains unknown; shared fixture roots cannot lend another row a run.

The final report keeps the complete proposed roster, original DEF refutations,
unknowns, residual reconciliation and relevant effective blocked twins. A
source-acceptance decision does not substitute for case-bound theater/scope/
residual review or exact independent human Phase-1 approval.

## Preparation boundary

The existing EC profile declares CPython/MinGit only. Choose the actual runner
installation and collector before proposing a new bounded preparation. A
metadata-only preparation may read only specifically approved regular roots
and produce actual inventories; absent Node/dependencies must remain missing.
Installation, downloading, invoking runtime/runner tools or resolving packages
are separate execution scope and must be named in a concrete new proposal.
No previous exact-source framework grant covers them. Preparation may acquire
identity inputs; it must not run these cases or manufacture Phase-1 approval.

M12 may use externally captured attachments with these truthful source inputs.
M13 adapter pin/vendor/nightly work is a later mechanism, not an excuse to fill
missing M12 identities or indefinitely add offline inspection layers.

NOT_RUN: source design only; no product, runner, fixture, install, collection,
probe or workload execution. No formal profile, admission or result is supplied.
