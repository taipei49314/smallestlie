# Native single-action producer (M12 D)

`produce_action()` receives one exact frozen `PreparedRun`, an unused
`ActionReservation`, and the original complete ledger prefix ending at that
ticket. It produces actual raw bytes for one runner materialization or one
Windows CPython/pytest command. It is a library entry point for a separately
admitted coordinator, with no default authority, registry discovery, CLI,
campaign continuation or external publisher.

## Receive before work

The receiver checks the full prefix hash chain, v2 lock/plan and final exact
reservation. It checks the actual complete Python source closure against the
frozen contracts and requires the collector pin to identify this module.
Dispatch identities have strict integer/string/hash shapes and bind the frozen
request, lock, product source and collector. Those checks do not authenticate
the caller's EC dispatch; its external acceptance is still required.

Producer, fixture and one-use journal roots must be separate absolute plain
paths. Parent traversal, alternate streams, trailing dot/space aliases, reparse
points and overlapping roots are rejected; existing short-name aliases are
normalized after the reparse checks.
The receiver exclusively creates and fsyncs/readbacks separate claim files for
the exact ticket and external `(epoch, action_id)`. It persists/readbacks the
original prefix and ticket ACK before writing fixtures or releasing a child.
Both claim identities remain consumed after interruption or later failure.
There is no automatic retry or retrospective ticket filling. Recovery needs
an external decision and a fresh request; deleting claims is not recovery.

`runner_materialize` writes only frozen variant bytes to a fresh workspace,
then measures its entire regular-file closure. Hidden files and bytecode count;
links, case aliases, extra files and byte-budget overflow are rejected. It
seals completed only after the actual map equals the frozen map. Its v1
`work_started` event records frozen input intention before copying; the final
map is independently measured after copying. The compatible successful journal
requires equality between these maps. Partial/failed materialization therefore
keeps the prefix, native events and measured partial diagnostics, raises an
error, and seals no completion/publication. It remains missing evidence in the
lifecycle, rather than claiming a compatible observed completion for v1.

## Command and native capture

Before command preflight, every required materialization is freshly checked
through its independently configured `EcLifecycleCompletionAuthority`. The
exact prior ticket, raw completion digest and immutable provenance must match
the ledger, with completed exit zero, full output and writer closure. A local
bundle, caller `verify` hook, generic success flag or still-running native job
cannot supply this ACK. Each prior action may come from a different terminal
dispatch; its explicit external grant retains that original dispatch.

The first command implementation supports only the current actual CPython
executable with frozen `-I -B -m pytest` argv and one explicit JUnit destination
newly created inside the fixture. It hashes the executable, both installed
pytest package trees, and the entire regular-file `sys.prefix` closure, including
bytecode. It reads the installed distribution version and actual frozen lock
bytes. These values must match the preregistered profile before launch and
remain identical after capture. The executable hash does not describe all
base-interpreter DLLs/loaders outside a virtual environment; admitting that
transitive runtime remains an external host contract. Hashing installation
bytes does not adopt or install any runner.

The receiver measures the actual full fixture and config files, instantiates
argv/cwd, and supplies the scrubbed environment. Frozen semantic values must
survive scrubbing exactly; credential/proxy values cannot be retained by a
semantic allowlist. Capture records only an environment digest, without
publishing the full host environment. Reports with parent traversal,
drive-relative paths or existing destinations are refused before launch.

`capture_windows()` creates an anonymous action Job Object with
`KILL_ON_JOB_CLOSE` and no breakaway permission. It creates the child suspended,
assigns it to the job, then resumes it. The only inherited handles are NUL stdin
and the two capture pipe writers. It records the parent native exit separately
and releases parent process/thread handles before accounting readback.

Completed requires both `ActiveProcesses == 0` and broken-pipe EOF on both
streams. Parent exit zero alone cannot establish either fact. Timeout covers
the launched action through descendant/pipe closure, with a separate bounded
cleanup period; native setup and installation measurement are not covered by
that launch timer. Failed assignment never resumes the suspended child.
Termination, accounting, pipe and handle failures preserve incomplete/unknown
closure; a kill request is not a successful reap measurement.

Raw stdout/stderr bytes are retained in bounded memory, without decoding or
newline normalization. Exceeding the combined output budget kills the action
as quota, retaining only the bounded original prefixes. Retained and observed
byte lengths are distinct; observed bytes are not a claim to all bytes emitted
after termination. Report reads have a separate bound. Missing, oversized or
changed inputs/installation leave output incomplete and cannot become a green
completed result. A normally terminated assertion exit one remains native
`completed` exit one; runner semantics are a separate consumer decision.

This primitive has no filesystem-write, disk-quota, memory/CPU or network
sandbox. Bounded capture retention and bounded report reads do not enforce a
host disk quota. The caller must separately admit fixture isolation, protected
source/runtime/journal/output storage, network policy and resource limits.
Attack code must not have write access to the producer or claim roots; plain
path checks cannot stop concurrent changes by an unisolated local actor.

## Seal and publication boundary

Successful materialization and captured commands emit the existing canonical
raw facts, prefix, five-event journal, acyclic action inventory and completion
wrapper. Every write is exclusive, fsynced and compared with its raw readback.
Native event logs and capture diagnostics are archived sidecars, outside the
canonical action source closure. Windows directory-entry power-loss durability
is not established by Python file fsync; it requires separate storage adoption.

`ProducedAction` returns local hashes and termination kind. It has no trusted
envelope, immutable commit, acceptance or publication ACK field. The external
publisher must archive these exact bytes, obtain immutable commit/tree/blob
identity, and independently read/accept the source before a coordinator records
completion or releases the next ticket. Push success, local hash equality and
test transport grants do not establish that production fact.

The existing terminal-only readers remain unchanged. This cross-terminal
single-action entry point cannot directly populate the current offline source
map, which requires one dispatch across anchor/actions/final archive. It does
not solve that live coordinator/publisher/aggregate mapping contract, provide
actual external admission, execute a verifier, adopt Mocha/Vitest, or open the
public v2 campaign/replay/minimize gates. Full M12 D and formal W3 remain
unfinished. Agent framework merges do not supply the independent human Phase 1.

## Qualification

Authored tests exercise actual tiny native Python processes and one tiny pytest
assertion run on the authorized Windows pool host. They check raw bytes/native
nonzero exit, descendant writes after parent exit, capture quota, failed native
setup/cleanup, one-use claims, partial materialization, malformed paths/dispatch,
lost prefix persistence, missing/oversized reports, changed installation/input,
and fresh rejection of changed or nonterminal prerequisite sources. Synthetic
external API/admission grants qualify the local producer-to-reader contract;
they are not an actual EC publisher, host acceptance or campaign evidence.
On non-Windows hosts, tests explicitly check unsupported native capture and
use labeled synthetic installation markers for pure contracts; those branches
provide no actual installation or native-process qualification. The authorized
Windows pool uses actual measured installation and native process APIs.

NOT_RUN: work-machine rule (`POLICY work-machine-local`); no local product,
pytest/collection, syntax probe, compilation, lint, typecheck, build or install.
PR35's consumed source grant and its native924 regression results do not test
this source. A new exact-source bounded pool dispatch must retain all924 prior
case identities and inspect original receipt/JUnit/log bytes independently.
The existing five focused groups, workload declaration, uv.lock and engine
pins are unchanged.

Native API references: [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[handle-list attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[job accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information),
and [nested jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs).
