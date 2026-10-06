# Mutex fault test lifetime — R4 SOURCE_ONLY / NOT_RUN

STOP source proposal. This new complete nine-file cut repairs only R3 B2 test
integration from the preserved independent report, SHA-256
`8811b05540a10c7c51f3738c0d0fe2ff73efe73996f561381593572872943b5c`.
All five production files are byte-identical to stopped R3, including
output_bound.py `68122bad2258f181bd34c89f3287a04e4cf76615fd50b8045bf66e4826ac6239`.
Only the two test files and these two notes change. R3/report/actual repo remain
untouched; root performs independent review and any eventual mirror/CI.

All five affected actual helper-fault functions now install their global
acquire/release/OS patches inside monkeypatch.context() in the function body.
The contexts include their assertions and existing finally cleanup, restoring
the genuine helpers before pytest's call logreport even when assertions or
cleanup raise. Thread-dependent contexts retain the existing unblock/join and
known fixture-owned disposal before restoration. Alive/uncertain fixture
holders are not guessed closed; no production custody, hook order or output
accounting was weakened.

A new genuine TinyPytest populated contract imports the actual output-bound
test functions and invokes every affected parameter branch using the real
monkeypatch fixture and the unchanged actual partition plugin. It verifies
helper identities after each return. Its separate assertion branch corrupts
only the diagnostic returned from the real refusal, causing the actual fault
function's assertion to unwind its context into a real failed pytest call.
The negative requires child exit1, successful setup/teardown and log boundaries,
no output-refusal artifact, and refusal of completion by the real raw protocol;
the positive requires exit0 and full protocol acceptance. An actual autouse
yield fixture checks helper/diagnostic restoration at teardown. No dummy
replacement test population or copied production predicate substitutes for
the affected functions. These are authored contracts, not execution results.

Formal NOT_STARTED; final_start=null; C OFF. Source-only self-read and hashes
confirm the limited edit scope. NOT_RUN：工作機規則（POLICY work-machine-local），
未執行產品/import/AST/parser/compile/tests/native/helper/Git/API/EC/POST。
Native qualification, old-job initiating cause, replay authority, source
adoption, fit and whole q2 readiness are not established. STOP.

## Preserved R3 production rationale (historical delta against R2)

STOP proposal, no source adoption or execution result. This namespace preserves
the stopped diagnostic package and all actual failure records. It does not
diagnose the consumed shard-0 run: that receipt has no initiating refusal reason.
Formal NOT_STARTED; final_start=null; C OFF. Root is sole repo/Git/API/EC/mirror/
dispatch mutator; no source file outside this new package was edited.

## R3 exact ownership repair

Read the preserved R2 independent STOP report, raw SHA-256
`856021429dd0983befe8dbf5639bec1ca8f4fa479465e58b8917cbad60d7905d`.
Its B1 is a concrete source counterexample, not this old job's established cause.
In that preserved R3 cut only output_bound.py and its output contracts changed relative to R2; the other
five source/contract files are copied byte-for-byte. These two notes describe
the new package; R2 and actual product/frozen/declaration/receipts are untouched.

One _MutexCustody owns the actual threading.Lock, shared by the original entry
owner and every stage view. OutputBudget.mutex is a read-only reference to it.
Every charge registers a distinct _MutexAttempt retaining its exact owner and
shared custody before its one actual acquisition. Only that attempt's caller
changes its state/removes it after its own known not-attempted, False acquire or
None release outcome. No self-membership deduplication/removal remains.

An exception or invalid returned type from the actual acquire/release sets an
irreversible private uncertainty bit and retains the exact attempt/error. New
charge admissions refuse before another native call; a previously admitted
in-flight call can still return. Its own known False or known release retires
only itself. After a known True acquire it checks shared uncertainty before any
ledger work and releases only its own known acquisition. Final checking refuses
an otherwise normal return if another uncertainty is already observed. No
locked() result, another reader's success, alternate stage, release retry or
deadline is treated as resolving the retained unknown. There is no reset API.

Bookkeeping uses individual append/remove on the private list of exact objects
in the required CPython3.12 process, single-writer attempt state and one-way
shared uncertainty. It introduces no second blocking bookkeeping mutex or new
clock. Pending admission can overlap uncertainty observed by another caller;
it remains owned and gets the one in-flight outcome/independent known cleanup,
not permission to retry. This is not a free-threaded/other-interpreter promise.
Acquire remaining time is re-read from its original owner's absolute deadline
immediately before the actual call, without extending any deadline. Closed
diagnostics add MUTEX_CUSTODY_UNCONFIRMED/INVALID_MUTEX_ATTEMPT and distinguish
an invalid release result, never serializing the primary's message.

Contracts now inject faults at the actual acquire/release helper after a real
Lock take/release, retaining the original mutex identity. Same owner, another
stage and entry owner repeat refusals must leave calls, ledger and exact unknown
holder unchanged. Real interleaved threads test (a) a successful first call
while a second acquisition is pending, then a second take/throw, both for a
shared view and separate stage views; (b) an uncertain first release while a
previously admitted second call returns genuine False or True, with only its
own known cleanup and no extra ledger mutation. First-primary identity remains
checked through independent unlock/close/release errors. Fixture-only disposal
follows its actual take/release/join observations, never a production closure
inference or uncertainty reset. These contracts are authored, NOT_RUN.

## Actual bridge

Runner still uses the original entry Budget.timeout, existing phase cap and
reserves. Its allocated absolute deadline is the minimum of began+cap,
current original clock+original timeout and original entry deadline. It is
computed before sink opening/spawn, never recomputed as a new child allowance.

OutputBudget.for_stage creates an exact OutputBudget view only from the original
entry owner, with a closed stage and finite positive deadline at most that same
entry deadline. It shares the original ledger path, work/root, actual clock and
parent mutex; it does not construct/read/reset a ledger, counter or budget.
The root owner keeps its original entry deadline. A stage view cannot acquire a
later stage or extend itself. All its writer/charge/flush/close checks use that
allocated absolute deadline.

The very same stage owner goes into both parent sinks and PipeCapture. Runner's
actual spawn environment contains SL_OUTPUT_STAGE, SL_OUTPUT_STAGE_DEADLINE and
the unchanged SL_OUTPUT_DEADLINE. OutputBudget.child requires exact expected
stage, present finite environment deadlines and stage<=entry; missing/wrong/
late/NaN/inf context refuses before writer acquisition, without an entry-only
fallback. Focused guard supplies expected_stage=focused. Partition plugin binds
expected_stage=collection/partition to its validated collect/execute mode.
The child uses its process-local Python mutex with the same original native
ledger file lock. No cross-process Python-mutex sharing is claimed.

The ordinary entry/occurrence protocol, collection population, inventory schema
and source-stable configuration remain unchanged. Runtime stage deadlines are
not inserted in the shared ordered inventory. The actual received plugin source
digest must naturally be captured from the new product source when adopted.

## Lock progress and refusal

The 200 ms mutex/file-lock sublimits are removed. Mutex acquisition uses the
remaining time to that same original allocated deadline. Nonblocking file lock
retries only errno EACCES/EAGAIN until that deadline; other errors are raised
unchanged, not guessed contention or retried. Checks after acquire, ledger IO,
unlock/close/release and payload/flush/close prevent a late synchronous return
from succeeding. Failed/unknown acquire/release retains its exact attempt and
shared mutex custody; no guessed release/retry resolves it. Cleanup faults preserve the first
primary and fixed non-secret diagnostic. ENTRY_DEADLINE legacy messages for
effective writer deadlines use neutral OUTPUT_DEADLINE codes; actual stage and
absolute deadline are separate fields from the genuinely passed owner.

Taskkill uses original Budget.timeout(15, closing=True) and its separately
computed absolute deadline, with a child_cleanup view of the original ledger.
Parent reap uses the existing 5-second closing allowance bounded by original
remaining time and checks its actual returned value/time. Neither gets an
expired focused owner or changes its original child's deadline. Actual cleanup
return is recorded separately; it cannot turn an incomplete phase into success.
Final source/status still use the existing Runner.run(final=True) 15-second cap
and original reserve policy. Entry finalization keeps the original entry owner.

Popen returning after its allocated stage preserves the existing TimeoutExpired/
124 semantics with actual child_return_observed=false. Exact prefixes, actual
EOF, withheld incomplete hashes, primary identity and unknown-owner retention
remain. Native process creation, pipe reads and synchronous IO are not made
preemptible; checked late returns refuse, and outer 35 minutes remains the
existing hard workflow limit, not a fit guarantee.

## Contracts authored, not run

Original diagnostic/first-primary/partial-capture/genuine-JUnit/unlock-close
contracts remain. The new contracts call actual production helpers for shared
owner/counter conservation; invalid/subsequent/extended stage; actual parent
handoff; child missing/wrong/nonfinite/late context; malformed cap; late acquire/
flush; unknown mutex ownership; and expired focus with independent cleanup.
Real thread plus real native file-lock fixtures exercise success after >200 ms
and original stage expiry; these use the active Windows msvcrt or POSIX flock
branch on the eventual pool/source-CI host, not a fabricated successful kernel
result. Existing tiny pytest subprocess fixtures now receive actual allocated
stage fields, and real plugins reject wrong roles/modes/expiry. Tiny inputs
remain under pytest temporary directories outside the product population.

Fixture cleanup only disposes precisely known synthetic BytesIO/real Lock test
objects. It is not a production native-closure repair. Source CI/native Windows
qualification have not happened for this candidate. No future source, run,
capacity PASS, grant, human click or replay is invented.

Unchanged: 256 MiB attempted aggregate, 64 opens, separate 64 KiB refusal slot,
per-file caps, no refund, entry1800/platform35, eight-wheel lock, runner choice,
declaration D, frozen209 material and top attributes. Physical test/temp/venv/EC
copies, host loss, synchronous blocking and native descendant closure remain
explicit residuals. Actual main completion still requires existing complete
phases/raw terminal/native exit0/elapsed<=1800 and four fresh reconciled receipts
for full Windows. Stage/diagnostic fields do not grant completion.

Official documentation only was read to check API semantics, without API/native
probes: Python 3.12 describes monotonic as system-wide, supporting transport of
an absolute value between these same-host processes; its reference epoch is not
wall time. [Python time](https://docs.python.org/3.12/library/time.html#time.monotonic).
The selected nonblocking Windows operation reports locking violations through
EACCES; invalid descriptor/argument errors are separate.
[Microsoft _locking](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/locking?view=msvc-170).
POSIX nonblocking lock documentation identifies EACCES/EAGAIN for contention.
[Python fcntl](https://docs.python.org/3.12/library/fcntl.html).
These documentation facts are not fresh host observations or qualification.

Original anchors: diagnostic output_bound `2d5027015f7a914d01c622a913788d901de1c0e31a8dda2b7283515c8427036f`,
pipe `4596109276237966ccc9e43f48219866a34b96076369b9dcfff7e336eac872d0`,
Runner `9194699ef8e55d82bc70288aafbf7026168944e13dc61b013214126e929bc9e7`,
output contracts `b8ec707bb6cdee54c31b3957be01d9a69a4000e1afeb2d802ad9674d690df38a`.
Actual P2 focused caller `6d572c9560934e5c961c35a2033576f1bd210069e147d4a74b1a4c2c34245b02`,
partition caller `e8b919f5e0308ead84e6b732e8915ba55257b1ea319bf64e7bf587dbf1801646`,
protocol contracts `d6af8eddaad22031710dba5ea5eea80121dd85f053f2ed9d928b01dbb0f85877`.

NOT_RUN：工作機規則（POLICY work-machine-local），只讀與新 source 編輯；
未執行產品/import/AST/parser/compile/tests/native/helper/Git/API/EC/POST。
Independent source readback and actual pool checks remain pending. STOP.


# R4 complete dependency map — not adopted

| Package file | Eventual product target |
| --- | --- |
| output_bound.py | workloads/m12_adjudication_verify/output_bound.py |
| pipe_capture.py | workloads/m12_adjudication_verify/pipe_capture.py |
| bounded_runner.py | workloads/m12_adjudication_verify/bounded_runner.py |
| pytest_outcome_guard.py | workloads/m12_adjudication_verify/pytest_outcome_guard.py |
| pytest_partition.py | workloads/m12_adjudication_verify/pytest_partition.py |
| test_windows_output_bound.py | tests/unit/test_windows_output_bound.py |
| test_windows_partition_protocol.py | tests/unit/test_windows_partition_protocol.py |

Seven complete source/contract files plus these two notes form one coherent
proposal, copied from the preserved nine-file R3 STOP. Only the two test files
and these notes change for B2: body-scoped fault patches and genuine populated
TinyPytest normal/assertion-failure call/teardown coverage. All five production
files remain byte-identical to R3. Their exact raw anchors:

| Unchanged coupled file | SHA-256 |
| --- | --- |
| output_bound.py | 68122bad2258f181bd34c89f3287a04e4cf76615fd50b8045bf66e4826ac6239 |
| pipe_capture.py | 2a4b7d25d90f32341697c59f81618f59a6e3af341e34d78494f318fb919c5006 |
| bounded_runner.py | 5182f909403ca22a2e34ba108102358892b8a74f2ffd45f315f6ecc7eeb55052 |
| pytest_outcome_guard.py | d549ac9e7f85f35c76ea2fc9731ca5d6da33bec545c00c50d2fa777827e779d1 |
| pytest_partition.py | bf43f5f0b62579c2ce7256932313eb21b4db849ddc28c239747317fe6a61d863 |

| Changed test file | R4 SHA-256 |
| --- | --- |
| test_windows_output_bound.py | f400cdb278f0c57e5766013e5592d31d74a2f269dc234e76bacf125f0cdd27ce |
| test_windows_partition_protocol.py | 60223c2665c72cf2bb2ebe3ccf420cbeb80bf5b17bae87aa60add8b2e58839c3 |

Child expected role remains bound to source mode, not an environment assertion.
No provider/importer/workflow/entry Budget/occurrence protocol/declaration/frozen
asset is changed. No worktree source was edited or source/CI/dispatch adopted.
Preserved R3 production charge retains exact pending attempts; no other caller relies
on the old private _UNCLOSED_MUTEX owner-list shape. Its output fault fixtures
use the actual helper seams while preserving original real Lock identity.
Those seam patches are now scoped inside each test body, including finally
cleanup, before actual plugin call-report output. Plugin hooks are unchanged.

Caller closure: partitioned.Runner.run supplies each actual allocated absolute
stage; its parent sinks and actual Popen env get the same view/deadline. The
focused caller consumes only focused; the partition caller consumes the real
collect/execute counterpart. Taskkill uses its own child_cleanup closing view;
final source/status use the existing final=True budget. Base finalization remains
entry-wide. Record stage fields come from the actual view, with no fallback to
an unvalidated name on acquisition failure.

Tests import eventual product modules; the flat proposal directory is not an
alternative runnable route. Root must mirror/review these coupled files together
and obtain actual source CI and separately permitted accounted pool evidence.
This map grants no deployment/dispatch, retries, fit or completed qualification.

Original consumed failure and stopped later shards remain unchanged. Formal
NOT_STARTED; final_start=null; C OFF. NOT_RUN under work-machine-local. STOP.

## R5: preserve the first observed reader refusal through closure

Actual PR51 R4 source CI37396312113/1 fast112053008445 failed1/1415pass727.96s. The separate full job passed its catalog gate. PipeCapture.finish previously initialized a new primary after the reader had already recorded FILE_CAP, allowing a later unknown resource close to replace it. R5 adopts the recorded first error before later cleanup errors and after actual joins, retaining independent cleanup and every unknown owner. The original identity/diagnostic/prefix/terminal assertions remain; new Event-controlled actual-thread contracts cover refusal during join and later join failure. Only pipe_capture and output tests change. Original failed CI and R1-R4 sources remain preserved. Root independent source review found no narrow blocker. Fresh exact-source CI and Windows qualification remain pending. Formal NOT_STARTED, final_start=null, C OFF.
