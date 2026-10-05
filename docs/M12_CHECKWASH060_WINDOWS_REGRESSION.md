# Checkwash 0.6.0 Windows regression partitions

SOURCE_ONLY / NOT_RUN: this protocol has not yet been qualified or dispatched.
Local verification remains `NOT_RUN：工作機規則（POLICY work-machine-local），source editing only`.

The previous HOST50 attempt `37357652775/1`, product
`7db15f04574d4b10821db96aac7040396a4291ff`, failed. Its immutable receipt commit
is `da33d6b894202c4d97f2f1176e3aaa209393c7e8`. Focused JUnit recorded 222 tests
with no failures/errors/skips. The full subprocess recorded exit 124, timeout
true and 1600.109 seconds, with no full.xml. The incomplete full observation
remains a failure. Its focused result and the separate Ubuntu CI result do not
establish the complete Windows denominator.

`m12-adjudication-verify` now requires one string parameter, `shard`, exactly
`0`, `1`, `2` or `3`, with no default. This changed declaration and its new exact
source require actual admission and accounting before any dispatch. Four jobs
run serially on the same reviewed product/EC sources and HOST50 generation,
once per explicitly named parameter. There is no automatic retry or alternate
source/attempt fallback. A failure or changed generation stops the series.

Each entry retains the original eight lock-hashed Windows wheels and the same
five focused paths. A focused outcome guard also retains final raw phase
outcomes and a terminal handshake: a non-strict xpass can have exit zero and no
JUnit failure/skip, so XML counts alone cannot qualify that diagnostic phase.
The entry performs real `pytest --collect-only tests`, preserving
the complete ordered nodeid inventory with zero-based ordinal and same-nodeid
occurrence. Inventory bytes include stable source/plugin/lock/version/config
facts and omit per-run paths, timestamps, native IDs and shard. Each execution
recollects the complete tests population and compares the inventory bytes before
partitioning by `int(SHA256(nodeid UTF-8), 16) mod 4`. Duplicate occurrences stay
in the same shard and retain separate identities. Additional selectors or other
deselection are refused, including `-k`, `-m`, `--ignore` and `--deselect`.

The explicitly loaded pytest plugin writes assignment and terminal handshakes,
plus each occurrence's actual logstart, setup/call/teardown outcomes, logfinish
and the final session-end record. Exact ordered boundaries and matching nodeid/
location pairs are required; an extra or missing invocation boundary refuses.
The plugin attaches identities
to actual pytest reports; pytest writes the genuine JUnit. The harness requires
exit zero, nonempty JUnit, exact selected occurrence coverage, all three phases
passed, and zero failures/errors/skips/xfail/xpass. Missing plugin, collection
error/empty/drift, partial XML/phase stream, unknown or duplicate identity, or
timeout cannot produce `partition_complete`. Raw stdout/stderr go directly to
files, retaining prefixes on interruption. No synthetic success XML is written.
Bounded inventory/handshake reads cap at 32 MiB, phase streams and JUnit at 64 MiB;
exceeding those bounds is an incomplete observation, not a reduced denominator.

One monotonic 1800-second deadline starts at entry invocation. Venv creation,
wheel installation, focused tests (300 seconds), collection (120 seconds), and
partition tests (at most the previous 1600 seconds) share that deadline. Every
new child reserves 20 seconds for bounded close, plus 120 seconds for final
source/status/result handling. Cleanup and final checks use the same remaining
deadline. The existing EC workflow remains hard limited to 35 minutes. Checkout
and preparation occur before this entry origin: nominal 300-second outer
headroom is conditional, not a fit guarantee or a trusted workflow-start clock.
Native creation and synchronous file IO can block independently of Python's
monotonic checks; an outer termination still leaves the partition incomplete.

Children receive an allowlist of OS environment necessities and fixed Python/
Git controls. App keys, tokens, Actions file commands, inherited Python startup
and pytest overrides are absent. The workload never imports the unchanged
shared regression harness or executes formal W3 lifecycle/cases/collector.

Once the trusted pool/output identity is established, input acquisition failures
have structured incomplete results. Exactly received parameter/lock/plugin
bytes are retained. A bounded oversized prefix has a received-prefix digest
only; missing or unreceived whole-file digests remain null. Invalid parameters,
missing/changed lock or missing plugin start no setup/pytest. Error records use
bounded error types, not exception messages or parameter values. Initial/final
source/status observations remain null wherever they were not obtained.

Internal result/summary records `phase_checks_complete` and keeps
`partition_complete: false`, with `full_windows_verdict: NOT_ESTABLISHED`.
The retained provisional epoch also makes no completion claim. `terminal.json`
binds the exact result/summary/provisional digests and states a closed predicate:
phase checks and readiness must hold, all refusal artifacts must be absent, and
the independent native EC wrapper must actually exit zero with elapsed <=1800
seconds. Source fields or App labels cannot replace that native observation.
Each final write is followed by the same deadline check; a write that crosses
the deadline returns nonzero and attempts the separate fixed CreateNew
`output-refusal.json` slot. Normal payload writes keep the same deadline, so
late refusal must not promise another backup, `late-refusal.json`, or result
replacement. Already-written provisional, pending result, summary and terminal
bytes remain intact; the native nonzero exit and present refusal make terminal
acceptance false. An unavailable output filesystem also
returns nonzero; its missing closure is not a success. The final synchronous
write or the interval until native return cannot self-authenticate, so actual
wrapper exit/elapsed remain necessary even with a readiness marker.

Complete Windows acceptance requires a
separate read-only reconciliation of four fresh immutable receipt graphs and
their actual terminal native jobs. That review checks exact sources/declaration/
parameters/HOST50/generation, identical original inventories, four disjoint
selected occurrence populations whose union equals the complete inventory, and
matching genuine JUnit plus raw phases. Four counts or four App checks alone do
not establish that fact. Source review and hosted synthetic CI do not replace
the Windows observations. Formal W3 remains separately gated by human review.
