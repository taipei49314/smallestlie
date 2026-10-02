# Independent evidence sources (M12 D source subcut)

`EcReceiptStore`, `EcExecutionAuthority`, `EcVerifierAuthority` and
`GitHubReviewAuthority` implement the existing retrieval boundaries. They have
no CLI activation, root discovery, default repository or local-file fallback.
The legacy v2 campaign gate remains closed. This change does **not** implement
an outer collector, formal orchestration, ledger integration or evidence replay.

The trusted integration process configures all roots outside the product,
fixture workspace and replay bundle. Arbitrary Python callers remain a trust
boundary. Configuration constructors cannot authenticate their own caller or
make an untrusted process into a trusted collector. Never construct grants by
reading `approved`, producer `passed`, `ec_task DONE`, a digest or an allowed
GitHub account from product-written data.

## Immutable EC publication and dispatch

`EcReceiptTrustRoot` names an independent EC repository and numeric ID, exact
workflow ID/path/bytes, destination branch, numeric runner ID/name, measured
host/generation, job name, workload/declaration hash, outer collector path/bytes,
and verifier runtime/environment contract. `EcPublicationGrant` binds one
externally accepted publication to the exact formal request digest, lock,
product source, EC source, run ID/attempt, **numeric job ID**, receipt commit,
publication bytes and acceptance reference. It is not discovered from a branch
or publication body. One request/lock has one publication; a rerun requires a
new bounded request, not replacement of an old reservation.

The store reads the exact GitHub run attempt and job independently, verifies
numeric identities without accepting bools, repository identity, workflow/source,
runner and terminal status, then checks the workflow and collector blobs at the
exact EC source. These source pins establish code identity, not proof that it
was actually launched. Publication context and `ec-workload.json` must agree
with the configured source/dispatch/workload/host/generation/declaration.
`GITHUB_JOB` remains a job name and cannot substitute for the numeric job ID.

Raw receipt traversal uses exact Git objects, nonrecursive complete trees,
regular blobs and Git SHA-1/size verification. Every publication inventory item
must have exact size/SHA-256 and the inventory must cover every blob except the
publication itself. Bytes are never newline-normalized or UTF-8-replaced.
Links/submodules, truncated or empty trees, duplicate/case aliases, reserved
Windows paths, excessive depth/files/total bytes and missing artifacts fail
closed. Limits: 256 files, 64 trees, depth 32, 10 MB per blob and 50 MB total.
Production transport is GET-only at the fixed GitHub origin, bounded and
redirect-rejecting. No branch/latest lookup or execution is performed.

## Accepted outer supervisor, not generic job success

A raw publication grant alone can read bytes but cannot mint an execution or
verifier envelope. It additionally needs **both** an exact
`supervisor_sha256` and a distinct `supervisor_acceptance_ref`, supplied only by
the external trusted process after accepting the actual outer collector's
measurement, isolation and output-completion contract. Computing an artifact
hash or observing a successful job is not that acceptance. No real acceptance
registry or formal W3 supervisor artifact is introduced in this PR.

The reserved `m12-supervisor.json` contract is
`smallestlie.outer-supervisor/v1`. It binds the full formal request/lock,
actually launched collector, independent dispatch and observed persisted lock
sequence. It preserves every frozen case once, with canonical case bindings;
missing runner/verifier records remain unknown. Every recorded command sequence
is a distinct integer after the lock, including commands in different cases.
The future collector must measure these facts durably before launch and must
not give a crashed reservation to a retry.

Each runner record points to the immutable receipt and independently measured
arm observations, command sequences, native termination/exit, complete outputs
and reaped descendants. Observations must match the raw receipt, and all raw
stdout/stderr/native-report references must exist in the publication. Existing
runner validation then checks frozen fixtures/config, runtime/dependencies/env,
argv/cwd, native assertion red, attack/twin green and repair calibration. A green
outer job does not imply any arm is green. An accepted failed outer job may
still contain valid completed arm captures. Missing/incomplete facts stay
unknown; an actual baseline already green can refute a DEF and retain its kill.

Each verifier record independently binds actual complete baseline/attack
file maps, published engine artifact, observed interpreter/runtime/environment,
absolute workspace/argv/cwd, resolved Git commits, native disposition and raw
metadata/stdout/stderr. `logical_cwd="."` is kept separate from the measured
absolute cwd; changing a metadata label alone cannot satisfy the source.
Canonical file-map digests are not Git tree object IDs or EC inventory hashes.
The external accepted collector must measure raw Git tree bytes and actual
launched artifacts; expected values copied from a profile do not meet that
contract.

Initial effective-policy support is deliberately bounded to an actual complete
baseline tree with no `.checkwash` or `.greenwash` policy directory. The pinned
v0.5.0 [config source](https://github.com/taipei49314/checkwash/blob/24b60a2019a5900291ecb35ab8290f34af2d5438/src/checkwash/config.py)
uses `high` by default and reads base-side policy files; the pinned
[allowlist source](https://github.com/taipei49314/checkwash/blob/24b60a2019a5900291ecb35ab8290f34af2d5438/src/checkwash/allowlist.py)
uses no exemptions when absent. The provider requires those defaults and no
native allowlisted findings. Any policy directory remains unknown until a
resolver for actual baseline config/allowlist/precedence is implemented. Native
metadata/findings cannot pick their own effective policy.

## Separate post-run semantic approval

`GovernanceTrustRoot.reviews` explicitly configures a review repository/account
role, independent of the product. It can use the same governance repository as
requests, but the review role and exact grants are separately required. A
merged request or allowed GitHub `User` cannot imply review approval.

`PostRunReviewGrant` comes from the trusted human-input/governance process and
binds its approved PR/path, formal request, lock, case, review bytes, actual
observation-digest mapping and independent semantic approval reference. The
store also requires the exact human merge registry entry and exact changed blob
at the approved merge. A grant attests the human-approved complete-source,
case-specific theater/residual/scope and near-shape judgment; caller-supplied
reviewer names and YAML hypotheses cannot create it.

`GitHubReviewAuthority` retrieves those exact bytes and rejects context or
observation substitution. `validate_case_review()` still independently checks
current actual observation digests, complete pinned documents, citations,
residual-row coverage, frozen diff and declared twin contrast. Approval cannot
skip these checks. `adjudicate_campaign()` retains the complete denominator and
performs pair qualification only after both cases have their own observations.

## Validation and remaining work

New tests use synthetic API transports, exact fake grants and native XML/JSON
fixtures; they mint no real approval and make no network requests. They cover
raw bytes/inventory, wrong source/run/attempt/numeric job/runner/role, incomplete
supervisor facts, sequence reuse, metadata/policy substitution, a real synthetic
kill, missing-case retention and full pair adjudication with independent sources.

NOT_RUN: POLICY work-machine-local; product execution, pytest/collection,
compile/lint/typecheck/build/install are not run on this work machine. A new
exact-source pool grant is required; prior one-dispatch grants are consumed.
The accepted `m12-adjudication-verify` declaration/payload/uv.lock is unchanged.

The first authorized pool run at source
`4fa85aa96100793c9d2c9d1e2912adff5f3ea54d` was
`36988167830/1`, immutable receipt
`10b7dd868ba5e852d0e3187d2ba6ed882283ecca`. Native focused XML has
222 tests with no failures/errors/skips; full XML has 616 tests, two failures,
no errors/skips. Both failing assertions expected `ProvenanceError`, while the
shared strict integer guard correctly rejected bool values with its parent
`PreregistrationError`. The assertions now check that error and its field-specific
message; production validation and fail-closed behavior are unchanged. The failed
run remains recorded. Read-only follow-up also checks the later assertion that
was not reached after the bool job-ID failure: a missing supervisor acceptance
reference is rejected by the shared nonempty-string guard with `DeclarationError`,
so that assertion now checks this type and its field-specific message. This is
an additional static diagnosis, not a third observed pool failure. These
corrections have not been executed locally or in the
pool; a new exact-source one-dispatch grant is required before merge.

Remaining D: implement/adopt the trustworthy outer collector and actual policy
resolver; version formal ledger reservations/evidence/review/adjudication
bindings; formal campaign entry; reports and evidence-only replay with renewed
source authority; actual Phase 1/2 and separately authorized W3 execution.

The subsequent [formal lifecycle subcut](campaign-lifecycle.md) supplies the
versioned recording and evidence-only revalidation contract. Its new
reservation-aware `CompletionAuthority` is a separate external boundary;
these existing `outer-supervisor/v1` providers cannot authenticate that ticket.
It introduces no accepted production collector or formal launch entry point.
