# Adapter design & M0 plan: Checkwash (the real engine)

**Document type:** Real-repository adapter — **brand-new M0 plan (executed)**
**Status:** `M1_EXECUTED` — M0 signed and closed (D-1..D-4). M1 beyond-taxonomy wave frozen and executed 2026-09-02 (human go: 「下刀smallestlie」). Logs: [`CHECKWASH_CAMPAIGN.md`](CHECKWASH_CAMPAIGN.md) (wave0) + [`CHECKWASH_M1.md`](CHECKWASH_M1.md) (wave1).
**Adapter id:** `checkwash`
**Plan version:** 0.1.0
**Target repo:** `taipei49314/checkwash` (owned, local observation; never mutated by this line)
**Observed HEAD (at planning):** `50e969fdbbe169284b380c7f544c8afcd5990cdf` — `v0.2.8` (2026-09-02 01:36 +0800)
**Engine artifact (M0.1, pinned):** `verifiers/checkwash.pyz` — SHA-256 `83878db57a243386a10fa49b3f4a2d4d2863c808f7b2f77a516e35c99b3338ea`
**SmallestLie baseline:** v0.7.1 @ `4485c6b`
**Campaign coordination:** estate-consolidation LEDGER **T-11** (plan, DONE) + **T-12** (execution)
**Supersedes:** [`greenwash.md`](greenwash.md) **for the real-engine line only.** The synthetic-SUT campaigns it records remain valid history.

### Human decisions (recorded 2026-09-02)

| # | Decision | Ruling |
|---|---|---|
| D-1 | Approve M0 plan + sign M0.1 authorization | **Approved and signed** (this document + `verifiers/README.md` provenance + fixture auto-authorization) |
| D-2 | Engine delivery | **`.pyz` vendored at `verifiers/checkwash.pyz`**, SHA-pinned above |
| D-3 | Does this line count as checkwash's "second independent user"? | **No** — red-team harness ≠ product user; release freeze unaffected |
| D-4 | If a false acceptance is observed | **Issue on checkwash only; no fix PRs** (per its AGENTS.md) |

---

## 0. Why a brand-new M0 (and not a patch)

The `greenwash` adapter (2026-08-10) was designed against a **guessed product**:
an auditor that consumes CI artifact bundles (junit, coverage, policy.yaml).
The real engine — renamed greenwash → **checkwash** on 2026-08-29 — is a
different instrument on every axis that matters:

| Axis | greenwash.md assumed | Real checkwash v0.2.8 (observed) |
|---|---|---|
| Input | artifact bundle on disk | a **git range** (`BASE..HEAD` / `BASE...HEAD`) |
| Method | bundle policy check | diff → IR → 21 detectors → frozen strength lattice → gating |
| Output | clean / theater / blocked | findings JSON + exit `0` pass / `1` block / `2` engine error |
| Runtime | assumed deps | **zero runtime deps**, Python 3.11+, offline, never executes reviewed code |

The adapter contract, the attack surface, the oracle, and the fixtures are all
wrong-shaped. On top of that, the rename broke identity: nothing in this repo
references `checkwash` and nothing in checkwash references us. Patching the old
adapter would preserve neither code nor assumptions worth keeping. **Restart as
M0.** What carries over is the host, not the target: campaign engine, mutation
kernel, disposable workspaces, ledger, meters, `ddmin` minimizer, language rule.

Positioning, updated:

```text
checkwash:   did this diff weaken the test oracle without a real fix?
smallestlie: what is the smallest weakening that checkwash still accepts?
```

checkwash measures itself from the inside (benchmarks, decoy arms, sweeps).
SmallestLie is the external, independent falsifier for the same claim.

## 1. Observation record (M0.0 — recorded at planning time)

Pinned from the observed checkout; this section **is** the G0 stop-rule record.
No adapter may be implemented against any contract not written here.

| Item | Observed |
|---|---|
| Version / pin | `v0.2.8` @ `50e969f` (release-frozen — a **stable** SUT by decree, see §6) |
| CLI surface used | `checkwash check HEAD~1..HEAD --format json` (also `demo`, `sweep`; not needed for M0) |
| Exit codes (SPEC §9, frozen) | `0` = no finding at/above `fail_on` (default `high`); `1` = verdict block; `2` = engine error (all crash paths map to 2) |
| JSON payload | `checkwash_findings_version`, `run{base,head,checkwash_version}`, `findings[]`, `summary{critical,high,warn,info}`, `skipped_files`, `config_errors`, `verdict` |
| Determinism | sorted keys, no timestamps, LF only (SPEC §8) — replay-friendly |
| Environment | Python ≥3.11, git present, zero runtime deps, no network, no LLM |
| Claimed coverage | 21 detectors behind frozen rule IDs (SPEC §4); 535 tests; FP 1.50% in-sample / 1.65% out-of-sample (published harness numbers, not ours) |

**Engine delivery for campaigns:** the v0.2.8 single-file `checkwash.pyz`
release artifact, pinned by SHA-256 in the authorization package. One file,
zero deps, runs offline. Setup fetch is a separate, human-authorized network
step; campaigns themselves stay network-denied. (Fallback if the human prefers
a clone: local checkout at `50e969f`, `python -m checkwash`. Either way the
adapter preflight verifies version and pin before any attack runs.)

## 2. M0 goal (one sentence)

**Prove the wiring**: in a disposable git-backed workspace, apply a
theater-by-construction mutation as a commit, run real checkwash v0.2.8 pinned,
record a deterministic verdict, replay it — offline, with the honest controls
both directions.

Nothing in M0 claims anything about checkwash's security (language rule).

## 3. Non-goals (M0)

- **No blind-spot hunting.** Wave0 seeds only from checkwash's own published
  taxonomy. Whatever verdict falls out is *recorded*, not interpreted. Probing
  beyond the 21 detectors is M1.
- No JS/TS frontend attacks (T3.1 surface), no multi-language.
- No corpus scale, no fuzzing, no performance attacks, no `ddmin` runs.
- **Zero writes to the checkwash repo.** Release freeze and its AGENTS.md
  read-only zones are respected; findings (if any) are filed as issues only.
- No new repositories (estate campaign M4). All work lands in this repo.
- No external publication of any result. Campaign-bounded observation only.

## 4. The core engineering problem: mutations must become commits

`DisposableWorkspace` copies the source tree with `.git` **excluded** — but
checkwash reads a git range. M0 builds a **git-materializing workspace**:

1. Copy fixture tree as today (`.git` still excluded — no inherited history surprises).
2. `git init` + baseline commit with **fixed identity and timestamps**
   (`smallestlie-campaign <campaign@smallestlie.local>`, `GIT_AUTHOR_DATE` /
   `GIT_COMMITTER_DATE` derived from the seed) so diffs are byte-stable.
3. Apply mutations, commit as `HEAD` with the same discipline.
4. Adapter runs `checkwash check HEAD~1..HEAD --format json` inside the workspace.

Determinism is the acceptance criterion, not a nicety: same seed → same commits
→ same diff → same verdict (checkwash SPEC §8 does its part; we must do ours).
`git` presence becomes a doctor/preflight check.

### Verdict mapping

| checkwash | SmallestLie verdict |
|---|---|
| exit `0`, no blocking finding | target accepted → compare against oracle (theater-by-construction + accepted = `FALSE_ACCEPT_OBSERVED`) |
| exit `1` (block) | `ATTACK_REJECTED` — the lie was caught |
| exit `2` (engine error) | `HARNESS_ERROR` — never a target verdict |
| unparsable output / timeout | `HARNESS_ERROR` |

## 5. Phases (pre-registered; each ends with a commit and evidence)

| Phase | Deliverable | Gate to next |
|---|---|---|
| **M0.0** Observation record | This document §1 (done at planning); SHA-256 of the chosen engine artifact recorded when fetched | Human approves plan |
| **M0.1** Authorization package | Template filled for checkwash: `owned_local_repo`, network denied, expiry, adapter pin `50e969f` | **Human signature** |
| **M0.2** Git-materializing workspace + `checkwash` adapter | `sandbox` opt-in git mode; `adapters/checkwash.py` + registry entry; command allowlist (`checkwash.pyz check HEAD~1..HEAD --format json`, cwd=workspace); preflight pins version+sha; `parse_verdict` per §4 | unit tests green, determinism 3× |
| **M0.3** Fixture target + catalog `checkwash-wave0` | `fixtures/checkwash_target` (small Python repo: prod module + tests, minimal git-able tree); `attacks/checkwash/CW-W0-*.yaml` seeded 1:1 from checkwash's frozen rule IDs (see below); honest-fix control; `fixtures/checkwash_blind` positive-control stand-in (trivially clean-verdict engine) | catalog schema-valid; attacks theater-by-construction |
| **M0.4** Campaign + wiring | Campaign run (seed 49314), ledger, markdown report, regression fixtures for every verdict; ci-gate/nightly entry; README + `greenwash.md` supersede pointers | M0 exit criteria §7 |

**Wave0 attack seeds** (one per family checkwash *claims* to catch — expected
`ATTACK_REJECTED`; any `FALSE_ACCEPT_OBSERVED` is a recorded finding and an
issue on checkwash, nothing more):

- `CW-W0-01` assertion weakened (`== 105.3` → `> 0`) — ASSERT_WEAKENED
- `CW-W0-02` tolerance loosened (`abs(x-y) <= 1e-9` → `1e-3`) — TOLERANCE_LOOSENED
- `CW-W0-03` expectation hardcoded to the buggy value — EXPECTED_VALUE_HARDCODED
- `CW-W0-04` test disabled (`pytest.mark.skip`) — TEST_DISABLED
- `CW-W0-05` expectation constant edited in place — EXPECTED_VALUE_CHANGED
- `CW-W0-06` failing assert deleted — ASSERT_REMOVED
- `CW-W0-07` CI workflow step stops failing (`.github/workflows/*.yml`) — CI surface
- `CW-W0-08` assertion swapped for an unrelated same-strength one — ASSERT_SUBSTITUTED
- `CW-W0-CTL` **honest fix**: production bug fixed, test legitimately updated → expected `TRUE_ACCEPT` (mirrors checkwash's own demo control; proves our mapping is not "always block")

Every attack is theater-by-construction (we authored the mutation; ground truth
is declared, not inferred) — the oracle is the attack's own declaration, never
the target's verdict.

## 6. Known frictions, handled up front

1. **Release freeze is an asset.** checkwash v0.2.8 is frozen until the human
   lifts it, so the SUT pin cannot drift mid-campaign.
2. **"Second independent user" question.** The freeze lifts on a second
   independent user *or* human decree. **Recommendation: a red-team harness is
   not a product user** — this line does not claim that status. Human decides.
3. **Two-machine protocol.** T-11 is claimed in the campaign LEDGER; all work
   on this line is atomic commit + push; the other machine may take over only
   via the ledger.
4. **checkwash is actively developed** (docs merge landed 2026-09-02). We pin;
   we do not chase HEAD. Re-pin is a conscious, human-visible step.
5. **checkwash dogfoods as a required check on its own repo.** Any issue we
   file about a false acceptance will be judged by checkwash on itself —
   poetic, but also exactly the kind of recursion this ecosystem enjoys.

## 7. M0 exit criteria (all must hold)

1. Every wave0 attack (01–08 + CTL) has a recorded verdict; `ledger verify` passes.
2. Determinism: 3 replays, same seed → identical verdicts and ledger hashes.
3. Positive control: `checkwash_blind` stand-in shows `FALSE_ACCEPT_OBSERVED`
   on ≥1 wave0 attack (proves the harness can catch a lying-clean engine).
4. Honest-fix control: `TRUE_ACCEPT_OBSERVED` on `CW-W0-CTL`.
5. Fixture sources byte-identical after all campaigns (existing invariant).
6. Network denied and honored throughout; campaigns run fully offline.
7. Zero commits to the checkwash repo; zero new repositories.
8. No output anywhere claims SECURE/UNHACKABLE/NO VULNERABILITIES (language rule).

## 8. What M1 would be (preview; frozen as §11)

- Systematic false-negative probes **outside** the 21 detectors, then `ddmin`
  minimization of any survivor ("the smallest lie checkwash still accepts").
- Cross-check survivors against checkwash's published `benchmarks/FAILURES.md`
  to separate known limitation from new finding before filing anything.
- Direction note: checkwash's STATE.md publicly tracks its *false-positive*
  residuals (e.g. the nested-lexical-scope binding family). Those are its own
  internal concern; this line hunts the complement — false acceptances.

## 9. Human decision points (blocking)

| # | Decision | Recommendation |
|---|---|---|
| D-1 | Approve this M0 plan and sign the M0.1 authorization package | as written |
| D-2 | Engine delivery: pinned `checkwash.pyz` (v0.2.8 release artifact) vs pinned local clone at `50e969f` | `.pyz` — one file, hash-pinned, offline |
| D-3 | Does this line count as checkwash's "second independent user" (freeze-lift condition)? | No — red-team harness ≠ product user |
| D-4 | If wave0 produces a false acceptance: file issue on checkwash only (no fix PRs) | issue-only, per its AGENTS.md |

## 10. M0 outcome (2026-09-02, executed)

All eight exit criteria from §7 met — with one *finding*, recorded honestly:

| # | Criterion | Result |
|---|---|---|
| 1 | All wave0 verdicts recorded, ledger verifies | ✅ 9/9, `ledger_ok` |
| 2 | Determinism, 3 replays identical | ✅ byte-identical verdict tables |
| 3 | Blind positive control false-accepts | ✅ 8/8, replays stable |
| 4 | Honest-fix control true-accepts | ✅ `TRUE_ACCEPT_OBSERVED` |
| 5 | Fixture sources byte-identical | ✅ `source_immutable` all runs |
| 6 | Offline, network denied | ✅ zero network calls |
| 7 | Zero commits to checkwash repo, zero new repos | ✅ ([issue #60](https://github.com/taipei49314/checkwash/issues/60) filed per D-4, no code) |
| 8 | No SECURE-type claims | ✅ language rule held |

**The finding:** CW-W0-03 (reference-derived expectation replaced by a
literal matching the buggy output) is **accepted by checkwash v0.2.8** —
`FALSE_ACCEPT_OBSERVED`, stably replayed. The other seven seeded attacks were
rejected. Full evidence: [`CHECKWASH_CAMPAIGN.md`](CHECKWASH_CAMPAIGN.md).

Also fixed en route (named defect, separate commit): Windows `rmtree` could
not remove read-only git loose objects (`WinError 5`), which used to kill
false-accept replay processing.

**M1 gate:** human go recorded 2026-09-02（「下刀smallestlie」）. Frozen table: §11.

## 11. M1 — beyond-taxonomy probes (frozen 2026-09-02)

Human go: 「下刀smallestlie」. Pin still checkwash **v0.2.8** / pyz SHA above.
Wave0 catalog is not modified. D-1..D-4 still bind (issue-only, no checkwash
code, not a second user, network denied).

**Not in M1:** new detectors, checkwash PRs, live `campaign` as a tripwire Stop
gate, probing JS/TS, corpus scale.

### 11.1 Attack seeds (theater-by-construction; outside claimed live defence)

| ID | Shape | Classification source |
|---|---|---|
| `CW-W1-54` | Existing skip-guard `if sys.version_info < (3, 0)` flipped to `if True` | FAILURES.md **#54** open — no defence |
| `CW-W1-77` | `.ps1` runner that invoked pytest now `exit 0` | FAILURES.md **#77** open — no defence |
| `CW-W1-86a` | Unit-local `expected = EXPECTED_TOTAL` rewritten to `100.0`; assertion line byte-identical | FAILURES.md **#86a** narrowed, still open |
| `CW-W1-93` | Expectation freeze (`EXPECTED_TOTAL = 100.0`) escorted by alpha-rename of `invoice_total` → `invoice_subtotal` (alias in tests) | FAILURES.md **#93** narrowed, still open |
| `CW-W1-2HOP` | Two-hop subject wrap (`got` / `step` / `abs(step)`) | SPEC `SUBJECT_NORMALIZED` stated residual (two hops) |
| `CW-W1-91H` | Helper still holds the assert; the test stops calling it (`pass`) | FAILURES.md **#91** closed in part |
| `CW-W1-TWIN` | Replace `reference_total` with a same-bug twin (`src/twin.py`, unused at baseline) | **Not** in FAILURES.md — candidate new finding if accepted |

Every FA is classified as: **published hole** / **stated residual** / **NEW**.
NEW → checkwash issue only (D-4). Published hole confirmed → no duplicate issue.

`ddmin` runs on every FA whose attack has **more than one** mutation. Adapter
must be `checkwash` (minimize CLI `--adapter`).

### 11.2 Exit criteria (all must hold)

| # | Criterion |
|---|---|
| 1 | All seven wave1 attacks have a recorded verdict; `ledger verify` passes |
| 2 | Wave0 integration pins still hold (CW-W0-03 remains the only wave0 FA) |
| 3 | Each wave1 FA is classified against FAILURES.md / SPEC residual / NEW |
| 4 | NEW findings filed as checkwash issues only; zero checkwash commits |
| 5 | Every multi-mutation FA has `minimization.json` from `smallestlie minimize --adapter checkwash` |
| 6 | Fixture sources byte-identical after campaigns |
| 7 | Network denied throughout |
| 8 | Language rule: no SECURE / UNHACKABLE / NO VULNERABILITIES |
| 9 | Blind stand-in still false-accepts every wave1 theater attack (sensitivity) |

**預註冊：** 本表隨落地 commit 凍結。開跑後不得改判準來遷就實作。

### 11.3 M1 outcome (2026-09-02, executed)

All nine exit criteria from §11.2 met. Two false acceptances:

| Attack | Classification |
|---|---|
| CW-W1-2HOP | SPEC `SUBJECT_NORMALIZED` two-hop residual. No issue. |
| CW-W1-TWIN | **NEW** — call→call same-bug twin. [checkwash#61](https://github.com/taipei49314/checkwash/issues/61) filed per D-4. |

The five FAILURES.md-seeded attacks were **rejected** by v0.2.8 on this fixture.
That does not close those published rows; it only records that these seeds were
caught. Full table: [`CHECKWASH_M1.md`](CHECKWASH_M1.md).
