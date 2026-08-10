# Adapter design: Greenwash

**Document type:** Real-repository adapter design (M6 prep)  
**Status:** `DESIGN_ONLY` — **no campaign execution authorized by this document**  
**Adapter id:** `greenwash`  
**Design version:** `0.1.0-design`  
**Local source tree:** **NOT OBSERVED** at design time  
**Evidence base:** SmallestLie North Star (hostile counterpart family); VectorLock §4.3 claim-verification boundary (“你憑什麼宣稱這項工作完成？”); ecosystem anti-theater themes shared with ClaimGate/TomorrowCI  
**SmallestLie baseline:** v0.2.0+

---

## 0. Executive summary

**Greenwash** is treated as the ecosystem’s **anti-theater / green-credibility** product:

> *Is this green result substantive, or is it cosmetic success that would not survive independent scrutiny of coverage, execution, and reporting?*

Where **ClaimGate** asks whether a claim is **authorized**, **Greenwash** asks whether a green presentation is **materially real**:

```text
ClaimGate:
    Is this claim licensed by bound evidence and command semantics?

Greenwash:
    Is this green the smallest cosmetic lie (tests skipped, coverage hollow,
    warnings erased, matrix shrunk, report polished) still sold as success?

SmallestLie:
    What is the smallest adversarial mutation that makes the target accept a lie?
```

SmallestLie is the **hostile laboratory**; Greenwash (when present) is a **product that tries to detect greenwashing**. The adapter red-teams Greenwash’s detector/gate the same way: disposable mutants, independent oracle, false-acceptance of “not greenwashed” / “clean” verdicts.

### Wave A stance

Prefer **offline greenwash audit** of a report bundle + policy:

```text
disposable package (CI summary, coverage, junit, workflow projection, policy)
  → mutate theater surfaces
  → allowlisted: greenwash audit|check --json
  → parse “clean / theater_detected / blocked”
  → oracle establishes whether theater is actually present
  → FALSE_ACCEPT if Greenwash says clean while oracle says theater
```

---

## 1. Observation status & honesty

| Item | Status |
|---|---|
| Local git checkout | **Missing** |
| Public CLI contract | **Unknown** until clone |
| Pinned revision | **TBD** |
| Name collision risk | “greenwash” is also a general term — pin package/module identity on observation |

**Stop rule:** Do not implement against guessed subcommands. Phase G0 records observed binary identity, schemas, and sample outputs.

---

## 2. Product positioning (design assumptions)

| ID | Assumption | Confidence |
|---|---|---|
| A-01 | Greenwash consumes CI-like artifacts (junit, coverage, job summaries) | high |
| A-02 | It classifies results into clean vs theater/suspicious vs blocked | medium-high |
| A-03 | It cares about empty discovery, skipped jobs, suppressed warnings, shrunk matrices | high (name + family) |
| A-04 | Fail-closed when inputs incomplete | medium |
| A-05 | Offline audit mode exists or can be the first integration surface | medium |
| A-06 | Distinct from ClaimGate: more about **cosmetic success detection** than claim legalism | medium-high |

If the real product differs, rewrite this section in G0; do not force the name onto a mismatched binary.

---

## 3. Claims inventory (target claims under test)

### 3.1 Product claims (expected)

| ID | Claim | False-accept meaning |
|---|---|---|
| GW-C01 | Result is not greenwashed | Theater present but classified clean |
| GW-C02 | Required tests ran | Skipped/empty suite still clean |
| GW-C03 | Matrix complete | Platforms dropped silently |
| GW-C04 | Coverage material | Hollow coverage accepted as real |
| GW-C05 | Warnings decision-relevant | Warnings erased in projection |
| GW-C06 | Report matches exit | Channel disagreement ignored |
| GW-C07 | Policy enforced | Missing policy defaults to clean |
| GW-C08 | Fresh inputs | Stale report for new revision marked clean |

### 3.2 Meta-claims

| ID | Meta-claim |
|---|---|
| GW-M01 | “A green badge implies substantive verification.” |
| GW-M02 | “Our detector would have caught theater of class X.” |

SmallestLie does **not** prove GW-M02 globally; it only reports campaign-bounded false accepts.

---

## 4. Trust-surface map (expected)

```text
greenwash package /
├─ policy.yaml                    # theater rules, thresholds, fail-closed
├─ ci-summary.json                # job statuses, skips, matrix
├─ junit/ or test-report.xml
├─ coverage/ (lcov|json)
├─ workflow.yml fragment
├─ warnings.json
├─ subject.json                   # revision, artifact ids
└─ audit-report.json              # Greenwash output (target verdict channel)
```

| Surface | SmallestLie families |
|---|---|
| empty discovery / skip | EXE-003, EXE-002, EVD-001 |
| matrix shrink | EXE-001, WF-006 class |
| warning erasure | PROJ-001/002 class, SEM-008 class |
| coverage hollow | EVD / SEM scope games |
| stale report | TIME-001, EVD-002 |
| policy missing | CFG-001, SEM-003 |
| path disguise of reports | PATH-* |
| exit vs report | PROJ-005 |

---

## 5. Adapter interface (provisional)

### 5.1 Modes

| Mode | Purpose | Network | First? |
|---|---|---|---|
| `audit_package` | Offline theater audit | denied | **Yes** |
| `audit_repo` | Repo-native config + checked-in reports | denied | Second |
| `live_ci_import` | Import artifacts from disposable CI run | deferred | No |

### 5.2 Provisional allowlist

| command_id | Provisional argv | Notes |
|---|---|---|
| `run_greenwash_audit` | `[bin, "audit", "--package", pkg, "--json"]` | re-pin at G0 |
| `run_greenwash_check` | `[bin, "check", "--json"]` | alternate |
| `run_doctor` | `[bin, "doctor", "--json"]` | preflight |

### 5.3 Capabilities

```text
target_verdict
ci_summary
test_reports
coverage_reports
policy_file
warning_channel
report_json
offline_audit
```

### 5.4 Verdict parser

| Target output | `accepted` meaning for SmallestLie |
|---|---|
| `clean` / `PASS` / `not_greenwashed` | target **accepts** the world as non-theater |
| `theater_detected` / `FAIL` / `dirty` | target **rejects** |
| `blocked` / `inconclusive` | not accepting; map carefully, never as success |

False acceptance = Greenwash says **clean** while oracle says **theater present**.

### 5.5 Oracles (Greenwash-specific)

| Oracle | Theater fact |
|---|---|
| `required_execution_set` | required tests not executed |
| `workflow_completeness` | required jobs skipped / matrix incomplete |
| `warning_preservation` | decision-relevant warnings removed |
| `coverage_materiality` | coverage object empty/trivial while claimed full |
| `report_exit_consistency` | channels disagree |
| `revision_binding` | report subject ≠ current revision |
| `fail_closed_defaults` | missing policy |

---

## 6. Attack applicability (canonical M1 — provisional)

| Attack | Wave A | Theater story |
|---|:---:|---|
| EVD-001 | A | assertions present, not executed |
| EVD-002 | A | stale green report |
| EVD-003 | A | coverage/report hash mismatch |
| EXE-001 | A | partial run projected full |
| EXE-002 | A | skipped job still green |
| EXE-003 | A | zero tests success |
| SEM-001 | A | status token inversion |
| SEM-003 | A | open default on missing rule |
| PATH-001 | A | rename required report so rule misses it |
| PATH-002 | A | decoy report basename |
| TIME-001 | A | revision after report |
| WF-001 | A/P | gate job conditionally skipped |
| AUTH-001 | P | if clean badge requires approver |
| CFG-001 | A | missing anti-theater policy |
| PROJ-005 | A | exit dirty / report clean |

Greenwash is expected to be **especially dense** on EXE/PROJ/SEM — ideal second or third real adapter after TomorrowCI verify kernel and ClaimGate packages.

---

## 7. Control campaign

| Input | Expectation |
|---|---|
| Honest full matrix + real execution evidence | `clean` + oracle non-theater → `TRUE_ACCEPT` |
| Known theater fixture | target `dirty` + oracle theater → `ATTACK_REJECTED` when we mutate toward theater? |

Clarify comparator orientation:

- SmallestLie invalid world = **theater present** (oracle_valid=false means “not a clean world”).
- Target accepted = Greenwash marks **clean**.
- Classic false accept = clean badge on theater world.

Control (honest package): oracle_valid=true, target clean → TRUE_ACCEPT.

---

## 8. Distinction: Greenwash vs ClaimGate vs SmallestLie

| System | Question | SmallestLie false-accept |
|---|---|---|
| ClaimGate | Is claim authorized? | Unauthorized claim accepted |
| Greenwash | Is green substantive? | Theater labeled clean |
| SmallestLie | Smallest lie target still accepts | Harness; not a product under test |

Do **not** merge adapters. Shared attack IDs may use overlays.

---

## 9. Authorization package notes

```yaml
adapter:
  name: greenwash
  version: "0.1.0-design"
  mode: audit_package
  pinned_revision: "<sha>"
  package_path: "fixtures/greenwash_package/valid"
  binary_path: "<observed>"
```

`network: denied` for Wave A.

---

## 10. Implementation phases (blocked)

| Phase | Work | Gate |
|---|---|---|
| G0 | Obtain owned clone; pin CLI/schemas; rewrite §5 | source present |
| G1 | Synthetic theater packages (`naive` accepts theater, `honest` rejects) | unit tests |
| G2 | `GreenwashAdapter` + control | auth signed |
| G3 | Wave A ≥10 attacks | control green |
| G4 | Cross-suite with ClaimGate packages (same theater, different product claim) | optional |

---

## 11. Known limitations

1. No local repository observed.  
2. Product boundaries vs ClaimGate may collapse in a monorepo — reassess at G0.  
3. No execution authorized.  
4. Coverage “materiality” oracles are heuristic; must stay fail-closed and documented.  
5. Findings never imply “all greenwashing is found.”

---

## 12. Success criteria (future)

North Star M6 adapter criteria apply unchanged. Additional Greenwash-specific:

- At least one EXE-003-class and one PROJ-class false accept on naive package.  
- Honest package rejects the same.  
- Limitations list which theater classes were not modeled.

---

## 13. Document control

| Field | Value |
|---|---|
| Status | DESIGN_ONLY |
| Execution | **NOT AUTHORIZED** |
| Next | Operator provides Greenwash path + auth → Phase G0 |
