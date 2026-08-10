# Adapter design: ClaimGate

**Document type:** Real-repository adapter design (M6 prep)  
**Status:** `DESIGN_ONLY` — **no campaign execution authorized by this document**  
**Adapter id:** `claimgate`  
**Design version:** `0.1.0-design`  
**Local source tree:** **NOT OBSERVED** at design time  
**Evidence base:** SmallestLie North Star positioning; TomorrowCI Alpha.2 forensic audit (ClaimGate case study); VectorLock boundary notes (claim verification layer)  
**SmallestLie baseline:** v0.2.0+

---

## 0. Executive summary

**ClaimGate** is treated as the ecosystem’s **claim-authorization** product:

> *Did the repository (or workflow) issue a completion / verification claim that is actually licensed by the evidence and command semantics behind it?*

It is **not** a generic scanner and not a mission controller (VectorLock). It sits in the **claim verification layer**:

```text
Claim verification (ClaimGate / Greenwash family):
    你憑什麼宣稱這項工作完成？ / 這條 claim 是否被證據授權？

TomorrowCI:
    未來環境是否會破？證據 inventory 是否可核驗？

VectorLock:
    這項工作為什麼被允許開始？使命是否仍一致？
```

TomorrowCI Alpha.2 is documented as a **ClaimGate case study**: a public workflow ran the required command, but the command’s **semantics did not authorize the claim**. That pattern is the adapter’s primary hostile objective:

> Cause `claim_accepted = true` while independent oracle shows the claim is **not** authorized by bound evidence / command meaning / authority.

### Wave A stance (when a repo appears)

Prefer **offline claim-package verification** over live CI orchestration:

```text
disposable clone + pinned claim package (manifest + evidence refs)
  → mutate allowlisted claim/evidence/policy surfaces
  → allowlisted: claimgate verify|check <package> --json
  → parse claim verdict
  → SmallestLie oracle establishes authorization truth
  → compare → minimize → regression
```

---

## 1. Observation status & honesty

| Item | Status |
|---|---|
| Local git checkout | **Missing** — design is interface-first |
| Public CLI contract | **Unknown** — to be filled on first clone |
| Pinned revision | **TBD** when operator provides path |
| Synthetic stand-in | Optional `fixtures/claimgate_naive/` later |

**Stop rule:** Do not invent fake CLI flags as production truth. Implementation Phase C0 must replace §5 command table with observed `--help` and schemas.

Until then, this document defines **required adapter capabilities** and **claim surfaces**, not a frozen binary contract.

---

## 2. Product positioning (design assumptions)

Assumptions are labeled. They must be validated against a real tree before execution.

| ID | Assumption | Confidence |
|---|---|---|
| A-01 | ClaimGate evaluates structured **claims** (completion, verification, release, coverage) | high (ecosystem role) |
| A-02 | Claims reference **evidence objects** (paths, hashes, run ids, logs) | high |
| A-03 | A green workflow step is insufficient without **semantic authorization** | high (TomorrowCI audit) |
| A-04 | Fail-closed on missing evidence / unknown claim types | medium (aligned with Nelson products) |
| A-05 | Offline verify of a claim package is first-class | medium |
| A-06 | Network denied is viable for package verify | medium-high |

---

## 3. Claims inventory (target claims under test)

### 3.1 Explicit claim classes (expected)

| ID | Claim class | False-accept meaning |
|---|---|---|
| CG-C01 | Work completed | Completion accepted without required evidence |
| CG-C02 | Tests executed | Presence of test files confused with execution |
| CG-C03 | Gate passed | Workflow job green without semantic check |
| CG-C04 | Evidence current | Stale evidence authorizes current claim |
| CG-C05 | Artifact bound | Hash/manifest mismatch still accepts |
| CG-C06 | Actor authorized | Unauthorized approver completes claim |
| CG-C07 | Policy satisfied | Missing/weak policy defaults open |
| CG-C08 | Report honest | Exit/report/projection disagree but claim accepted |

### 3.2 The ClaimGate meta-claim

| ID | Meta-claim |
|---|---|
| CG-M01 | “Running the documented verify command is sufficient to authorize the public claim.” |
| CG-M02 | “Command success ⇒ claim semantics satisfied.” |

SmallestLie attacks **CG-M01/M02** by preserving command success shape while breaking semantic preconditions (the Alpha.2 pattern).

---

## 4. Trust-surface map (expected)

```text
claim package root
├─ claim.json / claims.json          # claim statements + types
├─ claim-policy.yaml                 # required evidence types, fail-closed rules
├─ evidence/                         # referenced objects
│  ├─ *.json / logs / junit / etc.
├─ bindings.json                     # claim_id → evidence digests / paths
├─ actor.json / approval.json        # optional authority
├─ workflow-projection.json          # optional CI summary projection
└─ report.json                       # human/automation-facing verdict
```

| Surface | Families |
|---|---|
| claim statements | SEM, CFG |
| bindings / digests | EVD, TIME |
| evidence blobs | EVD, EXE |
| actor / approval | AUTH |
| workflow projection | WF, PROJ |
| policy defaults | CFG, SEM-003 |
| verify binary meaning | VRF (later) |

---

## 5. Adapter interface (provisional)

### 5.1 Modes

| Mode | Purpose | Network | First? |
|---|---|---|---|
| `verify_package` | Offline claim package check | denied | **Yes** |
| `verify_repo` | Repo-native claim gate on disposable clone | denied | Second |
| `ci_projection` | Evaluate checked-in CI summary artifacts only | denied | Optional |

### 5.2 Provisional allowlist (must re-pin on observation)

| command_id | Provisional argv | Constraint |
|---|---|---|
| `run_claim_verify` | `[bin, "verify", "--package", pkg, "--json"]` | replace after `--help` |
| `run_claim_check` | `[bin, "check", "--json"]` | alternate entry |
| `run_doctor` | `[bin, "doctor", "--json"]` | preflight |

Attack YAML may only use `command_ref`, never raw shell.

### 5.3 Capabilities

```text
target_verdict
claim_manifest
evidence_files
evidence_bindings
policy_file
authority_metadata
report_json
offline_verify
```

### 5.4 Verdict parser contract

Normalize to `TargetVerdict`:

| Field | Rule |
|---|---|
| `accepted` | package/report says claim authorized (`accepted`/`authorized`/`PASS`) |
| `raw_status` | raw token |
| `exit_code` | process |
| `channels` | exit vs report vs claim-status kept separate |
| `evidence_refs` | binding paths |

**Never** treat “command ran” as oracle truth.

### 5.5 Independent oracle focus (ClaimGate-specific)

| Oracle | Ground truth |
|---|---|
| `claim_evidence_binding` | every required evidence ref exists + digest matches |
| `claim_type_allowlist` | claim type known; unknown not accepted |
| `command_semantic_preconditions` | required phases/files for that claim type present |
| `revision_binding` | claim revision/digest matches package subject |
| `actor_authority` | approver allowlisted when required |
| `report_exit_consistency` | channels sound |
| `fail_closed_defaults` | missing policy fields do not open |

The **command_semantic_preconditions** oracle is the ClaimGate differentiator: it encodes “green command ≠ authorized claim.”

---

## 6. Attack applicability (canonical M1 — provisional)

| Attack | `verify_package` | Notes |
|---|:---:|---|
| EVD-001 | A | claim says tests ran; evidence lacks execution trace |
| EVD-002 | A | stale evidence authorizes current claim |
| EVD-003 | A | binding hash ≠ bytes |
| EXE-001 | A/P | partial matrix claimed complete |
| EXE-002 | A/P | skipped job projected green |
| EXE-003 | A | zero tests / empty discovery still authorized |
| SEM-001 | A | PASS/FAIL token inversion in claim status map |
| SEM-003 | A | missing deny-default field |
| PATH-001 | A | rename required evidence path |
| PATH-002 | A | basename collision on evidence leaf |
| TIME-001 | A | subject revision after evidence |
| WF-001 | D/P | needs workflow fixtures |
| AUTH-001 | A | unauthorized claim approver |
| CFG-001 | A | missing claim policy default-open |
| PROJ-005 | A | exit vs claim-report disagreement |

**Wave A target:** ≥10 applicable after real CLI observation.

---

## 7. Control campaign

| Step | Expectation |
|---|---|
| Unmutated valid claim package | target accepts |
| Oracle bindings hold | `valid=true` |
| Comparison | `TRUE_ACCEPT_OBSERVED` |
| Source/package digest | unchanged after campaign |

If control fails, **stop** — do not score attacks.

---

## 8. Authorization package notes

Use `authorization-package.template.yaml` with:

```yaml
adapter:
  name: claimgate
  version: "0.1.0-design"
  mode: verify_package
  pinned_revision: "<git sha when available>"
  package_path: "fixtures/claimgate_package/valid"  # or absolute under allowlist
  binary_path: "<observed>"
```

`network: denied` required for Wave A.

---

## 9. Implementation phases (blocked on source + auth)

| Phase | Work | Gate |
|---|---|---|
| C0 | Obtain owned clone; freeze CLI/schema; rewrite §5 | source present |
| C1 | Synthetic `claimgate_naive` / `claimgate_honest` packages in SmallestLie | unit tests |
| C2 | `ClaimGateAdapter` + control TRUE_ACCEPT | auth signed |
| C3 | Wave A catalog ≥10 attacks | control green |
| C4 | Optional live clone path | separate auth |

---

## 10. Relationship to other adapters

| Adapter | Boundary |
|---|---|
| TomorrowCI | Environment/future breakage + evidence inventory kernel |
| **ClaimGate** | **Whether a claim is authorized by evidence + command semantics** |
| Greenwash | Cosmetic green / test-theater / coverage-theater detection |
| VectorLock | Pre-execution mission admission (not this adapter) |

Overlap is expected; findings should name **which product claim** failed.

---

## 11. Known limitations

1. **No local repository observed** — design is provisional.  
2. CLI/schema are placeholders until C0.  
3. No execution authorized.  
4. Must not claim ClaimGate is secure/insecure without campaigns.  
5. Alpha.2 lesson is a **pattern**, not a ClaimGate product bug report.

---

## 12. Success criteria (future implementation)

Same as North Star M6 adapter criteria: disposable only, control case, ≥10 applicable attacks, honest `INAPPLICABLE`, replayable findings, no “SECURE” language.

---

## 13. Document control

| Field | Value |
|---|---|
| Status | DESIGN_ONLY |
| Execution | **NOT AUTHORIZED** |
| Next | Operator provides ClaimGate path + auth → Phase C0 |
