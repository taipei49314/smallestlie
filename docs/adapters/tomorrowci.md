# Adapter design: TomorrowCI

**Document type:** Real-repository adapter design (M6 prep)  
**Status:** `DESIGN_ONLY` — **no campaign execution authorized by this document**  
**Adapter id:** `tomorrowci`  
**Design version:** `0.1.0-design`  
**Target repo (local observation):** `C:\Users\1\tomorrowci`  
**Observed HEAD (at design time):** `bf41f16784e328d1770d4f8276128ad46e96fe84`  
**Observed branch:** `repair/alpha3-semantic-authority-rc2`  
**SmallestLie baseline:** v0.2.0 (M0–M3 synthetic kernel complete)

---

## 0. Executive summary

TomorrowCI is an evidence-first “CI against the future” system. It claims that:

1. scenario results and frontiers are backed by **replayable evidence**;
2. `verify` can detect **tampered or incoherent evidence**;
3. **BLOCKED / UNSUPPORTED / INCONCLUSIVE never become PASS**;
4. release/provenance artifacts bind to inventory hashes.

SmallestLie’s first real adapter should **not** start by running full multi-runtime `scan` matrices (containers, fetch network). It should start with the **offline evidence authorization kernel**:

```text
disposable clone of repo + disposable copy of a pinned evidence run
        → apply declarative mutations to allowlisted evidence/config surfaces
        → run allowlisted: tomorrowci verify <run_id> --json
        → parse target verdict (ok / errors)
        → independent SmallestLie oracles establish ground truth
        → compare → ledger → minimize → regression export
```

This yields a high-signal, low-blast-radius integration that exercises real product logic TomorrowCI already treats as a trust boundary.

---

## 1. Scope and non-goals

### 1.1 In scope (Wave A — `verify_offline`)

| Item | In scope |
|---|---|
| Adapter class `TomorrowCiAdapter` | yes |
| Mode `verify_offline` | yes |
| Mutating **disposable copies** of evidence runs under the clone | yes |
| Allowlisted `tomorrowci verify --json` | yes |
| Independent oracles for inventory/hash/revision/path/semantic claims | yes |
| Applicability matrix for canonical M1 catalog | yes |
| Control campaign on **unmutated** pinned evidence | yes |
| Authorization package + pinned revision binding | yes |

### 1.2 Explicitly out of scope for Wave A

| Item | Reason |
|---|---|
| Live `tomorrowci scan` against arbitrary paths | needs container engine + fetch network |
| Attacking remote registries / public CI | forbidden by constitution |
| Mutating the operator’s original TomorrowCI tree in place | source protection |
| Declaring TomorrowCI “secure” if no false accept | language rule |
| Replacing TomorrowCI’s own adversarial suite | complementary, not a takeover |
| Model-generated mutations executing without schema compile | M7 only |

### 1.3 Deferred (Wave B+)

- `scan_fixture` mode against `fixtures/python-runtime-break` with network grant `fetch-only` **inside target’s own sandbox policy** (still no external egress from SmallestLie harness beyond what adapter explicitly allowlists — prefer keeping SmallestLie network denied and letting TomorrowCI’s container policy own fetch).
- Self-mutation of `crates/evidence` / `crates/core` (VRF family) then re-running unit/adversarial tests.
- Compare-mode (`tomorrowci compare`) frontier honesty attacks.
- Release bundle / SBOM / provenance path (`RELEASE_PROVENANCE.json`, `SHA256SUMS.txt`).

---

## 2. Claims inventory

Derived from README, `docs/CLAIM_TO_EVIDENCE.md`, `docs/EVIDENCE_AUTHORITY_MAP.md`, `docs/threat-model`, ADR verdict honesty, and CLI surfaces.

### 2.1 Explicit product claims

| ID | Claim (paraphrased) | Where asserted |
|---|---|---|
| C-01 | No breakage claim without replayable evidence | README / product slogan |
| C-02 | Evidence verify detects inventory/hash/semantic forgery | `tomorrowci verify`, `crates/evidence` |
| C-03 | Every fact has one canonical owner; mirrors must match | `EVIDENCE_AUTHORITY_MAP.md` |
| C-04 | Forbidden paths (e.g. scenario-local checksums) fail closed | authority map |
| C-05 | Hash form is strict (`sha256:` + lowercase hex) | authority map |
| C-06 | BLOCKED / UNSUPPORTED / INCONCLUSIVE never convert to PASS | ADR + `enforce_verdict_honesty` |
| C-07 | Baseline failure prevents breakage horizon authorization | `verdict.rs` / RC2 mutations |
| C-08 | Source tree is not mutated by runs | threat model / mutation id `source_tree_immutability` |
| C-09 | Symlink / path traversal in evidence is rejected | adversarial suite |
| C-10 | Report links must resolve to indexed payload | authority map / mutations |
| C-11 | Replay requires matching config/digest/preconditions | mutation list |
| C-12 | Public statuses are honest: PASS / FAIL / BLOCKED / NOT_RUN | claim-to-evidence |

### 2.2 Implicit claims (attack-relevant)

| ID | Implicit claim |
|---|---|
| I-01 | `verify` exit code and JSON `ok` agree on acceptance |
| I-02 | Re-indexing after multi-file coherent forgery still fails semantic checks |
| I-03 | Directory name / `run_id` / index identity are bound |
| I-04 | Workspace bytes bind to `workspace-manifest.json` |
| I-05 | Scenario result/verdict/exit channels are cross-checked |
| I-06 | Partial scenario matrices cannot invent a clean full PASS |
| I-07 | Attestations outside inventory rules cannot launder acceptance |

### 2.3 Non-claims (must not attack as if claimed)

- “Finds every future breakage”
- “Secure multi-tenant SaaS isolation”
- “Node/Rust/React/image paths are production-ready” (README marks many **NOT_RUN**)

---

## 3. Trust-surface map

### 3.1 Primary trust surfaces (Wave A)

```text
Evidence run root (e.g. .tomorrowci/runs/<run_id>/ or imported fixture run)
├─ run.json                         # run identity, plan, aggregate results
├─ evidence-index.json              # inventory authority
├─ checksums.txt                    # index path multiset + hashes
├─ config.normalized.json           # config bytes / config_hash binding
├─ workspace/ + workspace-manifest  # source snapshot binding
├─ scenarios/<id>/
│  ├─ scenario.json
│  ├─ environment.json
│  ├─ result.json                   # verdict / exit
│  ├─ replay.json / commands*
│  ├─ *-stdout.log / *-stderr.log
│  └─ failure-signature.json
├─ frontier.json / verdicts.json / claims.json / report.*
└─ attestations/                    # external-to-payload rules
```

### 3.2 Secondary trust surfaces (Wave B)

| Surface | Risk class |
|---|---|
| `.tomorrowci.yml` / config schema | CFG |
| `crates/evidence` verify rules | VRF |
| `crates/core` verdict aggregation | SEM / VRF |
| GitHub Action / workflow templates | WF |
| Release provenance + SBOM | EVD / TIME |
| Container engine identity | EXE / ENV |

### 3.3 Trust boundaries (SmallestLie mapping)

| Boundary | TomorrowCI objects | SmallestLie families |
|---|---|---|
| source ↔ workspace snapshot | `workspace/`, workspace-manifest | EVD-003, PATH-* |
| execution ↔ scenario result | result.json, logs, phases | EXE-*, EVD-001 |
| result ↔ aggregate/frontier | run.json, frontier.json | EXE-001, SEM-*, PROJ-* |
| evidence ↔ revision/config | config_hash, identity | TIME-001, EVD-002 |
| path identity ↔ inventory | index paths, checksums | PATH-*, EVD-* |
| verifier binary ↔ verdict meaning | tomorrowci.exe build | VRF-* (later) |
| actor/provenance ↔ release claim | RELEASE_PROVENANCE | AUTH-* (later) |

---

## 4. Operating modes

### 4.1 Mode `verify_offline` (recommended first implementation)

**Purpose:** Red-team the evidence authorization kernel without container execution.

**Inputs:**

| Input | Description |
|---|---|
| `repo_root` | Owned TomorrowCI clone (disposable) |
| `run_id` | Existing evidence run id present under an allowlisted relative root |
| `binary` | Allowlisted path to `tomorrowci` CLI built at pinned revision |
| `seed` | Campaign seed |

**Evidence corpus strategy:**

1. Prefer a **fixture-owned evidence run** checked into SmallestLie under `fixtures/tomorrowci_evidence/<run_id>/` **after** operator exports a scrubbed, non-secret run (no host paths, no tokens).
2. Alternatively, copy from operator-provided path listed in authorization (`evidence_source_path`) into the disposable workspace at campaign start.
3. Never mutate evidence under the original TomorrowCI tree.

**Command (only):**

```text
command_ref: run_verify
argv: ["${TODAY_BIN}", "verify", "${RUN_ID}", "--json"]
cwd: <disposable repo root or evidence parent as required by CLI>
timeout_seconds: 120
```

Note: `${TODAY_BIN}` is resolved by the adapter from authorization/`binary_path`, not from attack YAML.

### 4.2 Mode `scan_fixture` (deferred)

**Purpose:** End-to-end scan honesty on `fixtures/python-runtime-break`.

**Blockers for Wave A:**

- Docker/Podman availability variance → risk of `BLOCKED` collapsed incorrectly
- Fetch network during dependency install
- Long wall-clock budgets
- Non-determinism across engines

**Gate to open Wave B:** separate authorization field `adapter.network_grant: target_managed_fetch_only` plus doctor checks for engine presence; SmallestLie harness network policy remains denied for its own process tree except invoking the allowlisted binary.

---

## 5. Adapter interface design

### 5.1 Type sketch

```python
class TomorrowCiAdapter(Adapter):
    name = "tomorrowci"
    version = "0.1.0"  # implementation version, not design version

    def __init__(self, mode: str = "verify_offline", **cfg): ...

    def command_allowlist(self) -> CommandAllowlist: ...
    def capabilities(self) -> list[str]: ...
    def preflight(self, workspace: Path) -> dict: ...
    def parse_verdict(self, workspace: Path, execution: ExecutionResult) -> TargetVerdict: ...
    def materialize_evidence(self, workspace: Path, auth: Authorization) -> str:  # returns run_id
    def resolve_binary(self, workspace: Path, auth: Authorization) -> Path: ...
```

### 5.2 Capabilities (declared)

Wave A:

```text
target_verdict
evidence_files
evidence_inventory
revision_file          # via run identity / config_hash
path_inventory
report_json
offline_verify
```

Not claimed in Wave A:

```text
test_discovery          # unless scan_fixture
container_execution
workflow_graph          # GH workflows
release_provenance
```

### 5.3 Allowlisted commands

| command_id | argv template | Notes |
|---|---|---|
| `run_verify` | `[bin, "verify", run_id, "--json"]` | primary |
| `run_doctor` | `[bin, "doctor", "--json"]` | preflight only |
| `run_trust` | `[bin, "trust", "--json"]` | optional control; no target code exec |

**Forbidden:** any argv from attack YAML; shell strings; `scan` in Wave A; `cargo` rebuild inside mutant unless later VRF mode explicitly allowlists a pinned `cargo test -p tomorrowci-evidence` with resource caps.

### 5.4 Binary resolution policy

1. Prefer prebuilt binary path from authorization (`adapter.binary_path`) if it resolves **inside** disposable workspace or an allowlisted tools root.
2. Optionally build once **outside** mutant loop at campaign start into campaign `tools/` cache, hash the binary, record digest in baseline.
3. Record `verifier_digest` in baseline and ledger; Wave B freshness attacks bind evidence to this digest.

### 5.5 Verdict parser contract

Parse `stdout` as JSON when `--json` is used; fall back to exit-only with `raw_status=EXIT_ONLY`.

Normalized `TargetVerdict`:

| Field | Mapping |
|---|---|
| `accepted` | `report.ok is True` **and** `exit_code == 0` preference: **do not collapse** — set `accepted` from JSON `ok` if present, keep channels for disagreement |
| `raw_status` | `"VERIFIED"` if ok else `"REJECTED"` / error codes join |
| `exit_code` | process exit |
| `report_path` | optional copy of parsed JSON under run outputs |
| `evidence_refs` | `[f"evidence-run/{run_id}"]` |
| `channels` | `{exit_accepted, report_ok, error_count, error_codes[]}` |
| `warnings` | non-fatal messages if any |

**Channel honesty:** If `ok:true` with `exit_code!=0` (or reverse), preserve disagreement for PROJ-005-class observations. SmallestLie oracle decides validity; target channels stay raw.

### 5.6 Preflight checks

Fail closed (`BLOCKED_BY_POLICY` / `HARNESS_ERROR`) if:

- binary missing or not executable
- run_id missing after materialization
- authorization mode ≠ allowed
- network ≠ denied in Wave A
- path escapes workspace
- pinned_revision in auth does not match baseline git HEAD when `require_pinned_revision: true`

---

## 6. Baseline capture extensions

In addition to generic file inventory, TomorrowCI baseline should record:

```yaml
adapter_baseline:
  adapter: tomorrowci
  mode: verify_offline
  git_head: <sha>
  git_dirty: <bool>
  verifier_digest: sha256:...
  run_id: <id>
  evidence_inventory_digest: sha256:...
  evidence_file_count: <n>
  config_hash: <from config.normalized.json if present>
  tool_version: <tomorrowci --version>
```

Source immutability still uses full content digest of the **owned repo path** (or of the exported evidence fixture root if campaigns are fixture-only).

---

## 7. Oracle mapping (independent of target `ok`)

| Oracle plugin | Fact sources | Valid when |
|---|---|---|
| `artifact_hash_binding` / inventory | recompute sha256 of allowlisted files; compare to `checksums.txt` / index | all indexed files match |
| `revision_binding` | `run_id`, directory name, `run.json.run_id`, index run_id | all equal |
| `execution_trace` (scenario) | presence of required phase/result files per planned scenarios | required scenario artifacts present |
| `workflow_completeness` | plan scenarios vs scenario directories | no missing required scenarios |
| `path_canonicalization` | reject `..`, absolute, symlink entries in index | all paths safe + resolvable inside run root |
| `report_exit_consistency` | JSON `ok` vs process exit | channels sound |
| `semantic_policy` | error codes / ok flag vocabulary | no success alias injection in parser inputs |
| `protected_identity` | canonical owners per authority map | mirrors match owners (spot-check critical pairs) |
| `freshness` (Wave B) | verifier_digest / config_hash binding | evidence binds to current verifier+config |

**Rule:** Even if TomorrowCI `ok:true`, oracle may set `valid=false` when independent recomputation shows mismatch. That is the definition of false acceptance for this adapter.

**Dual-ledger:**

- **Reality ledger:** recomputed hashes, path resolution, file presence, channel facts  
- **Claim ledger:** target JSON `ok`, error list, exit code, report fields  

---

## 8. Attack applicability matrix (canonical M1)

Legend: **A** = applicable Wave A · **D** = deferred · **I** = inapplicable with reason · **P** = partial

| Attack | Wave A | Notes |
|---|:---:|---|
| EVD-001 unexecuted assertion | P/D | Map to missing test-phase / forged “pass” without logs; better after scan mode or scenario phase checks |
| EVD-002 stale evidence replay | **A** | Reuse older run evidence against different config_hash / workspace |
| EVD-003 artifact/hash mismatch | **A** | Flip bytes in workspace or log; leave checksum entry stale |
| EXE-001 partial run as full | P | Drop one scenario dir but keep aggregate PASS-like fields if present |
| EXE-002 skipped job projection | P | Align with missing scenario + green summary fields |
| EXE-003 empty discovery success | I/D | Verify mode has no test discovery; scan_fixture later |
| SEM-001 PASS/FAIL inversion | P | Mutate result verdict tokens / ok polarity if parser accepts aliases |
| SEM-003 boolean default open | P | Delete required config fields in normalized config if verify soft-fails |
| PATH-001 rename escape | **A** | Rename canonical owner file; leave mirrors |
| PATH-002 basename collision | **A** | Two scenario paths collapsing by leaf if any basename logic exists |
| TIME-001 revision after evidence | **A** | Change workspace or config after evidence sealed |
| WF-001 conditional skip gate | D | GH workflow surface; not verify kernel |
| AUTH-001 unauthorized approver | D/P | Map to attestation actor later; weak in pure verify |
| CFG-001 missing config default-open | P | Remove `config.normalized.json` / break config_hash binding |
| PROJ-005 exit/report disagree | **A** | If inducible; else harness still records channel facts on natural disagreement |

**Minimum Wave A executable set (design target ≥ 10 applicable):**

1. EVD-002  
2. EVD-003  
3. PATH-001  
4. PATH-002  
5. TIME-001  
6. CFG-001 (config binding)  
7. EXE-001 (scenario omission)  
8. EXE-002 (scenario skip projection)  
9. PROJ-005 (channel disagreement observation)  
10. SEM-001 (verdict token / ok polarity)  
11. EVD-001 (missing phase / unexecuted scenario work) — if preconditions met  
12. protected mirror mismatch composite (EVD + PATH)

Unsupported catalog entries must appear as `INAPPLICABLE` with reasons in the plan — never silently omitted.

---

## 9. Mutation allowlist (Wave A)

Only these primitives against **relative paths under the evidence run root** (and optionally `.tomorrowci.yml` in scan mode later):

| Primitive | Allowed targets (examples) |
|---|---|
| `write_json` / `structured_set` / `structured_delete` | `run.json`, `scenarios/*/result.json`, `evidence-index.json`, `frontier.json` |
| `write_text` | log files, `checksums.txt` lines (careful) |
| `delete_path` | scenario files, config.normalized.json |
| `rename_path` | scenario owner files, workspace files |
| `duplicate_path` | basename collision setups |
| `replace_text` | hash strings, run_id fields |

**Never allowlisted:**

- paths outside disposable workspace  
- mutation of host Docker socket / engine config  
- injection of real secrets  
- arbitrary `cargo`/`curl`/`powershell` from attack specs  

---

## 10. Control campaign

### 10.1 Definition of valid control

On unmutated pinned evidence + pinned binary:

| Expectation | Value |
|---|---|
| Target | `ok: true`, exit 0 |
| Oracle | inventory recompute matches; paths safe; channels sound |
| Comparison | `TRUE_ACCEPT_OBSERVED` |
| Source digest | unchanged |

If control fails, **stop** — do not interpret attack rejections as defense.

### 10.2 Suggested control recipe (operator steps — not yet automated)

```text
1. Build tomorrowci at pinned SHA
2. Export a scrubbed verify-green run into fixtures/tomorrowci_evidence/<run_id>
3. authorization-package.yaml → mode owned_local_repo or synthetic_fixture if evidence is vendored
4. smallestlie campaign run --adapter tomorrowci --catalog catalogs/tomorrowci-wave-a.yaml
5. First run profile: control-only catalog (zero mutations) must TRUE_ACCEPT
6. Then full wave-A catalog
```

### 10.3 Catalog sketch

`catalogs/tomorrowci-wave-a.yaml` (to be added at implementation time):

```yaml
name: tomorrowci-wave-a
seed_default: 49314
attacks:
  - EVD-002
  - EVD-003
  - PATH-001
  - PATH-002
  - TIME-001
  - CFG-001
  - EXE-001
  - EXE-002
  - SEM-001
  - PROJ-005
  - EVD-001
```

Attack YAML bodies for TomorrowCI will reference **evidence-relative paths**, not fixture_gate paths. Shared attack IDs may need adapter-specific variants (`EVD-002@tomorrowci`) if mutations differ — prefer **adapter overlays** over forking IDs when possible.

---

## 11. Relationship to TomorrowCI’s own adversarial suite

TomorrowCI already contains:

- `crates/evidence/tests/adversarial_verifier.rs`
- `scripts/run-authority-mutations.py` (RC2 named negative cases)

| | TomorrowCI suite | SmallestLie adapter |
|---|---|---|
| Purpose | Product self-test of verify | External harness with independent oracle + minimization + regression factory |
| Execution | Inside tomorrowci CI/dev | Outside, disposable clone, campaign ledger |
| Success meaning | verify rejects mutants | false accept if verify **accepts** while oracle says invalid |
| Overlap | healthy | expected; do not delete either |

SmallestLie should **import ideas** from RC2 mutation IDs as attack seeds, but each must be compiled into schema-valid attack specs with independent oracle expectations.

---

## 12. Authorization & safety package

### 12.1 Required before any real run

1. Filled `authorization-package` (see template)  
2. Operator confirmation of ownership  
3. `network: denied` for Wave A  
4. `disposable_clone_required: true`  
5. Pinned revision + verifier digest recorded  
6. Evidence corpus free of secrets (scan for tokens before import)

### 12.2 Kill conditions

Immediate `BLOCKED_BY_POLICY` / `HARNESS_ERROR` if:

- path escape / symlink escape  
- attempt to run non-allowlisted command  
- original repo digest changes  
- binary path outside policy  
- auth expired  
- control campaign not green when required  

### 12.3 Data handling

- Do not copy `_rd/`, large release tarballs, or unrelated secrets into mutants  
- Prefer minimal evidence fixture export  
- Redact absolute username paths in reports where possible  

---

## 13. Implementation plan (when authorized)

### Phase T0 — Scaffold (no real mutation campaign)

- [ ] `src/smallestlie/adapters/tomorrowci.py`
- [ ] register in `get_adapter`
- [ ] adapter schema fields in auth validation
- [ ] unit tests with **synthetic mini evidence tree** (handcrafted, not full tomorrowci clone)
- [ ] control parse tests for sample verify JSON fixtures

### Phase T1 — Vendored evidence fixture

- [ ] Operator exports scrubbed run → `fixtures/tomorrowci_evidence/<run_id>/`
- [ ] `doctor` checks fixture presence
- [ ] control campaign TRUE_ACCEPT on fixture + mocked or real binary

### Phase T2 — Wave A attacks

- [ ] Adapter-specific attack overlays / YAML
- [ ] Oracles for inventory recompute
- [ ] ≥10 applicable attacks execute with honest INAPPLICABLE for the rest
- [ ] minimize + replay + regression export

### Phase T3 — Optional live binary integration test

- [ ] CI job (offline) using vendored evidence + prebuilt binary artifact
- [ ] Still no claim of product security

### Stop rules

- Do not open `scan_fixture` until Wave A control + ≥10 attacks are stable.
- Do not raise network grants to unblock flaky scans.
- Do not treat tomorrowci suite pass as SmallestLie oracle truth.

---

## 14. Known limitations (design-time)

1. This document **does not authorize** execution.  
2. Observed repo state includes untracked evidence/release dirs (`_ci_evidence`, `_live_ev`, `_rd*`) — **not** trusted as clean fixtures without scrubbing.  
3. Full product surface (scan/replay/compare/release) is larger than Wave A.  
4. Windows path canonicalization and Docker presence differ from Linux CI — applicability may vary by host.  
5. TomorrowCI itself is pre-alpha / RC2 track; findings may reflect intentional unfinished surfaces — report with product status context.  
6. Binary build reproducibility is not yet part of SmallestLie baseline beyond hashing the resolved binary.  
7. No ClaimGate/Greenwash/RepoPassport local trees were required for this design; those adapters remain separate designs.

---

## 15. Success criteria for “adapter implemented” (future)

Only when **all** hold:

1. Authorization validated; network denied (Wave A).  
2. Original target byte-identical after campaign.  
3. Valid control → `TRUE_ACCEPT_OBSERVED`.  
4. ≥10 applicable deterministic attacks run.  
5. Unsupported attacks → `INAPPLICABLE` with reasons.  
6. Each false accept minimized, 3/3 replayed, regression exported.  
7. Ledger verifies.  
8. Report limitations list unfinished TomorrowCI surfaces and adapter mode.  
9. No “SECURE” language in outputs.

---

## 16. Suggested next human decisions

| Decision | Options | Recommendation |
|---|---|---|
| First executable corpus | Vendored scrubbed run vs live clone path | **Vendored scrubbed run** under SmallestLie fixtures |
| Binary supply | Prebuilt in fixture tools/ vs build at campaign start | **Prebuilt + hashed** for determinism |
| Wave A start date | After auth package signed | Block on signature/path confirmation |
| Parallel adapter | ClaimGate design | Only after TomorrowCI Wave A green |

---

## 17. Appendix A — Sample verify JSON (illustrative)

```json
{
  "ok": true,
  "run_id": "0564e2b72ab0",
  "checked_files": 120,
  "semantic_checks": 40,
  "errors": []
}
```

Acceptance channel candidates:

- `ok == true`
- `errors` empty
- process exit `0`

---

## 18. Appendix B — Mapping RC2 mutation IDs → SmallestLie seeds

| RC2 / mutation idea | SmallestLie seed family |
|---|---|
| tampered_scenario_stderr/stdout | EVD / EXE |
| scenario_checksum_entry_removed | EVD-003 / inventory |
| run_id_directory_mismatch | PATH / revision binding |
| result_json_forged_reindexed | EVD + VRF |
| path_traversal_index | PATH |
| symlink_escape | PATH |
| changed_config_rejects_replay | TIME / CFG |
| workspace_size_mismatch | EVD-003 |
| report_links_resolve | PROJ |
| identity_removed | AUTH / EVD |
| run_timestamps_reversed | TIME |

Each seed must still become a **declarative attack YAML** with oracle expectations before execution.

---

## 19. Document control

| Field | Value |
|---|---|
| Status | DESIGN_ONLY |
| Execution | **NOT AUTHORIZED** |
| Owner | Nelson |
| Builder | Grok |
| Supersedes | n/a |
| Next doc | Implementation plan PR / auth package filled by operator |
