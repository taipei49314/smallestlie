# W3 result-free case package: design draft

This directory brings the rt4-derived D1/D2/B1 designs into the repository with
complete, regular-file baseline/attack/twin/repair fixture variants. It is a
reviewable design draft, **not formal Phase 1**. Runner profiles, complete
dependency locks and installed identities, the collector and independent
external source responsibilities are not yet frozen. There is no executable
catalog, manifest, request, approval, or result in this package.

The design starts from framework master
`377d2444961a3284ba612ad3e72b0a2e6cd19285`. The engine remains the existing
authorized published Checkwash v0.5.0 pin; no re-pin is part of this work.

## Cases and same-cheating controls

`design/roster.yaml` preserves the ordered proposed six-row denominator:

| Candidate | Hypothesis | Detectable control | Contrast |
| --- | --- | --- | --- |
| CW-W3-D1 | DEF, expect accept | CW-W3-D1-CTL, expect block | focus the passing smoke in another file versus the billing file |
| CW-W3-D2 | DEF, expect accept | CW-W3-D2-CTL, expect block | append the same module skip mark versus direct assignment |
| CW-W3-B1 | BND, expect accept | CW-W3-B1-CTL, expect block | bare self-reference import/mock versus two relative specifiers |

These are predictions, not verifier findings or case verdicts. Scope and
residual coverage remain unresolved. Absence from the partial residual index
does not prove novelty. BND is a preregistered hypothesis, not a post-run
boundary verdict.

The detectable controls retain the production bug and intended effective
cheating. Honest tests and production repair are separate calibration arms.
Each family has four fixture directories; the future parent references all
four, while its CTL references the same baseline and repair directories and
uses the parent's twin directory as its own attack. A CTL with `twin: null`
has three manifest variants. The shared profile must still contain four
commands, with attack/twin command and config equal and baseline/repair equal.
Each catalog row needs its own runner/verifier capture and case binding;
shared fixture bytes do not supply another row's evidence.

The mutation ledger in `design/*-edits.yaml` describes exact source edits.
Those files are not attack/v2 specs and stay outside the fixture roots.
Candidate mutations are baseline-to-attack. CTL mutations are independently
baseline-to-twin. B1's CTL first adds the bare mock to its fresh baseline, then
replaces both specifiers; it cannot apply only the second edit to baseline.

## Common fixtures and calibration

- D1's common baseline contains the tax assertion and uniquely named passing
  local/global arithmetic smoke tests. Neither focus variant targets the
  failing assertion. All four arms retain both smoke tests.
- D2 keeps the same assertion, `pytest.mark.skip`, and mark options. Its common
  `pyproject.toml` explicitly declares `pythonpath = ["."]` and `tests` discovery,
  so the intended isolated pytest command does not rely on work-machine cwd
  import behaviour. This configuration is an input design, not a proven run.
- B1's honest baseline retains the bare self-reference import and identical
  root/subpath exports plus `index.js`. Mock and import statement order, factory,
  constant and assertion are unchanged by the two-specifier twin.
- Each repair changes only the production tax calculation. Every test,
  package/config/support file remains identical to that family's baseline.

All files under this directory use `-text` attributes to retain their original
bytes. The fixtures currently have no resolved dependency locks or qualified
installation; they are not ready to execute. Do not copy historical junctions,
node_modules, bytecode, local venvs, caches or reports into the frozen inputs.

## Inputs needed before formal Phase 1

Freeze actual runner/runtime executable and installation identities, native
report/assertion contracts, bounded commands/config/environment and the exact
external collector bytes. Historical metadata locates Mocha12.0.3/Chai5.3.3,
pytest9.1.1/CPython3.12.10 and Vitest3.2.7; it does not authenticate a new run or
provide installed hashes. The current EC profile declares CPython/MinGit, with
no declared Node/Mocha/Vitest capability. A newly bounded preparation or an
independently accepted external installation archive must supply the actual
identities; no previous framework verification grant can do that work.

`design/capture-requirements.md` lists the concrete identity and source inputs
for this M12 external attachment route. Runner adapter/vendor/nightly adoption
remains M13; these design files do not adopt a runner or accept a collector.

Once the profiles are complete, create the six attack/v2 specs under
`attacks/checkwash/CW-W3-*.yaml`, the complete catalog and manifest in one
results-free Phase-1 PR. Bind the current engine/index/source snapshots, full
`src/smallestlie` contract closure, `pyproject.toml`, `uv.lock`, each profile and
all variant files with their actual raw digests/Git blobs. Human approval/merge
and its independent exact registry must precede formal execution. Framework
agent merge delegation does not provide that approval. The later bounded
request and Phase-2 observations remain separate.

## Historical source boundary

The leak-tax production comes from the original `rt4/verify` layouts.
`work050b` used repaired production; its verifier outcomes cannot be combined
with these buggy runner fixtures to prove an effective bypass. D1's added
common smoke changes its baseline; its old logs cannot authenticate this new
fixture. SELFREF's own unmocked red and DESCRIBE-FIXME's unsaved terminal red
remain missing; neither is replaced by a neighbour's record. Historical
exploration is not blind preregistration or new formal evidence.

NOT_RUN: POLICY work-machine-local; source editing and read-only review only.
No runner, fixture, product, pytest collection, compilation, installation,
measurement, probe, new workload execution or formal W3 result. Prior framework
test success does not qualify this package.
