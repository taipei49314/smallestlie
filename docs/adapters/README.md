# Real-repository adapters

This directory holds **design packages** for connecting SmallestLie to Nelson-owned repositories.

## Non-negotiable rules

1. **Design before execution.** No campaign against a real repo until an authorization package is present and valid.
2. **Disposable clones only.** Source repositories must remain byte-identical.
3. **Network denied by default.** Adapters that need fetch/container phases must declare a separate, explicitly authorized mode.
4. **Independent oracle.** Target `PASS`/`ok:true` is never ground truth.
5. **Honest language.** Adapters report `FALSE_ACCEPT_OBSERVED` / `ATTACK_REJECTED` / `INAPPLICABLE` / `BLOCKED` — never “secure.”

## Recommended order (North Star M6)

| Order | Target | Status |
|------:|--------|--------|
| 0 | Synthetic `fixture_gate` | **Implemented** (M0–M3) |
| 1 | **TomorrowCI** (verify / evidence authority) | **Design only** — this folder |
| 2 | ClaimGate | Planned |
| 3 | Greenwash | Planned |
| 4 | RepoPassport | Planned |
| 5 | TraceCapsule | Planned |
| 6 | Larger evidence systems | Deferred |

## Why TomorrowCI first

Among locally available Nelson projects, TomorrowCI is the strongest first real adapter because:

- it already makes **explicit claims** about evidence integrity and verdict honesty;
- it has a **pinned offline verify path** (`tomorrowci verify <run_id> --json`);
- it ships an **adversarial mutation corpus** (complementary, not redundant);
- trust surfaces map cleanly onto SmallestLie families (EVD, TIME, PATH, PROJ, VRF, EXE);
- a full `scan` path can be deferred (containers/network) while still exercising real product logic.

## Adapter deliverables checklist

Each adapter design must include:

- [ ] claims inventory
- [ ] trust-surface map
- [ ] allowlisted command map
- [ ] verdict parser contract
- [ ] oracle mapping
- [ ] attack applicability matrix
- [ ] control campaign definition
- [ ] authorization package template
- [ ] known limitations
- [ ] implementation phases with stop rules

## Documents

- [tomorrowci.md](./tomorrowci.md) — first real adapter design
- [authorization-package.template.yaml](./authorization-package.template.yaml) — auth object for real targets
