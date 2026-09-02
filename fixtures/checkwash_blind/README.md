# checkwash_blind — positive-control fixture

Identical target to `checkwash_target`, plus a deliberately blind stand-in
engine (`blind_check.py`) that always prints a clean verdict and exits 0.

Run with adapter `checkwash_blind` and the same `checkwash-wave0` catalog:
every theater attack must come back `FALSE_ACCEPT_OBSERVED`. That proves this
harness observes false acceptances when the engine under test lies clean —
the sensitivity control for the real-engine campaign. Mirrors the
`greenwash_naive` pattern for the real-engine line.
