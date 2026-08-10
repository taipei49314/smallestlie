"""Delta-debugging minimizer tests."""

from __future__ import annotations

from smallestlie.minimize.ddmin import ddmin


def test_ddmin_reduces_to_single_necessary_step() -> None:
    steps = [
        {"type": "a", "id": 1},
        {"type": "b", "id": 2},
        {"type": "c", "id": 3},
    ]

    def interesting(subset: list) -> bool:
        return any(s.get("id") == 2 for s in subset)

    result = ddmin(steps, interesting)
    assert result.minimal_steps == 1
    assert result.minimal_mutations == [{"type": "b", "id": 2}]


def test_ddmin_keeps_two_necessary_steps() -> None:
    steps = [
        {"type": "a", "id": 1},
        {"type": "b", "id": 2},
        {"type": "c", "id": 3},
    ]

    def interesting(subset: list) -> bool:
        ids = {s["id"] for s in subset}
        return 1 in ids and 3 in ids

    result = ddmin(steps, interesting)
    assert result.minimal_steps == 2
    ids = {s["id"] for s in result.minimal_mutations}
    assert ids == {1, 3}
