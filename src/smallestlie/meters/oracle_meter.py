"""Oracle independence meters (static instrumentation)."""

from __future__ import annotations

import ast
from pathlib import Path

from smallestlie.meters.models import Measurement, MeterVerdict


def measure_oracle_independence_static(project_root: Path) -> Measurement:
    """
    Static check: evaluate_oracle must not set valid from target_verdict.accepted.

    This is a meter on code structure, not a rhetorical claim.
    """
    path = project_root / "src" / "smallestlie" / "oracle" / "base.py"
    if not path.is_file():
        return Measurement(
            meter_id="oracle.independence_static",
            name="Oracle independence static analysis",
            verdict=MeterVerdict.NOT_MEASURED,
            evidence={"error": "base.py missing"},
        )
    src = path.read_text(encoding="utf-8")
    # Fail if we assign valid from target accepted
    bad_patterns = [
        "target_verdict.accepted",
        "target.accepted",
        "verdict.accepted",
    ]
    # Allow reading for report_exit plugin only — flag direct valid = ...accepted
    suspicious = []
    for i, line in enumerate(src.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "valid" in stripped and "=" in stripped:
            if any(p in stripped for p in bad_patterns) and "valid" == stripped.split("=")[0].strip().split(":")[0].strip():
                suspicious.append({"line": i, "text": stripped})
            # also catch valid = target_verdict.accepted
            if any(
                stripped.replace(" ", "").startswith(f"valid={p}")
                or stripped.replace(" ", "").startswith(f"valid=bool({p}")
                for p in bad_patterns
            ):
                suspicious.append({"line": i, "text": stripped})

    # Positive evidence: explicit independence guard in source
    low = src.lower()
    has_guard_comment = (
        ("never allow target_verdict" in low)
        or ("not from the target" in low and "verdict" in low)
        or ("never" in low and "target_verdict.accepted" in low)
    )

    # AST: ensure function evaluate_oracle exists
    try:
        tree = ast.parse(src)
        fns = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
        has_eval = "evaluate_oracle" in fns
    except SyntaxError as exc:
        return Measurement(
            meter_id="oracle.independence_static",
            name="Oracle independence static analysis",
            verdict=MeterVerdict.MEASURED_FAIL,
            evidence={"syntax_error": str(exc)},
        )

    if suspicious:
        verdict = MeterVerdict.MEASURED_FAIL
    elif has_eval and has_guard_comment:
        verdict = MeterVerdict.MEASURED_PASS
    elif has_eval:
        verdict = MeterVerdict.MEASURED_WARN
    else:
        verdict = MeterVerdict.MEASURED_FAIL

    return Measurement(
        meter_id="oracle.independence_static",
        name="Oracle independence static analysis",
        verdict=verdict,
        value=len(suspicious),
        unit="suspicious_assignments",
        threshold={"max_suspicious": 0},
        evidence={
            "suspicious": suspicious,
            "has_evaluate_oracle": has_eval,
            "has_guard_comment": has_guard_comment,
            "limitation": "static pattern meter; not a proof of all dynamic paths",
        },
        notes=["O2/O3 classification is inventory-only until runtime trace meters land"],
    )


def measure_oracle_plugin_inventory(project_root: Path) -> Measurement:
    oracle_dir = project_root / "src" / "smallestlie" / "oracle"
    plugins = sorted(
        p.stem
        for p in oracle_dir.glob("*.py")
        if p.stem not in {"__init__", "base"} and p.is_file()
    )
    # Expected core plugins
    expected = {
        "discovery",
        "revision_binding",
        "policy_presence",
        "protected_identity",
        "report_exit",
        "artifact_hash",
        "execution_trace",
        "workflow",
        "authority",
        "semantic_policy",
        "path_canonical",
        "verifier_rules",
    }
    missing = sorted(expected - set(plugins))
    verdict = MeterVerdict.MEASURED_PASS if not missing else MeterVerdict.MEASURED_WARN
    return Measurement(
        meter_id="oracle.plugin_inventory",
        name="Oracle plugin module inventory",
        verdict=verdict,
        value=len(plugins),
        unit="modules",
        evidence={"plugins": plugins, "missing_expected": missing},
    )
