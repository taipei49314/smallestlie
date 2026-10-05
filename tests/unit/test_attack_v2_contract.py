"""A declaration cannot quietly lose preregistration or cross-case controls."""

from copy import deepcopy
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest
import yaml

from smallestlie.attacks.catalog import catalog_snapshot, load_catalog
from smallestlie.attacks.composition import compose_pair, pairwise_candidates
from smallestlie.attacks.schema import AttackSchemaError, load_attack_spec, parse_attack_spec
from smallestlie.ci.diff_select import filter_catalog_file
from smallestlie.cli import cmd_minimize, cmd_replay
from smallestlie.campaign import runner
from smallestlie.models import ComparisonResult, ExitCode

ROOT = Path(__file__).resolve().parents[2]
INDEX = "catalogs/residual-rows-checkwash-v0.6.0.json"


def declaration(case_id="D", *, control=False):
    raw = yaml.safe_load((ROOT / "attacks/checkwash/CW-W1-2HOP.yaml").read_text(encoding="utf-8"))
    raw.update(schema_version="smallestlie.attack/v2", attack_id=case_id)
    raw["adjudication"] = {
        "preregistered_class": "CTL" if control else "DEF",
        "expected_verifier_outcome": "block" if control else "accept",
        "claim_scope": {"status": "unresolved", "rationale": "Review pinned product claims."},
        "residual_mapping": {"status": "unresolved", "row_refs": [], "rationale": "Not reviewed."},
        "control_role": "detectable_attack_control" if control else None,
        "twin": None if control else {
            "case_id": "C", "role": "detectable_attack_control", "contrast": "One declared edit.",
            "detection": {"rule_ids": ["SUBJECT_NORMALIZED"], "paths": ["tests/test_billing.py"]},
        },
    }
    raw["runner_protocol"] = {"profile_id": "protocol", "profile_sha256": "a" * 64,
                              "baseline_assertion": "test_total_exact_value"}
    return raw


def catalog_files(tmp_path, cases=None, **changes):
    cases = cases if cases is not None else [declaration(), declaration("C", control=True)]
    (tmp_path / "attacks").mkdir()
    (tmp_path / "catalogs").mkdir()
    shutil.copytree(ROOT / "provenance", tmp_path / "provenance")
    shutil.copyfile(ROOT / INDEX, tmp_path / INDEX)
    for idx, case in enumerate(cases):
        (tmp_path / "attacks" / f"case-{idx}.yaml").write_text(yaml.safe_dump(case), encoding="utf-8")
    index = yaml.safe_load((tmp_path / INDEX).read_text(encoding="utf-8"))
    body = {"schema_version": "smallestlie.catalog/v2", "name": "contract",
            "attacks": [case["attack_id"] for case in cases], "residual_index": INDEX,
            "engine": {key: index["engine"][key] for key in ("version", "artifact_sha256", "source_revision")}}
    body.update(changes)
    path = tmp_path / "catalogs/v2.yaml"
    path.write_text(yaml.safe_dump(body), encoding="utf-8")
    return path


def test_all_shipped_v1_declarations_roundtrip():
    for path in (ROOT / "attacks").rglob("*.yaml"):
        original = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert load_attack_spec(path).to_dict() == original


@pytest.mark.parametrize("version", ["smallestlie.attack/v3", None, 2, []])
def test_unknown_schema_cannot_drop_declarations(version):
    raw = declaration()
    raw["schema_version"] = version
    with pytest.raises(AttackSchemaError, match="unsupported"):
        parse_attack_spec(raw)


def test_v2_fields_cannot_be_downgraded_to_v1():
    raw = declaration()
    raw["schema_version"] = "smallestlie.attack/v1"
    with pytest.raises(AttackSchemaError, match="silently"):
        parse_attack_spec(raw)


@pytest.mark.parametrize("field,value", [("preregistered_class", "def"), ("twin", None),
                                        ("claim_scope", True), ("expected_verifier_outcome", "bypass")])
def test_invalid_research_design_rejected(field, value):
    raw = declaration()
    raw["adjudication"][field] = value
    with pytest.raises(AttackSchemaError):
        parse_attack_spec(raw)


def test_observations_do_not_belong_in_phase_one_declarations():
    raw = declaration()
    raw["runner_evidence"] = {"base_exit": 1, "attack_exit": 0}
    with pytest.raises(AttackSchemaError, match="unknown v2"):
        parse_attack_spec(raw)
    del raw["runner_evidence"]
    raw["runner_protocol"]["base_exit"] = 1
    with pytest.raises(AttackSchemaError, match="unknown"):
        parse_attack_spec(raw)


def test_self_twin_and_path_escape_rejected():
    raw = declaration()
    raw["adjudication"]["twin"]["case_id"] = "D"
    with pytest.raises(AttackSchemaError, match="own twin"):
        parse_attack_spec(raw)
    raw = declaration()
    raw["adjudication"]["twin"]["detection"]["paths"] = ["../outside"]
    with pytest.raises(AttackSchemaError, match="confined"):
        parse_attack_spec(raw)


def test_v2_roundtrip_and_serialization_do_not_alias_input():
    raw = declaration()
    expected = deepcopy(raw)
    spec = parse_attack_spec(raw)
    raw["adjudication"]["preregistered_class"] = "CTL"
    assert spec.to_dict() == expected
    exported = spec.to_dict()
    exported["runner_protocol"]["profile_id"] = "changed"
    assert spec.to_dict() == expected


def test_v2_serializes_current_typed_fields():
    spec = parse_attack_spec(declaration())
    spec.attack_id = "changed"
    spec.false_accept_condition["extra"] = "changed"
    spec.authorization_requirements["extra"] = "changed"
    exported = spec.to_dict()
    assert exported["attack_id"] == "changed"
    assert exported["false_accept_condition"]["extra"] == "changed"
    assert exported["authorization_requirements"]["extra"] == "changed"
    exported["authorization_requirements"]["extra"] = "outside"
    assert spec.authorization_requirements["extra"] == "changed"


def test_full_catalog_resolves_positive_twin(tmp_path):
    catalog = load_catalog(catalog_files(tmp_path))
    assert list(catalog.attacks) == ["D", "C"]
    assert catalog.metadata["schema_version"] == "smallestlie.catalog/v2"
    assert catalog_snapshot(catalog)["schema_version"] == "smallestlie.catalog-snapshot/v1"


@pytest.mark.parametrize("changes", [{"name": None}, {"name": ""},
                                    {"seed_default": True}, {"seed_default": 1.5}])
def test_v2_catalog_never_coerces_invalid_types(tmp_path, changes):
    with pytest.raises(ValueError):
        load_catalog(catalog_files(tmp_path, **changes))


@pytest.mark.parametrize("row", ["THREATMODEL:5", "THREATMODEL:108", "unknown-row"])
def test_nonresidual_or_missing_source_cannot_excuse_bypass(tmp_path, row):
    attack = declaration()
    attack["adjudication"]["residual_mapping"].update(status="matched_residual", row_refs=[row])
    path = catalog_files(tmp_path, [attack, declaration("C", control=True)])
    with pytest.raises(ValueError, match="residual"):
        load_catalog(path)


@pytest.mark.parametrize("problem", ["missing", "honest", "accept", "runner", "duplicate"])
def test_bad_control_cannot_satisfy_a_defect_declaration(tmp_path, problem):
    attack, control = declaration(), declaration("C", control=True)
    cases = [attack, control]
    if problem == "missing":
        cases = [attack]
    elif problem == "honest":
        control["adjudication"]["control_role"] = "honest_control"
    elif problem == "accept":
        control["adjudication"]["expected_verifier_outcome"] = "accept"
    elif problem == "runner":
        control["runner_protocol"]["profile_sha256"] = "b" * 64
    else:
        cases.append(deepcopy(control))
    with pytest.raises(ValueError):
        load_catalog(catalog_files(tmp_path, cases))


def test_duplicate_file_id_and_malformed_selected_case_are_not_hidden(tmp_path):
    path = catalog_files(tmp_path)
    duplicate = tmp_path / "attacks/duplicate.yaml"
    shutil.copyfile(tmp_path / "attacks/case-0.yaml", duplicate)
    with pytest.raises(ValueError, match="duplicate attack ID"):
        load_catalog(path)
    duplicate.unlink()
    malformed = tmp_path / "attacks/case-0.yaml"
    raw = declaration()
    raw["adjudication"]["preregistered_class"] = 1
    malformed.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(AttackSchemaError, match="invalid selected attacks"):
        load_catalog(path)


def test_duplicate_yaml_keys_rejected(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("attack_id: A\nattack_id: B\n", encoding="utf-8")
    with pytest.raises(AttackSchemaError, match="duplicate YAML key"):
        load_attack_spec(path)


def test_unreadable_file_cannot_hide_a_duplicate_in_v2_catalog(tmp_path):
    path = catalog_files(tmp_path)
    (tmp_path / "attacks/ambiguous.yaml").write_text("attack_id: D\nattack_id: C\n", encoding="utf-8")
    with pytest.raises(AttackSchemaError, match="unreadable attack"):
        load_catalog(path)


@pytest.mark.parametrize("mode", ["pairwise", "mixed"])
def test_v2_composition_and_filtering_cannot_discard_registration(tmp_path, mode):
    with pytest.raises(ValueError, match="single-case"):
        load_catalog(catalog_files(tmp_path, mode=mode))
    with pytest.raises(ValueError, match="auto-composed"):
        compose_pair(parse_attack_spec(declaration()), parse_attack_spec(declaration("C", control=True)), seed=1)
    with pytest.raises(ValueError, match="auto-composed"):
        pairwise_candidates([parse_attack_spec(declaration())], seed=1)


def test_v2_diff_filter_is_blocked_even_when_ids_are_unchanged(tmp_path):
    catalog = load_catalog(catalog_files(tmp_path))
    output = tmp_path / "filtered.yaml"
    with pytest.raises(ValueError, match="diff-filtered"):
        filter_catalog_file(output, catalog, catalog.attack_ids)
    assert not output.exists()


def test_private_execution_and_replay_do_not_bypass_pending_protocol(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("a v2 case reached execution before protocol integration")
    monkeypatch.setattr(runner.DisposableWorkspace, "create", forbidden)
    attack = parse_attack_spec(declaration())
    result = runner._run_mutant_once(mutations=attack.mutations, attack=attack, target_path=tmp_path,
                                     baseline={}, adapter=None, allowlist=None)
    assert result["comparison"]["result"] == ComparisonResult.BLOCKED_BY_POLICY.value
    assert runner._replay_false_accept(attack=attack, target_path=tmp_path, baseline={}, adapter=None,
                                        allowlist=None, attempts=0)["stable"] is False
    direct = runner._execute_run(run_id="r", attack=attack, target_path=tmp_path, baseline={},
                                  adapter=None, allowlist=None, campaign_dir=tmp_path,
                                  runs_dir=tmp_path / "runs", witnesses_dir=tmp_path / "witnesses",
                                  ledger=None, auth=None, keep_workspaces=False, seed=1)
    assert direct["comparison"]["result"] == ComparisonResult.BLOCKED_BY_POLICY.value
    assert not (tmp_path / "runs").exists()


def test_public_campaign_cannot_execute_v2_as_an_old_observation(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("v2 public campaign reached mutant execution")
    path = catalog_files(tmp_path)
    monkeypatch.setattr(runner.DisposableWorkspace, "create", forbidden)
    result = runner.run_campaign(target=ROOT / "fixtures/naive_gate", catalog_path=path,
                                 project_root=tmp_path, output_root=tmp_path / "results")
    assert result["status"] == "HARNESS_ERROR"
    assert "preregistration/evidence" in result["error"]
    assert result["false_accept_count"] == 0


@pytest.mark.parametrize("command", ["replay", "minimize"])
def test_cli_never_reports_success_for_v2_single_step_witness(tmp_path, command):
    raw = declaration()
    filename = "minimized-attack.yaml" if command == "replay" else "attack.yaml"
    (tmp_path / filename).write_text(yaml.safe_dump(raw), encoding="utf-8")
    args = SimpleNamespace(witness_dir=str(tmp_path), run_dir=str(tmp_path))
    function = cmd_replay if command == "replay" else cmd_minimize
    assert function(args, ROOT) == int(ExitCode.INVALID_CONFIG)
    assert not (tmp_path / "replay-result.json").exists()


@pytest.mark.parametrize("command", ["replay", "minimize"])
def test_cli_uses_duplicate_key_safe_loader(tmp_path, command):
    filename = "minimized-attack.yaml" if command == "replay" else "attack.yaml"
    (tmp_path / filename).write_text("schema_version: smallestlie.attack/v2\nschema_version: smallestlie.attack/v1\n",
                                    encoding="utf-8")
    args = SimpleNamespace(witness_dir=str(tmp_path), run_dir=str(tmp_path))
    function = cmd_replay if command == "replay" else cmd_minimize
    assert function(args, ROOT) == int(ExitCode.INVALID_CONFIG)
