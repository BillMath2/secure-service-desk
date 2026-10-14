import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from scripts.check_frameworks import ROOT, check, read_json, scenario_sources, validate_tags


@pytest.fixture
def framework_tree(tmp_path: Path) -> Path:
    paths = {
        "config/risk-taxonomies.json",
        "config/risk-register.json",
        "docs/risk-register.md",
        "config/taxonomies/ATLAS-2026.07.yaml",
        *scenario_sources(ROOT),
    }
    for risk in read_json(ROOT / "config/risk-register.json")["risks"]:
        paths.update(risk["evidence"])
    for path in paths:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    return tmp_path


def save(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def test_repository_framework_gate() -> None:
    counts = check()
    assert counts["scenarios"] >= 35
    assert counts["threats"] >= 10


@pytest.mark.parametrize(
    "tags",
    [
        None,
        "AML.T0051.001",
        ["AML.T0051.01"],
        ["LLM01:2026"],
        ["AML.M0029"],
        [12],
        ["AML.T0051.001", "AML.T0051.001"],
    ],
)
def test_invalid_scenario_tags_are_rejected(tags: Any) -> None:
    with pytest.raises(ValueError):
        validate_tags(tags, {"AML.T0051.001", "LLM01:2025"}, "case")


def test_benign_empty_tags_are_valid() -> None:
    validate_tags([], set(), "benign")


def test_catalog_tampering_is_rejected(framework_tree: Path) -> None:
    path = framework_tree / "config/taxonomies/ATLAS-2026.07.yaml"
    path.write_bytes(path.read_bytes() + b"\n# changed\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        check(framework_tree)


def test_unverified_atlas_name_is_rejected(framework_tree: Path) -> None:
    path = framework_tree / "config/risk-taxonomies.json"
    data = read_json(path)
    data["mitre_atlas"]["allowed"]["AML.T0053"] = "Wrong meaning"
    save(path, data)
    with pytest.raises(ValueError, match="ID/name mismatch"):
        check(framework_tree)


@pytest.mark.parametrize(
    "source",
    [
        "fixtures/company.json",
        "lab_baseline/cases.json",
        "config/phase2-model-cases.json",
        "config/phase3-channel-model-cases.json",
        "config/phase3-workflow-model-cases.json",
        "config/phase4-model-cases.json",
    ],
)
def test_every_case_source_is_validated(framework_tree: Path, source: str) -> None:
    path = framework_tree / source
    data = read_json(path)
    cases = (
        data["scenarios"]
        if source == "fixtures/company.json"
        else (data["cases"] if source == "lab_baseline/cases.json" else data)
    )
    cases[0]["risks"] = ["AML.T0051.01"]
    save(path, data)
    with pytest.raises(ValueError, match="Unknown or unreviewed"):
        check(framework_tree)


def test_new_model_source_cannot_escape_registration(framework_tree: Path) -> None:
    save(framework_tree / "config/new-model-cases.json", [{"id": "new", "risks": []}])
    with pytest.raises(ValueError, match="Unregistered"):
        check(framework_tree)


@pytest.mark.parametrize(
    "change, message",
    [
        ("missing", "Missing model case source"),
        ("duplicate", "Duplicate case"),
        ("removed", "Stale scenario reference"),
    ],
)
def test_missing_duplicate_and_stale_cases_fail(
    framework_tree: Path, change: str, message: str
) -> None:
    path = framework_tree / "config/phase4-model-cases.json"
    data = read_json(path)
    if change == "missing":
        path.unlink()
    else:
        save(path, data + [data[0]] if change == "duplicate" else data[:1])
    with pytest.raises(ValueError, match=message):
        check(framework_tree)


def test_generated_view_cannot_silently_drift(framework_tree: Path) -> None:
    path = framework_tree / "config/risk-register.json"
    data = read_json(path)
    data["risks"][0]["owner"] = "Changed owner"
    save(path, data)
    with pytest.raises(ValueError, match="view is stale"):
        check(framework_tree)
    check(framework_tree, write_view=True)
    assert "Changed owner" in (framework_tree / "docs/risk-register.md").read_text()


def test_model_case_extraction_preserves_existing_workflows() -> None:
    cases = scenario_sources(ROOT)
    assert [
        (c["user"], c["channel"], c["attack"])
        for c in cases["config/phase3-channel-model-cases.json"]
    ] == [
        ("erin", "internal", False),
        ("erin", "requester", False),
        ("erin", "requester", True),
        ("alice", "requester", True),
    ]
    assert [
        (c["id"], c["ticket"], c["resource"]) for c in cases["config/phase4-model-cases.json"]
    ] == [
        ("benign", "ticket-alice", "engineering-workspace"),
        ("injected", "ticket-alice-injected", "engineering-admin"),
    ]
    assert [
        (c["ticket"], c["channel"])
        for c in cases["config/phase3-workflow-model-cases.json"]
        if c["kind"] == "draft"
    ] == [
        ("ticket-alice", "requester"),
        ("ticket-alice", "internal"),
        ("ticket-alice-injected", "requester"),
        ("ticket-alice-injected", "internal"),
    ]
    assert [
        c["id"] for c in cases["config/phase3-workflow-model-cases.json"] if c["kind"] == "chat"
    ] == ["self_chat"]
