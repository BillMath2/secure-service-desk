"""Offline taxonomy, scenario traceability, and generated risk-register gate."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASE_SOURCES = {"fixtures/company.json": "scenarios", "lab_baseline/cases.json": "cases"}
MODEL_SOURCES = {
    "phase2-model-cases.json",
    "phase3-channel-model-cases.json",
    "phase3-workflow-model-cases.json",
    "phase4-model-cases.json",
}
LEVELS = {"designed", "implemented", "deterministically-tested", "real-model-evaluated"}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_tags(tags: Any, allowed: set[str], location: str) -> None:
    require(isinstance(tags, list), f"Missing risks array: {location}")
    require(all(isinstance(t, str) for t in tags), f"Non-string tag: {location}")
    require(len(tags) == len(set(tags)), f"Duplicate tag: {location}")
    require(all(t in allowed for t in tags), f"Unknown or unreviewed tag: {location}")


def scenario_sources(root: Path) -> dict[str, list[dict[str, Any]]]:
    result = {path: read_json(root / path)[key] for path, key in BASE_SOURCES.items()}
    files = sorted((root / "config").glob("*model-cases.json"))
    require({p.name for p in files} >= MODEL_SOURCES, "Missing model case source")
    for path in files:
        result[path.relative_to(root).as_posix()] = read_json(path)
    return result


def render_register(register: dict[str, Any]) -> str:
    lines = [
        "# Risk register",
        "",
        "Generated from [config/risk-register.json](../config/risk-register.json). "
        "Edit that source, then run `python scripts/check_frameworks.py --write-view`.",
        "",
        f"Reviewed {register['reviewed']}; source revision `{register['source_revision']}`. "
        + register["scope"]
        + ".",
        "",
        "Ratings describe inherent likelihood/impact in this synthetic lab, not measured "
        "probabilities. Mitigated means evidence for the stated scope; it does not mean zero "
        "residual risk. Planned treatment work remains open; see the "
        "[owner review](phase5-owner-review.md) for residual-risk acceptance and scope. "
        "Model evidence "
        "on a row does not turn every linked deterministic test into a model trial.",
        "",
    ]
    for risk in register["risks"]:
        lines += [f"## {risk['id']}: {risk['description']}", ""]
        for label, key in (
            ("Actor / entry", "actor_entry"),
            ("Assets / affected parties", "affected_assets"),
            ("Threats", "threat_ids"),
            ("STRIDE", "stride"),
            ("OWASP / ATLAS", "risks"),
            ("ATLAS mitigations", "mitigations"),
            ("AI RMF", "ai_rmf"),
            ("Requirements", "requirements"),
            ("Evidence levels", "evidence_levels"),
            ("Decision", "decision"),
        ):
            value = risk[key]
            if isinstance(value, list):
                value = ", ".join(value) or "No mapping claimed"
            lines.append(f"- **{label}:** {value}")
        links = ", ".join(f"[{p}](../{p})" for p in risk["evidence"])
        lines += [
            f"- **Evidence:** {links}",
            f"- **Likelihood / impact:** {risk['likelihood']} / {risk['impact']}. "
            + risk["rationale"],
            f"- **Residual / gap:** {risk['residual']}",
            f"- **Owner / next review:** {risk['owner']}; {risk['next_review']}",
            "",
        ]
    lines += [
        "## Scenario index",
        "",
        "Empty risk lists identify benign controls, not excluded trials.",
        "",
        "| Source and case | Risk IDs |",
        "|---|---|",
    ]
    for case, risks in register["scenarios"].items():
        lines.append(f"| `{case}` | {', '.join(risks) or 'Benign control'} |")
    return "\n".join(lines) + "\n"


def check(root: Path = ROOT, *, write_view: bool = False) -> dict[str, int]:
    taxonomy = read_json(root / "config/risk-taxonomies.json")
    atlas = taxonomy["mitre_atlas"]
    raw = (root / atlas["catalog"]).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == atlas["sha256"], "ATLAS catalog hash mismatch")
    catalog = raw.decode("utf-8")
    require(
        catalog.startswith(f"format-version: {atlas['data_format']}\n"), "ATLAS format mismatch"
    )
    require(
        f"  version: '{atlas['content_version'].removeprefix('v')}'\n" in catalog,
        "ATLAS content version mismatch",
    )
    for tag, name in atlas["allowed"].items():
        match = re.search(r"^  " + re.escape(tag) + r":\n    name: (.+)$", catalog, re.M)
        require(
            match is not None and match[1].strip("'\"") == name, f"ATLAS ID/name mismatch: {tag}"
        )
    allowed = {tag for tag in atlas["allowed"] if tag.startswith("AML.T")}
    for name, prefix, edition in (("owasp_llm", "LLM", "2025"), ("owasp_agentic", "ASI", "2026")):
        expected = {f"{prefix}{i:02}:{edition}" for i in range(1, 11)}
        require(
            taxonomy[name]["edition"] == edition and set(taxonomy[name]["allowed"]) == expected,
            f"OWASP edition mismatch: {name}",
        )
        allowed.update(expected)
    register = read_json(root / "config/risk-register.json")
    risks = {r["id"]: r for r in register["risks"]}
    require(len(risks) == len(register["risks"]), "Duplicate risk ID")
    threats: set[str] = set()
    for ident, risk in risks.items():
        require(re.fullmatch(r"RISK-\d{2}", ident) is not None, "Invalid risk ID")
        for field in (
            "description",
            "actor_entry",
            "affected_assets",
            "requirements",
            "evidence",
            "rationale",
            "residual",
            "owner",
            "next_review",
            "evidence_levels",
            "ai_rmf",
        ):
            require(bool(risk.get(field)), f"Missing {field}: {ident}")
        require(set(risk["evidence_levels"]) <= LEVELS, f"Invalid evidence level: {ident}")
        require(
            risk["decision"]
            in {"mitigated-in-tested-scope", "planned", "accepted", "out-of-scope"},
            f"Invalid risk decision: {ident}",
        )
        require(
            risk["likelihood"] in {"Low", "Medium", "High"}
            and risk["impact"] in {"Low", "Medium", "High"},
            f"Invalid rating: {ident}",
        )
        require(set(risk["stride"]) <= set("STRIDE"), f"Invalid STRIDE category: {ident}")
        validate_tags(risk["risks"], allowed, ident)
        validate_tags(
            risk.get("mitigations"),
            {tag for tag in atlas["allowed"] if tag.startswith("AML.M")},
            ident + " mitigations",
        )
        for path in risk["evidence"]:
            require((root / path).is_file(), f"Missing evidence: {path}")
        for threat in risk["threat_ids"]:
            require(
                re.fullmatch(r"T-F(?:10|[1-9])-[STRIDE]-\d{2}", threat) is not None,
                f"Invalid threat ID: {threat}",
            )
            require(threat not in threats, f"Duplicate threat ID: {threat}")
            threats.add(threat)
    require(
        {f"F{i}" for i in range(1, 11)} <= {t.split("-")[1] for t in threats},
        "Missing data-flow threat",
    )
    found: set[str] = set()
    for path, cases in scenario_sources(root).items():
        require(bool(cases), f"Empty case source: {path}")
        for case in cases:
            ident = path + "#" + case["id"]
            require(ident not in found, f"Duplicate case: {ident}")
            found.add(ident)
            validate_tags(case.get("risks"), allowed, ident)
            require(ident in register["scenarios"], f"Unregistered case: {ident}")
            refs = register["scenarios"][ident]
            require(all(r in risks for r in refs), f"Unknown risk reference: {ident}")
            mapped = {t for r in refs for t in risks[r]["risks"]}
            require(set(case["risks"]) <= mapped, f"Unmapped case tag: {ident}")
    require(found == set(register["scenarios"]), "Stale scenario reference")
    view = render_register(register)
    if write_view:
        (root / "docs/risk-register.md").write_text(view, encoding="utf-8")
    require(
        (root / "docs/risk-register.md").read_text(encoding="utf-8") == view,
        "Risk register view is stale; use --write-view",
    )
    return {"risks": len(risks), "threats": len(threats), "scenarios": len(found)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-view", action="store_true")
    args = parser.parse_args()
    print(json.dumps(check(write_view=args.write_view)))
