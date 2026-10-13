"""Local fixture commands; no network listener or real directory changes."""

import argparse
import json
from pathlib import Path

from service_desk.contracts import AuditEvent, LabConfig, ReadDocumentArgs, ScenarioResult
from service_desk.evaluation import run_suite
from service_desk.fixtures import fingerprint, load_config, load_fixtures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "evaluate", "schemas"])
    parser.add_argument("--fixtures", type=Path, default=Path("fixtures/company.json"))
    parser.add_argument("--config", type=Path, default=Path("config/lab.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "schemas":
        if args.output is None:
            parser.error("schemas requires --output")
        args.output.mkdir(parents=True, exist_ok=True)
        for model in (AuditEvent, LabConfig, ReadDocumentArgs, ScenarioResult):
            (args.output / f"{model.__name__}.json").write_text(
                json.dumps(model.model_json_schema(), indent=2) + "\n", encoding="utf-8"
            )
        return 0
    fixtures, config = load_fixtures(args.fixtures), load_config(args.config)
    if args.command == "validate":
        print(
            json.dumps(
                {"fixture_sha256": fingerprint(fixtures), "scenarios": len(fixtures.scenarios)}
            )
        )
        return 0
    if args.output is None:
        parser.error("evaluate requires --output pointing to a new run directory")
    counts = run_suite(fixtures, config, args.output)
    print(json.dumps(counts))
    return 1 if counts["failure"] or counts["error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
