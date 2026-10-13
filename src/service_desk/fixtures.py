"""Load and fingerprint synthetic fixtures without mutating their source."""

import hashlib
from pathlib import Path

from service_desk.contracts import FixtureSet, LabConfig


def load_fixtures(path: Path) -> FixtureSet:
    return FixtureSet.model_validate_json(path.read_text(encoding="utf-8"))


def load_config(path: Path) -> LabConfig:
    return LabConfig.model_validate_json(path.read_text(encoding="utf-8"))


def fingerprint(fixtures: FixtureSet) -> str:
    return hashlib.sha256(fixtures.model_dump_json().encode()).hexdigest()
