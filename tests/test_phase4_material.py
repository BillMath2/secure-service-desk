"""Isolated credentials and bootstrap failures for the Phase 4 service layout."""

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from psycopg.conninfo import make_conninfo
from test_app_material import application
from test_read_process import staged

from scripts.prepare_phase4 import prepare
from service_desk import phase4_bootstrap
from service_desk.phase4_layout import FILES, LOGINS
from service_desk.phase4_process import material

__all__ = ["application", "staged"]


@pytest.fixture
def workflow_material(application: Path) -> Path:
    for role, login in LOGINS.items():
        path = application / ".lab/phase2-read" / (role + ".dsn")
        if not path.exists():
            path.write_text(
                make_conninfo(
                    host="127.0.0.1",
                    port=15433,
                    dbname="service_desk_read_lab",
                    user=login,
                    password="synthetic",
                )
            )
    prepare(application)
    return application


def test_staging_exposes_only_distinct_service_authority(workflow_material: Path) -> None:
    root = workflow_material / ".lab/phase4"
    expected = {
        "browser": set(),
        "agent": {"creator.dsn", "gateway.dsn"},
        "workflow": {"workflow.dsn"},
        "proposals": {"proposals.dsn"},
        "execution": {"execution.dsn"},
        "collector": {"collector.dsn"},
        "worker": {"lifecycle.dsn"},
        "executor": set(),
        "delivery": {"delivery.dsn"},
    }
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    prepare(workflow_material)
    assert all(p.read_bytes() == value for p, value in before.items())
    for role, dsns in expected.items():
        config, _ = material(root / role, role, "192.0.2.10")
        assert {n for n in config if n.endswith(".dsn")} == dsns
        assert ("executor.secret" in config) is (role == "executor")
        assert ("service.secret" in config) is (role in {"agent", "workflow"})
    assert len({(root / role / "private.key").read_bytes() for role in FILES}) == 9
    assert (
        len(
            {
                (root / "collector" / (writer + ".secret")).read_bytes()
                for writer in ("workflow", "execution", "lifecycle", "reads")
            }
        )
        == 4
    )


def test_peer_credentials_keys_and_changed_provider_fail_closed(workflow_material: Path) -> None:
    root = workflow_material / ".lab/phase4"
    for role in FILES:
        extra = root / role / "unexpected.secret"
        extra.write_text("PRIVATE")
        with pytest.raises(ValueError, match="Invalid workflow material"):
            material(root / role, role, "192.0.2.10")
        extra.unlink()
    (root / "workflow/private.key").write_bytes((root / "executor/private.key").read_bytes())
    with pytest.raises(ValueError):
        material(root / "workflow", "workflow", "192.0.2.10")
    (root / "agent/provider.json").write_text(json.dumps({"provider": "cloud"}))
    with pytest.raises(ValueError):
        material(root / "agent", "agent", "192.0.2.10")


@pytest.mark.parametrize("role", list(FILES))
def test_failed_firewall_never_executes_runtime(monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    execute = Mock()
    monkeypatch.setattr(
        "service_desk.phase4_bootstrap.socket.gethostbyname", lambda _: "192.0.2.10"
    )
    monkeypatch.setattr("service_desk.phase4_bootstrap.os.execv", execute)
    monkeypatch.setattr(
        "service_desk.phase4_bootstrap.subprocess.run",
        Mock(side_effect=subprocess.CalledProcessError(1, "nft")),
    )
    with pytest.raises(subprocess.CalledProcessError):
        phase4_bootstrap.launch(role)
    execute.assert_not_called()
