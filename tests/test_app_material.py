"""Application credential staging, fixed routes and bootstrap failure boundaries."""

import json
import subprocess
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from psycopg.conninfo import make_conninfo
from test_read_process import staged

from scripts.prepare_phase3_app import prepare
from service_desk import app_bootstrap
from service_desk.app_network import routed
from service_desk.app_process import FILES, material

__all__ = ["staged"]


@pytest.fixture
def application(staged: Path) -> Path:
    (staged / ".lab/phase2/credentials.json").write_text(
        json.dumps({"clients": {"web": "w" * 43, "gateway": "g" * 43, "executor": "e" * 43}})
    )
    for name, login in (
        ("creator", "read_app"),
        ("gateway", "read_gateway"),
        ("publisher", "read_publisher"),
    ):
        (staged / ".lab/phase2-read" / (name + ".dsn")).write_text(
            make_conninfo(
                host="127.0.0.1",
                port=15433,
                dbname="service_desk_read_lab",
                user=login,
                password="synthetic",
            )
        )
    prepare(staged)
    return staged


def test_distinct_process_authority_and_preserved_keys(application: Path) -> None:
    root = application / ".lab/phase3-app"
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    prepare(application)
    assert all(p.read_bytes() == value for p, value in before.items())
    for role in FILES:
        config, _ = material(root / role, role, "192.0.2.10")
        assert all("executor" not in key for key in config)
        if role == "browser":
            assert not any(key.endswith(".dsn") for key in config)
        elif role == "agent":
            assert not any("publisher" in key or "web" in key for key in config)
        else:
            assert "publisher.dsn" in config and "gateway.secret" not in config
    assert len({(root / role / "private.key").read_bytes() for role in FILES}) == 3
    assert (root / "agent/service.secret").read_bytes() != (
        root / "publisher/service.secret"
    ).read_bytes()


@pytest.mark.parametrize("role", ["browser", "agent", "publisher"])
@pytest.mark.parametrize("change", ["extra", "peer_key", "missing", "secret"])
def test_application_material_fails_closed(application: Path, role: str, change: str) -> None:
    root = application / ".lab/phase3-app" / role
    if change == "extra":
        (root / "master.json").write_text("PRIVATE")
    elif change == "peer_key":
        peer = "publisher" if role != "publisher" else "agent"
        (root / "private.key").write_bytes((root.parent / peer / "private.key").read_bytes())
    elif change == "missing":
        (root / "identities.json").unlink()
    else:
        (root / ("web.secret" if role == "browser" else "service.secret")).write_text("PRIVATE")
    with pytest.raises(ValueError, match="^Invalid application material$"):
        material(root, role, "192.0.2.10")


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.invalid:19443/x",
        "http://127.0.0.1:19443/x",
        "https://127.0.0.1:19487/x",
        "https://user:pw@127.0.0.1:19443/x",
    ],
)
def test_pinned_transport_rejects_unregistered_destination(url: str) -> None:
    with pytest.raises(httpx.ConnectError, match="Destination denied"):
        routed(httpx.Request("POST", url), "192.0.2.10", (19443,))


def test_pinned_transport_preserves_tls_identity_without_dns() -> None:
    request = httpx.Request("POST", "https://127.0.0.1:19443/token", content=b"neutral")
    result = routed(request, "192.0.2.10", (19443,))
    assert result.url.host == "192.0.2.10" and result.headers["host"] == "127.0.0.1:19443"
    assert result.extensions["sni_hostname"] == "127.0.0.1"
    assert request.url.host == "127.0.0.1" and result.read() == b"neutral"


@pytest.mark.parametrize("role", ["browser", "agent", "publisher"])
@pytest.mark.parametrize("failure", ["resolve", "install"])
def test_application_bootstrap_never_serves_after_setup_failure(
    monkeypatch: pytest.MonkeyPatch, role: str, failure: str
) -> None:
    resolve, install, launch = Mock(return_value="192.0.2.10"), Mock(), Mock()
    monkeypatch.setattr("service_desk.app_bootstrap.socket.gethostbyname", resolve)
    monkeypatch.setattr("service_desk.app_bootstrap.subprocess.run", install)
    monkeypatch.setattr("service_desk.app_bootstrap.os.execv", launch)
    if failure == "resolve":
        resolve.side_effect = OSError()
    else:
        install.side_effect = subprocess.CalledProcessError(1, "nft")
    with pytest.raises((OSError, subprocess.CalledProcessError)):
        app_bootstrap.launch(role)
    launch.assert_not_called()
