"""Database startup policy rejects relaxed settings without exposing connection details."""

from typing import Any

import psycopg
import pytest

from service_desk.core.database import (
    SERVER_SETTINGS,
    SESSION_SETTINGS,
    check_database,
    database_checks,
)


def role() -> dict[str, Any]:
    return {
        "rolname": "read_app",
        "rolconnlimit": 12,
        "rolcanlogin": True,
        "rolsuper": False,
        "rolcreaterole": False,
        "rolcreatedb": False,
        "rolreplication": False,
        "rolbypassrls": False,
        "reserved_access": False,
    }


@pytest.mark.parametrize("setting", [*SERVER_SETTINGS, *SESSION_SETTINGS])
def test_changed_database_limit_fails_gate(setting: str) -> None:
    settings = SERVER_SETTINGS | SESSION_SETTINGS
    assert all(database_checks(settings, role(), "read_app").values())
    settings[setting] = "1" if settings[setting] == "0" else "0"
    assert not all(database_checks(settings, role(), "read_app").values())


@pytest.mark.parametrize("attribute", list(role()))
def test_unexpected_role_privileges_fail_gate(attribute: str) -> None:
    value = role()
    value[attribute] = {
        "rolname": "read_lab_migrator",
        "rolconnlimit": -1,
        "rolcanlogin": False,
    }.get(attribute, True)
    assert not all(database_checks(SERVER_SETTINGS | SESSION_SETTINGS, value, "read_app").values())


def test_connection_failure_does_not_echo_details(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise psycopg.OperationalError("PRIVATE CONNECTION DETAILS")

    monkeypatch.setattr("service_desk.core.database.psycopg.connect", fail)
    with pytest.raises(RuntimeError, match="^Database capacity check failed$") as caught:
        check_database("private-dsn", "read_app")
    assert caught.value.__suppress_context__
