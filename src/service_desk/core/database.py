"""Trusted database capacity defaults and a read-only service startup gate."""

from typing import Any

import psycopg
from psycopg import sql

LOGIN_LIMITS = {
    "read_app": 12,
    "read_gateway": 12,
    "read_knowledge": 12,
    "read_tickets": 12,
    "read_publisher": 6,
    "access_workflow": 6,
    "access_proposals": 4,
    "access_executor": 4,
    "access_lifecycle": 2,
    "access_collector": 4,
    "access_delivery": 2,
}
SERVER_SETTINGS = {
    "max_connections": "40",
    "superuser_reserved_connections": "4",
    "reserved_connections": "0",
    "authentication_timeout": "5s",
}
# These are service defaults, not protection against a client with arbitrary SQL:
# PostgreSQL permits users to change their own USERSET timeout parameters.
SESSION_SETTINGS = {
    "statement_timeout": "10s",
    "lock_timeout": "3s",
    "transaction_timeout": "15s",
    "idle_in_transaction_session_timeout": "5s",
    "idle_session_timeout": "30s",
}


def configure_login(db: psycopg.Connection[tuple[Any, ...]], login: str) -> None:
    """Apply on both first preparation and upgrade; caller owns the transaction."""
    limit = LOGIN_LIMITS[login]
    db.execute(
        sql.SQL("ALTER ROLE {} CONNECTION LIMIT {}").format(
            sql.Identifier(login), sql.Literal(limit)
        )
    )
    for name, value in SESSION_SETTINGS.items():
        db.execute(
            sql.SQL("ALTER ROLE {} SET {} = {}").format(
                sql.Identifier(login), sql.Identifier(name), sql.Literal(value)
            )
        )


def database_checks(
    settings: dict[str, str], role: dict[str, Any], expected_login: str
) -> dict[str, bool]:
    return {
        "server_connection_policy": all(settings.get(k) == v for k, v in SERVER_SETTINGS.items()),
        "session_timeout_defaults": all(settings.get(k) == v for k, v in SESSION_SETTINGS.items()),
        "service_login_bound": expected_login in LOGIN_LIMITS
        and role.get("rolname") == expected_login
        and role.get("rolconnlimit") == LOGIN_LIMITS[expected_login],
        "service_login_unprivileged": role.get("rolcanlogin") is True
        and all(
            role.get(k) is False
            for k in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls")
        )
        and role.get("reserved_access") is False,
    }


def check_database(dsn: str, expected_login: str) -> dict[str, bool]:
    """Use only the service credential. Never emit connection or exception details."""
    try:
        with psycopg.connect(dsn, connect_timeout=3, autocommit=True) as db:
            settings: dict[str, str] = dict(
                db.execute(
                    "SELECT name, current_setting(name) FROM unnest(%s::text[]) AS name",
                    (list(SERVER_SETTINGS) + list(SESSION_SETTINGS),),
                ).fetchall()
            )
            row = db.execute(
                "SELECT row_to_json(r) FROM (SELECT rolname,rolconnlimit,rolcanlogin,"
                "rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,"
                "pg_has_role(current_user,'pg_use_reserved_connections','USAGE') "
                "AS reserved_access "
                "FROM pg_roles WHERE rolname=current_user) r"
            ).fetchone()
            checks = database_checks(settings, row[0] if row else {}, expected_login)
    except psycopg.Error:
        raise RuntimeError("Database capacity check failed") from None
    if not all(checks.values()):
        raise RuntimeError("Database capacity check failed")
    return checks
