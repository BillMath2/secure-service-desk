"""Pure configuration gate for the two credential-scoped read containers."""

from pathlib import Path
from typing import Any

from service_desk.app_network import OUTBOUND
from service_desk.app_network import PORTS as APP_PORTS
from service_desk.read_bootstrap import PORTS, destination


def firewall_matches(
    policy: dict[str, Any], service: str, host_ip: str, *, application: bool = False
) -> bool:
    """Compare the entire dedicated table, ignoring only volatile kernel handles."""
    address = destination(host_ip)
    table = "service_desk_app" if application else "service_desk_read"
    listener = APP_PORTS[service] if application else PORTS[service]
    destinations = OUTBOUND[service] if application else (15433, 19443)

    def match(left: dict[str, Any], right: Any, op: str = "==") -> dict[str, Any]:
        return {"match": {"op": op, "left": left, "right": right}}

    def rule(expressions: list[dict[str, Any]]) -> dict[str, Any]:
        return {"rule": {"family": "inet", "table": table, "chain": "output", "expr": expressions}}

    expected = [
        {"table": {"family": "inet", "name": table}},
        {
            "chain": {
                "family": "inet",
                "table": table,
                "name": "output",
                "type": "filter",
                "hook": "output",
                "prio": -150,
                "policy": "drop",
            }
        },
        rule(
            [
                match({"ct": {"key": "direction"}}, "reply"),
                match({"ct": {"key": "state"}}, "established", "in"),
                match({"payload": {"protocol": "tcp", "field": "sport"}}, listener),
                {"accept": None},
            ]
        ),
        *[
            rule(
                [
                    match({"payload": {"protocol": "ip", "field": "daddr"}}, address),
                    match({"payload": {"protocol": "tcp", "field": "dport"}}, port),
                    match({"ct": {"key": "state"}}, {"set": ["established", "new"]}),
                    {"accept": None},
                ]
            )
            for port in destinations
        ],
    ]
    actual = [
        {kind: {key: value for key, value in record.items() if key != "handle"}}
        for entry in policy.get("nftables", [])
        for kind, record in entry.items()
        if kind != "metainfo"
    ]
    return actual == expected


def deployment_checks(
    record: dict[str, Any],
    service: str,
    image: dict[str, Any],
    root: Path,
    *,
    application: bool = False,
) -> dict[str, bool]:
    config, host = record["Config"], record["HostConfig"]
    port = APP_PORTS[service] if application else PORTS[service]
    project = "app" if application else "reads"
    entrypoint = "app_bootstrap" if application else "read_bootstrap"
    expected = (
        str((root / (".lab/phase3-" + project) / service).resolve()).replace("\\", "/").lower()
    )
    sources = {expected}
    if len(expected) > 2 and expected[1] == ":":
        sources.add("/run/desktop/mnt/host/" + expected[0] + expected[2:])
    mounts = record["Mounts"]
    return {
        "running": record["State"]["Running"] is True,
        "pinned_image": config["Image"] == image["Id"] == record["Image"],
        "fixed_command": config["Entrypoint"]
        == ["python", "-I", "-B", "-m", "service_desk." + entrypoint]
        and config["Cmd"] == [service],
        "environment_from_image_only": config["Env"] == image["Config"]["Env"],
        "bootstrap_user": config["User"] == "0:0",
        "no_privilege": not host["Privileged"]
        and {cap.removeprefix("CAP_") for cap in host.get("CapAdd") or []}
        == {"NET_ADMIN", "SETUID", "SETGID", "SETPCAP"}
        and set(host["CapDrop"] or []) == {"ALL"}
        and "no-new-privileges:true" in host["SecurityOpt"],
        "private_process_namespace": not host.get("PidMode") and host.get("IpcMode") == "private",
        "root_read_only": host["ReadonlyRootfs"] is True,
        "resource_limits": host["Memory"] == 256 * 1024 * 1024
        and host["PidsLimit"] == 64
        and host["NanoCpus"] == 1000000000,
        "no_logs": host["LogConfig"]["Type"] == "none",
        "only_scoped_mount": len(mounts) == 1
        and mounts[0]["Type"] == "bind"
        and mounts[0]["Destination"] == "/run/desk"
        and mounts[0]["RW"] is False
        and mounts[0]["Source"].replace("\\", "/").lower() in sources,
        "loopback_port_only": host["PortBindings"]
        == {f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]},
        "own_network_only": set(record["NetworkSettings"]["Networks"])
        == {"service-desk-phase3-" + project + "_" + service},
    }
