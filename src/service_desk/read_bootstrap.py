"""Install the read namespace's outbound policy before starting any listener."""

import argparse
import ipaddress
import os
import socket
import subprocess

PORTS = {"knowledge": 19482, "tickets": 19483}


def destination(value: str) -> str:
    address = ipaddress.IPv4Address(value)
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise ValueError("Invalid read dependency address")
    return str(address)


def rules(service: str, host_ip: str) -> str:
    port = PORTS[service]
    address = destination(host_ip)
    # After conntrack (-200), before Docker's DNS destination translation (-100).
    return f"""
add table inet service_desk_read
delete table inet service_desk_read
table inet service_desk_read {{
    chain output {{
        type filter hook output priority -150; policy drop;
        ct direction reply ct state established tcp sport {port} accept
        ip daddr {address} tcp dport 15433 ct state {{ new, established }} accept
        ip daddr {address} tcp dport 19443 ct state {{ new, established }} accept
    }}
}}
"""


def launch(service: str) -> None:
    # Resolve the fixed trusted destination only during bootstrap. Runtime DNS is denied.
    host_ip = destination(socket.gethostbyname("host.docker.internal"))
    subprocess.run(
        ["/usr/sbin/nft", "-f", "-"],
        input=rules(service, host_ip),
        text=True,
        capture_output=True,
        timeout=5,
        check=True,
    )
    os.execv(
        "/usr/bin/setpriv",
        [
            "setpriv",
            "--reuid=65532",
            "--regid=65532",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "python",
            "-I",
            "-B",
            "-m",
            "service_desk.read_process",
            service,
            host_ip,
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=tuple(PORTS))
    args = parser.parse_args()
    try:
        launch(args.service)
    except Exception:
        raise SystemExit("Read isolation setup failed") from None


if __name__ == "__main__":
    main()
