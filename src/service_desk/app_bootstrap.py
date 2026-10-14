"""Install per-role outbound policy and discard all setup privileges before serving."""

import argparse
import os
import socket
import subprocess

from service_desk.app_network import OUTBOUND, PORTS
from service_desk.read_bootstrap import destination


def rules(role: str, host_ip: str) -> str:
    address = destination(host_ip)
    allow = "\n".join(
        f"ip daddr {address} tcp dport {port} ct state {{ new, established }} accept"
        for port in OUTBOUND[role]
    )
    return f"""
add table inet service_desk_app
delete table inet service_desk_app
table inet service_desk_app {{
 chain output {{
  type filter hook output priority -150; policy drop;
  ct direction reply ct state established tcp sport {PORTS[role]} accept
  {allow}
 }}
}}
"""


def launch(role: str) -> None:
    host_ip = destination(socket.gethostbyname("host.docker.internal"))
    subprocess.run(
        ["/usr/sbin/nft", "-f", "-"],
        input=rules(role, host_ip),
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
            "service_desk.app_process",
            role,
            host_ip,
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=tuple(PORTS))
    args = parser.parse_args()
    try:
        launch(args.role)
    except Exception:
        raise SystemExit("Application isolation setup failed") from None


if __name__ == "__main__":
    main()
