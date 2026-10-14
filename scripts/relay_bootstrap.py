"""Trusted Linux-only bootstrap: install namespace policy before dropping privileges."""

import ipaddress
import os
import socket
import subprocess


def rules(model_ip: str) -> str:
    address = ipaddress.IPv4Address(model_ip)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("Invalid model address")
    # One atomic transaction, including on a restart with an existing table.
    # Conntrack runs at -200; Docker's DNS DNAT runs at -100. Filter between them.
    return f"""
add table inet service_desk_relay
delete table inet service_desk_relay
table inet service_desk_relay {{
    chain output {{
        type filter hook output priority -150; policy drop;
        ct direction reply ct state established tcp sport 8080 accept
        ip daddr {address} tcp dport 11434 ct state {{ new, established }} accept
    }}
}}
"""


def main() -> None:
    # Resolve only a trusted Compose service, before any listener or request worker exists.
    model_ip = socket.gethostbyname("model")
    subprocess.run(
        ["/usr/sbin/nft", "-f", "-"],
        input=rules(model_ip),
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
            "/relay.py",
            model_ip,
        ],
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Relay isolation setup failed") from None
