"""Network namespace probe; emits booleans only, never sends fixture content."""

import json
import socket
import sys


def reachable(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    target = sys.argv[1]
    checks = {
        "internal_service_reachable": reachable("knowledge", 8080),
        "external_tcp_denied": not reachable("1.1.1.1", 443),
        "external_dns_name_denied": not reachable("example.com", 443),
        "protected_network_denied": not reachable(target, 8080),
        "host_service_denied": not reachable("host.docker.internal", 15432),
    }
    print(json.dumps(checks))
    sys.exit(0 if all(checks.values()) else 1)
