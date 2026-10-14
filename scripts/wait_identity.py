"""Wait a bounded time for the lab issuer using the generated CA, without credentials."""

import ssl
import time

import httpx
from phase2_runtime import LOCAL

from service_desk.core.auth.lab import ISSUER


def main() -> None:
    deadline = time.monotonic() + 120
    with httpx.Client(
        verify=ssl.create_default_context(cafile=str(LOCAL / "tls/certificate.pem")),
        timeout=2,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get(ISSUER + "/.well-known/openid-configuration")
                if response.status_code == 200 and response.json().get("issuer") == ISSUER:
                    print("Local identity issuer ready.")
                    return
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(1)
    raise SystemExit("Local identity issuer did not become ready within 120 seconds")


if __name__ == "__main__":
    main()
