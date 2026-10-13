"""Prepare isolated, temporary Keycloak admin credentials for the rotation probe only."""

import json
import secrets
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1] / ".lab/phase2-rotation"
    root.mkdir(parents=True, exist_ok=True)
    path = root / "credentials.json"
    if not path.exists():
        path.write_text(
            json.dumps(
                {"username": "phase2-rotation-admin", "password": secrets.token_urlsafe(32)}
            ),
            encoding="utf-8",
        )
    credentials = json.loads(path.read_text())
    (root / "bootstrap.env").write_text(
        "KC_BOOTSTRAP_ADMIN_USERNAME=" + credentials["username"] + "\n"
        "KC_BOOTSTRAP_ADMIN_PASSWORD=" + credentials["password"] + "\n",
        encoding="utf-8",
    )
    print("Prepared disposable rotation-probe credentials; application credentials unchanged.")


if __name__ == "__main__":
    main()
