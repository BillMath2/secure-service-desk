"""Independent process deadline; kills the experimental runner if it hangs."""

import subprocess
import sys


def supervise(command: list[str], seconds: float = 600) -> int:
    try:
        # No raw prompts, tool bodies, model output or SDK exceptions in Docker logs.
        return subprocess.run(
            command,
            timeout=seconds,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    except subprocess.TimeoutExpired:
        return 124


if __name__ == "__main__":
    sys.exit(supervise([sys.executable, "-m", "lab_baseline.runner", *sys.argv[1:]]))
