"""Start/stop the isolated local TwoKey services without Docker."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / ".runtime"
LOGS = RUNTIME / "logs"
MANIFEST = RUNTIME / "local-processes.json"
SERVICES = [
    ("commerce-live", "twokey.commerce:app", "live", 8201, {}),
    ("commerce-shadow", "twokey.commerce:app", "shadow", 8202, {}),
    ("commerce-baseline", "twokey.commerce:app", "baseline", 8203, {}),
    ("gateway-live", "twokey.gateway:app", "live", 8101, {"TWOKEY_COMMERCE_URL": "http://127.0.0.1:8201"}),
    ("gateway-shadow", "twokey.gateway:app", "shadow", 8102, {"TWOKEY_COMMERCE_URL": "http://127.0.0.1:8202"}),
    ("gateway-baseline", "twokey.gateway:app", "baseline", 8103, {"TWOKEY_COMMERCE_URL": "http://127.0.0.1:8203"}),
    ("verifier", "twokey.verifier:app", "verifier", 8300, {}),
    ("control", "twokey.control:app", "control", 8100, {}),
]


def alive(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError):
        return False


def start() -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    if MANIFEST.exists():
        print("Existing process manifest found. Run stop before starting a new stack.")
        raise SystemExit(1)
    launched: list[dict] = []
    try:
        for name, module, role, port, extra in SERVICES:
            if alive(port):
                raise RuntimeError(f"port {port} already serves an application")
            environment = os.environ.copy()
            environment.update({"TWOKEY_ROLE": role, "TWOKEY_PORT": str(port), "TWOKEY_RUNTIME_DIR": str(RUNTIME), **extra})
            log = (LOGS / f"{name}.log").open("ab")
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            process = subprocess.Popen([sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1", "--port", str(port), "--no-access-log"], cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
            log.close()
            launched.append({"name": name, "pid": process.pid, "port": port})
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and not alive(port):
                if process.poll() is not None:
                    raise RuntimeError(f"{name} exited; inspect {LOGS / (name + '.log')}")
                time.sleep(.2)
            if not alive(port):
                raise RuntimeError(f"{name} did not become ready; inspect {LOGS / (name + '.log')}")
        MANIFEST.write_text(json.dumps(launched, indent=2), encoding="utf-8")
        print("TwoKey local stack ready: http://127.0.0.1:8100")
        print("Services:", ", ".join(item["name"] for item in launched))
    except Exception:
        for item in reversed(launched):
            try:
                os.kill(item["pid"], signal.SIGTERM)
            except OSError:
                pass
        raise


def stop() -> None:
    if not MANIFEST.exists():
        print("No local process manifest.")
        return
    items = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for item in reversed(items):
        try:
            os.kill(item["pid"], signal.SIGTERM)
            print("Stopped", item["name"])
        except OSError:
            print("Already stopped", item["name"])
    MANIFEST.unlink()


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "start"
    if command == "start":
        start()
    elif command == "stop":
        stop()
    elif command == "status":
        for name, _, _, port, _ in SERVICES:
            print(name, "ready" if alive(port) else "down")
    else:
        raise SystemExit("usage: python scripts/local.py start|stop|status")
