"""Run the whole TwoKey lab in one container or VM.

The internal services listen on loopback only (the two reference-agent services are
skipped unless the model is live); the password-protected control UI
listens on 0.0.0.0:$PORT (default 7860, the Hugging Face Spaces port). Signing secrets
are generated fresh on every boot unless supplied. If any service exits, everything is
stopped and the launcher exits non-zero so the hosting platform restarts the container.

    python scripts/serve_all.py               # serve until stopped
    python scripts/serve_all.py --self-test   # start, check auth and a full S1 run, stop
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INTERNAL = [
    ("commerce-live", "twokey.commerce:app", "live", 8201, {}),
    ("commerce-shadow", "twokey.commerce:app", "shadow", 8202, {}),
    ("commerce-baseline", "twokey.commerce:app", "baseline", 8203, {}),
    ("gateway-live", "twokey.gateway:app", "live", 8101, {"TWOKEY_COMMERCE_URL": "http://127.0.0.1:8201"}),
    ("gateway-shadow", "twokey.gateway:app", "shadow", 8102, {"TWOKEY_COMMERCE_URL": "http://127.0.0.1:8202"}),
    ("gateway-baseline", "twokey.gateway:app", "baseline", 8103, {"TWOKEY_COMMERCE_URL": "http://127.0.0.1:8203"}),
    ("verifier", "twokey.verifier:app", "verifier", 8300, {}),
]
SECRETS = ("TWOKEY_INTERNAL_SECRET", "TWOKEY_KEY1_SECRET", "TWOKEY_KEY2_SECRET")


def request(url: str, auth: str | None = None, body: dict | None = None) -> tuple[int, dict | str]:
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method="POST" if body is not None else "GET")
    req.add_header("content-type", "application/json")
    if auth:
        req.add_header("authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            text = response.read().decode()
            status = response.status
    except urllib.error.HTTPError as exc:
        text, status = exc.read().decode(), exc.code
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


def healthy(port: int) -> bool:
    try:
        return request(f"http://127.0.0.1:{port}/healthz")[0] == 200
    except (urllib.error.URLError, OSError):
        return False


def self_test(port: int, env: dict) -> None:
    base = f"http://127.0.0.1:{port}"
    auth = "Basic " + base64.b64encode(f"{env.get('TWOKEY_DEMO_USER', 'judge')}:{env.get('TWOKEY_DEMO_PASSWORD', '')}".encode()).decode()
    assert request(base + "/healthz")[0] == 200, "health check must stay open"
    if env.get("TWOKEY_ALLOW_OPEN") != "1":
        assert request(base + "/")[0] == 401, "UI must require the demo password"
        assert request(base + "/api/state")[0] == 401, "API must require the demo password"
        assert request(base + "/", auth="Basic d3Jvbmc6d3Jvbmc=")[0] == 401, "wrong password must fail"
    assert request(base + "/", auth=auth)[0] == 200, "UI must load with the password"
    status, created = request(base + "/api/runs", auth=auth, body={"scenario": "s1"})
    assert status == 200, created
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        run = request(base + f"/api/runs/{created['id']}", auth=auth)[1]
        if run["status"] in {"contained", "escalated", "blocked", "error", "recovery_required"}:
            break
        time.sleep(.5)
    assert run["status"] == "contained", run.get("reason")
    replay = run["replays"][-1]
    print(f"SELF-TEST PASS: password gate enforced; S1 contained with {sum(x['passed'] for x in replay['attack'])}/12 attack probes "
          f"and {sum(x['passed'] for x in replay['business'])}/40 business assertions", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    port = int(os.getenv("PORT", "7860"))
    if port in {p for *_, p, _ in INTERNAL}:
        raise SystemExit(f"PORT {port} collides with an internal service port")
    env = os.environ.copy()
    for name in SECRETS:
        env.setdefault(name, secrets.token_hex(32))
    if len({env[name] for name in SECRETS}) != len(SECRETS):
        raise SystemExit("the internal, Key 1 and Key 2 secrets must be distinct")
    if not env.get("TWOKEY_DEMO_PASSWORD") and env.get("TWOKEY_ALLOW_OPEN") != "1":
        raise SystemExit("Set TWOKEY_DEMO_PASSWORD (a Space/Render secret), or TWOKEY_ALLOW_OPEN=1 to serve without a password")
    runtime = Path(env.setdefault("TWOKEY_RUNTIME_DIR", "/tmp/twokey-runtime"))
    runtime.mkdir(parents=True, exist_ok=True)
    start_timeout = float(env.get("TWOKEY_START_TIMEOUT", "240"))
    services = INTERNAL
    if env.get("TWOKEY_MODEL_MODE", "disabled") != "live":
        # The reference-agent lab only runs when a live model proposes an action. Without a
        # model, skip its two processes (memory on small hosts) and point control's routine
        # resets at the shadow lab, which the verifier resets before every replay anyway.
        services = [s for s in INTERNAL if not s[0].endswith("-baseline")]
        env["TWOKEY_BASELINE_GATEWAY"] = "http://127.0.0.1:8102"
        env["TWOKEY_BASELINE_COMMERCE"] = "http://127.0.0.1:8202"

    children: list[tuple[str, subprocess.Popen]] = []

    def stop(*_: object) -> None:
        for _, process in reversed(children):
            if process.poll() is None:
                process.terminate()
        for _, process in children:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    signal.signal(signal.SIGTERM, lambda *_: (stop(), sys.exit(0)))
    try:
        # Start the internal services together (faster boot on small CPUs), then wait for all.
        for name, module, role, internal_port, extra in services:
            child_env = {**env, "TWOKEY_ROLE": role, "TWOKEY_PORT": str(internal_port), **extra}
            process = subprocess.Popen([sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1", "--port", str(internal_port), "--no-access-log"], cwd=ROOT, env=child_env)
            children.append((name, process))
        deadline = time.monotonic() + start_timeout
        for (name, process), (*_, internal_port, _) in zip(children, services):
            while not healthy(internal_port):
                if process.poll() is not None or time.monotonic() > deadline:
                    raise SystemExit(f"{name} failed to start")
                time.sleep(.5)
        control_env = {**env, "TWOKEY_ROLE": "control", "TWOKEY_PORT": str(port)}
        control = subprocess.Popen([sys.executable, "-m", "uvicorn", "twokey.public:app", "--host", "0.0.0.0", "--port", str(port), "--no-access-log", "--proxy-headers"], cwd=ROOT, env=control_env)
        children.append(("control", control))
        deadline = time.monotonic() + start_timeout
        while not healthy(port):
            if control.poll() is not None or time.monotonic() > deadline:
                raise SystemExit("control failed to start")
            time.sleep(.5)
        print(f"TwoKey lab ready on port {port}: {len(children)} processes (model mode: {env.get('TWOKEY_MODEL_MODE', 'disabled')})", flush=True)
        if args.self_test:
            self_test(port, env)
            return
        while True:
            for name, process in children:
                if process.poll() is not None:
                    raise SystemExit(f"{name} exited with code {process.returncode}; stopping the lab")
            time.sleep(2)
    finally:
        stop()


if __name__ == "__main__":
    main()
