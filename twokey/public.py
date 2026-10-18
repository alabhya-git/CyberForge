"""Public entry point: the control app behind HTTP Basic authentication.

Used by the single-container deployment (scripts/serve_all.py). `/healthz` stays open
for platform health checks; every other path, the UI included, needs the demo
password. Kept separate from control.py so the benchmarked control source is unchanged.
"""
from __future__ import annotations

import base64
import hmac
import os

from .control import app as control_app


USERNAME = os.getenv("TWOKEY_DEMO_USER", "judge")
PASSWORD = os.getenv("TWOKEY_DEMO_PASSWORD", "")
OPEN = os.getenv("TWOKEY_ALLOW_OPEN") == "1"
if not PASSWORD and not OPEN:
    raise RuntimeError("Set TWOKEY_DEMO_PASSWORD, or TWOKEY_ALLOW_OPEN=1 to serve the lab without a password")
EXPECTED = ("Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()).encode()
CHALLENGE = [(b"www-authenticate", b'Basic realm="TwoKey demo", charset="UTF-8"'), (b"content-type", b"text/plain; charset=utf-8")]


async def app(scope, receive, send):
    if scope["type"] == "http" and not OPEN and scope["path"] != "/healthz":
        supplied = dict(scope["headers"]).get(b"authorization", b"")
        if not hmac.compare_digest(supplied, EXPECTED):
            await send({"type": "http.response.start", "status": 401, "headers": CHALLENGE})
            await send({"type": "http.response.body", "body": b"TwoKey demo: sign in with the demo password."})
            return
    await control_app(scope, receive, send)
