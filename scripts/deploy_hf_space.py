"""Deploy the TwoKey lab to a Hugging Face Docker Space.

Hugging Face builds the Dockerfile on its servers, so no local Docker is needed. The
whole lab runs in one container behind the demo password (scripts/serve_all.py).

Prerequisite: a Hugging Face *write* token, via `huggingface-cli login` or HF_TOKEN.

    python scripts/deploy_hf_space.py --space twokey-cyberforge
    python scripts/deploy_hf_space.py --space twokey-cyberforge --private
    python scripts/deploy_hf_space.py --space twokey-cyberforge --with-model   # needs ANTHROPIC_API_KEY

The demo password is taken from TWOKEY_DEMO_PASSWORD, or generated and printed once.
It is stored as a Space secret, never in the repository. A public Space also shows
its source files to anyone; use --private to keep both the code and the app private.
"""
from __future__ import annotations

import argparse
import os
import secrets
import shutil
import tempfile
from pathlib import Path

from huggingface_hub import HfApi


ROOT = Path(__file__).resolve().parent.parent
FILES = [
    "Dockerfile", ".dockerignore", "requirements.txt", "twokey", "scripts/serve_all.py",
    "web/package.json", "web/package-lock.json", "web/index.html", "web/tsconfig.json", "web/vite.config.ts", "web/src",
]
SPACE_README = """---
title: TwoKey
emoji: 🔑
colorFrom: yellow
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
short_description: Evidence-authorized, replay-verified incident response lab
---

# TwoKey — Mitigata CyberForge demo

Every automated containment action needs two keys:

1. **Evidence authority.** The action must be backed by gateway-observed evidence; attacker-written text cannot authorize a target.
2. **Business replay.** The plan must stop the attack and keep the required business workflows working in an isolated shadow replay.

The live gateway applies a plan only when both signed receipts bind that exact plan.

This Space runs a **synthetic** commerce lab: fake customers, a local payment ledger and no external systems. Sign in with the demo password you were given (user `judge`). Open the app at its direct `*.hf.space` address if the embedded page does not show a sign-in prompt.
"""


def stage(target: Path) -> None:
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    for item in FILES:
        source, destination = ROOT / item, target / item
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination, ignore=ignore)
        else:
            shutil.copy2(source, destination)
    (target / "README.md").write_text(SPACE_README, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--space", required=True, help="Space name, for example twokey-cyberforge")
    parser.add_argument("--private", action="store_true", help="only you (and collaborators) can open the Space")
    parser.add_argument("--with-model", action="store_true", help="enable live model mode using ANTHROPIC_API_KEY from the environment")
    args = parser.parse_args()

    api = HfApi()
    owner = api.whoami()["name"]
    repo_id = f"{owner}/{args.space}"
    api.create_repo(repo_id, repo_type="space", space_sdk="docker", private=args.private, exist_ok=True)

    generated = not os.getenv("TWOKEY_DEMO_PASSWORD")
    password = os.getenv("TWOKEY_DEMO_PASSWORD") or secrets.token_urlsafe(12)
    api.add_space_secret(repo_id, "TWOKEY_DEMO_PASSWORD", password, description="TwoKey demo password (user: judge)")
    if args.with_model:
        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise SystemExit("--with-model needs ANTHROPIC_API_KEY in the environment")
        api.add_space_secret(repo_id, "ANTHROPIC_API_KEY", key)
        api.add_space_variable(repo_id, "TWOKEY_MODEL_MODE", "live")
    else:
        api.add_space_variable(repo_id, "TWOKEY_MODEL_MODE", "disabled")

    with tempfile.TemporaryDirectory() as staging:
        stage(Path(staging))
        api.upload_folder(folder_path=staging, repo_id=repo_id, repo_type="space", commit_message="Deploy TwoKey lab")

    info = api.space_info(repo_id)
    host = info.host or f"https://{(info.subdomain or repo_id.replace('/', '-')).lower()}.hf.space"
    print(f"Space:     https://huggingface.co/spaces/{repo_id} ({'private' if args.private else 'public'})")
    print(f"App:       {host}")
    print("Sign in:   user 'judge'")
    if generated:
        print(f"Password:  {password}   (generated; stored as a Space secret, shown only now)")
    print("The first build takes a few minutes; watch the Logs tab on the Space page.")


if __name__ == "__main__":
    main()
