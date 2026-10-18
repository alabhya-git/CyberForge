# TwoKey — evidence-authorized, replay-verified incident response

TwoKey is a **local synthetic security lab**. It detects an unauthorized customer-record export, checks whether the observed evidence authorizes a proposed containment action, plans a low-disruption gateway policy, tests that policy against real attack and commerce requests in an isolated shadow instance, and requires two bound approvals before applying it to the protected gateway.

The current application implements the three scenarios in the build plan, operator-editable business requirements with illustrative ₹/hour interruption costs, measured shadow replays of broader responses, a React operator interface, local process deployment, Docker Compose configuration, a real-model adapter when separately configured, and a deterministic 50-variant architecture benchmark. It has **not** run a live model benchmark unless a model key is supplied and that evaluation is performed. It does not connect to Mitigata, a payment processor, an EDR product, or real customer data.

## Current local deployment

On this Windows workspace, the app can be started with the existing `.venv` and built `web/dist`:

```powershell
.\.venv\Scripts\python.exe scripts\local.py start
# Visit http://127.0.0.1:8100
.\.venv\Scripts\python.exe scripts\smoke.py
.\.venv\Scripts\python.exe scripts\local.py status
.\.venv\Scripts\python.exe scripts\local.py stop
```

The launcher starts eight loopback-only processes: three commerce instances, three gateways, verifier and control. Logs, policy files, databases and run artifacts are under `.runtime/`. The protected live gateway is on 8101, shadow gateway 8102, reference gateway 8103, control UI 8100, verifier 8300 and commerce on 8201–8203. Local loopback ports and default demo secrets are appropriate only for a personal demonstration machine. Do not expose this launcher on a shared or public host.

The run button resets the synthetic instances before each scenario. The **Reset lab** button clears synthetic data and policies. It is distinct from incident-policy rollback. Individual run artifacts remain in `.runtime/runs/` and can be downloaded from the UI.

### Rebuild from a clean Python/Node environment

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd web
npm ci
npm run build
cd ..
.\.venv\Scripts\python.exe scripts\local.py start
```

The current workspace used a portable Node 24 distribution under `.tools/` because Node is not installed system-wide. That folder is excluded from version control; on another machine, install a compatible Node release or use Docker for the frontend build.

### Docker Compose deployment

Docker is **not installed on the current Windows machine**, so the Compose release is supplied but has not been built or run here. On a machine with Docker Engine and Compose:

```powershell
Copy-Item .env.example .env
# Replace all three secrets in .env with distinct random values.
docker compose config
docker compose up --build -d
docker compose ps
# Visit http://127.0.0.1:8100
docker compose down
```

Only control is published, explicitly on loopback. The fixture network is internal. The control container has a separate egress network so the optional model adapter can contact its provider. Each commerce/gateway instance has a separate persistent volume. Containers run as a non-root user with dropped capabilities and a read-only root filesystem.

The supplied Compose file is a **local** deployment.

### Hosted demo: one container behind a password

The default Docker image runs the whole lab in one container via `scripts/serve_all.py`:
- The internal services listen on loopback only. With the model disabled, the two reference-agent services are skipped (six processes, about half a gigabyte or less), which fits small hosts such as Render's free tier.
- The control UI listens on `$PORT` (default 7860) behind HTTP Basic authentication: user `judge`, password from `TWOKEY_DEMO_PASSWORD`.
- `/healthz` stays open for platform health checks.
- Signing secrets are generated fresh on each boot unless supplied.
- If any service exits, the container exits so the platform restarts it.

Check it end to end without Docker; this stops the local stack first because it reuses the same internal ports:

```powershell
.\.venv\Scripts\python.exe scripts\local.py stop
$env:TWOKEY_DEMO_PASSWORD = 'pick-a-password'; $env:TWOKEY_RUNTIME_DIR = "$PWD\.runtime\serve"
.\.venv\Scripts\python.exe scripts\serve_all.py --self-test
```

**Hugging Face Spaces (recommended, free, no local Docker).** Hugging Face builds the Dockerfile on its servers:

```powershell
.\.venv\Scripts\python.exe -m pip install huggingface_hub
huggingface-cli login            # paste a token with write access
.\.venv\Scripts\python.exe scripts\deploy_hf_space.py --space twokey-cyberforge
```

The script creates the Space, stores the password as a Space secret (generating and printing one if `TWOKEY_DEMO_PASSWORD` is unset) and uploads the build files. The first build takes a few minutes. Share the direct `https://<owner>-twokey-cyberforge.hf.space` address with judges; browsers may not show a password prompt inside the embedded Space page. A public Space also shows its source files; `--private` hides both the code and the app from people without access.

**Render.** Push the repository to GitHub and create a Blueprint from `render.yaml`, setting `TWOKEY_DEMO_PASSWORD` when prompted.

**Vercel is not suitable.** Its serverless functions cannot run eight long-lived services with background threads and local SQLite state.

Keep `TWOKEY_MODEL_MODE=disabled` on a shared deployment unless the password is private: in live mode, everyone who signs in spends your model credits (`deploy_hf_space.py --with-model` enables it).

## Model mode

Default: `TWOKEY_MODEL_MODE=disabled`. The investigator returns no proposal and the deterministic evidence/action catalog still drives the protected response. The UI labels the reference-agent comparison **not measured**. A manual Key 1 check in the Evidence tab is labeled **fault injection**; it is never counted as a model failure.

To use an Anthropic model, supply a valid key and `TWOKEY_MODEL_MODE=live` before launching control. The default model is `claude-opus-5-5`; override it with `TWOKEY_MODEL_ID`. On Windows local deployment:

```powershell
$env:ANTHROPIC_API_KEY = '<your key>'
$env:TWOKEY_MODEL_MODE = 'live'
.\.venv\Scripts\python.exe scripts\local.py start
```

The adapter requests JSON-schema structured output whose `action_id` is an enum of the fixed catalog, sends no sampling parameters (current Claude models reject `temperature`), and opts into server-side refusal fallback (`fallbacks: "default"`) on models that support it. A refusal, truncated output, invalid JSON, unknown action or provider error is recorded with its status and never becomes a proposal. Security-incident prompts can trip the provider's cyber safety classifier; a recorded `refused` status is an expected, visible outcome rather than a crash.

The model has no mutation tools. Its output is parsed as a proposal. Key 1 independently checks the action/evidence/target relationship; candidate enumeration does not depend on a valid model response. The unguarded reference agent is isolated in its own gateway and application instances and runs only when a live model produces a valid catalog proposal. Store no real customer data or credentials in the synthetic payload.

## Scenarios

- **S1:** observed unauthorized export with planted instruction. The full suite probes primary and alternate export routes, so the selected plan normally denies the compromised credential on the canonical export resource. Checkout, aggregate reporting and CFO export remain available.
- **S2:** the initial planning model covers only the primary route. The first path-only plan fails replay because the alternate route still leaks. The counterexample is added to the model, then a resource-level plan passes.
- **S3:** the operator requires an export using the same compromised credential and observable attributes to remain available. The planner returns an infeasible result and escalates. No policy is applied.

Each successful replay includes 12 attack probes and 40 semantic business assertions. These are **suite counts**, not independent users or a guarantee about future traffic. The post-apply live check reports synthetic exports before and after containment and confirms a new checkout.

### Business requirements and rupee estimates

Four business workflows are modeled: customer checkout, the sales summary report, the CFO customer export, and a customer export using the reports key (the same credential and route the attacker uses). Before a run, the operator marks each workflow as required or interruptible and enters an illustrative ₹/hour contribution. These figures are **operator assumptions, not measured losses**.

- Required workflows are hard solver constraints and are bound into the plan digest, so changing one invalidates both receipts. Key 2 needs every attack probe contained and every assertion of a required workflow to pass. Failures in interruptible workflows are recorded as accepted interruptions.
- The solver's first objective is the rupee interruption of interruptible workflows, counted once per workflow. Disruption weight, blast radius, action count and a stable tie-break follow, lexicographically.
- When no plan exists, a minimal unsatisfiable core names the specific requirements in conflict, for example "Block the alias export path" versus "Keep the reports-key export working".

The **Business impact** tab shows three things:

1. **Why this plan:** the planning model for every catalog action.
2. **What broader responses actually break:** a button that replays up to four broader authorized responses in the isolated shadow lab against the same suite. These comparison plans never receive Key 1 and are never applied.
3. **Re-evaluate this incident:** a judge control that re-runs the solver on a finished incident under changed rules. It never modifies the live gateway. A conflict keeps the current quarantine and escalates. A different plan requires a fresh verified run, offered as one click.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\smoke.py
```

The smoke run checks:
- S1, S2 and S3, with real replay counts;
- model-independent rejection of the unrelated payments target;
- blocked direct policy mutation, tampered-plan rejection and unsafe-undo rejection;
- a conflicting requirement change that escalates without touching the live policy;
- measured broader-response replays, including storefront isolation breaking checkout.

The unit tests (`tests/`) cover:
- Key 1 target binding;
- receipt binding;
- the solver against an exhaustive subset oracle across three rupee cost profiles;
- the protected executor in-process: no credential, forged, swapped or cross-plan receipts, tampered actions or requirements, stale revision, wrong epoch, expired plan, idempotent retry, plan-ID reuse, restart persistence;
- requirement validation and digest binding, legacy-digest compatibility and minimal conflict cores;
- the model adapter against a fake client: structured-output request, refusal, truncation, invalid JSON, unknown action and provider error.

Download a contained run from the UI, then verify its evidence digest, both historical receipt signatures, replay report binding, measured assertions and applied-plan digest:

```powershell
$runId = 'paste-run-id-here'
.\.venv\Scripts\python.exe scripts\verify_bundle.py ".runtime\runs\$runId.json"
```

For a Compose run with custom signing secrets, provide the corresponding `TWOKEY_KEY1_SECRET` and `TWOKEY_KEY2_SECRET` environment variables to the verifier script. This historical audit check accepts an expired receipt's valid original signature; the live gateway still rejects expired receipts during application.

The fixed 50-variant manifest is in `evaluation/variants.json`: 10 development variants and 40 held-out variants from distinct families. With model mode disabled, run the **architecture** evaluation with:

```powershell
.\.venv\Scripts\python.exe evaluation\benchmark.py --limit 50
```

It performs 50 sequential full S1 runs and preserves one JSONL row per variant under `artifacts/`. It can resume after interruption. It reports model trials as zero; it does not claim the planned 120-run live-model comparison. The benchmark may take several minutes because each case performs real HTTP replay.

With live model mode configured, `python evaluation/model_benchmark.py --limit 60` runs the separate 50-variant and 10-benign-control comparison. Each case invokes the same configured model for the reference agent and TwoKey, giving 120 planned system trials. This can incur provider charges. Report the actual completed count and provider errors; no live-model result is bundled by default.

For a short visual backup, run `python scripts/record_demo.py` after the benchmark. It covers S1, the measured broader responses, a requirement conflict and S2. It needs `pip install playwright` and an installed Chrome browser; it uses Chrome directly, so no Playwright browser download is required. It saves screenshots and `artifacts/twokey-demo.webm`. This recording presents actual local runs and retains the visible model-mode label.

## Security boundary and limits

The lab assumes trusted application code, operator policy, detector, gateway, verifier and host. Gateway-collected facts have collection integrity, but the attacker can choose requests and may possess the synthetic credential. Client-written text and values extracted from it keep their attacker-influenced label. The Key 1 verifier checks target binding and freshness, while Key 2 verifies the specified finite suite and environment. The two HMAC approvals are distinct machine approvals on one host, not independent organizations or formal threshold cryptography.

The current narrow S1 policy is a quarantine rule. The **Undo supplementary policy** operation refuses to remove that sole rule, since that would reopen the compromised export. If an authorized applied plan includes the quarantine plus another restriction, the endpoint can verify and remove only the extra restriction. **Reset lab** is separate and destroys synthetic state.

Replay adds response time while the attacker may continue exporting. The run artifact counts pre-containment exports, post-containment exports and measured duration. This prototype does not prove zero downtime, zero leakage, production safety, insurer savings or legal compliance.

## Architecture and source

- [Full implementation specification](docs/TWOKEY_BUILD_PLAN.md)
- [Execution and deployment playbook](docs/TWOKEY_EXECUTION_PLAYBOOK.md)
- [Coding packets](docs/TWOKEY_CODING_PACKETS.md)

The product story was derived from the supplied TwoKey CyberForge idea deck. The evidence/authority boundary is informed by [CaMeL](https://arxiv.org/abs/2503.18813). Planning uses [Z3 Optimize](https://microsoft.github.io/z3guide/docs/optimization/combiningobjectives/). This code does not claim to implement CaMeL or to inherit its formal guarantees.

Third-party runtime packages are declared in `requirements.txt` and `web/package-lock.json`. The original implementation was produced with Codex assistance for this workspace. Claude Code assisted with the continuation: business requirements and rupee estimates, conflict explanation, measured alternative replays, the model-adapter fix, executor and adapter tests, and the Business impact UI. Review third-party licenses and disclose assistance according to the hackathon submission rules.
