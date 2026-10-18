# TwoKey — evidence-authorized, replay-verified incident response

TwoKey is a **local synthetic security lab**. It detects an unauthorized customer-record export, checks whether the observed evidence authorizes a proposed containment action, plans a low-disruption gateway policy, tests that policy against real attack and commerce requests in an isolated shadow instance, and requires two bound approvals before applying it to the protected gateway.

The current application implements the three scenarios in the build plan, a React operator interface, local process deployment, Docker Compose configuration, a real-model adapter when separately configured, and a deterministic 50-variant architecture benchmark. It has **not** run a live model benchmark unless a model key is supplied and that evaluation is performed. It does not connect to Mitigata, a payment processor, an EDR product, or real customer data.

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

For a public demonstration, put an authenticated operator front end in front of control and review the network, secret and session model first. The supplied Compose file is a **local** deployment. No public server or domain has been deployed.

## Model mode

Default: `TWOKEY_MODEL_MODE=disabled`. The investigator returns no proposal and the deterministic evidence/action catalog still drives the protected response. The UI labels the reference-agent comparison **not measured**. A manual Key 1 check in the Evidence tab is labeled **fault injection**; it is never counted as a model failure.

To use an Anthropic model, supply a valid key, a model identifier available to that account, and `TWOKEY_MODEL_MODE=live` before launching control. On Windows local deployment:

```powershell
$env:ANTHROPIC_API_KEY = '<your key>'
$env:TWOKEY_MODEL_ID = '<available model identifier>'
$env:TWOKEY_MODEL_MODE = 'live'
.\.venv\Scripts\python.exe scripts\local.py start
```

The model has no mutation tools. Its output is parsed as a proposal. Key 1 independently checks the action/evidence/target relationship; candidate enumeration does not depend on a valid model response. The unguarded reference agent is isolated in its own gateway and application instances and runs only when a live model produces a valid catalog proposal. Store no real customer data or credentials in the synthetic payload.

## Scenarios

- **S1:** observed unauthorized export with planted instruction. The full suite probes primary and alternate export routes, so the selected plan normally denies the compromised credential on the canonical export resource. Checkout, aggregate reporting and CFO export remain available.
- **S2:** the initial planning model covers only the primary route. The first path-only plan fails replay because the alternate route still leaks. The counterexample is added to the model, then a resource-level plan passes.
- **S3:** the operator requires an export using the same compromised credential and observable attributes to remain available. The planner returns an infeasible result and escalates. No policy is applied.

Each successful replay includes 12 attack probes and 40 semantic business assertions. These are **suite counts**, not independent users or a guarantee about future traffic. The post-apply live check reports synthetic exports before and after containment and confirms a new checkout.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\smoke.py
```

The smoke run checks S1, S2 and S3, real replay counts, a model-independent rejection of the unrelated payments target, blocked direct policy mutation, tampered-plan rejection and unsafe-undo rejection.

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

For a short visual backup of S1 and S2, run `python scripts/record_demo.py` after the benchmark. It uses Playwright and an installed Chrome browser, then saves screenshots and `artifacts/twokey-demo.webm`. This recording presents actual local runs and retains the visible model-mode label.

## Security boundary and limits

The lab assumes trusted application code, operator policy, detector, gateway, verifier and host. Gateway-collected facts have collection integrity, but the attacker can choose requests and may possess the synthetic credential. Client-written text and values extracted from it keep their attacker-influenced label. The Key 1 verifier checks target binding and freshness, while Key 2 verifies the specified finite suite and environment. The two HMAC approvals are distinct machine approvals on one host, not independent organizations or formal threshold cryptography.

The current narrow S1 policy is a quarantine rule. The **Undo supplementary policy** operation refuses to remove that sole rule, since that would reopen the compromised export. If an authorized applied plan includes the quarantine plus another restriction, the endpoint can verify and remove only the extra restriction. **Reset lab** is separate and destroys synthetic state.

Replay adds response time while the attacker may continue exporting. The run artifact counts pre-containment exports, post-containment exports and measured duration. This prototype does not prove zero downtime, zero leakage, production safety, insurer savings or legal compliance.

## Architecture and source

- [Full implementation specification](docs/TWOKEY_BUILD_PLAN.md)
- [Execution and deployment playbook](docs/TWOKEY_EXECUTION_PLAYBOOK.md)
- [Coding packets](docs/TWOKEY_CODING_PACKETS.md)

The product story was derived from the supplied TwoKey CyberForge idea deck. The evidence/authority boundary is informed by [CaMeL](https://arxiv.org/abs/2503.18813). Planning uses [Z3 Optimize](https://microsoft.github.io/z3guide/docs/optimization/combiningobjectives/). This code does not claim to implement CaMeL or to inherit its formal guarantees.

Third-party runtime packages are declared in `requirements.txt` and `web/package-lock.json`. The original implementation was produced with Codex assistance for this workspace. Review third-party licenses and disclose assistance according to the hackathon submission rules.
